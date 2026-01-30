import asyncio
import hashlib
import json
import random
import time
import uuid

from fastapi import HTTPException
from starlette.concurrency import run_in_threadpool

from api.files import get_image_size, get_file_extension, determine_file_use_case
from api.models import model_proxy
from chatgpt.authorization import get_req_token, verify_token
from chatgpt.chatFormat import api_messages_to_chat, stream_response, format_not_stream_response, head_process_response
from chatgpt.chatLimit import check_is_limit, handle_request_limit
from chatgpt.fp import get_fp
from chatgpt.proofofWork import get_config, get_dpl, get_answer_token, get_requirements_token, cached_dpl, cached_build_number

from utils.Client import Client
from utils.Logger import logger
from utils.configs import (
    chatgpt_base_url_list,
    ark0se_token_url_list,
    sentinel_proxy_url_list,
    history_disabled,
    pow_difficulty,
    conversation_only,
    enable_limit,
    upload_by_url,
    auth_key,
    turnstile_solver_url,
    oai_language,
)


class _OaiEchoLogsTracker:
    """Tracks timing events for Oai-Echo-Logs header (H3).

    Forensic evidence: Cumulative timing pairs sent on conversation POSTs.
    Format: toggle,ms_offset pairs where toggle=1 for start, 0 for end.
    """

    def __init__(self):
        self._session_start = time.time()
        self._events = []

    def record_event(self, is_start: bool) -> None:
        offset_ms = int((time.time() - self._session_start) * 1000)
        toggle = 1 if is_start else 0
        self._events.append((toggle, offset_ms))

    def get_header_value(self) -> str:
        if not self._events:
            return ""
        return ','.join(f"{t},{ms}" for t, ms in self._events)


class ChatService:
    def __init__(self, origin_token=None):
        # self.user_agent = random.choice(user_agents_list) if user_agents_list else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
        self.req_token = get_req_token(origin_token)
        self.chat_token = "gAAAAAB"
        self.s = None
        self.ss = None
        self.ws = None

    async def set_dynamic_data(self, data):
        if self.req_token:
            req_len = len(self.req_token.split(","))
            if req_len == 1:
                self.access_token = await verify_token(self.req_token)
                self.account_id = None
            else:
                self.access_token = await verify_token(self.req_token.split(",")[0])
                self.account_id = self.req_token.split(",")[1]
        else:
            logger.info("Request token is empty, use no-auth 3.5")
            self.access_token = None
            self.account_id = None

        self.fp = get_fp(self.req_token).copy()
        self.proxy_url = self.fp.pop("proxy_url", None)
        self.impersonate = self.fp.pop("impersonate", "safari15_3")
        self.user_agent = self.fp.get("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0")
        logger.info(f"Request token: {self.req_token}")
        logger.info(f"Request proxy: {self.proxy_url}")
        logger.info(f"Request UA: {self.user_agent}")
        logger.info(f"Request impersonate: {self.impersonate}")

        self.data = data
        await self.set_model()
        if enable_limit and self.req_token:
            limit_response = await handle_request_limit(self.req_token, self.req_model)
            if limit_response:
                raise HTTPException(status_code=429, detail=limit_response)

        self.account_id = self.data.get('Chatgpt-Account-Id', self.account_id)
        self.parent_message_id = self.data.get('parent_message_id')
        self.conversation_id = self.data.get('conversation_id')
        self.history_disabled = self.data.get('history_disabled', history_disabled)

        self.api_messages = self.data.get("messages", [])
        self.prompt_tokens = 0
        self.max_tokens = self.data.get("max_tokens", 2147483647)
        if not isinstance(self.max_tokens, int):
            self.max_tokens = 2147483647

        # self.proxy_url = random.choice(proxy_url_list) if proxy_url_list else None

        self.host_url = random.choice(chatgpt_base_url_list) if chatgpt_base_url_list else "https://chatgpt.com"
        self.ark0se_token_url = random.choice(ark0se_token_url_list) if ark0se_token_url_list else None

        session_id = hashlib.md5(self.req_token.encode()).hexdigest()
        proxy_url = self.proxy_url.replace("{}", session_id) if self.proxy_url else None
        self.s = Client(proxy=proxy_url, impersonate=self.impersonate)
        if sentinel_proxy_url_list:
            sentinel_proxy_url = (random.choice(sentinel_proxy_url_list)).replace("{}", session_id) if sentinel_proxy_url_list else None
            self.ss = Client(proxy=sentinel_proxy_url, impersonate=self.impersonate)
        else:
            self.ss = self.s

        self.persona = None
        self.ark0se_token = None
        self.proof_token = None
        self.turnstile_token = None

        # Phase 2 stealth: Turn tracking and conduit token (H1, H2, H3)
        self._conduit_token = 'no-token'  # H1: Initial value per forensic capture
        self._turn_trace_id = str(uuid.uuid4())  # H2: UUID per conversation turn
        self._echo_logs = _OaiEchoLogsTracker()  # H3: Cumulative timing pairs

        # Phase 3 stealth: Cookie state (M5, M6)
        self._oai_sc_counter = 0  # M5: Track oai-sc rotation count
        self._oai_state_cookies = {}  # M6: OAI state cookies

        self.chat_headers = None
        self.chat_request = None

        self.base_headers = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'oai-language': oai_language,
            'origin': self.host_url,
            'priority': 'u=1, i',
            'referer': f'{self.host_url}/',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            # Chrome 144 Client Hints (CRITICAL - all 9 required)
            'sec-ch-ua': '"Not(A:Brand";v="8", "Chromium";v="144"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-ch-ua-arch': '""',
            'sec-ch-ua-bitness': '""',
            'sec-ch-ua-full-version': '""',
            'sec-ch-ua-full-version-list': '',
            'sec-ch-ua-model': '""',
            'sec-ch-ua-platform-version': '""',
        }
        self.base_headers.update(self.fp)

        # Add OAI-specific headers (CRITICAL - required for stealth)
        self.base_headers['oai-device-id'] = self.fp.get('oai-device-id', str(uuid.uuid4()))

        # SHOULD FIX #6: Add build number/version to base_headers (90% of requests)
        from chatgpt.proofofWork import cached_dpl as _dpl, cached_build_number as _build
        if _build:
            self.base_headers['oai-client-build-number'] = _build
        else:
            self.base_headers['oai-client-build-number'] = '4331890'
        if _dpl:
            self.base_headers['oai-client-version'] = _dpl

        if self.access_token:
            if self.access_token.startswith("session-"):
                self.base_url = self.host_url + "/backend-api"
                # Use cookie authentication for session tokens
                session_token = self.access_token.replace("session-", "")
                self.base_headers['Cookie'] = f'__Secure-next-auth.session-token={session_token}'
                # Ensure Authorization header is NOT set or set to something minimal if needed (usually not for cookie auth)
                if self.account_id:
                     self.base_headers['chatgpt-account-id'] = self.account_id
            else:
                self.base_url = self.host_url + "/backend-api"
                self.base_headers['authorization'] = f'Bearer {self.access_token}'
                if self.account_id:
                    self.base_headers['chatgpt-account-id'] = self.account_id
        else:
            self.base_url = self.host_url + "/backend-anon"

        if auth_key:
            self.base_headers['authkey'] = auth_key

        # M6: Initialize OAI state cookies (normally set by client-side JS)
        oai_asli_id = str(uuid.uuid4())
        self._oai_state_cookies = {
            'oai-hm': 'READY_WHEN_YOU_ARE',  # Home message state
            'oai-hlib': 'true',  # Help library state
            'oai-asli': oai_asli_id,  # Assistive library session ID
        }

        # N2: Additional OAI cookies observed in forensic capture
        self._oai_state_cookies['oai-gn'] = 'User'  # User first name (generic default)
        model_config = json.dumps({"model": self.data.get("model", "gpt-4o")})
        self._oai_state_cookies['oai-last-model-config'] = model_config

        # L2: g_state cookie (Google ITP optimization)
        g_state_val = json.dumps({"i_l": 0, "i_ll": int(time.time() * 1000), "i_e": {"enable_itp_optimization": 0}})
        self._oai_state_cookies['g_state'] = g_state_val

        # L3: _dd_s cookie (DataDog session tracking)
        dd_session_id = uuid.uuid4().hex
        dd_aid = uuid.uuid4().hex
        self._oai_state_cookies['_dd_s'] = f'aid={dd_aid}&rum=0&expire={int(time.time() * 1000) + 900000}&logs=1&id={dd_session_id}&created={int(time.time() * 1000)}'

        # Append all state cookies to existing Cookie header
        existing_cookies = self.base_headers.get('Cookie', '')
        state_cookie_str = '; '.join(f'{k}={v}' for k, v in self._oai_state_cookies.items())
        if existing_cookies:
            self.base_headers['Cookie'] = f'{existing_cookies}; {state_cookie_str}'
        else:
            self.base_headers['Cookie'] = state_cookie_str

        await get_dpl(self)

    async def set_model(self):
        self.origin_model = self.data.get("model", "gpt-3.5-turbo-0125")
        self.resp_model = model_proxy.get(self.origin_model, self.origin_model)
        if "gizmo" in self.origin_model or "g-" in self.origin_model:
            self.gizmo_id = "g-" + self.origin_model.split("g-")[-1]
        else:
            self.gizmo_id = None

        if "o3-mini-high" in self.origin_model:
            self.req_model = "o3-mini-high"
        elif "o3-mini-medium" in self.origin_model:
            self.req_model = "o3-mini-medium"
        elif "o3-mini-low" in self.origin_model:
            self.req_model = "o3-mini-low"
        elif "o3-mini" in self.origin_model:
            self.req_model = "o3-mini"
        elif "o3" in self.origin_model:
            self.req_model = "o3"
        elif "o1-preview" in self.origin_model:
            self.req_model = "o1-preview"
        elif "o1-pro" in self.origin_model:
            self.req_model = "o1-pro"
        elif "o1-mini" in self.origin_model:
            self.req_model = "o1-mini"
        elif "o1" in self.origin_model:
            self.req_model = "o1"
        elif "gpt-4.5o" in self.origin_model:
            self.req_model = "gpt-4.5o"
        elif "gpt-4o-canmore" in self.origin_model:
            self.req_model = "gpt-4o-canmore"
        elif "gpt-4o-mini" in self.origin_model:
            self.req_model = "gpt-4o-mini"
        elif "gpt-4o" in self.origin_model:
            self.req_model = "gpt-4o"
        elif "gpt-4-mobile" in self.origin_model:
            self.req_model = "gpt-4-mobile"
        elif "gpt-4" in self.origin_model:
            self.req_model = "gpt-4"
        elif "gpt-3.5" in self.origin_model:
            self.req_model = "text-davinci-002-render-sha"
        elif "auto" in self.origin_model:
            self.req_model = "auto"
        else:
            self.req_model = "gpt-4o"

    async def get_chat_requirements(self):
        if conversation_only:
            return None
        url = f'{self.base_url}/sentinel/chat-requirements'
        headers = self.base_headers.copy()
        try:
            config = get_config(self.user_agent, self.req_token)
            p = get_requirements_token(config)
            data = {'p': p}
            r = await self.ss.post(url, headers=headers, json=data, timeout=5)
            if r.status_code == 200:
                resp = r.json()

                self.persona = resp.get("persona")
                if self.persona != "chatgpt-paid":
                    if self.req_model == "gpt-4" or self.req_model == "o1-preview":
                        logger.error(f"Model {self.resp_model} not support for {self.persona}")
                        raise HTTPException(
                            status_code=404,
                            detail={
                                "message": f"The model `{self.origin_model}` does not exist or you do not have access to it.",
                                "type": "invalid_request_error",
                                "param": None,
                                "code": "model_not_found",
                            },
                        )

                turnstile = resp.get('turnstile', {})
                turnstile_required = turnstile.get('required')
                if turnstile_required:
                    turnstile_dx = turnstile.get("dx")
                    try:
                        if turnstile_solver_url:
                            res = await self.s.post(
                                turnstile_solver_url, json={"url": "https://chatgpt.com", "p": p, "dx": turnstile_dx, "ua": self.user_agent}
                            )
                            self.turnstile_token = res.json().get("t")
                    except Exception as e:
                        logger.info(f"Turnstile ignored: {e}")
                    # raise HTTPException(status_code=403, detail="Turnstile required")

                ark0se = resp.get('ark' + 'ose', {})
                ark0se_required = ark0se.get('required')
                if ark0se_required:
                    if self.persona == "chatgpt-freeaccount":
                        ark0se_method = "chat35"
                    else:
                        ark0se_method = "chat4"
                    if not self.ark0se_token_url:
                        raise HTTPException(status_code=403, detail="Ark0se service required")
                    ark0se_dx = ark0se.get("dx")
                    ark0se_client = Client(impersonate=self.impersonate)
                    try:
                        r2 = await ark0se_client.post(
                            url=self.ark0se_token_url, json={"blob": ark0se_dx, "method": ark0se_method}, timeout=15
                        )
                        r2esp = r2.json()
                        logger.info(f"ark0se_token: {r2esp}")
                        if r2esp.get('solved', True):
                            self.ark0se_token = r2esp.get('token')
                        else:
                            raise HTTPException(status_code=403, detail="Failed to get Ark0se token")
                    except Exception:
                        raise HTTPException(status_code=403, detail="Failed to get Ark0se token")
                    finally:
                        await ark0se_client.close()

                proofofwork = resp.get('proofofwork', {})
                proofofwork_required = proofofwork.get('required')
                if proofofwork_required:
                    proofofwork_diff = proofofwork.get("difficulty")
                    if proofofwork_diff <= pow_difficulty:
                        raise HTTPException(status_code=403, detail=f"Proof of work difficulty too high: {proofofwork_diff}")
                    proofofwork_seed = proofofwork.get("seed")
                    self.proof_token, solved = await run_in_threadpool(
                        get_answer_token, proofofwork_seed, proofofwork_diff, config
                    )
                    if not solved:
                        raise HTTPException(status_code=403, detail="Failed to solve proof of work")

                self.chat_token = resp.get('token')
                if not self.chat_token:
                    raise HTTPException(status_code=403, detail=f"Failed to get chat token: {r.text}")
                return self.chat_token
            else:
                if "application/json" == r.headers.get("Content-Type", ""):
                    detail = r.json().get("detail", r.json())
                else:
                    detail = r.text
                if "cf_chl_opt" in detail:
                    raise HTTPException(status_code=r.status_code, detail="cf_chl_opt")
                if r.status_code == 429:
                    raise HTTPException(status_code=r.status_code, detail="rate-limit")
                raise HTTPException(status_code=r.status_code, detail=detail)
        except HTTPException as e:
            raise HTTPException(status_code=e.status_code, detail=e.detail)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    async def prepare_send_conversation(self):
        try:
            chat_messages, self.prompt_tokens = await api_messages_to_chat(self, self.api_messages, upload_by_url)
        except Exception as e:
            logger.error(f"Failed to format messages: {str(e)}")
            raise HTTPException(status_code=400, detail="Failed to format messages.")
        # H2: New turn trace ID per conversation turn
        self._turn_trace_id = str(uuid.uuid4())
        # H3: Record turn start timing event
        self._echo_logs.record_event(is_start=True)

        self.chat_headers = self.base_headers.copy()
        self.chat_headers.update(
            {
                'accept': 'text/event-stream',
                'openai-sentinel-chat-requirements-token': self.chat_token,
                'openai-sentinel-proof-token': self.proof_token,
            }
        )
        # Add OAI build headers (CRITICAL - forensic analysis 2026-01-30)
        # These change with each ChatGPT deployment, extracted from HTML
        from chatgpt.proofofWork import cached_dpl as current_dpl, cached_build_number as current_build
        if current_dpl:
            self.chat_headers['oai-client-version'] = current_dpl
        if current_build:
            self.chat_headers['oai-client-build-number'] = current_build
        else:
            # Fallback to known value from forensic capture 2026-01-30
            self.chat_headers['oai-client-build-number'] = '4331890'

        # H1: Echo conduit token (initial: 'no-token', then from response)
        self.chat_headers['x-conduit-token'] = self._conduit_token or 'no-token'

        # H2: Turn trace ID (UUID per conversation turn)
        self.chat_headers['x-oai-turn-trace-id'] = self._turn_trace_id

        # H3: Echo logs (cumulative timing pairs)
        echo_value = self._echo_logs.get_header_value()
        if echo_value:
            self.chat_headers['oai-echo-logs'] = echo_value

        if self.ark0se_token:
            self.chat_headers['openai-sentinel-ark' + 'ose-token'] = self.ark0se_token

        if self.turnstile_token:
            self.chat_headers['openai-sentinel-turnstile-token'] = self.turnstile_token

        if conversation_only:
            self.chat_headers.pop('openai-sentinel-chat-requirements-token', None)
            self.chat_headers.pop('openai-sentinel-proof-token', None)
            self.chat_headers.pop('openai-sentinel-ark' + 'ose-token', None)
            self.chat_headers.pop('openai-sentinel-turnstile-token', None)

        if self.gizmo_id:
            conversation_mode = {"kind": "gizmo_interaction", "gizmo_id": self.gizmo_id}
            logger.info(f"Gizmo id: {self.gizmo_id}")
        else:
            conversation_mode = {"kind": "primary_assistant"}

        # SHOULD FIX #9: Evolve Referer with conversation_id after first turn (L5)
        if self.conversation_id:
            self.chat_headers['referer'] = f'{self.host_url}/c/{self.conversation_id}'

        logger.info(f"Model mapping: {self.origin_model} -> {self.req_model}")
        self.chat_request = {
            "action": "next",
            "client_contextual_info": {
                "is_dark_mode": False,
                "time_since_loaded": random.randint(50, 500),
                "page_height": random.randint(500, 1000),
                "page_width": random.randint(1000, 2000),
                "pixel_ratio": 1.5,
                "screen_height": random.randint(800, 1200),
                "screen_width": random.randint(1200, 2200),
            },
            "conversation_mode": conversation_mode,
            "conversation_origin": None,
            "force_paragen": False,
            "force_paragen_model_slug": "",
            "force_rate_limit": False,
            "force_use_sse": True,
            "history_and_training_disabled": self.history_disabled,
            "messages": chat_messages,
            "model": self.req_model,
            "paragen_cot_summary_display_override": "allow",
            "paragen_stream_type_override": None,
            "parent_message_id": self.parent_message_id if self.parent_message_id else f"{uuid.uuid4()}",
            "reset_rate_limits": False,
            "suggestions": [],
            "supports_buffering": True,
            "supported_encodings": ["v1"],
            "enable_message_followups": True,
            "force_parallel_switch": "auto",
            "system_hints": [],
            "timezone": "America/Los_Angeles",
            "timezone_offset_min": 480,
            "variant_purpose": "comparison_implicit",
            "websocket_request_id": f"{uuid.uuid4()}",
        }
        if self.conversation_id:
            self.chat_request['conversation_id'] = self.conversation_id
        return self.chat_request

    async def send_conversation(self):
        try:
            # Use new /f/conversation endpoint (critical for stealth - forensic analysis 2026-01-30)
            url = f'{self.base_url}/f/conversation'
            stream = self.data.get("stream", False)
            r = await self.s.post_stream(url, headers=self.chat_headers, json=self.chat_request, timeout=10, stream=True)
            if r.status_code != 200:
                rtext = await r.atext()
                if "application/json" == r.headers.get("Content-Type", ""):
                    detail = json.loads(rtext).get("detail", json.loads(rtext))
                    if r.status_code == 429:
                        check_is_limit(detail, token=self.req_token, model=self.req_model)
                else:
                    if "cf_chl_opt" in rtext:
                        # logger.error(f"Failed to send conversation: cf_chl_opt")
                        raise HTTPException(status_code=r.status_code, detail="cf_chl_opt")
                    if r.status_code == 429:
                        # logger.error(f"Failed to send conversation: rate-limit")
                        raise HTTPException(status_code=r.status_code, detail="rate-limit")
                    detail = r.text[:100]
                # logger.error(f"Failed to send conversation: {detail}")
                raise HTTPException(status_code=r.status_code, detail=detail)

            # H1: Extract conduit token from response for next request
            conduit = r.headers.get("x-conduit-token") or r.headers.get("X-Conduit-Token")
            if conduit:
                self._conduit_token = conduit

            # M5: Track oai-sc cookie rotation from Set-Cookie headers
            set_cookies = r.headers.get("set-cookie", "")
            if "oai-sc=" in set_cookies:
                self._oai_sc_counter += 1
                logger.debug(f"oai-sc rotated (count: {self._oai_sc_counter})")

            # H3: Record turn end timing event
            self._echo_logs.record_event(is_start=False)

            content_type = r.headers.get("Content-Type", "")
            if "text/event-stream" in content_type:
                res, start = await head_process_response(r.aiter_lines())
                if not start:
                    raise HTTPException(
                        status_code=403,
                        detail="Our systems have detected unusual activity coming from your system. Please try again later.",
                    )
                if stream:
                    return stream_response(self, res, self.resp_model, self.max_tokens)
                else:
                    return await format_not_stream_response(
                        stream_response(self, res, self.resp_model, self.max_tokens),
                        self.prompt_tokens,
                        self.max_tokens,
                        self.resp_model,
                    )
            elif "application/json" in content_type:
                rtext = await r.atext()
                resp = json.loads(rtext)
                raise HTTPException(status_code=r.status_code, detail=resp)
            else:
                rtext = await r.atext()
                raise HTTPException(status_code=r.status_code, detail=rtext)
        except HTTPException as e:
            raise HTTPException(status_code=e.status_code, detail=e.detail)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    async def get_download_url(self, file_id):
        url = f"{self.base_url}/files/{file_id}/download"
        headers = self.base_headers.copy()
        try:
            r = await self.s.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                download_url = r.json().get('download_url')
                return download_url
            else:
                raise HTTPException(status_code=r.status_code, detail=r.text)
        except Exception as e:
            logger.error(f"Failed to get download url: {e}")
            return ""

    async def get_attachment_url(self, file_id, conversation_id):
        url = f"{self.base_url}/conversation/{conversation_id}/attachment/{file_id}/download"
        headers = self.base_headers.copy()
        try:
            r = await self.s.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                download_url = r.json().get('download_url')
                return download_url
            else:
                raise HTTPException(status_code=r.status_code, detail=r.text)
        except Exception as e:
            logger.error(f"Failed to get download url: {e}")
            return ""

    async def get_download_url_from_upload(self, file_id):
        url = f"{self.base_url}/files/{file_id}/uploaded"
        headers = self.base_headers.copy()
        try:
            r = await self.s.post(url, headers=headers, json={}, timeout=10)
            if r.status_code == 200:
                download_url = r.json().get('download_url')
                return download_url
            else:
                raise HTTPException(status_code=r.status_code, detail=r.text)
        except Exception as e:
            logger.error(f"Failed to get download url from upload: {e}")
            return ""

    async def get_upload_url(self, file_name, file_size, use_case="multimodal"):
        url = f'{self.base_url}/files'
        headers = self.base_headers.copy()
        try:
            r = await self.s.post(
                url,
                headers=headers,
                json={"file_name": file_name, "file_size": file_size, "reset_rate_limits": False, "timezone_offset_min": 480, "use_case": use_case},
                timeout=5,
            )
            if r.status_code == 200:
                res = r.json()
                file_id = res.get('file_id')
                upload_url = res.get('upload_url')
                logger.info(f"file_id: {file_id}, upload_url: {upload_url}")
                return file_id, upload_url
            else:
                raise HTTPException(status_code=r.status_code, detail=r.text)
        except Exception as e:
            logger.error(f"Failed to get upload url: {e}")
            return "", ""

    async def upload(self, upload_url, file_content, mime_type):
        headers = self.base_headers.copy()
        headers.update(
            {
                'accept': 'application/json, text/plain, */*',
                'content-type': mime_type,
                'x-ms-blob-type': 'BlockBlob',
                'x-ms-version': '2020-04-08',
            }
        )
        headers.pop('authorization', None)
        headers.pop('oai-device-id', None)
        headers.pop('oai-language', None)
        try:
            r = await self.s.put(upload_url, headers=headers, data=file_content, timeout=60)
            if r.status_code == 201:
                return True
            else:
                raise HTTPException(status_code=r.status_code, detail=r.text)
        except Exception as e:
            logger.error(f"Failed to upload file: {e}")
            return False

    async def upload_file(self, file_content, mime_type):
        if not file_content or not mime_type:
            return None

        width, height = None, None
        if mime_type.startswith("image/"):
            try:
                width, height = await get_image_size(file_content)
            except Exception as e:
                logger.error(f"Error image mime_type, change to text/plain: {e}")
                mime_type = 'text/plain'
        file_size = len(file_content)
        file_extension = await get_file_extension(mime_type)
        file_name = f"{uuid.uuid4()}{file_extension}"
        use_case = await determine_file_use_case(mime_type)

        file_id, upload_url = await self.get_upload_url(file_name, file_size, use_case)
        if file_id and upload_url:
            if await self.upload(upload_url, file_content, mime_type):
                download_url = await self.get_download_url_from_upload(file_id)
                if download_url:
                    file_meta = {
                        "file_id": file_id,
                        "file_name": file_name,
                        "size_bytes": file_size,
                        "mime_type": mime_type,
                        "width": width,
                        "height": height,
                        "use_case": use_case,
                    }
                    logger.info(f"File_meta: {file_meta}")
                    return file_meta

    async def check_upload(self, file_id):
        url = f'{self.base_url}/files/{file_id}'
        headers = self.base_headers.copy()
        try:
            for i in range(30):
                r = await self.s.get(url, headers=headers, timeout=5)
                if r.status_code == 200:
                    res = r.json()
                    retrieval_index_status = res.get('retrieval_index_status', '')
                    if retrieval_index_status == "success":
                        break
                await asyncio.sleep(1)
            return True
        except HTTPException:
            return False

    async def get_response_file_url(self, conversation_id, message_id, sandbox_path):
        try:
            url = f"{self.base_url}/conversation/{conversation_id}/interpreter/download"
            params = {"message_id": message_id, "sandbox_path": sandbox_path}
            headers = self.base_headers.copy()
            r = await self.s.get(url, headers=headers, params=params, timeout=10)
            if r.status_code == 200:
                return r.json().get("download_url")
            else:
                return None
        except Exception:
            logger.info("Failed to get response file url")
            return None

    async def close_client(self):
        if self.s:
            await self.s.close()
            del self.s
        if self.ss:
            await self.ss.close()
            del self.ss
        if self.ws:
            await self.ws.close()
            del self.ws

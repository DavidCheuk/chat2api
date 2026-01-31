# SPDX-License-Identifier: MIT
# Ported from upstream lanqian528/chat2api commit c549d41 (v1.9.0-beta1)
# P1-49: v1 delta encoding support for stealth compliance

import json
from typing import AsyncGenerator

from utils.Logger import logger


async def transform_delta_stream(input_stream) -> AsyncGenerator[bytes, None]:
    """Transform v1 delta-encoded SSE events into old-format events.

    V1 delta format (ChatGPT's compact streaming):
      event: delta_encoding
      data: "v1"

      event: delta
      data: {"p": "", "o": "add", "v": {"message": {...}, "conversation_id": "..."}}

      event: delta
      data: {"p": "/message/content/parts/0", "o": "append", "v": "Hello"}

      data: [DONE]

    Old format (what stream_response/head_process_response expect):
      data: {"message": {...}, "conversation_id": "..."}

    IMPORTANT: v1 delta patches use paths relative to the root state object
    (e.g., /message/content/parts/0), NOT relative to the message itself.
    We maintain current_state as the full root state including "message" wrapper.

    This function yields bytes to be compatible with downstream .decode("utf-8") calls.
    """
    # Full root state: {"message": {...}, "conversation_id": "...", ...}
    # Patches are applied to this, not to the message directly.
    current_state = None
    current_event = None

    async for line in input_stream:
        if isinstance(line, bytes):
            line = line.decode("utf-8")
        line = line.strip()

        if not line:
            continue

        # Handle event type lines
        if line.startswith("event: "):
            current_event = line[7:]
            continue

        # Handle data lines
        if not line.startswith("data: "):
            continue

        data = line[6:]

        # [DONE] marker - pass through
        if data == "[DONE]":
            yield line.encode("utf-8")
            continue

        try:
            json_data = json.loads(data)
        except json.JSONDecodeError:
            yield line.encode("utf-8")
            continue

        # Skip non-dict data (e.g., "v1" string from delta_encoding event)
        if not isinstance(json_data, dict):
            yield line.encode("utf-8")
            continue

        # 1. Old-format message (has "message" key directly, no "p"/"o") - pass through
        if "message" in json_data and "p" not in json_data:
            current_state = json_data
            yield line.encode("utf-8")
            continue

        # 2. Delta-encoded events
        if current_event == "delta" or "v" in json_data or ("p" in json_data and "o" in json_data):

            # 2a. Full state in v field: {"v": {"message": {...}, ...}, "c": N}
            #     or root add: {"p": "", "o": "add", "v": {"message": {...}}}
            if "v" in json_data and isinstance(json_data["v"], dict) and "message" in json_data["v"]:
                current_state = json_data["v"]
                # Yield old-format for downstream parsers
                old_fmt = {"message": current_state["message"]}
                if "conversation_id" in current_state:
                    old_fmt["conversation_id"] = current_state["conversation_id"]
                if "error" in current_state:
                    old_fmt["error"] = current_state["error"]
                yield f'data: {json.dumps(old_fmt)}'.encode("utf-8")
                continue

            # 2b. Patch operation: {"p": "/message/content/parts/0", "o": "append", "v": "text"}
            #     Paths are relative to root state, so apply to current_state
            if "p" in json_data and "o" in json_data:
                if current_state is None:
                    current_state = {"message": {}}
                current_state = apply_patch(current_state, json_data)
                message = current_state.get("message", {})
                old_fmt = {"message": message}
                if "conversation_id" in current_state:
                    old_fmt["conversation_id"] = current_state["conversation_id"]
                yield f'data: {json.dumps(old_fmt)}'.encode("utf-8")
                continue

            # 2c. Text append shorthand: {"v": "text_chunk"} (no "p"/"o" keys)
            #     Appends directly to message.content.parts[0]
            if "v" in json_data and isinstance(json_data["v"], str):
                if current_state is None:
                    current_state = {"message": {
                        "content": {"content_type": "text", "parts": [""]},
                        "status": "in_progress",
                    }}
                message = current_state.get("message", {})
                # Ensure content.parts structure exists
                if "content" not in message:
                    message["content"] = {"content_type": "text", "parts": [""]}
                if "parts" not in message.get("content", {}):
                    message["content"]["parts"] = [""]
                if not message["content"]["parts"]:
                    message["content"]["parts"].append("")
                # Append text to first part
                message["content"]["parts"][0] += json_data["v"]
                current_state["message"] = message
                yield f'data: {json.dumps({"message": message})}'.encode("utf-8")
                continue

        # 3. Non-delta v data with message: {"v": {"message": {...}}}
        if isinstance(json_data, dict) and "v" in json_data and isinstance(json_data["v"], dict) and "message" in json_data["v"]:
            current_state = json_data["v"]
            yield f'data: {json.dumps({"message": current_state["message"]})}'.encode("utf-8")
            continue

        # 4. Everything else - pass through as-is
        yield line.encode("utf-8")


def apply_patch(state: dict, patch: dict) -> dict:
    """Apply a single v1 delta patch operation to the state.

    Operations (RFC 6902 inspired + ChatGPT extensions):
      add     - Create new field at path
      replace - Overwrite value at path
      append  - Append to array or string at path
      truncate - Cut array/string to length at path
      remove  - Delete field at path
      patch   - Recursive nested patches
    """
    path = patch["p"]
    operation = patch["o"]
    value = patch.get("v", None)

    # Root path operations
    if path == "" or path == "/":
        if operation == "add":
            return value if isinstance(value, dict) else state
        elif operation == "patch":
            if isinstance(value, list):
                for sub_patch in value:
                    state = apply_patch(state, sub_patch)
            return state
        elif operation == "replace":
            return value if isinstance(value, dict) else state
        return state

    # Split path into segments (skip empty leading segment from "/a/b/c")
    parts = [p for p in path.split("/") if p]
    if not parts:
        return state

    # Navigate to parent of target
    target = state
    for part in parts[:-1]:
        if isinstance(target, dict):
            if part not in target:
                target[part] = {}
            target = target[part]
        elif isinstance(target, list):
            try:
                idx = int(part)
                target = target[idx]
            except (ValueError, IndexError):
                return state
        else:
            return state

    last_part = parts[-1]

    # Handle list index access
    if isinstance(target, list):
        try:
            idx = int(last_part)
            if operation == "replace":
                target[idx] = value
            elif operation == "append":
                if isinstance(target[idx], str):
                    target[idx] += str(value)
                elif isinstance(target[idx], list):
                    target[idx].append(value)
            elif operation == "truncate":
                if isinstance(target[idx], (list, str)):
                    target[idx] = target[idx][:value]
            elif operation == "remove":
                target.pop(idx)
        except (ValueError, IndexError):
            pass
        return state

    # Handle dict field access
    if operation == "replace":
        target[last_part] = value
    elif operation == "add":
        target[last_part] = value
    elif operation == "append":
        if last_part not in target:
            target[last_part] = [] if isinstance(value, dict) else ""
        if isinstance(target[last_part], list):
            target[last_part].append(value)
        elif isinstance(target[last_part], str):
            target[last_part] += str(value)
    elif operation == "truncate":
        if last_part in target and isinstance(target[last_part], (list, str)):
            target[last_part] = target[last_part][:value]
    elif operation == "remove":
        if last_part in target:
            del target[last_part]
    elif operation == "patch":
        if isinstance(value, list):
            if last_part not in target:
                target[last_part] = {}
            for sub_patch in value:
                target[last_part] = apply_patch(target[last_part], sub_patch)

    return state

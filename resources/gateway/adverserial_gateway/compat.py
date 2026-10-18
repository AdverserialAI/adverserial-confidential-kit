"""Local, lossless-enough adapters for coding-agent protocol dialects.

The gateway deliberately turns every request into one OpenAI-compatible Chat
Completions request before it is encrypted for the attested endpoint. These
adapters preserve text, function definitions, function calls, and tool
results. Features that cannot be represented without weakening the
confidential path (hosted tools, files, or provider-side conversation state)
fail closed instead of being silently dropped.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import Any, Mapping

from .core import ClientRequestError


def _text(value: Any, *, response: bool = False) -> str:
    """Return text from an Anthropic or Responses content value.

    Tool calls/results are handled by their enclosing protocol adapters. A
    content helper must never flatten them into prose because that loses the
    tool-call identity required for the next agent turn.
    """
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        raise ClientRequestError("content must be text or a list of supported text blocks")
    accepted = {"input_text", "output_text", "text"} if response else {"text"}
    parts: list[str] = []
    for block in value:
        if not isinstance(block, Mapping):
            raise ClientRequestError("content blocks must be objects")
        kind = block.get("type")
        if kind in {"thinking", "redacted_thinking"}:
            # Thinking is display-only here. The actual next-turn tool state
            # is represented by the structured tool call/result below.
            continue
        if kind not in accepted or not isinstance(block.get("text"), str):
            raise ClientRequestError("only text content is available through the confidential gateway")
        parts.append(block["text"])
    return "\n".join(parts)


def _tool_id_to_anthropic(raw: str) -> str:
    return raw if raw.startswith("toolu_") else "toolu_" + raw


def _tool_id_from_anthropic(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ClientRequestError("Anthropic tool_result requires tool_use_id")
    return value.removeprefix("toolu_")


def _anthropic_messages(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    system = payload.get("system")
    if system:
        messages.append({"role": "system", "content": _text(system)})

    raw_messages = payload.get("messages", [])
    if not isinstance(raw_messages, list):
        raise ClientRequestError("Anthropic messages must be an array")
    for message in raw_messages:
        if not isinstance(message, Mapping) or message.get("role") not in {"user", "assistant", "system"}:
            raise ClientRequestError("Anthropic messages must use user, assistant, or system roles")
        role = message["role"]
        content = message.get("content", "")
        if isinstance(content, str):
            messages.append({"role": role, "content": content})
            continue
        if not isinstance(content, list):
            raise ClientRequestError("content must be text or a list of supported text blocks")

        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        tool_results: list[dict[str, Any]] = []
        for block in content:
            if not isinstance(block, Mapping):
                raise ClientRequestError("Anthropic content blocks must be objects")
            kind = block.get("type")
            if kind == "text":
                if not isinstance(block.get("text"), str):
                    raise ClientRequestError("Anthropic text blocks require text")
                text_parts.append(block["text"])
            elif kind in {"thinking", "redacted_thinking"}:
                # The upstream model's own tool state is sufficient to resume
                # an agent turn. Do not claim opaque provider thinking is
                # portable across providers.
                continue
            elif kind == "tool_use":
                if role != "assistant" or not isinstance(block.get("name"), str) or not block["name"]:
                    raise ClientRequestError("Anthropic tool_use must appear in an assistant message with a name")
                tool_id = _tool_id_from_anthropic(block.get("id"))
                arguments = json.dumps(block.get("input") or {}, separators=(",", ":"))
                tool_calls.append({"id": tool_id, "type": "function", "function": {"name": block["name"], "arguments": arguments}})
            elif kind == "tool_result":
                if role != "user":
                    raise ClientRequestError("Anthropic tool_result must appear in a user message")
                inner = block.get("content", "")
                text = _text(inner) if isinstance(inner, list) else (inner if isinstance(inner, str) else "")
                if block.get("is_error"):
                    text = "[tool error]\n" + text
                tool_results.append({"role": "tool", "tool_call_id": _tool_id_from_anthropic(block.get("tool_use_id")), "content": text})
            else:
                raise ClientRequestError("only text and function tool blocks are available through the confidential gateway")
        if role == "assistant":
            if text_parts or tool_calls:
                messages.append({"role": "assistant", "content": "\n".join(text_parts) or None, **({"tool_calls": tool_calls} if tool_calls else {})})
        elif role == "system":
            if tool_results:
                raise ClientRequestError("system messages cannot contain tool_result blocks")
            messages.append({"role": "system", "content": "\n".join(text_parts)})
        else:
            if text_parts:
                messages.append({"role": "user", "content": "\n".join(text_parts)})
            messages.extend(tool_results)
    return messages


def _anthropic_tools(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ClientRequestError("Anthropic tools must be an array")
    converted: list[dict[str, Any]] = []
    for tool in value:
        if not isinstance(tool, Mapping) or not isinstance(tool.get("name"), str) or not tool["name"]:
            raise ClientRequestError("invalid Anthropic tool")
        schema = tool.get("input_schema", {"type": "object"})
        if not isinstance(schema, Mapping):
            raise ClientRequestError("Anthropic tool input_schema must be an object")
        converted.append({"type": "function", "function": {"name": tool["name"], "description": tool.get("description", ""), "parameters": dict(schema)}})
    return converted


def anthropic_to_chat(payload: Mapping[str, Any]) -> dict[str, Any]:
    messages = _anthropic_messages(payload)
    if not messages:
        raise ClientRequestError("at least one message is required")
    max_tokens = payload.get("max_tokens")
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens < 1:
        raise ClientRequestError("Anthropic max_tokens must be a positive integer")
    out: dict[str, Any] = {"messages": messages, "max_tokens": max_tokens}
    for name in ("temperature", "top_p"):
        if name in payload:
            out[name] = payload[name]
    if payload.get("stop_sequences"):
        out["stop"] = payload["stop_sequences"]
    tools = _anthropic_tools(payload.get("tools"))
    if tools:
        out["tools"] = tools
    choice = payload.get("tool_choice")
    if isinstance(choice, Mapping):
        kind = choice.get("type")
        if kind == "tool":
            if not isinstance(choice.get("name"), str):
                raise ClientRequestError("Anthropic tool_choice tool requires a name")
            out["tool_choice"] = {"type": "function", "function": {"name": choice["name"]}}
        elif kind in {"auto", "any", "none"}:
            out["tool_choice"] = "required" if kind == "any" else kind
        else:
            raise ClientRequestError("unsupported Anthropic tool_choice")
    return out


def chat_to_anthropic(response: Mapping[str, Any], model: str) -> dict[str, Any]:
    choice = (response.get("choices") or [{}])[0]
    if not isinstance(choice, Mapping):
        raise ClientRequestError("confidential endpoint returned invalid completion choices")
    message = choice.get("message") or {}
    content: list[dict[str, Any]] = []
    if isinstance(message, Mapping) and isinstance(message.get("reasoning_content"), str) and message["reasoning_content"]:
        thinking = message["reasoning_content"]
        content.append({"type": "thinking", "thinking": thinking, "signature": base64.b64encode(hashlib.sha256(thinking.encode()).digest()).decode()})
    if isinstance(message, Mapping) and message.get("content"):
        content.append({"type": "text", "text": str(message["content"])})
    for call in (message.get("tool_calls") or []) if isinstance(message, Mapping) else []:
        fn = call.get("function", {}) if isinstance(call, Mapping) else {}
        if not isinstance(fn, Mapping) or not isinstance(fn.get("name"), str):
            raise ClientRequestError("confidential endpoint returned an invalid tool call")
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except (TypeError, ValueError):
            args = {}
        call_id = call.get("id") if isinstance(call.get("id"), str) else uuid.uuid4().hex
        content.append({"type": "tool_use", "id": _tool_id_to_anthropic(call_id), "name": fn["name"], "input": args if isinstance(args, dict) else {}})
    if not content:
        content = [{"type": "text", "text": ""}]
    usage = response.get("usage") or {}
    details = usage.get("prompt_tokens_details") or {}
    reason = {"length": "max_tokens", "tool_calls": "tool_use"}.get(choice.get("finish_reason"), "end_turn")
    return {"id": response.get("id", "msg_" + uuid.uuid4().hex), "type": "message", "role": "assistant", "model": response.get("model", model), "content": content, "stop_reason": reason, "stop_sequence": None, "usage": {"input_tokens": usage.get("prompt_tokens", 0), "output_tokens": usage.get("completion_tokens", 0), "cache_read_input_tokens": details.get("cached_tokens", 0)}}


def _responses_message(item: Mapping[str, Any]) -> dict[str, Any]:
    role = item.get("role", "user")
    if role not in {"user", "assistant", "system", "developer"}:
        raise ClientRequestError("unsupported Responses role")
    return {"role": "system" if role == "developer" else role, "content": _text(item.get("content", ""), response=True)}


def _responses_tools(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ClientRequestError("Responses tools must be an array")
    converted: list[dict[str, Any]] = []
    for tool in value:
        if not isinstance(tool, Mapping) or tool.get("type") != "function" or not isinstance(tool.get("name"), str) or not tool["name"]:
            raise ClientRequestError("only Responses function tools are available through the confidential gateway")
        params = tool.get("parameters", {"type": "object"})
        if not isinstance(params, Mapping):
            raise ClientRequestError("Responses function parameters must be an object")
        converted.append({"type": "function", "function": {"name": tool["name"], "description": tool.get("description", ""), "parameters": dict(params)}})
    return converted


def _responses_tool_choice(value: Any) -> Any:
    if value is None or isinstance(value, str):
        return value
    if not isinstance(value, Mapping):
        raise ClientRequestError("unsupported Responses tool_choice")
    if value.get("type") == "function" and isinstance(value.get("name"), str):
        return {"type": "function", "function": {"name": value["name"]}}
    if value.get("type") == "allowed_tools":
        raise ClientRequestError("Responses allowed_tools is unavailable; send function tool definitions directly")
    raise ClientRequestError("unsupported Responses tool_choice")


def _response_function_output(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return _text(value, response=True)
    raise ClientRequestError("Responses function_call_output must be text")


def responses_to_chat(payload: Mapping[str, Any]) -> dict[str, Any]:
    if payload.get("previous_response_id") or payload.get("conversation") or payload.get("background"):
        raise ClientRequestError("server-side Responses state is unavailable; send complete history in input")
    items = payload.get("input", [])
    if isinstance(items, str):
        items = [{"role": "user", "content": items}]
    if not isinstance(items, list):
        raise ClientRequestError("Responses input must be a string or array")
    messages: list[dict[str, Any]] = []
    instructions = payload.get("instructions")
    if instructions:
        messages.append({"role": "system", "content": _text(instructions, response=True) if isinstance(instructions, list) else str(instructions)})
    for item in items:
        if not isinstance(item, Mapping):
            raise ClientRequestError("Responses input items must be objects")
        kind = item.get("type", "message")
        if kind == "message":
            messages.append(_responses_message(item))
        elif kind == "function_call":
            name, call_id = item.get("name"), item.get("call_id")
            if not isinstance(name, str) or not name or not isinstance(call_id, str) or not call_id:
                raise ClientRequestError("Responses function_call requires name and call_id")
            arguments = item.get("arguments", "{}")
            if not isinstance(arguments, str):
                raise ClientRequestError("Responses function_call arguments must be JSON text")
            messages.append({"role": "assistant", "content": None, "tool_calls": [{"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments}}]})
        elif kind == "function_call_output":
            call_id = item.get("call_id")
            if not isinstance(call_id, str) or not call_id:
                raise ClientRequestError("Responses function_call_output requires call_id")
            messages.append({"role": "tool", "tool_call_id": call_id, "content": _response_function_output(item.get("output", ""))})
        elif kind == "reasoning":
            # Responses reasoning can include opaque encrypted state. Preserve
            # only a visible summary as normal assistant context; never send
            # foreign opaque state to the confidential model endpoint.
            summary = item.get("summary", [])
            if isinstance(summary, list):
                text = "\n".join(part.get("text", "") for part in summary if isinstance(part, Mapping) and isinstance(part.get("text"), str))
                if text:
                    messages.append({"role": "assistant", "content": "[reasoning summary]\n" + text})
        else:
            raise ClientRequestError("only Responses message and function tool items are available through the confidential gateway")
    if not messages:
        raise ClientRequestError("at least one input message is required")
    out: dict[str, Any] = {"messages": messages}
    if payload.get("max_output_tokens"):
        out["max_tokens"] = payload["max_output_tokens"]
    for name in ("temperature", "top_p", "parallel_tool_calls"):
        if name in payload:
            out[name] = payload[name]
    tools = _responses_tools(payload.get("tools"))
    if tools:
        out["tools"] = tools
    choice = _responses_tool_choice(payload.get("tool_choice"))
    if choice is not None:
        out["tool_choice"] = choice
    return out


def chat_to_response(response: Mapping[str, Any], model: str) -> dict[str, Any]:
    choice = (response.get("choices") or [{}])[0]
    if not isinstance(choice, Mapping):
        raise ClientRequestError("confidential endpoint returned invalid completion choices")
    message = choice.get("message") or {}
    output: list[dict[str, Any]] = []
    if isinstance(message, Mapping) and message.get("content"):
        output.append({"id": "msg_" + uuid.uuid4().hex, "type": "message", "status": "completed", "role": "assistant", "content": [{"type": "output_text", "text": str(message["content"]), "annotations": []}]})
    for call in (message.get("tool_calls") or []) if isinstance(message, Mapping) else []:
        fn = call.get("function", {}) if isinstance(call, Mapping) else {}
        if not isinstance(fn, Mapping) or not isinstance(fn.get("name"), str):
            raise ClientRequestError("confidential endpoint returned an invalid tool call")
        call_id = call.get("id") if isinstance(call.get("id"), str) else "call_" + uuid.uuid4().hex
        arguments = fn.get("arguments") if isinstance(fn.get("arguments"), str) else "{}"
        output.append({"id": "fc_" + call_id, "type": "function_call", "status": "completed", "call_id": call_id, "name": fn["name"], "arguments": arguments})
    if not output:
        output = [{"id": "msg_" + uuid.uuid4().hex, "type": "message", "status": "completed", "role": "assistant", "content": [{"type": "output_text", "text": "", "annotations": []}]}]
    usage = response.get("usage") or {}
    status = "incomplete" if choice.get("finish_reason") == "length" else "completed"
    return {"id": "resp_" + uuid.uuid4().hex, "object": "response", "created_at": int(time.time()), "status": status, "model": response.get("model", model), "output": output, "usage": {"input_tokens": usage.get("prompt_tokens", 0), "output_tokens": usage.get("completion_tokens", 0), "total_tokens": usage.get("total_tokens", usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0))}}

"""A loopback HTTP surface for OpenAI-compatible confidential clients."""
from __future__ import annotations

import argparse
import errno
from dataclasses import replace
import hmac
import os
import ipaddress
import json
import socket
import threading
import time
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import Config, ConfigError
from adverserial import VerificationError

from .compat import anthropic_to_chat, chat_to_anthropic, chat_to_response, responses_to_chat
from .core import AuthorizationError, ClientRequestError, Dispatcher, GatewayError


MAX_LOCAL_REQUEST_BYTES = 8 * 1024 * 1024
MAX_LOCAL_CONNECTIONS = 16
LOCAL_CONNECTION_TIMEOUT_SECONDS = 20.0
LOCAL_BODY_DEADLINE_SECONDS = 30.0


class RequestBodyTimeout(ClientRequestError):
    """The client did not finish its declared body within the local deadline."""

    status_code = HTTPStatus.REQUEST_TIMEOUT


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """A loopback HTTP server with bounded connection work.

    A local gateway is intentionally useful to developer tools, including
    tools that may execute repository-controlled code.  Binding to loopback
    does not make an unbounded HTTP parser safe: a local process could
    otherwise hold an arbitrary number of handler threads in incomplete
    headers or bodies and prevent the customer's actual client from using the
    gateway.  Keep the small public surface responsive by bounding active
    connections and timing out each connection, while allowing normal
    inference streams to keep their handler for their lifetime.
    """

    daemon_threads = True
    block_on_close = False
    request_queue_size = MAX_LOCAL_CONNECTIONS

    def __init__(
        self,
        server_address,
        request_handler_class,
        *,
        max_connections: int = MAX_LOCAL_CONNECTIONS,
        connection_timeout: float = LOCAL_CONNECTION_TIMEOUT_SECONDS,
        body_deadline: float = LOCAL_BODY_DEADLINE_SECONDS,
    ):
        if max_connections < 1:
            raise ValueError("max_connections must be positive")
        if connection_timeout <= 0 or body_deadline <= 0:
            raise ValueError("gateway timeouts must be positive")
        super().__init__(server_address, request_handler_class)
        self.connection_timeout = connection_timeout
        self.body_deadline = body_deadline
        self._connection_slots = threading.BoundedSemaphore(max_connections)

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(self.connection_timeout)
        return request, client_address

    def verify_request(self, request, client_address):
        """Defend in depth if a hostname unexpectedly resolves off-loopback."""
        try:
            return ipaddress.ip_address(client_address[0]).is_loopback
        except ValueError:
            return False

    def process_request(self, request, client_address):
        if not self._connection_slots.acquire(blocking=False):
            # Do not block the accept loop trying to write an error to a
            # peer that has stopped reading.  The close is sufficient for
            # clients that did not complete a request yet.
            try:
                # Drain only data already queued by a well-behaved local
                # client.  On some TCP stacks, closing with a complete small
                # request still unread converts a just-written 503 into a
                # reset.  A bounded, nonblocking drain preserves a useful
                # retry signal without letting an attacker consume work.
                request.setblocking(False)
                remaining = 8 * 1024
                while remaining:
                    try:
                        data = request.recv(min(remaining, 1024))
                    except (BlockingIOError, OSError):
                        break
                    if not data:
                        break
                    remaining -= len(data)
                request.settimeout(0.25)
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\n"
                    b"Cache-Control: no-store\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


class Handler(BaseHTTPRequestHandler):
    dispatcher: Dispatcher
    server_version = "AdverserialConfidentialGateway/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        # Do not log request paths, headers, bodies, identities, or prompts.
        return

    def _json(self, status: int, payload: dict, *, close: bool = False):
        data = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if close:
            # A rejected request may still have unread body bytes.  Never let
            # those bytes be interpreted as a following keep-alive request.
            self.close_connection = True
            self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, OSError):
            # A caller that timed out or disconnected is not a server error,
            # and request/error logs must not contain customer content.
            pass

    def _request_size(self) -> int:
        if self.headers.get("transfer-encoding"):
            raise ClientRequestError("Chunked request bodies are not supported by the local gateway")
        values = self.headers.get_all("content-length") or []
        if len(values) != 1:
            raise ClientRequestError("Exactly one Content-Length header is required")
        value = values[0].strip()
        if not value.isascii() or not value.isdecimal():
            raise ClientRequestError("Content-Length must be a positive decimal integer")
        size = int(value)
        if not 1 <= size <= MAX_LOCAL_REQUEST_BYTES:
            raise ClientRequestError(f"Request body must be between 1 and {MAX_LOCAL_REQUEST_BYTES} bytes")
        return size

    def _read_body(self, size: int) -> bytes:
        deadline = time.monotonic() + self.server.body_deadline
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                raise RequestBodyTimeout("Request body upload timed out")
            try:
                # Socket timeouts alone are insufficient: a peer can send a
                # byte before each idle timeout forever.  Bound total upload
                # time as well as each blocking read.
                self.connection.settimeout(min(self.server.connection_timeout, timeout))
                chunk = self.rfile.read(min(64 * 1024, remaining))
            except (socket.timeout, TimeoutError, OSError) as exc:
                raise RequestBodyTimeout("Request body upload timed out") from exc
            if not chunk:
                raise ClientRequestError("Request body ended before Content-Length")
            chunks.append(chunk)
            remaining -= len(chunk)
        self.connection.settimeout(self.server.connection_timeout)
        return b"".join(chunks)

    def _sse_start(self):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        # No Content-Length and no chunked framing: the only end-of-response
        # signal is closing the connection. Without this, HTTP/1.1 keep-alive
        # leaves clients waiting forever after [DONE].
        self.close_connection = True
        self.send_header("Connection", "close")
        self.end_headers()

    def _sse(self, payload: dict, event: str | None = None):
        if event:
            self.wfile.write(f"event: {event}\n".encode())
        self.wfile.write(b"data: " + json.dumps(payload, separators=(",", ":")).encode() + b"\n\n")
        self.wfile.flush()

    def _stream_openai(self, stream):
        self._sse_start()
        try:
            for chunk in stream:
                self._sse(chunk)
            if not stream.receipt_verified:
                raise ClientRequestError("confidential stream ended without a verified receipt")
            self.wfile.write(b"data: [DONE]\n\n")
        except (GatewayError, VerificationError, ValueError, OSError) as exc:
            self._sse({"error": {"type": "confidential_gateway_error", "message": str(exc)}}, "error")

    def _stream_anthropic(self, stream, model: str):
        self._sse_start(); message_id = "msg_" + uuid.uuid4().hex
        self._sse({"type":"message_start","message":{"id":message_id,"type":"message","role":"assistant","model":model,"content":[],"stop_reason":None,"stop_sequence":None,"usage":{"input_tokens":0,"output_tokens":0}}}, "message_start")
        # Preserve each OpenAI stream tool-call index. Anthropic requires
        # content blocks to close in order, so each upstream tool-call block
        # is closed before the next begins while its argument fragments remain
        # associated with its original OpenAI index.
        next_index = 0; open_block = None; blocks = {}; saw_tool = False
        def close_block(block):
            nonlocal open_block
            if block is None or block.get("closed"):
                return
            if block["kind"] == "thinking":
                # Anthropic clients require a terminal signature marker for a
                # thinking block. It is a transport marker only here; the
                # attested receipt remains the cryptographic proof.
                self._sse({"type":"content_block_delta","index":block["index"],"delta":{"type":"signature_delta","signature":""}}, "content_block_delta")
            self._sse({"type":"content_block_stop","index":block["index"]}, "content_block_stop")
            block["closed"] = True
            if open_block is block:
                open_block = None

        def start_plain(kind):
            nonlocal next_index, open_block
            if open_block is not None and open_block["kind"] != kind:
                close_block(open_block)
            if open_block is not None:
                return open_block
            block = {"kind": kind, "index": next_index, "closed": False}
            next_index += 1
            payload = {"type": kind, kind: ""}
            self._sse({"type":"content_block_start","index":block["index"],"content_block":payload}, "content_block_start")
            open_block = block
            return block

        def tool_block(call):
            nonlocal next_index, open_block, saw_tool
            raw_index = call.get("index")
            key = raw_index if isinstance(raw_index, int) else call.get("id")
            if key is None:
                raise ClientRequestError("upstream streamed a tool call without an index or id")
            block = blocks.get(key)
            fn = call.get("function") or {}
            name = fn.get("name") if isinstance(fn, dict) and isinstance(fn.get("name"), str) else ""
            call_id = call.get("id") if isinstance(call.get("id"), str) else ""
            if block is None:
                if not name:
                    raise ClientRequestError("upstream streamed a tool argument before its function name")
                if open_block is not None:
                    close_block(open_block)
                block = {"kind": "tool_use", "index": next_index, "closed": False, "id": call_id or "toolu_" + uuid.uuid4().hex, "name": name}
                next_index += 1
                blocks[key] = block
                self._sse({"type":"content_block_start","index":block["index"],"content_block":{"type":"tool_use","id": "toolu_" + block["id"].removeprefix("toolu_"), "name":name,"input":{}}}, "content_block_start")
                open_block = block
                saw_tool = True
            elif block is not open_block:
                if block.get("closed"):
                    raise ClientRequestError("upstream interleaved tool arguments after an earlier tool block closed")
                if open_block is not None:
                    close_block(open_block)
                open_block = block
            return block
        try:
            usage = {}
            for chunk in stream:
                choice = (chunk.get("choices") or [{}])[0]
                delta = choice.get("delta") or {}
                thinking = delta.get("reasoning_content")
                text = delta.get("content")
                if thinking:
                    block = start_plain("thinking")
                    self._sse({"type":"content_block_delta","index":block["index"],"delta":{"type":"thinking_delta","thinking":thinking}}, "content_block_delta")
                for call in (delta.get("tool_calls") or []):
                    if not isinstance(call, dict):
                        raise ClientRequestError("upstream streamed an invalid tool call")
                    block = tool_block(call)
                    fn = call.get("function") or {}
                    args = fn.get("arguments") if isinstance(fn, dict) and isinstance(fn.get("arguments"), str) else ""
                    if args:
                        self._sse({"type":"content_block_delta","index":block["index"],"delta":{"type":"input_json_delta","partial_json":args}}, "content_block_delta")
                if text:
                    block = start_plain("text")
                    self._sse({"type":"content_block_delta","index":block["index"],"delta":{"type":"text_delta","text":text}}, "content_block_delta")
                usage = chunk.get("usage") or usage
            if not stream.receipt_verified:
                raise ClientRequestError("confidential stream ended without a verified receipt")
            close_block(open_block)
            for block in blocks.values():
                close_block(block)
            self._sse({"type":"message_delta","delta":{"stop_reason":"tool_use" if saw_tool else "end_turn","stop_sequence":None},"usage":{"output_tokens":usage.get("completion_tokens",0)}}, "message_delta")
            self._sse({"type":"message_stop"}, "message_stop")
        except (GatewayError, VerificationError, ValueError, OSError) as exc:
            self._sse({"type":"error","error":{"type":"api_error","message":str(exc)}}, "error")

    def _stream_responses(self, stream, model: str):
        self._sse_start(); rid = "resp_" + uuid.uuid4().hex
        self._sse({"type":"response.created","response":{"id":rid,"object":"response","status":"in_progress","model":model,"output":[]}}, "response.created")
        next_index = 0; text_state = None; tools = {}; completed = []

        def start_text():
            nonlocal next_index, text_state
            if text_state is not None:
                return text_state
            text_state = {"id":"msg_" + uuid.uuid4().hex, "index":next_index, "text":""}
            next_index += 1
            self._sse({"type":"response.output_item.added","output_index":text_state["index"],"item":{"id":text_state["id"],"type":"message","status":"in_progress","role":"assistant","content":[]}}, "response.output_item.added")
            self._sse({"type":"response.content_part.added","item_id":text_state["id"],"output_index":text_state["index"],"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}, "response.content_part.added")
            return text_state

        def start_tool(call):
            nonlocal next_index
            raw_index = call.get("index")
            key = raw_index if isinstance(raw_index, int) else call.get("id")
            if key is None:
                raise ClientRequestError("upstream streamed a tool call without an index or id")
            state = tools.get(key)
            fn = call.get("function") or {}
            name = fn.get("name") if isinstance(fn, dict) and isinstance(fn.get("name"), str) else ""
            call_id = call.get("id") if isinstance(call.get("id"), str) else ""
            if state is None:
                if not name:
                    raise ClientRequestError("upstream streamed a tool argument before its function name")
                call_id = call_id or "call_" + uuid.uuid4().hex
                state = {"id":"fc_" + call_id, "call_id":call_id, "name":name, "index":next_index, "arguments":""}
                next_index += 1
                tools[key] = state
                self._sse({"type":"response.output_item.added","output_index":state["index"],"item":{"id":state["id"],"type":"function_call","status":"in_progress","call_id":call_id,"name":name,"arguments":""}}, "response.output_item.added")
            return state
        try:
            usage = {}
            for chunk in stream:
                choice = (chunk.get("choices") or [{}])[0]
                delta = choice.get("delta") or {}
                text = delta.get("content")
                if text:
                    state = start_text(); state["text"] += text
                    self._sse({"type":"response.output_text.delta","item_id":state["id"],"output_index":state["index"],"content_index":0,"delta":text}, "response.output_text.delta")
                for call in (delta.get("tool_calls") or []):
                    if not isinstance(call, dict):
                        raise ClientRequestError("upstream streamed an invalid tool call")
                    state = start_tool(call)
                    fn = call.get("function") or {}
                    args = fn.get("arguments") if isinstance(fn, dict) and isinstance(fn.get("arguments"), str) else ""
                    if args:
                        state["arguments"] += args
                        self._sse({"type":"response.function_call_arguments.delta","item_id":state["id"],"output_index":state["index"],"delta":args}, "response.function_call_arguments.delta")
                usage = chunk.get("usage") or usage
            if not stream.receipt_verified:
                raise ClientRequestError("confidential stream ended without a verified receipt")
            if text_state is not None:
                item={"id":text_state["id"],"type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":text_state["text"],"annotations":[]}]}
                self._sse({"type":"response.output_text.done","item_id":text_state["id"],"output_index":text_state["index"],"content_index":0,"text":text_state["text"]}, "response.output_text.done")
                self._sse({"type":"response.content_part.done","item_id":text_state["id"],"output_index":text_state["index"],"content_index":0,"part":item["content"][0]}, "response.content_part.done")
                self._sse({"type":"response.output_item.done","output_index":text_state["index"],"item":item}, "response.output_item.done")
                completed.append((text_state["index"], item))
            for state in tools.values():
                item={"id":state["id"],"type":"function_call","status":"completed","call_id":state["call_id"],"name":state["name"],"arguments":state["arguments"]}
                self._sse({"type":"response.function_call_arguments.done","item_id":state["id"],"output_index":state["index"],"name":state["name"],"arguments":state["arguments"]}, "response.function_call_arguments.done")
                self._sse({"type":"response.output_item.done","output_index":state["index"],"item":item}, "response.output_item.done")
                completed.append((state["index"], item))
            output=[item for _index, item in sorted(completed)]
            self._sse({"type":"response.completed","response":{"id":rid,"object":"response","status":"completed","model":model,"output":output,"usage":{"input_tokens":usage.get("prompt_tokens",0),"output_tokens":usage.get("completion_tokens",0),"total_tokens":usage.get("total_tokens",0)}}}, "response.completed")
        except (GatewayError, VerificationError, ValueError, OSError) as exc:
            self._sse({"type":"response.failed","response":{"id":rid,"object":"response","status":"failed","error":{"code":"confidential_gateway_error","message":str(exc)}}}, "response.failed")

    def do_GET(self):
        if self.path == "/healthz":
            return self._json(HTTPStatus.OK, {"status": "ok", "bind": "loopback"})
        return self._json(HTTPStatus.NOT_FOUND, {"error": {"message": "Not found"}})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        # Shape-only request log: method, path, and outcome — never content,
        # headers, or keys. This is the local debugging trail.
        log = getattr(self.server, "logger", None) or (lambda *a: print(*a, flush=True))
        log(f"[gateway] POST {path}")
        if path not in {"/v1/chat/completions", "/v1/messages", "/v1/responses", "/responses"}:
            return self._json(
                HTTPStatus.NOT_FOUND,
                {"error": {"message": "Unsupported local gateway endpoint"}},
                close=True,
            )
        try:
            if not is_json_content_type(self.headers.get("content-type", "")):
                raise ClientRequestError("Content-Type must be application/json")
            size = self._request_size()
            auth = self.headers.get("authorization", "")
            api_key = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else self.headers.get("x-api-key", "").strip()
            local_token = os.environ.get("ADVERSERIAL_LOCAL_GATEWAY_TOKEN", "")
            if local_token and hmac.compare_digest(api_key, local_token):
                api_key = os.environ.get("ADVERSERIAL_UPSTREAM_API_KEY", "")
            payload = json.loads(self._read_body(size))
            if not isinstance(payload, dict):
                raise ClientRequestError("Request must be a JSON object")
            streaming = bool(payload.get("stream"))
            if path == "/v1/messages":
                model = payload.get("model")
                if not isinstance(model, str):
                    raise ClientRequestError("model is required")
                chat = anthropic_to_chat(payload); chat["stream"] = streaming
                result = self.dispatcher.adapted_completion(api_key, model, chat)
                if streaming: return self._stream_anthropic(result, model)
                self._json(HTTPStatus.OK, chat_to_anthropic(dict(result), model))
            elif path in {"/v1/responses", "/responses"}:
                model = payload.get("model")
                if not isinstance(model, str):
                    raise ClientRequestError("model is required")
                chat = responses_to_chat(payload); chat["stream"] = streaming
                result = self.dispatcher.adapted_completion(api_key, model, chat)
                if streaming: return self._stream_responses(result, model)
                self._json(HTTPStatus.OK, chat_to_response(dict(result), model))
            else:
                result = self.dispatcher.completion(api_key, payload)
                if streaming: return self._stream_openai(result)
                self._json(HTTPStatus.OK, dict(result))
        except GatewayError as exc:
            log(f"[gateway] POST {path} -> {exc.status_code} {exc}")
            self._json(exc.status_code, {"error": {"type": "confidential_gateway_error", "message": str(exc)}}, close=True)
        except (ValueError, TypeError, RecursionError) as exc:
            log(f"[gateway] POST {path} -> 400 {exc}")
            self._json(HTTPStatus.BAD_REQUEST, {"error": {"message": str(exc)}}, close=True)


def is_json_content_type(value: str) -> bool:
    return value.split(";", 1)[0].strip().lower() == "application/json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Loopback-only Adverserial confidential OpenAI gateway")
    parser.add_argument("--port", type=int, default=None, help="listen port; 0 requests an OS-assigned port")
    parser.add_argument("--ready-fd", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--fallback-port", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.port is not None and not 0 <= args.port <= 65535:
        parser.error("port must be between 0 and 65535")
    try:
        config = Config.from_env()
    except ConfigError as exc:
        raise SystemExit(f"configuration error: {exc}")
    if args.port is not None:
        config = replace(config, listen_port=args.port)
    Handler.dispatcher = Dispatcher(config)
    try:
        server = BoundedThreadingHTTPServer((config.listen_host, config.listen_port), Handler)
    except OSError as exc:
        if not args.fallback_port or exc.errno != errno.EADDRINUSE:
            raise
        server = BoundedThreadingHTTPServer((config.listen_host, 0), Handler)
    port = server.server_address[1]
    if args.ready_fd is not None:
        with os.fdopen(args.ready_fd, "w", closefd=False) as ready:
            ready.write(json.dumps({"port": port, "pid": os.getpid()}) + "\n")
            ready.flush()
    print(f"adverserial confidential gateway listening on http://{config.listen_host}:{port}", flush=True)
    server.serve_forever()

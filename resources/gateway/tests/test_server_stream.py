import io
import unittest

from adverserial_gateway.server import Handler


class Stream:
    def __init__(self, chunks, verified=True):
        self.chunks = chunks
        self.receipt_verified = verified

    def __iter__(self):
        return iter(self.chunks)


class FixtureHandler(Handler):
    def __init__(self):
        self.wfile = io.BytesIO()

    def send_response(self, *_args):
        pass

    def send_header(self, *_args):
        pass

    def end_headers(self):
        pass


class GatewayStreamTests(unittest.TestCase):
    def test_openai_emits_done_only_after_verified_receipt(self):
        handler = FixtureHandler()
        handler._stream_openai(Stream([{"choices": [{"delta": {"content": "pong"}}]}]))
        wire = handler.wfile.getvalue()
        self.assertIn(b'"pong"', wire)
        self.assertTrue(wire.endswith(b"data: [DONE]\n\n"))

    def test_openai_emits_error_when_receipt_is_missing(self):
        handler = FixtureHandler()
        handler._stream_openai(Stream([{"choices": []}], verified=False))
        wire = handler.wfile.getvalue()
        self.assertIn(b"confidential stream ended without a verified receipt", wire)
        self.assertNotIn(b"data: [DONE]", wire)

    def test_claude_and_responses_streams_emit_native_event_names(self):
        chunk = {"choices": [{"delta": {"content": "pong"}}], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
        claude = FixtureHandler(); claude._stream_anthropic(Stream([chunk]), "lordx64/cyberglm")
        responses = FixtureHandler(); responses._stream_responses(Stream([chunk]), "lordx64/cyberglm")
        self.assertIn(b"event: message_start", claude.wfile.getvalue())
        self.assertIn(b"event: message_stop", claude.wfile.getvalue())
        self.assertIn(b"event: response.created", responses.wfile.getvalue())
        self.assertIn(b"event: response.completed", responses.wfile.getvalue())

    def test_claude_stream_preserves_tool_use_id_and_json_deltas(self):
        chunks = [
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_abc", "function": {"name": "read_file", "arguments": "{\"path\":"}}]}}]},
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "\"a.py\"}"}}]}}]},
        ]
        handler = FixtureHandler(); handler._stream_anthropic(Stream(chunks), "lordx64/cyberglm")
        wire = handler.wfile.getvalue()
        self.assertIn(b'"id":"toolu_call_abc"', wire)
        self.assertIn(b'"type":"input_json_delta"', wire)
        self.assertIn(b'"stop_reason":"tool_use"', wire)

    def test_claude_streams_thinking_then_tool_call_with_a_terminal_stop(self):
        chunks = [
            {"choices": [{"delta": {"reasoning_content": "I will inspect the files."}}]},
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_bash", "function": {"name": "Bash", "arguments": "{\"command\":\"ls\"}"}}]}}]},
        ]
        handler = FixtureHandler(); handler._stream_anthropic(Stream(chunks), "lordx64/cyberglm")
        wire = handler.wfile.getvalue()
        thinking_start = wire.index(b'"type":"thinking"')
        tool_start = wire.index(b'"type":"tool_use"')
        self.assertLess(thinking_start, tool_start)
        self.assertIn(b'"type":"thinking_delta"', wire)
        self.assertIn(b'"type":"signature_delta"', wire)
        self.assertIn(b'"name":"Bash"', wire)
        self.assertIn(b'"stop_reason":"tool_use"', wire)
        self.assertTrue(wire.endswith(b'event: message_stop\ndata: {"type":"message_stop"}\n\n'))

    def test_responses_stream_preserves_function_call_events(self):
        chunks = [
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_abc", "function": {"name": "read_file", "arguments": "{\"path\":"}}]}}]},
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "\"a.py\"}"}}]}}]},
        ]
        handler = FixtureHandler(); handler._stream_responses(Stream(chunks), "lordx64/cyberglm")
        wire = handler.wfile.getvalue()
        self.assertIn(b"event: response.function_call_arguments.delta", wire)
        self.assertIn(b"event: response.function_call_arguments.done", wire)
        self.assertIn(b'"call_id":"call_abc"', wire)

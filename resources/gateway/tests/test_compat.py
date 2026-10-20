import unittest

from adverserial_gateway.compat import anthropic_to_chat, chat_to_anthropic, chat_to_response, responses_to_chat
from adverserial_gateway.core import ClientRequestError


class CompatibilityTests(unittest.TestCase):
    def test_responses_rejects_invalid_output_limits(self):
        for value in (0, -1, False, True, "20", 1.5):
            with self.subTest(value=value), self.assertRaises(ClientRequestError):
                responses_to_chat({"input": "hello", "max_output_tokens": value})

    def test_anthropic_text_is_translated_without_dropping_system(self):
        chat = anthropic_to_chat({"system": "Be precise", "max_tokens": 50, "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]})
        self.assertEqual(chat["messages"], [{"role": "system", "content": "Be precise"}, {"role": "user", "content": "hello"}])
        self.assertEqual(chat["max_tokens"], 50)

    def test_anthropic_refuses_unrepresentable_content(self):
        with self.assertRaises(ClientRequestError):
            anthropic_to_chat({"max_tokens": 1, "messages": [{"role": "user", "content": [{"type": "image"}]}]})

    def test_anthropic_preserves_tool_turns_and_tool_ids(self):
        chat = anthropic_to_chat({
            "max_tokens": 50,
            "tools": [{"name": "read_file", "description": "read", "input_schema": {"type": "object"}}],
            "messages": [
                {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_call_1", "name": "read_file", "input": {"path": "a.py"}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_call_1", "content": "print('ok')"}]},
            ],
        })
        self.assertEqual(chat["messages"][0]["tool_calls"][0]["id"], "call_1")
        self.assertEqual(chat["messages"][1], {"role": "tool", "tool_call_id": "call_1", "content": "print('ok')"})
        self.assertEqual(chat["tools"][0]["function"]["name"], "read_file")

    def test_responses_maps_developer_and_text_content(self):
        chat = responses_to_chat({"instructions": "top", "input": [{"role": "developer", "content": [{"type": "input_text", "text": "policy"}]}, {"role": "user", "content": "hi"}], "max_output_tokens": 9})
        self.assertEqual(chat["messages"][0], {"role": "system", "content": "top"})
        self.assertEqual(chat["messages"][1], {"role": "system", "content": "policy"})
        self.assertEqual(chat["max_tokens"], 9)

    def test_responses_discards_hosted_codex_tools_but_preserves_local_functions(self):
        chat = responses_to_chat({
            "input": "hello",
            "tools": [
                {"type": "function", "name": "exec_command", "description": "local shell", "parameters": {"type": "object"}, "strict": True},
                {"type": "namespace", "name": "multi_agent_v1", "tools": [{"type": "function", "name": "spawn_agent", "parameters": {"type": "object"}}]},
                {"type": "web_search", "external_web_access": True},
                {"type": "image_generation", "output_format": "png"},
            ],
        })
        self.assertEqual([tool["function"]["name"] for tool in chat["tools"]], ["exec_command"])

    def test_responses_optional_image_generation_does_not_block_plain_text(self):
        chat = responses_to_chat({"input": "hello", "tools": [{"type": "image_generation"}], "tool_choice": "auto"})
        self.assertEqual(chat["messages"], [{"role": "user", "content": "hello"}])
        self.assertNotIn("tools", chat)

    def test_responses_cannot_force_unsupported_image_generation(self):
        for choice in ({"type": "image_generation"}, "required"):
            with self.subTest(choice=choice), self.assertRaises(ClientRequestError):
                responses_to_chat({"input": "draw a cat", "tools": [{"type": "image_generation"}], "tool_choice": choice})

    def test_responses_rejects_an_unknown_hosted_tool_class(self):
        with self.assertRaisesRegex(ClientRequestError, "unavailable"):
            responses_to_chat({"input": "hello", "tools": [{"type": "computer"}]})

    def test_responses_preserves_function_call_result_and_tool_definition(self):
        chat = responses_to_chat({
            "input": [
                {"role": "user", "content": "find the file"},
                {"type": "function_call", "call_id": "call_123", "name": "glob", "arguments": "{\"pattern\":\"*.py\"}"},
                {"type": "function_call_output", "call_id": "call_123", "output": "main.py"},
            ],
            "tools": [{"type": "function", "name": "glob", "description": "search", "parameters": {"type": "object"}}],
            "tool_choice": {"type": "function", "name": "glob"},
        })
        self.assertEqual(chat["messages"][1]["tool_calls"][0]["id"], "call_123")
        self.assertEqual(chat["messages"][2], {"role": "tool", "tool_call_id": "call_123", "content": "main.py"})
        self.assertEqual(chat["tools"][0]["function"]["name"], "glob")
        self.assertEqual(chat["tool_choice"], {"type": "function", "function": {"name": "glob"}})

    def test_response_adapters_preserve_usage(self):
        raw = {"id": "chat_1", "model": "lordx64/cyberglm", "choices": [{"message": {"content": "pong"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 2, "completion_tokens": 1}}
        anthropic = chat_to_anthropic(raw, "lordx64/cyberglm")
        response = chat_to_response(raw, "lordx64/cyberglm")
        self.assertEqual(anthropic["content"][0]["text"], "pong")
        self.assertEqual(response["output"][0]["content"][0]["text"], "pong")
        self.assertEqual(response["usage"]["total_tokens"], 3)

    def test_response_adapter_emits_native_function_call_items(self):
        raw = {"choices": [{"message": {"tool_calls": [{"id": "call_456", "function": {"name": "read_file", "arguments": "{\"path\":\"a.py\"}"}}]}, "finish_reason": "tool_calls"}], "usage": {}}
        response = chat_to_response(raw, "lordx64/cyberglm")
        self.assertEqual(response["output"][0], {"id": "fc_call_456", "type": "function_call", "status": "completed", "call_id": "call_456", "name": "read_file", "arguments": "{\"path\":\"a.py\"}"})

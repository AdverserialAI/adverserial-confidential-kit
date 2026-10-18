import json
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from adverserial import UpstreamHTTPError
from adverserial_gateway.config import Config
from adverserial_gateway.core import (
    ClientRequestError,
    Dispatcher,
    OutcomeUnknownError,
    UpstreamRejected,
    canonical_model_id,
)


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        keys = Path(self.tmp.name) / "keys.json"
        keys.write_text(json.dumps({"kid": {"kty": "EC"}}))
        self.cfg = Config.from_env({
            "ADVERSERIAL_RECEIPT_KEYS_FILE": str(keys),
            "ADVERSERIAL_HARDWARE_VERIFIER_COMMAND": sys.executable,
        })
        self.dispatcher = Dispatcher(self.cfg)

    def tearDown(self):
        self.tmp.cleanup()

    def test_unknown_models_cannot_reach_the_entitlement_exchange(self):
        with self.assertRaises(ClientRequestError):
            self.dispatcher.completion("sk-" + "x" * 24, {"model": "gpt-5", "messages": []})

    def test_billing_requests_ignore_shell_proxies_and_redirects(self):
        handlers = self.dispatcher._billing_opener.handlers
        # build_opener drops an empty ProxyHandler from the final handler chain;
        # its absence means it cannot consult environment proxy variables.
        self.assertFalse(any(isinstance(handler, urllib.request.ProxyHandler) for handler in handlers))
        redirect = next(handler for handler in handlers if type(handler).__name__ == "_NoBillingRedirect")
        request = urllib.request.Request("https://billing.example/cc/entitlements")
        self.assertIsNone(redirect.redirect_request(request, None, 302, "Found", {}, "https://other.example/"))

    def test_claude_child_model_aliases_resolve_to_canonical_cyberglm(self):
        self.assertEqual(canonical_model_id("claude-haiku-4-5-20251001"), "lordx64/cyberglm")
        self.assertEqual(canonical_model_id("claude-sonnet-4-6"), "lordx64/cyberglm")
        self.assertEqual(canonical_model_id("cyberglm"), "lordx64/cyberglm")

    def test_claude_alias_is_canonicalized_before_proof_entitlement_and_runtime(self):
        proof = object()
        payload = {"model": "claude-haiku-4-5-20251001", "messages": [{"role": "user", "content": "hello"}], "max_tokens": 12}
        with patch.object(self.dispatcher, "proof_for", return_value=proof) as proof_for, patch.object(
            self.dispatcher, "entitlement", return_value="signed-entitlement"
        ) as entitlement, patch("adverserial_gateway.core.VerifiedSession") as session:
            session.return_value.chat_completions.return_value = {"id": "ok"}
            self.dispatcher.completion("sk-" + "x" * 24, payload)
        self.assertEqual(proof_for.call_args.args[0], "lordx64/cyberglm")
        self.assertEqual(entitlement.call_args.args[1], "lordx64/cyberglm")
        self.assertEqual(session.return_value.chat_completions.call_args.kwargs["model"], "lordx64/cyberglm")

    def test_gateway_replaces_api_key_with_entitlement_before_direct_call(self):
        proof = object()
        payload = {"model": "lordx64/cyberglm", "messages": [{"role": "user", "content": "hello"}], "max_tokens": 12}
        with patch.object(self.dispatcher, "proof_for", return_value=proof), patch.object(
            self.dispatcher, "entitlement", return_value="signed-entitlement"
        ) as entitlement, patch("adverserial_gateway.core.VerifiedSession") as session:
            session.return_value.chat_completions.return_value = {"id": "ok"}
            result = self.dispatcher.completion("sk-" + "x" * 24, payload)
        self.assertEqual(result, {"id": "ok"})
        self.assertEqual(entitlement.call_args.args[0], "sk-" + "x" * 24)
        self.assertEqual(session.call_args.kwargs["entitlement"], "signed-entitlement")
        self.assertNotEqual(session.call_args.kwargs["entitlement"], entitlement.call_args.args[0])
        self.assertEqual(session.return_value.chat_completions.call_args.kwargs["model"], "lordx64/cyberglm")

    def test_gateway_forwards_stream_flag_to_verified_session(self):
        proof = object()
        payload = {"model": "lordx64/cyberglm", "messages": [{"role": "user", "content": "hello"}], "max_tokens": 12, "stream": True}
        with patch.object(self.dispatcher, "proof_for", return_value=proof), patch.object(
            self.dispatcher, "entitlement", return_value="signed-entitlement"
        ), patch("adverserial_gateway.core.VerifiedSession") as session:
            stream = object(); session.return_value.chat_completions.return_value = stream
            result = self.dispatcher.completion("sk-" + "x" * 24, payload)
        self.assertIs(result, stream)
        self.assertTrue(session.return_value.chat_completions.call_args.kwargs["stream"])

    def _completion_failure(self, exc, dispatched):
        payload = {"model": "lordx64/cyberglm", "messages": [{"role": "user", "content": "hello"}], "max_tokens": 12}
        with patch.object(self.dispatcher, "proof_for", return_value=object()), patch.object(
            self.dispatcher, "entitlement", return_value="signed-entitlement"
        ), patch.object(self.dispatcher, "release_reservation") as release, patch(
            "adverserial_gateway.core.VerifiedSession"
        ) as session:
            session.return_value.dispatched = dispatched
            session.return_value.chat_completions.side_effect = exc
            with self.assertRaises(Exception) as raised:
                self.dispatcher.completion("sk-" + "x" * 24, payload)
        return raised.exception, release

    def test_pre_dispatch_failure_releases_the_reservation(self):
        exc, release = self._completion_failure(ValueError("bad payload"), dispatched=False)
        self.assertIsInstance(exc, ValueError)
        release.assert_called_once()

    def test_gate_4xx_releases_and_surfaces_the_upstream_status(self):
        exc, release = self._completion_failure(UpstreamHTTPError(429, "queue full"), dispatched=True)
        self.assertIsInstance(exc, UpstreamRejected)
        self.assertEqual(exc.status_code, 429)
        release.assert_called_once()

    def test_upstream_5xx_never_releases_the_reservation(self):
        exc, release = self._completion_failure(UpstreamHTTPError(500, "generation failed"), dispatched=True)
        self.assertIsInstance(exc, UpstreamRejected)
        self.assertEqual(exc.status_code, 500)
        release.assert_not_called()

    def test_post_dispatch_timeout_is_outcome_unknown_and_never_released(self):
        exc, release = self._completion_failure(TimeoutError("timed out"), dispatched=True)
        self.assertIsInstance(exc, OutcomeUnknownError)
        self.assertEqual(exc.status_code, 502)
        release.assert_not_called()

    def test_successful_completion_never_releases(self):
        payload = {"model": "lordx64/cyberglm", "messages": [{"role": "user", "content": "hello"}], "max_tokens": 12}
        with patch.object(self.dispatcher, "proof_for", return_value=object()), patch.object(
            self.dispatcher, "entitlement", return_value="signed-entitlement"
        ), patch.object(self.dispatcher, "release_reservation") as release, patch(
            "adverserial_gateway.core.VerifiedSession"
        ) as session:
            session.return_value.chat_completions.return_value = {"id": "ok"}
            self.dispatcher.completion("sk-" + "x" * 24, payload)
        release.assert_not_called()


if __name__ == "__main__":
    unittest.main()

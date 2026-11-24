"""Server key rotation, enclave reboots, and the per-session prefix-cache salt."""
import json
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from adverserial import EHBPKeyMismatchError, TLSPinMismatchError, UpstreamHTTPError, VerificationError
from adverserial_gateway.config import Config
from adverserial_gateway.core import (
    Dispatcher,
    UpstreamRejected,
    VerificationFailed,
    new_cache_salt,
    valid_cache_salt,
)
from adverserial_gateway.server import carry_cache_salt

MODEL = "adverserial/cyberseek"
KEY = "sk-" + "x" * 24
SALT = re.compile(r"^[A-Za-z0-9_-]{43}$")


def proof(*, tls="sha256:tls-a", ehbp="sha256:ehbp-a", kid="kid-a", age=600):
    now = int(time.time())
    return SimpleNamespace(
        model_id=MODEL, dev_mode=False, issued_epoch=now - age, expires_epoch=now + 600,
        tls_spki_sha256=tls, ehbp_public_key_sha256=ehbp, receipt_key_id=kid,
    )


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.keys = Path(self.tmp.name) / "receipt-keys.json"
        self.keys.write_text(json.dumps({"kid-a": {"kty": "EC", "crv": "P-256", "x": "a", "y": "a"}}))
        self.dispatcher = Dispatcher(Config.from_env({
            "ADVERSERIAL_RECEIPT_KEYS_FILE": str(self.keys),
            "ADVERSERIAL_HARDWARE_VERIFIER_COMMAND": sys.executable,
        }))

    def tearDown(self):
        self.tmp.cleanup()

    def run_completion(self, payload, *, proofs, outcomes):
        """Dispatch with scripted proofs (verify_endpoint results) and session outcomes."""
        sessions = []

        def make_session(_url, *, proof, entitlement, timeout):
            outcome = outcomes[len(sessions)]
            session = SimpleNamespace(proof=proof, entitlement=entitlement, dispatched=outcome.get("dispatched", True), calls=[])

            def chat(messages, **kwargs):
                session.calls.append({"messages": messages, **kwargs})
                if "raise" in outcome:
                    raise outcome["raise"]
                return outcome["result"]
            session.chat_completions = chat
            sessions.append(session)
            return session

        with patch("adverserial_gateway.core.verify_endpoint", side_effect=proofs) as verify, patch.object(
            self.dispatcher, "entitlement", side_effect=lambda *args: f"entitlement-{len(sessions)}"
        ) as entitlement, patch.object(self.dispatcher, "release_reservation") as release, patch(
            "adverserial_gateway.core.VerifiedSession", side_effect=make_session
        ):
            try:
                result, error = self.dispatcher.completion(KEY, payload), None
            except Exception as exc:  # noqa: BLE001 - the tests assert on the type
                result, error = None, exc
        return SimpleNamespace(result=result, error=error, sessions=sessions, verify=verify, entitlement=entitlement, release=release)


class CacheSaltTests(Base):
    PAYLOAD = {"model": MODEL, "messages": [{"role": "user", "content": "hello"}], "max_tokens": 12}

    def forwarded(self, payload):
        run = self.run_completion(payload, proofs=[proof()], outcomes=[{"result": {"id": "ok"}}])
        self.assertIsNone(run.error)
        return run.sessions[0].calls[0], run

    def test_salt_is_32_random_bytes_unpadded_base64url(self):
        salt = new_cache_salt()
        self.assertRegex(salt, SALT)
        self.assertNotIn("=", salt)
        self.assertTrue(valid_cache_salt(salt))
        self.assertNotEqual(salt, new_cache_salt())

    def test_every_forwarded_request_carries_the_session_salt(self):
        first, _ = self.forwarded(dict(self.PAYLOAD))
        second, _ = self.forwarded({**self.PAYLOAD, "messages": [{"role": "user", "content": "again"}]})
        self.assertRegex(first["cache_salt"], SALT)
        self.assertEqual(first["cache_salt"], second["cache_salt"])

    def test_each_gateway_process_gets_its_own_salt(self):
        other = Dispatcher(self.dispatcher.config)
        self.assertNotEqual(other._cache_salt, self.dispatcher._cache_salt)

    def test_a_valid_client_salt_is_kept(self):
        for chosen in ("A" * 32, "client_salt-" + "z" * 40, "b" * 128):
            with self.subTest(chosen=chosen):
                call, _ = self.forwarded({**self.PAYLOAD, "cache_salt": chosen})
                self.assertEqual(call["cache_salt"], chosen)

    def test_a_malformed_client_salt_is_replaced_not_forwarded(self):
        for bad in ("short", "a" * 129, "has space" + "a" * 32, "a" * 32 + "\n", "é" * 40, 12345, None, ["a" * 32], ""):
            with self.subTest(bad=bad):
                call, _ = self.forwarded({**self.PAYLOAD, "cache_salt": bad})
                self.assertEqual(call["cache_salt"], self.dispatcher._cache_salt)

    def test_client_extra_key_is_never_forwarded(self):
        call, run = self.forwarded({**self.PAYLOAD, "extra_key": "tenant-override", "cache_salt": "A" * 32})
        self.assertNotIn("extra_key", call)
        self.assertEqual(call["cache_salt"], "A" * 32)
        # The stripped field is not billed for either.
        expected = {**self.PAYLOAD, "cache_salt": "A" * 32}
        size = len(json.dumps(expected, ensure_ascii=False, separators=(",", ":")).encode())
        self.assertEqual(run.entitlement.call_args.args[2], 2 * size + 4096)

    def test_reservation_counts_the_added_salt_and_bounds_the_wire_body(self):
        payload = {**self.PAYLOAD, "messages": [{"role": "user", "content": "héllo 🌍 " * 50}]}
        call, run = self.forwarded(dict(payload))
        with_salt = {**payload, "cache_salt": self.dispatcher._cache_salt}
        without = len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode())
        size = len(json.dumps(with_salt, ensure_ascii=False, separators=(",", ":")).encode())
        reserved = run.entitlement.call_args.args[2]
        self.assertEqual(reserved, 2 * size + 4096)
        self.assertGreater(reserved, 2 * without + 4096)
        # What VerifiedSession actually serializes (default separators, plus stream).
        wire = {"model": MODEL, "messages": call["messages"], "stream": call["stream"]}
        wire.update({k: v for k, v in call.items() if k not in {"messages", "model", "stream"}})
        self.assertIn("cache_salt", wire)
        self.assertLessEqual(len(json.dumps(wire, ensure_ascii=False).encode()), reserved)

    def test_a_request_at_the_input_limit_is_refused_locally_once_the_salt_is_counted(self):
        limit = self.dispatcher.config.max_input_tokens
        base = {**self.PAYLOAD, "messages": [{"role": "user", "content": ""}]}
        room = (limit - 4096) // 2 - len(json.dumps(base, ensure_ascii=False, separators=(",", ":")).encode())
        base["messages"][0]["content"] = "a" * room
        # Without the salt this body reserves exactly the limit; the salt is
        # billed like any other forwarded byte, so it is refused before billing.
        self.assertEqual(2 * len(json.dumps(base, ensure_ascii=False, separators=(",", ":")).encode()) + 4096, limit)
        run = self.run_completion(base, proofs=[proof()], outcomes=[])
        self.assertRegex(str(run.error), "exceeds the confidential input policy")
        run.entitlement.assert_not_called()
        run.verify.assert_not_called()

    def test_adapters_keep_a_client_salt_and_drop_extra_key(self):
        chat = {"messages": []}
        carry_cache_salt({"cache_salt": "A" * 32, "extra_key": "x"}, chat)
        self.assertEqual(chat, {"messages": [], "cache_salt": "A" * 32})
        untouched = {"messages": []}
        carry_cache_salt({"input": "hi"}, untouched)
        self.assertNotIn("cache_salt", untouched)
        run = self.run_completion({**chat, "model": MODEL}, proofs=[proof()], outcomes=[{"result": {"id": "ok"}}])
        self.assertEqual(run.sessions[0].calls[0]["cache_salt"], "A" * 32)


class RebootRecoveryTests(Base):
    PAYLOAD = {"model": MODEL, "messages": [{"role": "user", "content": "hello"}], "max_tokens": 12}

    def test_new_tls_key_after_reboot_reverifies_and_retries_once(self):
        old, new = proof(), proof(tls="sha256:tls-b", ehbp="sha256:ehbp-b", age=0)
        run = self.run_completion(self.PAYLOAD, proofs=[old, new], outcomes=[
            {"dispatched": False, "raise": TLSPinMismatchError("pin mismatch")},
            {"result": {"id": "ok"}},
        ])
        self.assertEqual(run.result, {"id": "ok"})
        self.assertEqual(run.verify.call_count, 2)
        self.assertIs(run.sessions[1].proof, new)
        self.assertEqual(run.entitlement.call_count, 2)
        self.assertIs(run.entitlement.call_args.args[4], new)
        run.release.assert_called_once_with(KEY, "entitlement-0")
        self.assertIs(self.dispatcher._proofs[MODEL].proof, new)

    def test_stale_ehbp_key_reverifies_and_retries_once(self):
        old, new = proof(age=5), proof(ehbp="sha256:ehbp-b", age=0)
        run = self.run_completion(self.PAYLOAD, proofs=[old, new], outcomes=[
            {"raise": EHBPKeyMismatchError(422, "key configuration mismatch")},
            {"result": {"id": "ok"}},
        ])
        self.assertEqual(run.result, {"id": "ok"})
        self.assertEqual(len(run.sessions), 2)
        self.assertIs(run.sessions[1].proof, new)
        run.release.assert_called_once_with(KEY, "entitlement-0")

    def test_generic_gate_rejection_with_rotated_keys_retries_once(self):
        old, new = proof(age=120), proof(ehbp="sha256:ehbp-b", age=0)
        run = self.run_completion(self.PAYLOAD, proofs=[old, new], outcomes=[
            {"raise": UpstreamHTTPError(400, "could not decrypt request")},
            {"result": {"id": "ok"}},
        ])
        self.assertEqual(run.result, {"id": "ok"})
        self.assertEqual(len(run.sessions), 2)

    def test_rejection_with_unchanged_keys_is_not_retried(self):
        old, same = proof(age=120), proof(age=0)
        run = self.run_completion(self.PAYLOAD, proofs=[old, same], outcomes=[{"raise": UpstreamHTTPError(400, "bad request")}])
        self.assertIsInstance(run.error, UpstreamRejected)
        self.assertEqual(run.error.status_code, 400)
        self.assertEqual(len(run.sessions), 1)
        self.assertEqual(run.verify.call_count, 2)
        run.release.assert_called_once()

    def test_rejection_with_a_just_verified_proof_does_not_reattest(self):
        run = self.run_completion(self.PAYLOAD, proofs=[proof(age=2)], outcomes=[{"raise": UpstreamHTTPError(429, "queue full")}])
        self.assertIsInstance(run.error, UpstreamRejected)
        self.assertEqual(run.verify.call_count, 1)
        self.assertEqual(len(run.sessions), 1)

    def test_rate_limits_never_trigger_a_reattestation(self):
        for status in (404, 409, 413, 429):
            with self.subTest(status=status):
                self.dispatcher._proofs[MODEL].proof = None
                run = self.run_completion(self.PAYLOAD, proofs=[proof(age=280), proof(ehbp="sha256:ehbp-b", age=0)], outcomes=[{"raise": UpstreamHTTPError(status, "no")}])
                self.assertEqual(run.error.status_code, status)
                self.assertEqual(run.verify.call_count, 1)
                self.assertEqual(len(run.sessions), 1)

    def test_a_rejection_is_not_retried_when_only_other_keys_changed(self):
        old, new = proof(age=120), proof(kid="kid-b", age=0)
        run = self.run_completion(self.PAYLOAD, proofs=[old, new], outcomes=[{"raise": UpstreamHTTPError(401, "entitlement rejected")}])
        self.assertIsInstance(run.error, UpstreamRejected)
        self.assertEqual(len(run.sessions), 1)

    def test_a_second_failure_is_final(self):
        old, new, newer = proof(), proof(tls="sha256:tls-b", age=0), proof(tls="sha256:tls-c", age=0)
        run = self.run_completion(self.PAYLOAD, proofs=[old, new, newer], outcomes=[
            {"dispatched": False, "raise": TLSPinMismatchError("pin mismatch")},
            {"dispatched": False, "raise": TLSPinMismatchError("pin mismatch again")},
        ])
        self.assertIsInstance(run.error, VerificationFailed)
        self.assertEqual(len(run.sessions), 2)
        self.assertEqual(run.verify.call_count, 2)
        self.assertEqual(run.release.call_count, 2)

    def test_stale_ehbp_key_is_retried_at_most_once(self):
        old, new = proof(), proof(ehbp="sha256:ehbp-b", age=0)
        run = self.run_completion(self.PAYLOAD, proofs=[old, new], outcomes=[
            {"raise": EHBPKeyMismatchError(422, "mismatch")},
            {"raise": EHBPKeyMismatchError(422, "mismatch")},
        ])
        self.assertIsInstance(run.error, UpstreamRejected)
        self.assertEqual(run.error.status_code, 422)
        self.assertEqual(len(run.sessions), 2)

    def test_failures_after_generation_may_have_started_are_never_retried(self):
        for failure in (UpstreamHTTPError(500, "failed"), UpstreamHTTPError(503, "restarting"), TimeoutError("timed out"), ConnectionResetError("reset")):
            with self.subTest(failure=failure):
                self.dispatcher._proofs[MODEL].proof = None
                run = self.run_completion(self.PAYLOAD, proofs=[proof(), proof(ehbp="sha256:ehbp-b", age=0)], outcomes=[{"raise": failure}])
                self.assertIsNotNone(run.error)
                self.assertEqual(len(run.sessions), 1)
                self.assertEqual(run.verify.call_count, 1)
                run.release.assert_not_called()

    def test_rotated_receipt_key_fails_closed_with_the_recovery_command(self):
        rotated = VerificationError("the service rotated its keys: … Run `ack upgrade` to re-pin the published policy")
        run = self.run_completion(self.PAYLOAD, proofs=[proof(), rotated], outcomes=[
            {"dispatched": False, "raise": TLSPinMismatchError("pin mismatch")},
        ])
        self.assertIsInstance(run.error, VerificationFailed)
        self.assertEqual(run.error.status_code, 503)
        self.assertIn("rotated its keys", str(run.error))
        self.assertIn("ack upgrade", str(run.error))
        self.assertEqual(len(run.sessions), 1)
        self.assertIsNone(self.dispatcher._proofs[MODEL].proof)

    def test_unreachable_enclave_reports_a_gateway_error_instead_of_dropping_the_client(self):
        down = VerificationError("could not reach the attestation endpoint: refused")
        run = self.run_completion(self.PAYLOAD, proofs=[proof(), down], outcomes=[
            {"dispatched": False, "raise": ConnectionRefusedError("refused")},
        ])
        self.assertIsInstance(run.error, VerificationFailed)
        run.release.assert_called_once()

    def test_recovery_never_reuses_material_from_the_failed_exchange(self):
        # The replacement proof must come from verify_endpoint (full attestation),
        # with the same pins, model and hardware verifier as the first one.
        old, new = proof(), proof(ehbp="sha256:ehbp-b", age=0)
        run = self.run_completion(self.PAYLOAD, proofs=[old, new], outcomes=[
            {"raise": EHBPKeyMismatchError(422, "mismatch")}, {"result": {"id": "ok"}},
        ])
        first, second = run.verify.call_args_list
        self.assertEqual(first.kwargs.keys(), second.kwargs.keys())
        for name in ("expected_model_id", "trusted_receipt_keys", "issuer", "audience", "expected_endpoint"):
            self.assertEqual(first.kwargs[name], second.kwargs[name])
        self.assertIsNotNone(second.kwargs["hardware_verifier"])

    def test_a_proof_replaced_by_another_request_is_not_verified_twice(self):
        old, new = proof(), proof(ehbp="sha256:ehbp-b", age=0)
        self.dispatcher._proofs[MODEL].proof = new
        with patch("adverserial_gateway.core.verify_endpoint") as verify:
            self.assertIs(self.dispatcher.reverified_proof(MODEL, old), new)
        verify.assert_not_called()


class PinReloadTests(Base):
    def rewrite(self, value):
        self.keys.write_text(value if isinstance(value, str) else json.dumps(value))
        stamp = time.time_ns() + 5_000_000_000
        os.utime(self.keys, ns=(stamp, stamp))

    def test_ack_upgrade_repin_reaches_a_running_gateway(self):
        self.assertEqual(list(self.dispatcher.pinned_receipt_keys()), ["kid-a"])
        self.rewrite({"kid-b": {"kty": "EC", "crv": "P-256", "x": "b", "y": "b"}})
        self.assertEqual(list(self.dispatcher.pinned_receipt_keys()), ["kid-b"])
        with patch("adverserial_gateway.core.verify_endpoint", return_value=proof(kid="kid-b")) as verify:
            self.dispatcher.proof_for(MODEL)
        self.assertEqual(list(verify.call_args.kwargs["trusted_receipt_keys"]), ["kid-b"])

    def test_a_broken_or_missing_pin_file_never_changes_the_loaded_pins(self):
        for broken in ("{not json", "{}", "[]", json.dumps({"kid": "not-a-jwk"})):
            with self.subTest(broken=broken):
                self.rewrite(broken)
                self.assertEqual(list(self.dispatcher.pinned_receipt_keys()), ["kid-a"])
        self.keys.unlink()
        self.assertEqual(list(self.dispatcher.pinned_receipt_keys()), ["kid-a"])


if __name__ == "__main__":
    unittest.main()

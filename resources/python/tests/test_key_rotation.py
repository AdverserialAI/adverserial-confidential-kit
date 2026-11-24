"""What a client sees when the service rotates its keys or reboots."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from adverserial import EHBPKeyMismatchError, ReceiptKeyNotPinnedError, UpstreamHTTPError, VerificationError, verify_endpoint
from adverserial.session import VerifiedSession, _is_ehbp_key_mismatch
from adverserial.verify import _unpinned_receipt_key_message

from fixture_server import FakeAttestProxy

MODEL = "lordx64/cyberglm"
ISSUER = "https://verify.adverserial.ai"
AUDIENCE = "https://chat.adverserial.ai"

PROBLEM = json.dumps({"type": "urn:ietf:params:ehbp:error:key-config", "title": "key configuration mismatch"}).encode()


def accept_hardware(*_args):
    from adverserial import HardwareVerification
    return HardwareVerification(verified=True, verifier="fixture")


class RotatedReceiptKeyTests(unittest.TestCase):
    def verify(self, fake, **overrides):
        options = dict(expected_model_id=MODEL, trusted_receipt_keys=fake.trusted_keys, issuer=ISSUER, audience=AUDIENCE,
                       expected_endpoint=fake.endpoint, hardware_verifier=accept_hardware, allow_dev_mode=True)
        options.update(overrides)
        return verify_endpoint(fake.v1_url, **options)

    def test_old_pins_fail_closed_and_name_the_recovery_command(self):
        # `rotated` is the service after it regenerated its receipt key; the
        # client still pins the key of the previous deployment.
        with FakeAttestProxy() as rotated, FakeAttestProxy() as previous:
            hardware = Mock(side_effect=accept_hardware)
            with self.assertRaises(ReceiptKeyNotPinnedError) as raised:
                self.verify(rotated, trusted_receipt_keys=previous.trusted_keys, hardware_verifier=hardware)
            self.assertIsInstance(raised.exception, VerificationError)
            self.assertIn("ack upgrade", str(raised.exception))
            self.assertIn("rotated its keys", str(raised.exception))
            # Nothing downstream of the signature check ran for an unknown signer.
            hardware.assert_not_called()

    def test_published_policy_only_changes_the_wording_never_the_verdict(self):
        with FakeAttestProxy() as rotated, FakeAttestProxy() as previous:
            kid = next(iter(rotated.trusted_keys))
            policy = {"status": "active", "model_id": MODEL, "receipt_keys": dict(rotated.trusted_keys)}
            with self.assertRaisesRegex(ReceiptKeyNotPinnedError, "published policy lists.*`ack upgrade`"):
                self.verify(rotated, trusted_receipt_keys=previous.trusted_keys, expected_policy=policy)
            self.assertIn(kid[:16], _unpinned_receipt_key_message(kid, policy))

    def test_a_signer_absent_from_the_published_policy_is_called_out(self):
        message = _unpinned_receipt_key_message("unknown-kid", {"receipt_keys": {"other": {}}})
        self.assertIn("neither pinned", message)
        self.assertIn("do not trust this endpoint", message)

    def test_after_repinning_the_rotated_service_verifies(self):
        with FakeAttestProxy() as rotated:
            proof = self.verify(rotated, trusted_receipt_keys=dict(rotated.trusted_keys))
            self.assertEqual(proof.status, "verified")

    def test_missing_or_wrong_algorithm_keeps_the_generic_rejection(self):
        with FakeAttestProxy() as fake, patch("adverserial.verify.parse_compact_jws", return_value=({"alg": "none", "kid": "k"}, {}, b"", b"")):
            with self.assertRaisesRegex(VerificationError, "configured ES256"):
                self.verify(fake)


class StaleEHBPKeyTests(unittest.TestCase):
    def test_only_the_ehbp_key_config_problem_document_counts(self):
        self.assertTrue(_is_ehbp_key_mismatch(422, "application/problem+json", PROBLEM))
        self.assertTrue(_is_ehbp_key_mismatch(422, "Application/Problem+JSON; charset=utf-8", PROBLEM))
        self.assertFalse(_is_ehbp_key_mismatch(400, "application/problem+json", PROBLEM))
        self.assertFalse(_is_ehbp_key_mismatch(422, "application/json", PROBLEM))
        self.assertFalse(_is_ehbp_key_mismatch(422, None, PROBLEM))
        self.assertFalse(_is_ehbp_key_mismatch(422, "application/problem+json", b"not json"))
        self.assertFalse(_is_ehbp_key_mismatch(422, "application/problem+json", b'{"type":"about:blank"}'))

    def session(self, status, content_type, body):
        session = object.__new__(VerifiedSession)
        session._base_path = "/v1"
        session._headers = lambda headers: dict(headers)
        session._require_receipts = True
        session.dispatched = False
        response = Mock(status=status)
        response.read.return_value = body
        response.getheader.side_effect = lambda name, default=None: content_type if name.lower() == "content-type" else default
        connection = Mock()
        connection.getresponse.return_value = response
        session._connect = lambda: connection
        session._ehbp_identity = Mock()
        session._ehbp_identity.return_value.encrypt_request_body.return_value = Mock(body=b"sealed", encapsulated_key=b"\x01" * 32)
        return session, connection

    def test_both_encrypted_paths_report_a_stale_receiver_key(self):
        for method in ("_ehbp_completion", "_ehbp_stream"):
            with self.subTest(method=method):
                session, connection = self.session(422, "application/problem+json", PROBLEM)
                with self.assertRaises(EHBPKeyMismatchError) as raised:
                    getattr(session, method)(b"{}", "nonce", MODEL)
                self.assertEqual(raised.exception.status, 422)
                self.assertIsInstance(raised.exception, UpstreamHTTPError)
                connection.close.assert_called_once()

    def test_other_rejections_stay_ordinary_upstream_errors(self):
        for method in ("_ehbp_completion", "_ehbp_stream"):
            with self.subTest(method=method):
                session, _ = self.session(422, "application/json", b'{"error":"unprocessable"}')
                with self.assertRaises(UpstreamHTTPError) as raised:
                    getattr(session, method)(b"{}", "nonce", MODEL)
                self.assertNotIsInstance(raised.exception, EHBPKeyMismatchError)


if __name__ == "__main__":
    unittest.main()

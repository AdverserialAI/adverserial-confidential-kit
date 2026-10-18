"""WP-7 per-request receipt tests against the fixture proxy.

Run: python -m unittest discover -s tests -v   (or: python -m pytest tests)
"""

from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fixture_server import FakeAttestProxy  # noqa: E402

from adverserial import (  # noqa: E402
    HardwareVerification,
    VerificationError,
    VerifiedSession,
    verify_endpoint,
)

MODEL = "lordx64/cyberglm"
ISSUER = "https://verify.adverserial.ai"
AUDIENCE = "https://chat.adverserial.ai"
MESSAGES = [{"role": "user", "content": "hi"}]


def test_hardware_verifier(*_args):
    return HardwareVerification(verified=True, verifier="test-synthetic-evidence")


class ReceiptTests(unittest.TestCase):
    def make_session(self, fake: FakeAttestProxy) -> VerifiedSession:
        proof = verify_endpoint(
            fake.v1_url,
            expected_model_id=MODEL,
            trusted_receipt_keys=fake.trusted_keys,
            issuer=ISSUER,
            audience=AUDIENCE,
            expected_endpoint=fake.endpoint,
            hardware_verifier=test_hardware_verifier,
            allow_dev_mode=True,
        )
        return VerifiedSession(fake.v1_url, proof=proof, entitlement="sk-test-key-123")

    def test_non_stream_happy_path(self):
        with FakeAttestProxy() as fake:
            session = self.make_session(fake)
            resp = session.chat_completions(MESSAGES)
            self.assertTrue(resp.receipt_verified)
            self.assertIsNotNone(resp.receipt_claims)
            claims = resp.receipt_claims
            assert claims is not None
            self.assertEqual(claims["v"], 1)
            self.assertEqual(claims["model_id"], MODEL)
            self.assertEqual(claims["policy_id"], "adverserial-policy/dev")
            self.assertEqual(claims["iss"], ISSUER)
            self.assertEqual(claims["aud"], AUDIENCE)
            self.assertTrue(claims["request_nonce"])
            self.assertTrue(claims["request_body_hash"].startswith("sha256:"))
            self.assertTrue(claims["response_hash"].startswith("sha256:"))
            self.assertEqual(
                claims["attestation_binding"]["tls_spki_sha256"], fake.tls_spki_sha256
            )
            self.assertIn("usage", claims)
            # The completion payload itself is intact.
            self.assertEqual(resp["choices"][0]["message"]["content"], "fake completion")

    def test_stream_happy_path(self):
        with FakeAttestProxy() as fake:
            session = self.make_session(fake)
            stream = session.chat_completions(MESSAGES, stream=True)
            events = list(stream)
            self.assertTrue(stream.receipt_verified)
            self.assertIsNotNone(stream.receipt_claims)
            text = "".join(e["choices"][0]["delta"]["content"] for e in events)
            self.assertEqual(text, "fake completion")
            # The receipt chunk itself is never yielded as a content event.
            self.assertFalse(any("adverserial_receipt" in e for e in events))

    def test_tampered_response_body_rejected(self):
        with FakeAttestProxy(tamper_response_body=True) as fake:
            session = self.make_session(fake)
            with self.assertRaisesRegex(VerificationError, "response hash"):
                session.chat_completions(MESSAGES)

    def test_tampered_stream_rejected(self):
        with FakeAttestProxy(tamper_response_body=True) as fake:
            session = self.make_session(fake)
            stream = session.chat_completions(MESSAGES, stream=True)
            with self.assertRaisesRegex(VerificationError, "response hash"):
                list(stream)

    def test_wrong_model_rejected(self):
        with FakeAttestProxy(receipt_model_override="other/model") as fake:
            session = self.make_session(fake)
            with self.assertRaisesRegex(VerificationError, "model"):
                session.chat_completions(MESSAGES)

    def test_expired_receipt_rejected(self):
        with FakeAttestProxy(receipt_expired=True) as fake:
            session = self.make_session(fake)
            with self.assertRaisesRegex(VerificationError, "expired"):
                session.chat_completions(MESSAGES)

    def test_server_generated_nonce_still_verifies(self):
        with FakeAttestProxy() as fake:
            session = self.make_session(fake)
            session._new_request_nonce = lambda: None  # send no X-Adverserial-Nonce
            resp = session.chat_completions(MESSAGES)
            self.assertTrue(resp.receipt_verified)
            assert resp.receipt_claims is not None
            self.assertTrue(resp.receipt_claims["request_nonce"])

    def test_absent_receipt_requires_explicit_compatibility_opt_out(self):
        with FakeAttestProxy(receipts=False) as fake:
            strict = self.make_session(fake)
            with self.assertRaisesRegex(VerificationError, "did not return a signed inference receipt"):
                strict.chat_completions(MESSAGES)
            proof = strict.proof
            session = VerifiedSession(fake.v1_url, proof=proof, entitlement="sk-test-key-123", require_receipts=False)
            resp = session.chat_completions(MESSAGES)
            self.assertFalse(resp.receipt_verified)
            self.assertIsNone(resp.receipt_claims)
            stream = session.chat_completions(MESSAGES, stream=True)
            self.assertEqual(len(list(stream)), 2)
            self.assertFalse(stream.receipt_verified)

    def test_quote_bound_ehbp_proof_cannot_be_downgraded(self):
        with FakeAttestProxy() as fake:
            proof = self.make_session(fake).proof
            quote_bound = replace(proof, ehbp_key_config=b"attested-key-configuration")
            with self.assertRaisesRegex(VerificationError, "cannot disable EHBP"):
                VerifiedSession(
                    fake.v1_url,
                    proof=quote_bound,
                    entitlement="sk-test-key-123",
                    use_ehbp=False,
                )
            with self.assertRaisesRegex(VerificationError, "cannot disable signed inference receipts"):
                VerifiedSession(
                    fake.v1_url,
                    proof=quote_bound,
                    entitlement="sk-test-key-123",
                    require_receipts=False,
                )


if __name__ == "__main__":
    unittest.main()

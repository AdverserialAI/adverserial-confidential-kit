"""SDK tests against a local fake attest-proxy (http.server + TLS in a thread).

Run: python -m unittest discover -s tests -v   (or: python -m pytest tests)
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fixture_server import FakeAttestProxy  # noqa: E402

from adverserial import (  # noqa: E402
    HardwareVerification,
    TLSPinMismatchError,
    VerificationError,
    VerifiedSession,
    canonical_json,
    evidence_digest,
    verify_endpoint,
)

MODEL = "lordx64/cyberglm"
ISSUER = "https://verify.adverserial.ai"
AUDIENCE = "https://chat.adverserial.ai"


def test_hardware_verifier(*_args):
    return HardwareVerification(verified=True, verifier="test-synthetic-evidence")


class CanonJsonTests(unittest.TestCase):
    """Pinned against the TS-generated vector in
    attest-proxy internal/canonjson/canonjson_test.go."""

    def test_matches_typescript_reference(self):
        fixture = {
            "alpha": "héllo <>& \"quote\" \u2028sep",
            "z_last": [1, "two", None, True, {"b": 2, "a": 1}],
            "num": 42,
            "neg": -7,
            "nested": {"k2": [], "k1": {}},
            "dev": True,
            "ref": None,
        }
        want_canonical_b64 = (
            "eyJhbHBoYSI6ImjDqWxsbyA8PiYgXCJxdW90ZVwiIOKAqHNlcCIsImRldiI6dHJ1ZSwi"
            "bmVnIjotNywibmVzdGVkIjp7ImsxIjp7fSwiazIiOltdfSwibnVtIjo0MiwicmVmIjpudWxs"
            "LCJ6X2xhc3QiOlsxLCJ0d28iLG51bGwsdHJ1ZSx7ImEiOjEsImIiOjJ9XX0="
        )
        want = base64.b64decode(want_canonical_b64).decode("utf-8")
        self.assertEqual(canonical_json(fixture), want)
        self.assertEqual(
            evidence_digest(fixture), "sha256:1mKIEeUwRHV8oq766icqSY6A6QMdHXwqSaAXSM5enLs"
        )

    def test_string_escaping(self):
        cases = {
            "": '""',
            "\x01": '"\\u0001"',
            "\x1f": '"\\u001f"',
            "\x7f": '"\x7f"',  # DEL raw, like JSON.stringify
            "\u2028": '"\u2028"',  # U+2028 raw
            "\u2029": '"\u2029"',  # U+2029 raw
            "<>&": '"<>&"',
            "héllo": '"héllo"',
            'a"b\\c\nd\te': '"a\\"b\\\\c\\nd\\te"',
        }
        for given, want in cases.items():
            self.assertEqual(canonical_json(given), want, f"input {given!r}")


class VerifyTests(unittest.TestCase):
    def verify(self, fake: FakeAttestProxy, **overrides):
        options = dict(
            expected_model_id=MODEL,
            trusted_receipt_keys=fake.trusted_keys,
            issuer=ISSUER,
            audience=AUDIENCE,
            expected_endpoint=fake.endpoint,
            hardware_verifier=test_hardware_verifier,
            allow_dev_mode=True,
        )
        options.update(overrides)
        return verify_endpoint(fake.v1_url, **options)

    def test_happy_path_dev_mode_surfaced(self):
        with FakeAttestProxy(dev=True) as fake:
            proof = self.verify(fake)
        self.assertEqual(proof.status, "verified")
        self.assertTrue(proof.dev_mode)
        self.assertEqual(proof.model_id, MODEL)
        self.assertEqual(proof.endpoint, fake.endpoint)
        self.assertTrue(proof.tls_spki_sha256.startswith("sha256:"))
        self.assertTrue(proof.evidence_digest.startswith("sha256:"))
        self.assertIn(proof.receipt_key_id, fake.trusted_keys)
        self.assertEqual(proof.policy_id, "adverserial-policy/dev")
        self.assertLess(proof.issued_epoch, proof.expires_epoch)

    def test_dev_mode_is_rejected_without_explicit_test_opt_in(self):
        with FakeAttestProxy(dev=True) as fake:
            with self.assertRaisesRegex(VerificationError, "DEV_MODE"):
                verify_endpoint(
                    fake.v1_url,
                    expected_model_id=MODEL,
                    trusted_receipt_keys=fake.trusted_keys,
                    issuer=ISSUER,
                    audience=AUDIENCE,
                    hardware_verifier=test_hardware_verifier,
                )

    def test_production_evidence_has_dev_mode_false(self):
        with FakeAttestProxy(dev=False) as fake:
            proof = self.verify(fake)
        self.assertFalse(proof.dev_mode)

    def test_wrong_model_rejected(self):
        with FakeAttestProxy(model_id="other/model") as fake:
            with self.assertRaisesRegex(VerificationError, "model"):
                self.verify(fake)

    def test_missing_hardware_verifier_rejected(self):
        with FakeAttestProxy() as fake:
            with self.assertRaisesRegex(VerificationError, "hardware_verifier"):
                self.verify(fake, hardware_verifier=None)

    def test_expired_receipt_rejected(self):
        with FakeAttestProxy(iat_offset=-600, lifetime=300) as fake:
            with self.assertRaisesRegex(VerificationError, "expired"):
                self.verify(fake)

    def test_future_receipt_rejected(self):
        with FakeAttestProxy(iat_offset=3600) as fake:
            with self.assertRaisesRegex(VerificationError, "future"):
                self.verify(fake)

    def test_bad_signature_rejected(self):
        with FakeAttestProxy(sign_with_wrong_key=True) as fake:
            with self.assertRaisesRegex(VerificationError, "signature"):
                self.verify(fake)

    def test_untrusted_key_rejected(self):
        with FakeAttestProxy() as fake, FakeAttestProxy() as stranger:
            with self.assertRaisesRegex(VerificationError, "configured ES256"):
                self.verify(fake, trusted_receipt_keys=stranger.trusted_keys)

    def test_nonce_mismatch_rejected(self):
        with FakeAttestProxy(nonce_override="AAAAAAAAAAAAAAAAAAAAAA") as fake:
            with self.assertRaisesRegex(VerificationError, "nonce|bound"):
                self.verify(fake)

    def test_wrong_verdict_rejected(self):
        with FakeAttestProxy(verdict="failed") as fake:
            with self.assertRaisesRegex(VerificationError, "verdict|evidence"):
                self.verify(fake)

    def test_wrong_issuer_rejected(self):
        with FakeAttestProxy(issuer="https://evil.example") as fake:
            with self.assertRaisesRegex(VerificationError, "issuer"):
                self.verify(fake)

    def test_wrong_audience_rejected(self):
        with FakeAttestProxy(audience="someone-else") as fake:
            with self.assertRaisesRegex(VerificationError, "audience|application"):
                self.verify(fake)

    def test_tampered_evidence_rejected(self):
        with FakeAttestProxy(tamper_evidence=True) as fake:
            with self.assertRaisesRegex(VerificationError, "bound to the returned evidence"):
                self.verify(fake)

    def test_missing_tdx_event_log_rejected_before_hardware_callback(self):
        with FakeAttestProxy(omit_event_log=True) as fake:
            with self.assertRaisesRegex(VerificationError, "event log"):
                self.verify(fake)

    def test_endpoint_claim_mismatch_rejected(self):
        with FakeAttestProxy() as fake:
            with self.assertRaisesRegex(VerificationError, "endpoint"):
                self.verify(fake, expected_endpoint="https://other.example")

    def test_model_digest_claim_checked_when_expected(self):
        with FakeAttestProxy(model_digest_claim="sha256:aaa") as fake:
            proof = self.verify(fake, expected_model_digest="sha256:aaa")
            self.assertEqual(proof.model_digest, "sha256:aaa")
        with FakeAttestProxy(model_digest_claim="sha256:aaa") as fake:
            with self.assertRaisesRegex(VerificationError, "digest"):
                self.verify(fake, expected_model_digest="sha256:bbb")

    def test_spki_lie_rejected(self):
        """Evidence claiming a different TLS SPKI than the observed peer."""
        with FakeAttestProxy(spki_lie=True) as fake:
            with self.assertRaises(TLSPinMismatchError):
                self.verify(fake)


class SessionTests(unittest.TestCase):
    def test_chat_completions_over_pinned_tls(self):
        with FakeAttestProxy() as fake:
            proof = verify_endpoint(
                fake.v1_url,
                expected_model_id=MODEL,
                trusted_receipt_keys=fake.trusted_keys,
                issuer=ISSUER,
                audience=AUDIENCE,
                hardware_verifier=test_hardware_verifier,
                allow_dev_mode=True,
            )
            session = VerifiedSession(fake.v1_url, proof=proof, entitlement="sk-test")
            response = session.chat_completions(
                messages=[{"role": "user", "content": "ping"}]
            )
        self.assertEqual(response["model"], MODEL)
        self.assertEqual(
            response["choices"][0]["message"]["content"], "fake completion"
        )

    def test_streaming_chat_completions(self):
        with FakeAttestProxy() as fake:
            proof = verify_endpoint(
                fake.v1_url,
                expected_model_id=MODEL,
                trusted_receipt_keys=fake.trusted_keys,
                issuer=ISSUER,
                audience=AUDIENCE,
                hardware_verifier=test_hardware_verifier,
                allow_dev_mode=True,
            )
            session = VerifiedSession(fake.v1_url, proof=proof)
            chunks = list(
                session.chat_completions(
                    messages=[{"role": "user", "content": "ping"}], stream=True
                )
            )
        self.assertEqual(len(chunks), 2)
        text = "".join(c["choices"][0]["delta"]["content"] for c in chunks)
        self.assertEqual(text, "fake completion")

    def test_pin_rejects_substituted_cert(self):
        """A session pinned to proxy A must refuse to talk to proxy B."""
        with FakeAttestProxy() as evil, FakeAttestProxy(endpoint=evil.endpoint) as good:
            proof = verify_endpoint(
                good.v1_url,
                expected_model_id=MODEL,
                trusted_receipt_keys=good.trusted_keys,
                issuer=ISSUER,
                audience=AUDIENCE,
                expected_endpoint=evil.endpoint,
                hardware_verifier=test_hardware_verifier,
                allow_dev_mode=True,
            )
            session = VerifiedSession(evil.v1_url, proof=proof, entitlement="sk-test")
            with self.assertRaises(TLSPinMismatchError):
                session.chat_completions(messages=[{"role": "user", "content": "ping"}])

    def test_session_refuses_a_proof_bound_to_another_endpoint_before_connecting(self):
        with FakeAttestProxy() as good, FakeAttestProxy() as other:
            proof = verify_endpoint(
                good.v1_url,
                expected_model_id=MODEL,
                trusted_receipt_keys=good.trusted_keys,
                issuer=ISSUER,
                audience=AUDIENCE,
                hardware_verifier=test_hardware_verifier,
                allow_dev_mode=True,
            )
            with self.assertRaisesRegex(VerificationError, "endpoint does not match"):
                VerifiedSession(other.v1_url, proof=proof, entitlement="sk-test")

    def test_session_requires_verified_proof(self):
        class Bogus:
            status = "failed"

        with self.assertRaises(VerificationError):
            VerifiedSession("https://127.0.0.1:1/v1", proof=Bogus())


class CliTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "adverserial", *args],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_cli_refuses_to_claim_hardware_verification_without_adapter(self):
        with FakeAttestProxy(dev=True) as fake:
            result = self.run_cli(
                "verify", fake.v1_url, "--trust-evidence-key", "--endpoint", fake.endpoint
            )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("independent hardware verifier", result.stderr)

    def test_cli_wrong_model_exit_1(self):
        with FakeAttestProxy() as fake:
            result = self.run_cli(
                "verify", fake.v1_url, "--model", "other/model", "--trust-evidence-key"
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("independent hardware verifier", result.stderr)

    def test_cli_require_hardware_still_requires_an_adapter(self):
        with FakeAttestProxy(dev=True) as fake:
            result = self.run_cli(
                "verify", fake.v1_url, "--trust-evidence-key", "--require-hardware"
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("independent hardware verifier", result.stderr)

    def test_cli_keys_file(self):
        with FakeAttestProxy(dev=False) as fake:
            keys_path = Path(fake._tmpdir.name) / "keys.json"
            keys_path.write_text(json.dumps(fake.trusted_keys))
            result = self.run_cli("verify", fake.v1_url, "--keys", str(keys_path))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("independent hardware verifier", result.stderr)


if __name__ == "__main__":
    unittest.main()

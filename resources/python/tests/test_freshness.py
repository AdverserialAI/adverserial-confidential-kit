import time
import http.client
import unittest
from unittest.mock import patch

import test_verify as fixtures
from fixture_server import FakeAttestProxy
from adverserial import VerifiedSession, VerificationError


class FreshnessTests(unittest.TestCase):
    def test_expiry_during_tls_handshake_closes_before_sending_credentials(self):
        with FakeAttestProxy() as fake:
            proof = fixtures.VerifyTests().verify(fake)
            session = VerifiedSession(fake.v1_url, proof=proof, entitlement="fixture-only")
            connection = session._connect()
            clock = [time.time()]
            original = http.client.HTTPSConnection.connect
            def delayed_handshake(conn):
                original(conn)
                clock[0] = proof.expires_epoch
            with patch("adverserial.session.time.time", side_effect=lambda: clock[0]), patch.object(http.client.HTTPSConnection, "connect", delayed_handshake), patch.object(session, "_connect", return_value=connection):
                with self.assertRaisesRegex(VerificationError, "expired"):
                    session.chat_completions([{"role": "user", "content": "fixture"}])
                self.assertIsNone(connection.sock)
                self.assertFalse(session.dispatched)

    def test_expired_session_proof_cannot_open_a_connection(self):
        with FakeAttestProxy() as fake:
            proof = fixtures.VerifyTests().verify(fake)
            session = VerifiedSession(fake.v1_url, proof=proof, entitlement="fixture-only")
            for expired in (proof.expires_epoch, proof.expires_epoch + 100):
                with self.subTest(now=expired), patch("adverserial.session.time.time", return_value=expired), patch("adverserial.session.PinnedHTTPSConnection") as connection:
                    with self.assertRaisesRegex(VerificationError, "expired"):
                        session.chat_completions([{"role": "user", "content": "test"}])
                    connection.assert_not_called()
                    self.assertFalse(session.dispatched)

    def test_expiry_during_hardware_verification_cannot_return_verified(self):
        with FakeAttestProxy() as fake:
            clock = [time.time()]
            def slow_verifier(*args):
                clock[0] += 600
                return fixtures.test_hardware_verifier(*args)
            with self.assertRaisesRegex(VerificationError, "expired"):
                fixtures.VerifyTests().verify(fake, now=lambda: clock[0], hardware_verifier=slow_verifier)

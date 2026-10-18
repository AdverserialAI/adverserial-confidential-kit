"""TLS helpers: SPKI hashing and an HTTPS connection pinned to the attested
certificate public key.

The attest-proxy serves a self-signed certificate by design — trust comes
from the TDX-quote-bound SPKI hash, not from a CA. Every connection made by
this SDK therefore disables CA validation and instead authenticates the peer
by comparing the SHA-256 of the leaf certificate's DER SubjectPublicKeyInfo
against the value published in the verified attestation evidence.
"""

from __future__ import annotations

import hashlib
import http.client
import ssl
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ._jws import b64url_encode


def spki_sha256_from_cert_der(cert_der: bytes) -> str:
    """``sha256:<base64url>`` over the certificate's DER SubjectPublicKeyInfo."""
    cert = x509.load_der_x509_certificate(cert_der)
    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return "sha256:" + b64url_encode(hashlib.sha256(spki).digest())


def attestation_ssl_context() -> ssl.SSLContext:
    """Context for the attestation fetch: no CA check (self-signed cert);
    the peer is authenticated afterwards via the SPKI hash in the evidence."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class TLSPinMismatchError(Exception):
    """The TLS peer presented a certificate whose SPKI does not match the
    attested ``tls_spki_sha256`` — the connection was closed before any
    request bytes were sent."""


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that accepts exactly one public key.

    The pin is enforced in connect(), immediately after the TLS handshake and
    *before* any HTTP request is written to the socket. A mismatch raises
    TLSPinMismatchError and closes the socket.
    """

    def __init__(
        self,
        host: str,
        port: Optional[int] = None,
        *,
        expected_spki_sha256: str,
        timeout: float = 60.0,
    ) -> None:
        super().__init__(
            host, port, context=attestation_ssl_context(), timeout=timeout
        )
        self._expected_spki_sha256 = expected_spki_sha256

    def connect(self) -> None:
        super().connect()
        assert self.sock is not None
        peer_der = self.sock.getpeercert(binary_form=True)
        actual = spki_sha256_from_cert_der(peer_der)
        if actual != self._expected_spki_sha256:
            self.close()
            raise TLSPinMismatchError(
                "TLS certificate pin mismatch: the peer's SPKI hash "
                f"{actual!r} does not match the attested "
                f"{self._expected_spki_sha256!r}. Refusing to send the request."
            )

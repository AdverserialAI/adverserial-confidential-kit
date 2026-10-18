"""adverserial — client-side verification SDK for Adverserial confidential
inference endpoints.

Usage:
    from adverserial import verify_endpoint, VerifiedSession

    proof = verify_endpoint(
        "https://host/v1",
        expected_model_id="lordx64/cyberglm",
        trusted_receipt_keys={kid: jwk},
        issuer="https://verify.adverserial.ai",
        audience="https://chat.adverserial.ai",
    )
    session = VerifiedSession("https://host/v1", proof=proof, entitlement="<short-lived-JWS>")
    response = session.chat_completions(messages=[...])

If proof.dev_mode is True the attestation evidence was synthetic: it proves
the plumbing (receipt signature, nonce binding, TLS SPKI pinning), NOT the
hardware. Never treat a dev_mode proof as a TEE guarantee.
"""

from ._canonjson import canonical_json, evidence_digest
from ._jws import b64url_decode, b64url_encode, jwk_thumbprint
from ._tls import TLSPinMismatchError, spki_sha256_from_cert_der
from .session import UpstreamHTTPError, VerifiedSession
from .verify import (
    HardwareEvidenceVerifier,
    HardwareVerification,
    VerificationError,
    VerifiedProof,
    fetch_attestation,
    verify_endpoint,
)

__version__ = "0.1.0"

__all__ = [
    "verify_endpoint",
    "VerifiedProof",
    "VerifiedSession",
    "VerificationError",
    "UpstreamHTTPError",
    "HardwareEvidenceVerifier",
    "HardwareVerification",
    "TLSPinMismatchError",
    "fetch_attestation",
    "canonical_json",
    "evidence_digest",
    "spki_sha256_from_cert_der",
    "jwk_thumbprint",
    "b64url_encode",
    "b64url_decode",
    "__version__",
]

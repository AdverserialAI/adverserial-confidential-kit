"""Endpoint verification against the Adverserial attestation protocol.

Protocol (mirrors the reference client, adverserial-webui
src/lib/confidential/verification.ts, plus a TLS channel-binding check):

1. GET <attestation_url>?nonce=<fresh 32-byte base64url> over TLS.
2. Parse {evidence, verification_receipt}.
3. Verify the receipt: compact ES256 JWS signed by a pinned receipt key
   (header alg == "ES256", kid must be in trusted_receipt_keys).
4. Check claims: iss, aud, nonce echo, verdict == "verified", iat/exp
   freshness, model_id, optional endpoint / model_digest / runtime_digest.
5. Check evidence_sha256 == sha256 of the canonicalized evidence
   (canonicalization: recursively sorted keys, no whitespace, JSON.stringify
   string semantics).
6. Check the TLS peer certificate of the attestation connection against the
   evidence's tls_spki_sha256 (the browser cannot do this; Python can, and
   must, because it is what binds the receipt to the live TLS endpoint).

The returned proof carries everything VerifiedSession needs to pin subsequent
API calls to the attested TLS public key.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature

from ._canonjson import evidence_digest as canonical_evidence_digest
from ._jws import b64url_decode, b64url_encode, jwk_thumbprint, parse_compact_jws, verify_es256
from ._tls import TLSPinMismatchError, attestation_ssl_context, spki_sha256_from_cert_der

__all__ = [
    "HardwareEvidenceVerifier",
    "HardwareVerification",
    "VerifiedProof",
    "VerificationError",
    "verify_endpoint",
]

_FUTURE_IAT_LEEWAY_SECONDS = 60


class VerificationError(Exception):
    """The endpoint's attestation could not be verified."""


@dataclass(frozen=True)
class HardwareVerification:
    """A successful independent verification of raw enclave evidence.

    The SDK deliberately does not implement a pretend hardware verifier. The
    caller supplies one backed by the selected platform's vendor verifier
    (for example, a reviewed DCAP-QVL / TDX verifier plus GPU-attestation
    verifier) and pins its trust policy out of band.
    """

    verified: bool
    verifier: str
    tee: Optional[str] = None
    gpu: Optional[str] = None


HardwareEvidenceVerifier = Callable[[Mapping[str, Any], str, str, Optional[str]], HardwareVerification]


@dataclass(frozen=True)
class VerifiedProof:
    """A successfully verified attestation."""

    status: str  # always "verified" for a constructed proof
    model_id: str
    endpoint: Optional[str]
    issuer: str
    audience: str
    issued_at: str  # RFC 3339 / ISO 8601
    expires_at: str
    issued_epoch: int
    expires_epoch: int
    nonce: str
    evidence_digest: str  # sha256:<base64url> over canonicalized evidence
    tls_spki_sha256: str  # sha256:<base64url> of the serving cert's SPKI
    receipt_key_id: str
    receipt_digest: str  # sha256:<base64url> of the raw receipt token
    dev_mode: bool  # evidence carried dev:true — synthetic plumbing proof
    model_digest: Optional[str] = None
    runtime_digest: Optional[str] = None
    policy_id: Optional[str] = None
    compose_digest: Optional[str] = None
    # Stable state digest cited by per-request inference receipts.
    attestation_state_digest: Optional[str] = None
    # The evidence-published receipt public JWK (thumbprint-checked against
    # the attestation receipt's kid). VerifiedSession uses it to verify WP-7
    # per-request receipts.
    receipt_jwk: Optional[Dict[str, Any]] = None
    # Name/version of the independent verifier that accepted raw evidence.
    hardware_verifier: Optional[str] = None
    # RFC 9458 EHBP receiver configuration, validated from attested evidence.
    # When present, VerifiedSession uses the reference EHBP transport rather
    # than allowing a plaintext request-body fallback.
    ehbp_key_config: Optional[bytes] = None
    ehbp_public_key_sha256: Optional[str] = None


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _attestation_url_for(base_url: str) -> str:
    parts = urlsplit(base_url)
    if parts.scheme != "https" or not parts.hostname:
        raise VerificationError(f"endpoint URL must be https://…, got {base_url!r}")
    return f"{parts.scheme}://{parts.netloc}/attestation"


def fetch_attestation(
    attestation_url: str, nonce: str, timeout: float
) -> Tuple[Dict[str, Any], bytes]:
    """GET the attestation endpoint; return (payload, peer certificate DER).

    Exported for the CLI's --trust-evidence-key bootstrap. The TLS peer is NOT
    CA-validated here (the proxy serves a self-signed cert by design); callers
    authenticate it via the evidence's tls_spki_sha256 instead.
    """
    parts = urlsplit(attestation_url)
    if parts.scheme != "https" or not parts.hostname:
        raise VerificationError(f"attestation URL must be https://…, got {attestation_url!r}")
    query = (parts.query + "&" if parts.query else "") + "nonce=" + nonce
    path = parts.path + "?" + query
    connection = http.client.HTTPSConnection(
        parts.hostname,
        parts.port or 443,
        context=attestation_ssl_context(),
        timeout=timeout,
    )
    try:
        connection.request("GET", path, headers={"Accept": "application/json"})
        # Capture the peer certificate before getresponse(): for responses
        # that will close the connection, http.client detaches connection.sock
        # as soon as the response headers arrive.
        peer_der = (
            connection.sock.getpeercert(binary_form=True) if connection.sock else None
        )
        response = connection.getresponse()
        body = response.read()
        status = response.status
    except OSError as exc:
        raise VerificationError(f"could not reach the attestation endpoint: {exc}") from exc
    finally:
        connection.close()
    if status != 200:
        raise VerificationError(f"the attestation endpoint returned HTTP {status}")
    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise VerificationError("the attestation response is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise VerificationError("the attestation response is not a JSON object")
    if peer_der is None:
        raise VerificationError("the attestation connection did not present a certificate")
    return payload, peer_der


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def verify_endpoint(
    base_url: str,
    *,
    expected_model_id: str,
    trusted_receipt_keys: Mapping[str, Mapping[str, Any]],
    issuer: str = "https://verify.adverserial.ai",
    audience: str = "https://chat.adverserial.ai",
    expected_endpoint: Optional[str] = None,
    expected_model_digest: Optional[str] = None,
    expected_runtime_digest: Optional[str] = None,
    hardware_verifier: Optional[HardwareEvidenceVerifier] = None,
    allow_dev_mode: bool = False,
    attestation_url: Optional[str] = None,
    timeout: float = 15.0,
    now: Optional[Callable[[], float]] = None,
) -> VerifiedProof:
    """Verify an endpoint's attestation and return a VerifiedProof.

    Raises VerificationError (or its subclass TLSPinMismatchError) on any
    failure. `trusted_receipt_keys` maps receipt key IDs (the JWS header kid)
    to pinned public JWKs. `hardware_verifier` is required and must validate
    the raw TEE/GPU evidence independently; a proxy-issued receipt alone is
    never hardware proof.
    """
    url = attestation_url or _attestation_url_for(base_url)
    nonce = b64url_encode(secrets.token_bytes(32))
    now_seconds = (now or time.time)()

    payload, peer_der = fetch_attestation(url, nonce, timeout)
    evidence = payload.get("evidence")
    receipt = payload.get("verification_receipt")
    if not isinstance(evidence, dict) or not isinstance(receipt, str) or not receipt:
        raise VerificationError("the attestation response is missing evidence or a receipt")

    # --- receipt signature -------------------------------------------------
    try:
        header, claims, signing_input, signature = parse_compact_jws(receipt)
    except ValueError as exc:
        raise VerificationError(str(exc)) from exc
    key_id = header.get("kid")
    pinned_jwk = trusted_receipt_keys.get(key_id) if isinstance(key_id, str) else None
    _expect(
        header.get("alg") == "ES256" and isinstance(key_id, str) and pinned_jwk is not None,
        "the receipt is not signed by a configured ES256 verification key",
    )
    try:
        verify_es256(pinned_jwk, signing_input, signature)  # type: ignore[arg-type]
    except (InvalidSignature, ValueError) as exc:
        raise VerificationError("the verification receipt signature is invalid") from exc

    # --- claims ------------------------------------------------------------
    iat, exp = claims.get("iat"), claims.get("exp")
    _expect(isinstance(iat, (int, float)), "the verification receipt is missing iat")
    _expect(isinstance(exp, (int, float)), "the verification receipt is missing exp")
    if exp <= now_seconds:
        raise VerificationError("the verification receipt has expired")
    if iat > now_seconds + _FUTURE_IAT_LEEWAY_SECONDS:
        raise VerificationError("the verification receipt was issued in the future")
    _expect(
        claims.get("iss") == issuer,
        "the receipt issuer does not match the configured verifier",
    )
    claim_aud = claims.get("aud")
    aud_ok = claim_aud == audience or (
        isinstance(claim_aud, list) and audience in claim_aud
    )
    _expect(aud_ok, "the receipt was not issued for this application")
    _expect(
        claims.get("nonce") == nonce,
        "the receipt is not bound to this verification attempt",
    )
    _expect(
        claims.get("verdict") == "verified",
        "the verifier did not accept the supplied hardware evidence",
    )
    _expect(
        claims.get("model_id") == expected_model_id,
        "the receipt model does not match the selected model",
    )
    if expected_endpoint is not None:
        _expect(
            claims.get("endpoint") == expected_endpoint,
            "the receipt is not bound to the configured inference endpoint",
        )
    if expected_model_digest is not None:
        _expect(
            claims.get("model_digest") == expected_model_digest,
            "the receipt model artifact digest does not match policy",
        )
    if expected_runtime_digest is not None:
        _expect(
            claims.get("runtime_digest") == expected_runtime_digest,
            "the receipt runtime digest does not match policy",
        )

    # --- evidence binding --------------------------------------------------
    evidence_digest = canonical_evidence_digest(evidence)
    _expect(
        claims.get("evidence_sha256") == evidence_digest,
        "the receipt is not bound to the returned evidence",
    )
    _expect(
        isinstance(evidence.get("tdx_quote"), str) and bool(evidence["tdx_quote"]),
        "the evidence is missing the TDX quote",
    )
    # A signed quote without its RTMR replay material cannot establish which
    # workload was measured. The independent verifier receives both fields.
    event_log = evidence.get("tdx_event_log")
    _expect(
        event_log is not None and event_log != "",
        "the evidence is missing the TDX event log",
    )
    if evidence.get("dev") is True and not allow_dev_mode:
        raise VerificationError("synthetic DEV_MODE evidence is not accepted by this client")
    tls_spki = evidence.get("tls_spki_sha256")
    _expect(
        isinstance(tls_spki, str) and tls_spki.startswith("sha256:"),
        "the evidence is missing tls_spki_sha256",
    )
    # The evidence-published receipt key must be the key that signed the
    # attestation receipt (thumbprint == header kid) — this is the key WP-7
    # per-request receipts are verified against.
    evidence_jwk = evidence.get("receipt_pubkey_jwk")
    receipt_jwk: Optional[Dict[str, Any]] = None
    if evidence_jwk is not None:
        _expect(isinstance(evidence_jwk, dict), "the evidence receipt_pubkey_jwk is not an object")
        _expect(
            jwk_thumbprint(evidence_jwk) == key_id,
            "the evidence receipt_pubkey_jwk does not match the receipt signer",
        )
        receipt_jwk = dict(evidence_jwk)

    # --- TLS channel binding (the check a browser cannot perform) ----------
    observed_spki = spki_sha256_from_cert_der(peer_der)
    if observed_spki != tls_spki:
        raise TLSPinMismatchError(
            "the TLS peer of the attestation connection does not match the "
            f"attested SPKI: observed {observed_spki!r}, evidence claims {tls_spki!r}"
        )
    tls_spki_der = evidence.get("tls_spki_der")
    _expect(isinstance(tls_spki_der, str) and bool(tls_spki_der), "the evidence is missing tls_spki_der")
    try:
        raw_tls_spki = base64.urlsafe_b64decode(tls_spki_der.encode("ascii") + b"=" * ((-len(tls_spki_der)) % 4))
    except (ValueError, UnicodeError) as exc:
        raise VerificationError("the evidence tls_spki_der is not base64url") from exc
    encoded_tls_spki = "sha256:" + base64.urlsafe_b64encode(hashlib.sha256(raw_tls_spki).digest()).rstrip(b"=").decode("ascii")
    _expect(encoded_tls_spki == tls_spki, "the evidence TLS SPKI DER does not match its fingerprint")

    # The encrypted-body receiver key is quote-bound by the v2 attestation
    # report-data construction. Validate the public representation here; the
    # independent hardware verifier validates that quote binding itself.
    ehbp_key_config: Optional[bytes] = None
    ehbp_public_key_sha256: Optional[str] = None
    if evidence.get("ehbp") is not None:
        try:
            from ehbp import ServerIdentity

            metadata = evidence["ehbp"]
            if not isinstance(metadata, Mapping):
                raise ValueError("EHBP metadata is not an object")
            key_config = metadata.get("key_config")
            public_key = metadata.get("public_key")
            key_digest = metadata.get("public_key_sha256")
            if not all(isinstance(value, str) and value for value in (key_config, public_key, key_digest)):
                raise ValueError("EHBP key configuration is incomplete")
            ehbp_key_config = b64url_decode(key_config)
            advertised_key = b64url_decode(public_key)
            if "sha256:" + b64url_encode(hashlib.sha256(advertised_key).digest()) != key_digest:
                raise ValueError("EHBP public-key digest is invalid")
            identity = ServerIdentity.unmarshal_public_config(ehbp_key_config)
            if identity.public_key_bytes() != advertised_key:
                raise ValueError("EHBP config does not contain the advertised public key")
            ehbp_public_key_sha256 = key_digest
        except (ImportError, KeyError, TypeError, ValueError) as exc:
            raise VerificationError("the evidence EHBP receiver key is invalid") from exc

    # A receipt is only a signed statement by the proxy. Require an
    # independent verifier for the raw quote/evidence before returning a
    # proof marked verified. This is deliberately injected so the SDK can
    # support different TEE and GPU vendors without hard-coding a provider.
    if hardware_verifier is None:
        raise VerificationError(
            "an independent hardware_verifier is required; proxy receipts alone are not hardware proof"
        )
    try:
        hardware = hardware_verifier(evidence, nonce, expected_model_id, expected_endpoint)
    except Exception as exc:
        raise VerificationError("the independent hardware verifier failed") from exc
    if not isinstance(hardware, HardwareVerification) or not hardware.verified or not hardware.verifier:
        raise VerificationError("the independent hardware verifier did not accept the evidence")

    receipt_digest = canonical_evidence_digest(receipt)
    workload = evidence.get("workload") if isinstance(evidence.get("workload"), dict) else {}
    return VerifiedProof(
        status="verified",
        model_id=expected_model_id,
        endpoint=claims.get("endpoint") if isinstance(claims.get("endpoint"), str) else None,
        issuer=issuer,
        audience=audience,
        issued_at=_iso(int(iat)),
        expires_at=_iso(int(exp)),
        issued_epoch=int(iat),
        expires_epoch=int(exp),
        nonce=nonce,
        evidence_digest=evidence_digest,
        tls_spki_sha256=tls_spki,
        receipt_key_id=key_id,
        receipt_digest=receipt_digest,
        dev_mode=evidence.get("dev") is True,
        model_digest=claims.get("model_digest") if isinstance(claims.get("model_digest"), str) else None,
        runtime_digest=claims.get("runtime_digest") if isinstance(claims.get("runtime_digest"), str) else None,
        policy_id=workload.get("policy_id") if isinstance(workload.get("policy_id"), str) else None,
        compose_digest=workload.get("compose_digest") if isinstance(workload.get("compose_digest"), str) else None,
        attestation_state_digest=evidence.get("attestation_state_digest") if isinstance(evidence.get("attestation_state_digest"), str) else None,
        receipt_jwk=receipt_jwk,
        hardware_verifier=hardware.verifier,
        ehbp_key_config=ehbp_key_config,
        ehbp_public_key_sha256=ehbp_public_key_sha256,
    )

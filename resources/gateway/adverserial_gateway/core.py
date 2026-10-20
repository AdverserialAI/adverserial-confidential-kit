"""Entitlement exchange and direct, pinned confidential dispatch."""
from __future__ import annotations

import json
import time
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

from adverserial import UpstreamHTTPError, VerificationError, VerifiedProof, VerifiedSession, verify_endpoint

from .config import CANONICAL_MODELS, Config
from .hardware import verifier_from_command


class GatewayError(RuntimeError):
    status_code = 502


class ClientRequestError(GatewayError):
    status_code = 400


class AuthorizationError(GatewayError):
    status_code = 401


class VerificationFailed(GatewayError):
    status_code = 503


class UpstreamRejected(GatewayError):
    """The enclave answered with a non-200 before generation (4xx), or failed
    after the request was dispatched (5xx). 4xx reservations are released;
    5xx reservations settle through the proxy's terminal meter event."""

    status_code = 502


class OutcomeUnknownError(GatewayError):
    """The request reached the enclave and its outcome is unknown (timeout,
    connection drop, receipt failure). The proxy's terminal meter event
    settles the reservation; a blind retry may run a second, separately
    billed generation."""

    status_code = 502


class _NoBillingRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects from the fixed billing origin.

    An entitlement request carries the customer's API key.  A redirect (or an
    HTTPS proxy inherited from a project shell) would turn the fixed billing
    URL into an attacker-controlled hop.  The gateway has no need for either,
    so it sends those requests directly and fails closed instead.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def _direct_billing_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoBillingRedirect(),
    )


def _entitlement_claims(entitlement: str) -> dict | None:
    """Decode a minted entitlement's claims (the JWS payload). None when
    undecodable; signature validity is the enclave's job, not ours."""
    try:
        parts = entitlement.split(".")
        if len(parts) != 3:
            return None
        import base64 as _b64
        claims = json.loads(_b64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        return claims if isinstance(claims, dict) else None
    except Exception:
        return None


def canonical_model_id(model: str) -> str:
    """Return the runtime model used for a locally supported client model.

    Claude Code assigns model names to its background roles independently of
    the main session.  Those requests still arrive at this loopback-only
    gateway, where all Claude-family aliases deliberately resolve to the one
    configured confidential runtime.  Nothing beyond the gateway sees an
    alias: evidence verification, entitlement issuance, EHBP encryption, and
    the attested proxy all receive the canonical model ID.

    Do not broaden this into a general compatibility fallback.  An unknown
    provider model must remain an error so a typo cannot silently select a
    different confidential policy.
    """
    if model in CANONICAL_MODELS:
        return model
    normalized = model.strip().lower()
    if normalized == "cyberglm" or normalized.startswith("claude-"):
        return "lordx64/cyberglm"
    raise ClientRequestError("Use a canonical confidential model ID: lordx64/cyberglm or lordx64/cyberkimi.")


def requested_output_tokens(payload: Mapping[str, Any]) -> int:
    """Normalize OpenAI's legacy and current Chat Completions output limits.

    Recent OpenAI-compatible clients, including Pi, send
    ``max_completion_tokens``. The confidential entitlement and forwarded
    runtime request must use one identical ``max_tokens`` value. Forwarding
    both lets an unbound value reach the runtime and makes its entitlement gate
    reject the request. Conflicting aliases therefore fail closed.
    """
    legacy = payload.get("max_tokens")
    current = payload.get("max_completion_tokens")
    for name, value in (("max_tokens", legacy), ("max_completion_tokens", current)):
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1):
            raise ClientRequestError(f"{name} must be a positive integer")
    if legacy is not None and current is not None and legacy != current:
        raise ClientRequestError("max_tokens and max_completion_tokens must match when both are provided")
    return current if current is not None else (legacy if legacy is not None else 4096)


@dataclass
class ProofCache:
    proof: VerifiedProof | None = None
    lock: Any = field(default_factory=threading.Lock, repr=False)

    def fresh_for(self, model: str) -> bool:
        return self.proof is not None and self.proof.model_id == model and self.proof.expires_epoch > int(time.time()) + 15


class Dispatcher:
    def __init__(self, config: Config):
        self.config = config
        self._proofs: dict[str, ProofCache] = {model: ProofCache() for model in CANONICAL_MODELS}
        self._billing_opener = _direct_billing_opener()

    def proof_for(self, model: str) -> VerifiedProof:
        model = canonical_model_id(model)
        cached = self._proofs[model]
        # Serialize refreshes per model, including expiry refreshes. Different
        # models can still verify concurrently, and failures never enter cache.
        with cached.lock:
            return self._refresh_proof(model, cached)

    def _refresh_proof(self, model: str, cached: ProofCache) -> VerifiedProof:
        if cached.fresh_for(model):
            return cached.proof  # type: ignore[return-value]
        try:
            # The proxy signs the receipt's endpoint claim with the bare origin
            # (e.g. https://api.adverserial.ai), while cc_api_url carries the
            # /v1 suffix for the OpenAI API; compare against the origin.
            parts = urlsplit(self.config.cc_api_url)
            expected_endpoint = f"{parts.scheme}://{parts.netloc}"
            proof = verify_endpoint(
                self.config.cc_api_url,
                expected_model_id=model,
                trusted_receipt_keys=self.config.receipt_keys,
                issuer=self.config.issuer,
                audience=self.config.audience,
                expected_endpoint=expected_endpoint,
                hardware_verifier=verifier_from_command(self.config.hardware_verifier_command),
            )
        except VerificationError as exc:
            raise VerificationFailed(f"Confidential endpoint verification failed: {exc}") from exc
        if proof.dev_mode:
            raise VerificationFailed("Confidential endpoint exposed synthetic dev-mode evidence.")
        cached.proof = proof
        return proof

    def entitlement(self, api_key: str, model: str, max_input_tokens: int, max_output_tokens: int, proof: VerifiedProof) -> str:
        payload = json.dumps({
            "model": model,
            "max_input_tokens": max_input_tokens,
            "max_output_tokens": max_output_tokens,
            "endpoint_spki_sha256": proof.tls_spki_sha256,
        }).encode()
        request = urllib.request.Request(
            self.config.billing_url + "/cc/entitlements",
            data=payload,
            method="POST",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with self._billing_opener.open(request, timeout=15) as response:
                body = response.read(64 * 1024)
        except urllib.error.HTTPError as exc:
            detail = exc.read(1024).decode("utf-8", "replace")
            if exc.code in {401, 403, 429}:
                error = AuthorizationError(detail or "Billing denied the confidential request.")
                error.status_code = exc.code
                raise error
            raise GatewayError("Billing entitlement service failed.") from exc
        except OSError as exc:
            raise GatewayError("Billing entitlement service is unavailable.") from exc
        try:
            result = json.loads(body)
            entitlement = result["entitlement"]
        except (ValueError, KeyError, TypeError) as exc:
            raise GatewayError("Billing returned an invalid confidential entitlement.") from exc
        if not isinstance(entitlement, str) or len(entitlement) > 16_384:
            raise GatewayError("Billing returned an invalid confidential entitlement.")
        return entitlement

    def completion(self, api_key: str, payload: Mapping[str, Any]):
        count = payload.get("n", 1)
        if count is not None and (isinstance(count, bool) or not isinstance(count, int) or count != 1):
            raise ClientRequestError("Only one completion per request is supported (n must be 1)")
        if payload.get("stream") is not None and not isinstance(payload["stream"], bool):
            raise ClientRequestError("stream must be a boolean or null")
        model = payload.get("model")
        if not isinstance(model, str):
            raise ClientRequestError("model is required")
        model = canonical_model_id(model)
        if not api_key.startswith("sk-") or len(api_key) < 20:
            raise AuthorizationError("A normal Adverserial API key is required.")
        # The JSON wire body is a safe upper bound on token count for text JSON:
        # a byte-level tokenizer cannot produce more than one token per UTF-8 byte.
        # The SDK re-serializes the payload before sending (adding "stream" and
        # its own separators), so reserve with headroom; the proxy bounds the
        # actual received body and settlement charges actual usage only.
        serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        max_input = 2 * len(serialized) + 4096
        if not 1 <= max_input <= self.config.max_input_tokens:
            raise ClientRequestError(f"Request exceeds the confidential input policy: {max_input} bytes reserved (limit {self.config.max_input_tokens}).")
        requested_output = requested_output_tokens(payload)
        max_output = min(requested_output, self.config.max_output_tokens)
        proof = self.proof_for(model)
        entitlement = self.entitlement(api_key, model, max_input, max_output, proof)
        # Billing may scale the reservation's output bound down to the plan's
        # remaining allowance (meter.py clamps min(wanted, day, week)). The
        # enclave gate 401s a request whose max_tokens exceeds the minted
        # bound, so the forwarded request follows the entitlement.
        claims = _entitlement_claims(entitlement)
        minted_output = claims.get("max_output_tokens") if claims else None
        if isinstance(minted_output, int) and not isinstance(minted_output, bool) and 1 <= minted_output < max_output:
            max_output = minted_output
        outbound = dict(payload)
        outbound.pop("model", None)
        stream = bool(outbound.pop("stream", False))
        # This modern client alias must not reach the runtime beside the
        # entitlement-bound value below.
        outbound.pop("max_completion_tokens", None)
        outbound["max_tokens"] = max_output
        session = None
        try:
            session = VerifiedSession(self.config.cc_api_url, proof=proof, entitlement=entitlement, timeout=600)
            return session.chat_completions(outbound.pop("messages", []), model=model, stream=stream, **outbound)
        except Exception as exc:
            # Release the billing reservation only when the request provably
            # never ran at the enclave: dispatch never began (attestation,
            # EHBP, TLS-pin, or local payload failure), or the gate rejected
            # it with a 4xx before any generation, so no meter event will
            # arrive. Billing independently refuses the release once the
            # proxy has marked the reservation started, so a misclassified
            # release cannot turn a completed inference into a free one.
            # Everything else — 5xx, timeout, stream break, receipt failure —
            # is outcome-unknown: the proxy's terminal meter settles the
            # reservation, and the caller must not blindly retry.
            if session is None or not session.dispatched:
                self.release_reservation(api_key, entitlement)
                raise
            if isinstance(exc, UpstreamHTTPError):
                rejected = UpstreamRejected(str(exc))
                rejected.status_code = exc.status
                if exc.status < 500:
                    self.release_reservation(api_key, entitlement)
                raise rejected from exc
            raise OutcomeUnknownError(
                "Confidential request outcome unknown: the request reached the enclave and may "
                "still complete; its reservation settles automatically. Do not retry blindly — "
                "a retry runs a second, separately billed generation. "
                f"Original error: {exc}"
            ) from exc

    def release_reservation(self, api_key: str, entitlement: str) -> None:
        """Best-effort release of the billing reservation behind a minted
        entitlement (its jti is the reservation id). Never raises."""
        try:
            claims = _entitlement_claims(entitlement)
            reservation_id = claims.get("jti") if claims else None
            if not isinstance(reservation_id, str) or not reservation_id:
                return
            request = urllib.request.Request(
                self.config.billing_url + "/cc/release",
                data=json.dumps({"reservation_id": reservation_id}).encode(),
                method="POST",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            )
            with self._billing_opener.open(request, timeout=10):
                pass
        except Exception:
            pass

    def adapted_completion(self, api_key: str, model: str, payload: Mapping[str, Any]):
        """Dispatch a locally translated request after binding it to a canonical model."""
        outbound = dict(payload)
        outbound["model"] = canonical_model_id(model)
        return self.completion(api_key, outbound)

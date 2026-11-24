"""Entitlement exchange and direct, pinned confidential dispatch."""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import time
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

from adverserial import (
    EHBPKeyMismatchError,
    TLSPinMismatchError,
    UpstreamHTTPError,
    VerificationError,
    VerifiedProof,
    VerifiedSession,
    verify_endpoint,
)

from .config import CANONICAL_MODELS, Config, ConfigError, load_receipt_keys

# Accepted by the attested proxy for the optional per-request prefix-cache
# salt. Anything else is answered with HTTP 400 by the enclave.
_CACHE_SALT = re.compile(r"[A-Za-z0-9_-]{32,128}")
# A proof this young was verified after any reboot that could explain a
# pre-generation rejection, so re-attesting again would only add latency.
_REVERIFY_MIN_PROOF_AGE_SECONDS = 30
# Pre-generation rejections that an undecryptable (stale-key) request could
# produce. Rate limits and the like never trigger a re-attestation.
_STALE_KEY_STATUSES = frozenset({400, 401, 403, 422})
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


class _RetryWithFreshProof(Exception):
    """Internal: the attempt provably did not run and a newer proof exists."""

    def __init__(self, proof: VerifiedProof):
        super().__init__("retry with a freshly verified proof")
        self.proof = proof


def new_cache_salt() -> str:
    """A random 32-byte, unpadded base64url prefix-cache salt (43 characters)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def valid_cache_salt(value: Any) -> bool:
    return isinstance(value, str) and _CACHE_SALT.fullmatch(value) is not None


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
    if normalized in CANONICAL_MODELS:
        return normalized
    if normalized in {"cyberseek", "cyberglm", "cyberkimi"} or normalized.startswith("claude-"):
        if normalized in {"cyberglm", "cyberkimi"}:
            raise ClientRequestError("CyberKimi and CyberGLM are available only on request.")
        return "adverserial/cyberseek"
    raise ClientRequestError("Use the canonical confidential model ID: adverserial/cyberseek. CyberKimi and CyberGLM are available only on request.")


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
        # One gateway process serves one `ack code` session or swarm and keeps
        # no conversation state, so the process lifetime is the session. The
        # salt partitions the enclave's prefix cache per session (inside the
        # per-tenant key the enclave derives itself); it is random, carries no
        # user data, is never logged, and is not written to disk.
        self._cache_salt = new_cache_salt()
        self._receipt_keys = dict(config.receipt_keys)
        self._receipt_keys_stamp = self._receipt_keys_file_stamp()
        self._receipt_keys_lock = threading.Lock()

    def _receipt_keys_file_stamp(self) -> tuple[int, int] | None:
        path = self.config.receipt_keys_file
        if not path:
            return None
        try:
            status = os.stat(path)
        except OSError:
            return None
        return status.st_mtime_ns, status.st_size

    def pinned_receipt_keys(self) -> dict[str, dict[str, Any]]:
        """The current local pins, following `ack upgrade` without a restart.

        The pin file is the same local trust anchor read at startup; only its
        owner (`ack init` / `ack upgrade`) rewrites it. A missing or malformed
        file never clears or widens the pins already loaded.
        """
        with self._receipt_keys_lock:
            stamp = self._receipt_keys_file_stamp()
            if stamp is not None and stamp != self._receipt_keys_stamp:
                try:
                    self._receipt_keys = load_receipt_keys(self.config.receipt_keys_file)
                    self._receipt_keys_stamp = stamp
                except ConfigError:
                    pass
            return self._receipt_keys

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
                trusted_receipt_keys=self.pinned_receipt_keys(),
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

    def reverified_proof(self, model: str, stale: VerifiedProof) -> VerifiedProof:
        """Drop `stale` from the cache and verify the endpoint from scratch.

        Used when a request could not be delivered with `stale` (the enclave
        rebooted and regenerated its keys). Nothing is taken from the failed
        exchange: the replacement goes through the full attestation, policy,
        pinned-receipt-key and hardware checks, or the request fails closed.
        """
        model = canonical_model_id(model)
        cached = self._proofs[model]
        with cached.lock:
            # Another request may already have replaced it; verify only once.
            if cached.proof is stale:
                cached.proof = None
            return self._refresh_proof(model, cached)

    @staticmethod
    def _ehbp_key_changed(old: Any, new: Any) -> bool:
        """True when the enclave now holds a different request-decryption key."""
        previous, current = getattr(old, "ehbp_public_key_sha256", None), getattr(new, "ehbp_public_key_sha256", None)
        return bool(current) and previous != current

    @staticmethod
    def _proof_age(proof: Any) -> float | None:
        issued = getattr(proof, "issued_epoch", None)
        if isinstance(issued, bool) or not isinstance(issued, (int, float)):
            return None
        return time.time() - issued

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
        # Prefix-cache isolation. The salt is part of the forwarded body, so it
        # is added before the entitlement bound below is computed. A valid
        # client-chosen salt is kept; a malformed one would be rejected by the
        # enclave, so the session salt replaces it. `extra_key` is refused by
        # the enclave and is never forwarded.
        payload = dict(payload)
        payload.pop("extra_key", None)
        if not valid_cache_salt(payload.get("cache_salt")):
            payload["cache_salt"] = self._cache_salt
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
        try:
            return self._dispatch(api_key, model, payload, max_input, max_output, proof, may_retry=True)
        except _RetryWithFreshProof as retry:
            # Exactly one retry, only after the first attempt provably did not
            # run, and only with a proof that passed full verification again.
            return self._dispatch(api_key, model, payload, max_input, max_output, retry.proof, may_retry=False)

    def _dispatch(self, api_key: str, model: str, payload: Mapping[str, Any], max_input: int, max_output: int, proof: VerifiedProof, *, may_retry: bool):
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
                if isinstance(exc, GatewayError) or not isinstance(exc, (VerificationError, TLSPinMismatchError, OSError)):
                    raise
                # The enclave was unreachable, presented a different TLS key,
                # or the proof could not be used: typically a reboot, after
                # which the cached proof names keys the enclave no longer
                # holds. No request bytes were sent, so re-verify and retry
                # once. A failed re-verification is the error the user needs
                # (for example "the service rotated its keys: run ack upgrade").
                if may_retry:
                    fresh = self.reverified_proof(model, proof)
                    if fresh is not proof:
                        raise _RetryWithFreshProof(fresh) from exc
                raise VerificationFailed(f"Confidential endpoint could not be used with its verified keys: {exc}") from exc
            if isinstance(exc, UpstreamHTTPError):
                rejected = UpstreamRejected(str(exc))
                rejected.status_code = exc.status
                if exc.status < 500:
                    self.release_reservation(api_key, entitlement)
                    # A pre-generation rejection can mean the request was
                    # sealed to an EHBP key the enclave replaced at boot. If a
                    # fresh, fully verified proof carries a different EHBP key,
                    # the enclave cannot have opened this request: retry once.
                    # An unchanged key means an ordinary rejection — no retry.
                    stale_key = isinstance(exc, EHBPKeyMismatchError)
                    age = self._proof_age(proof)
                    suspect = exc.status in _STALE_KEY_STATUSES and age is not None and age >= _REVERIFY_MIN_PROOF_AGE_SECONDS
                    if may_retry and (stale_key or suspect):
                        try:
                            fresh = self.reverified_proof(model, proof)
                        except VerificationFailed:
                            if stale_key:
                                raise
                            fresh = proof
                        if self._ehbp_key_changed(proof, fresh):
                            raise _RetryWithFreshProof(fresh) from exc
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

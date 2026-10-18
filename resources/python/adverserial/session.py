"""VerifiedSession: an OpenAI-compatible HTTPS session pinned to the
attested TLS public key, with WP-7 per-request receipt verification.

After verify_endpoint() succeeds, every request made through a
VerifiedSession is sent over a TLS connection whose peer certificate SPKI
SHA-256 equals the evidence's tls_spki_sha256. The pin is checked in
connect() — immediately after the handshake, before any request bytes
(including the Authorization header) are written. A substituted certificate
fails loudly with TLSPinMismatchError.

For chat completions the proxy attaches a WP-7 enclave receipt (compact ES256
JWS signed by the attested receipt key): as the X-Adverserial-Receipt header
on non-streaming responses, or as a final `data: {"adverserial_receipt": …}`
SSE chunk just before the upstream [DONE] on streams. The session verifies,
when present: signature against the proof's receipt key, nonce echo,
request/response hashes against the exact bytes sent/received, model, policy,
issuer/audience, expiry, and the attestation binding's TLS SPKI. A receipt
that fails any check raises VerificationError — the exchange is not to be
trusted. A missing receipt is reported as receipt_verified=False.

Stream hashing rule (must match the proxy): for every upstream `data:` line,
strip the trailing CR, drop "data:" and ONE leading space, and feed the
remaining payload bytes to the stream hash — including the "[DONE]" sentinel,
excluding the receipt chunk.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import secrets
import time
from typing import Any, Dict, Generator, Iterable, Iterator, Mapping, Optional
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from ehbp import ServerIdentity
from ehbp.protocol import ENCAPSULATED_KEY_HEADER, RESPONSE_NONCE_HEADER
from ._jws import b64url_encode, parse_compact_jws, verify_es256
from ._tls import PinnedHTTPSConnection
from .verify import VerificationError, VerifiedProof

__all__ = ["CompletionResponse", "ReceiptStream", "UpstreamHTTPError", "VerifiedSession"]


def _sha256_b64(data: bytes) -> str:
    return "sha256:" + b64url_encode(hashlib.sha256(data).digest())


def _https_origin(value: str, *, label: str, origin_only: bool = False) -> tuple[str, str, int, str]:
    """Validate an HTTPS URL and return (origin, host, port, path).

    The attestation policy binds a runtime key to an origin, not an arbitrary
    URL string.  Normalizing here prevents a proof for one virtual host from
    being reused through a different URL that happens to share a certificate.
    """
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise VerificationError(f"{label} must be a valid HTTPS URL") from exc
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or (origin_only and parts.path not in {"", "/"})
    ):
        raise VerificationError(f"{label} must be a plain HTTPS URL")
    host = parts.hostname
    rendered_host = f"[{host}]" if ":" in host else host
    effective_port = port or 443
    origin = f"https://{rendered_host}"
    if effective_port != 443:
        origin += f":{effective_port}"
    return origin, host, effective_port, parts.path.rstrip("/")


class UpstreamHTTPError(VerificationError):
    """The enclave answered a dispatched chat-completions request with a
    non-200 status. Carries the upstream status so callers can distinguish a
    pre-generation rejection (4xx: the reservation can be released safely)
    from a mid-generation failure (5xx: the outcome is unknown and the
    reservation settles through the proxy's terminal meter event)."""

    def __init__(self, status: int, detail: str) -> None:
        self.status = status
        super().__init__(f"POST /chat/completions failed with HTTP {status}: {detail}")


class CompletionResponse(dict):
    """A parsed JSON completion plus its WP-7 receipt verification outcome.

    receipt_verified is True only when a receipt was present and passed every
    check. receipt_claims carries the verified claim set (or None).
    """

    def __init__(
        self,
        payload: Mapping[str, Any],
        *,
        receipt_verified: bool,
        receipt_claims: Optional[Dict[str, Any]],
    ) -> None:
        super().__init__(payload)
        self.receipt_verified = receipt_verified
        self.receipt_claims = receipt_claims


class ReceiptStream:
    """Iterator over SSE data events with WP-7 receipt verification.

    Events arrive as parsed JSON objects. The proxy's final receipt chunk is
    intercepted (never yielded) and verified when the stream ends: a bad
    receipt raises VerificationError from the iteration, even though all
    content chunks were already consumed — treat a raise-at-end as "the whole
    exchange failed verification".
    """

    def __init__(self) -> None:
        self._generator: Optional[Generator[Any, None, None]] = None
        self.receipt_verified = False
        self.receipt_claims: Optional[Dict[str, Any]] = None

    def __iter__(self) -> "ReceiptStream":
        return self

    def __next__(self) -> Any:
        assert self._generator is not None
        return next(self._generator)

    def close(self) -> None:
        if self._generator is not None:
            self._generator.close()


class VerifiedSession:
    """OpenAI-compatible client for an attested endpoint.

    Parameters:
        base_url: endpoint base, e.g. "https://host/v1".
        proof: a VerifiedProof returned by verify_endpoint().
        entitlement: short-lived, model-bound billing entitlement sent as
            `Authorization: Bearer <entitlement>`. A long-lived platform API
            key must be exchanged at billing and must never enter the CVM.
        timeout: per-request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str,
        *,
        proof: VerifiedProof,
        entitlement: Optional[str] = None,
        timeout: float = 60.0,
        require_receipts: bool = True,
        use_ehbp: Optional[bool] = None,
    ) -> None:
        if getattr(proof, "status", None) != "verified":
            raise VerificationError(
                "VerifiedSession requires a proof with status 'verified'; "
                "call verify_endpoint() first"
            )
        origin, host, port, path = _https_origin(base_url, label="endpoint URL")
        if proof.endpoint is not None:
            proof_origin, _, _, _ = _https_origin(
                proof.endpoint,
                label="verified proof endpoint",
                origin_only=True,
            )
            if proof_origin != origin:
                raise VerificationError(
                    "verified proof endpoint does not match the requested inference endpoint"
                )
        self._host = host
        self._port = port
        self._base_path = path
        self._proof = proof
        self._entitlement = entitlement
        self._timeout = timeout
        self._require_receipts = require_receipts
        if use_ehbp is not None and not isinstance(use_ehbp, bool):
            raise VerificationError("use_ehbp must be a boolean when supplied")
        if not isinstance(require_receipts, bool):
            raise VerificationError("require_receipts must be a boolean")
        # A proof with a quote-bound EHBP key automatically selects encrypted
        # request/response transport. Explicit false remains only for a
        # legacy proof that has no EHBP key at all; a caller must never be
        # able to downgrade a verified production endpoint to plaintext after
        # it has advertised its quote-bound receiver key.
        ehbp_available = proof.ehbp_key_config is not None
        if ehbp_available and use_ehbp is False:
            raise VerificationError("cannot disable EHBP for an endpoint whose verified evidence requires it")
        if ehbp_available and not require_receipts:
            raise VerificationError("cannot disable signed inference receipts for an EHBP-attested endpoint")
        self._use_ehbp = ehbp_available if use_ehbp is None else use_ehbp
        if self._use_ehbp and not proof.ehbp_key_config:
            raise VerificationError("EHBP was requested but the verified evidence has no EHBP key configuration")
        if self._use_ehbp and not self._entitlement:
            raise VerificationError("a short-lived confidential entitlement is required; do not send a platform API key to the CVM")
        if require_receipts and not proof.attestation_state_digest:
            raise VerificationError("VerifiedSession requires attestation_state_digest to verify inference receipts")
        # Flipped immediately before request bytes are written to the enclave.
        # Once True, a failure is outcome-unknown: the request may have reached
        # the proxy, so the billing reservation must not be released locally.
        self.dispatched = False

    @property
    def proof(self) -> VerifiedProof:
        return self._proof

    def _connect(self) -> PinnedHTTPSConnection:
        return PinnedHTTPSConnection(
            self._host,
            self._port,
            expected_spki_sha256=self._proof.tls_spki_sha256,
            timeout=self._timeout,
        )

    def _new_request_nonce(self) -> Optional[str]:
        """Fresh 32-byte base64url WP-7 request nonce (test-hookable)."""
        return b64url_encode(secrets.token_bytes(32))

    def _headers(self, extra: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._entitlement:
            headers["Authorization"] = f"Bearer {self._entitlement}"
        if extra:
            headers.update(extra)
        return headers

    def request_json(
        self, method: str, path: str, payload: Optional[Mapping[str, Any]] = None
    ) -> Any:
        """Send a JSON request over a pinned connection; return parsed JSON."""
        connection = self._connect()
        try:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
            headers = self._headers(
                {"Content-Type": "application/json"} if body is not None else None
            )
            connection.request(method, self._base_path + path, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read()
            if response.status != 200:
                raise VerificationError(
                    f"{method} {path} failed with HTTP {response.status}: "
                    f"{data[:200].decode('utf-8', 'replace')}"
                )
            return json.loads(data)
        finally:
            connection.close()

    def models(self) -> Any:
        """GET {base_url}/models."""
        return self.request_json("GET", "/models")

    def chat_completions(
        self,
        messages: Iterable[Mapping[str, Any]],
        *,
        model: Optional[str] = None,
        stream: bool = False,
        **params: Any,
    ) -> Any:
        """POST {base_path}/chat/completions.

        stream=False (default) returns a CompletionResponse (a dict of the
        parsed JSON body, with .receipt_verified / .receipt_claims).
        stream=True returns a ReceiptStream yielding the parsed JSON object of
        each SSE `data:` event, stopping at `[DONE]`; receipt verification
        runs when the stream ends.
        """
        payload: Dict[str, Any] = {
            "model": model or self._proof.model_id,
            "messages": list(messages),
            "stream": bool(stream),
        }
        payload.update(params)
        # ensure_ascii=False is load-bearing: the gateway reserves the billing
        # input bound as 2x the UTF-8 body length. ASCII escaping inflates
        # non-ASCII content up to 3-6x (6-byte escape sequences, surrogate pairs
        # for astral characters), which would exceed the minted bound and fail
        # entitlement validation (401).
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        nonce = self._new_request_nonce()
        if stream:
            if self._use_ehbp:
                return self._ehbp_stream(body, nonce, payload["model"])
            return self._stream(body, nonce, payload["model"])
        if self._use_ehbp:
            return self._ehbp_completion(body, nonce, payload["model"])
        return self._completion(body, nonce, payload["model"])

    def _ehbp_identity(self) -> ServerIdentity:
        if not self._proof.ehbp_key_config:
            raise VerificationError("EHBP requires an attested receiver key configuration")
        try:
            return ServerIdentity.unmarshal_public_config(self._proof.ehbp_key_config)
        except Exception as exc:  # reference library exposes several concrete errors
            raise VerificationError("the attested EHBP key configuration is invalid") from exc

    @staticmethod
    def _error_detail(encrypted, response, wire_body: bytes) -> str:
        """Plaintext for an upstream error body. Confidential error responses
        are EHBP-encrypted like successful ones; decrypt when the response
        nonce is present so callers see the gate's actual rejection reason
        instead of ciphertext. Falls back to the raw body."""
        nonce_header = response.getheader(RESPONSE_NONCE_HEADER)
        if nonce_header:
            try:
                plain = encrypted.token.decrypt_response_body(bytes.fromhex(nonce_header), wire_body)
                return plain[:200].decode("utf-8", "replace")
            except Exception:
                pass
        return wire_body[:200].decode("utf-8", "replace")

    def _ehbp_completion(self, body: bytes, nonce: Optional[str], model_id: str) -> CompletionResponse:
        """Use the maintained EHBP reference framing over a hard-SPKI-pinned TLS connection."""
        if nonce is None:
            raise VerificationError("EHBP requires a fresh request nonce")
        try:
            encrypted = self._ehbp_identity().encrypt_request_body(body)
        except Exception as exc:
            raise VerificationError("could not encrypt the confidential request") from exc
        if encrypted is None:
            raise VerificationError("a confidential completion request must not be empty")
        connection = self._connect()
        try:
            headers = self._headers({"Content-Type": "application/json", "X-Adverserial-Nonce": nonce})
            headers[ENCAPSULATED_KEY_HEADER] = encrypted.encapsulated_key.hex()
            self.dispatched = True
            connection.request("POST", self._base_path + "/chat/completions", body=encrypted.body, headers=headers)
            response = connection.getresponse()
            wire_body = response.read()
            receipt_token = response.getheader("X-Adverserial-Receipt")
            if response.status != 200:
                raise UpstreamHTTPError(response.status, self._error_detail(encrypted, response, wire_body))
            try:
                response_nonce = response.getheader(RESPONSE_NONCE_HEADER)
                if not response_nonce:
                    raise ValueError("missing EHBP response nonce")
                data = encrypted.token.decrypt_response_body(bytes.fromhex(response_nonce), wire_body)
            except (ValueError, TypeError) as exc:
                raise VerificationError("could not decrypt authenticated confidential response") from exc
            claims: Optional[Dict[str, Any]] = None
            verified = False
            if receipt_token:
                claims = self._verify_request_receipt(token=receipt_token, request_nonce=nonce, request_body=body, response_hash=_sha256_b64(data), model_id=model_id)
                verified = True
            elif self._require_receipts:
                raise VerificationError("the confidential endpoint did not return a signed inference receipt")
            return CompletionResponse(json.loads(data), receipt_verified=verified, receipt_claims=claims)
        finally:
            connection.close()

    # --- non-streaming with receipt header ---------------------------------

    def _completion(self, body: bytes, nonce: Optional[str], model_id: str) -> CompletionResponse:
        connection = self._connect()
        try:
            headers = self._headers({"Content-Type": "application/json"})
            if nonce:
                headers["X-Adverserial-Nonce"] = nonce
            self.dispatched = True
            connection.request(
                "POST", self._base_path + "/chat/completions", body=body, headers=headers
            )
            response = connection.getresponse()
            data = response.read()
            receipt_token = response.getheader("X-Adverserial-Receipt")
            if response.status != 200:
                raise UpstreamHTTPError(response.status, data[:200].decode("utf-8", "replace"))
            claims: Optional[Dict[str, Any]] = None
            verified = False
            if receipt_token:
                claims = self._verify_request_receipt(
                    token=receipt_token,
                    request_nonce=nonce,
                    request_body=body,
                    response_hash=_sha256_b64(data),
                    model_id=model_id,
                )
                verified = True
            elif self._require_receipts:
                raise VerificationError("the confidential endpoint did not return a signed inference receipt")
            return CompletionResponse(
                json.loads(data), receipt_verified=verified, receipt_claims=claims
            )
        finally:
            connection.close()

    # --- streaming with final receipt chunk ---------------------------------

    def _ehbp_stream(self, body: bytes, nonce: Optional[str], model_id: str) -> ReceiptStream:
        """Stream an SSE response through standard EHBP framed decryption.

        No plaintext fallback is possible: a successful response without the
        protocol response nonce is rejected before any model bytes are yielded.
        """
        if nonce is None:
            raise VerificationError("EHBP requires a fresh request nonce")
        try:
            encrypted = self._ehbp_identity().encrypt_request_body(body)
        except Exception as exc:
            raise VerificationError("could not encrypt the confidential request") from exc
        if encrypted is None:
            raise VerificationError("a confidential completion request must not be empty")
        connection = self._connect()
        headers = self._headers({"Content-Type": "application/json", "Accept": "text/event-stream", "X-Adverserial-Nonce": nonce})
        headers[ENCAPSULATED_KEY_HEADER] = encrypted.encapsulated_key.hex()
        self.dispatched = True
        connection.request("POST", self._base_path + "/chat/completions", body=encrypted.body, headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            data = response.read()
            connection.close()
            raise UpstreamHTTPError(response.status, self._error_detail(encrypted, response, data))
        nonce_header = response.getheader(RESPONSE_NONCE_HEADER)
        if not nonce_header:
            connection.close()
            raise VerificationError("the confidential endpoint returned a successful plaintext response")
        try:
            decryptor = encrypted.token.create_response_decryptor(bytes.fromhex(nonce_header))
        except (TypeError, ValueError) as exc:
            connection.close()
            raise VerificationError("the confidential endpoint supplied an invalid EHBP response nonce") from exc

        stream = ReceiptStream()

        def events() -> Generator[Any, None, None]:
            hasher = hashlib.sha256()
            receipt_token: Optional[str] = None
            buffer = b""
            done = False
            try:
                while not done:
                    wire_chunk = response.read1(4096)
                    if not wire_chunk:
                        break
                    for chunk in decryptor.push(wire_chunk):
                        buffer += chunk
                        while b"\n" in buffer:
                            line, buffer = buffer.split(b"\n", 1)
                            if line.endswith(b"\r"):
                                line = line[:-1]
                            if not line or line.startswith(b":") or not line.startswith(b"data:"):
                                continue
                            payload = line[len(b"data:") :]
                            if payload.startswith(b" "):
                                payload = payload[1:]
                            if payload == b"[DONE]":
                                hasher.update(payload)
                                done = True
                                break
                            parsed = json.loads(payload)
                            if isinstance(parsed, dict) and "adverserial_receipt" in parsed:
                                token = parsed["adverserial_receipt"]
                                if not isinstance(token, str):
                                    raise VerificationError("malformed adverserial_receipt chunk")
                                receipt_token = token
                                continue
                            hasher.update(payload)
                            yield parsed
                decryptor.finish()
            finally:
                connection.close()
            if receipt_token is not None:
                claims = self._verify_request_receipt(
                    token=receipt_token,
                    request_nonce=nonce,
                    request_body=body,
                    response_hash="sha256:" + b64url_encode(hasher.digest()),
                    model_id=model_id,
                )
                stream.receipt_verified = True
                stream.receipt_claims = claims
            elif self._require_receipts:
                raise VerificationError("the confidential endpoint did not return a signed inference receipt")

        stream._generator = events()
        return stream

    def _stream(self, body: bytes, nonce: Optional[str], model_id: str) -> ReceiptStream:
        connection = self._connect()
        headers = self._headers(
            {"Content-Type": "application/json", "Accept": "text/event-stream"}
        )
        if nonce:
            headers["X-Adverserial-Nonce"] = nonce
        self.dispatched = True
        connection.request(
            "POST", self._base_path + "/chat/completions", body=body, headers=headers
        )
        response = connection.getresponse()
        if response.status != 200:
            data = response.read()
            connection.close()
            raise UpstreamHTTPError(response.status, data[:200].decode("utf-8", "replace"))

        stream = ReceiptStream()

        def events() -> Generator[Any, None, None]:
            hasher = hashlib.sha256()
            receipt_token: Optional[str] = None
            buffer = b""
            done = False
            try:
                while not done:
                    chunk = response.read1(4096)
                    if not chunk:
                        break
                    buffer += chunk
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        if line.endswith(b"\r"):
                            line = line[:-1]
                        if not line or line.startswith(b":"):
                            continue
                        if not line.startswith(b"data:"):
                            continue
                        payload = line[len(b"data:") :]
                        if payload.startswith(b" "):
                            payload = payload[1:]
                        if payload == b"[DONE]":
                            hasher.update(payload)
                            done = True
                            break
                        parsed = json.loads(payload)
                        # The proxy's receipt chunk is not part of the hashed
                        # upstream stream: intercept it before hashing.
                        if isinstance(parsed, dict) and "adverserial_receipt" in parsed:
                            token = parsed["adverserial_receipt"]
                            if not isinstance(token, str):
                                raise VerificationError("malformed adverserial_receipt chunk")
                            receipt_token = token
                            continue
                        hasher.update(payload)
                        yield parsed
            finally:
                connection.close()
            if receipt_token is not None:
                claims = self._verify_request_receipt(
                    token=receipt_token,
                    request_nonce=nonce,
                    request_body=body,
                    response_hash="sha256:" + b64url_encode(hasher.digest()),
                    model_id=model_id,
                )
                stream.receipt_verified = True
                stream.receipt_claims = claims
            elif self._require_receipts:
                raise VerificationError("the confidential endpoint did not return a signed inference receipt")

        stream._generator = events()
        return stream

    # --- WP-7 receipt verification -------------------------------------------

    def _verify_request_receipt(
        self,
        *,
        token: str,
        request_nonce: Optional[str],
        request_body: bytes,
        response_hash: str,
        model_id: str,
    ) -> Dict[str, Any]:
        """Verify a per-request enclave receipt against the proof. Raises
        VerificationError on any mismatch; returns the claims on success."""
        proof = self._proof
        try:
            header, claims, signing_input, signature = parse_compact_jws(token)
        except ValueError as exc:
            raise VerificationError(f"the per-request receipt is malformed: {exc}") from exc
        if header.get("alg") != "ES256" or header.get("kid") != proof.receipt_key_id:
            raise VerificationError(
                "the per-request receipt is not signed by the attested receipt key"
            )
        if not isinstance(proof.receipt_jwk, dict):
            raise VerificationError("the proof carries no receipt key to verify against")
        try:
            verify_es256(proof.receipt_jwk, signing_input, signature)
        except (InvalidSignature, ValueError) as exc:
            raise VerificationError("the per-request receipt signature is invalid") from exc

        now = time.time()
        if claims.get("v") != 1:
            raise VerificationError("the per-request receipt has an unsupported version")
        if claims.get("iss") != proof.issuer or claims.get("aud") != proof.audience:
            raise VerificationError("the per-request receipt issuer/audience mismatch")
        claim_nonce = claims.get("request_nonce")
        if request_nonce is not None:
            if claim_nonce != request_nonce:
                raise VerificationError(
                    "the per-request receipt is bound to a different request nonce"
                )
        elif not isinstance(claim_nonce, str) or not claim_nonce:
            raise VerificationError("the per-request receipt is missing its request nonce")
        if claims.get("request_body_hash") != _sha256_b64(request_body):
            raise VerificationError(
                "request body hash mismatch — the runtime saw different request bytes"
            )
        if claims.get("response_hash") != response_hash:
            raise VerificationError(
                "response hash mismatch — the delivered response differs from the attested one"
            )
        if claims.get("model_id") != model_id or claims.get("model_id") != proof.model_id:
            raise VerificationError("the per-request receipt model does not match")
        if proof.policy_id is not None and claims.get("policy_id") != proof.policy_id:
            raise VerificationError("the per-request receipt policy does not match")
        binding = claims.get("attestation_binding")
        if not isinstance(binding, dict) or binding.get("tls_spki_sha256") != proof.tls_spki_sha256:
            raise VerificationError(
                "the per-request receipt is bound to a different TLS key"
            )
        if proof.attestation_state_digest and binding.get("evidence_digest") != proof.attestation_state_digest:
            raise VerificationError("the per-request receipt is bound to a different attestation state")
        iat, exp = claims.get("iat"), claims.get("exp")
        if not isinstance(iat, (int, float)) or not isinstance(exp, (int, float)):
            raise VerificationError("the per-request receipt is missing iat/exp")
        if exp <= now:
            raise VerificationError("the per-request receipt has expired")
        if iat > now + 60:
            raise VerificationError("the per-request receipt was issued in the future")
        return claims

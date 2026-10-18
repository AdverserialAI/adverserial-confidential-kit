"""A local fake attest-proxy for tests: real TLS (self-signed P-256 cert),
real ES256 receipts, evidence shaped exactly like attest-proxy DEV_MODE
output. All failure knobs mirror things the real proxy or a MITM could do.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import ssl
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    EllipticCurvePrivateKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.x509.oid import NameOID

from adverserial._canonjson import canonical_json, evidence_digest
from adverserial._jws import b64url_encode


def _b64url(data: bytes) -> str:
    return b64url_encode(data)


def _pad32(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _public_jwk(key: EllipticCurvePrivateKey) -> Dict[str, Any]:
    numbers = key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(_pad32(numbers.x)),
        "y": _b64url(_pad32(numbers.y)),
    }
    thumbprint_input = canonical_json(
        {"crv": "P-256", "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    )
    jwk["kid"] = _b64url(hashlib.sha256(thumbprint_input.encode("utf-8")).digest())
    return jwk


def _mint_jws(key: EllipticCurvePrivateKey, kid: str, claims: Dict[str, Any]) -> str:
    header = canonical_json({"alg": "ES256", "kid": kid, "typ": "JWT"})
    payload = canonical_json(claims)
    signing_input = (
        _b64url(header.encode("utf-8")) + "." + _b64url(payload.encode("utf-8"))
    )
    der = key.sign(signing_input.encode("ascii"), ECDSA(SHA256()))
    r, s = decode_dss_signature(der)
    return signing_input + "." + _b64url(_pad32(r) + _pad32(s))


def _self_signed_cert(key: EllipticCurvePrivateKey):
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    import ipaddress

    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now.replace(year=now.year - 1))
        .not_valid_after(now.replace(year=now.year + 1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, SHA256())
    )


class _Handler(BaseHTTPRequestHandler):
    server_version = "FakeAttestProxy/0.1"
    protocol_version = "HTTP/1.0"

    def log_message(self, *args: Any) -> None:  # keep test output clean
        pass

    @property
    def fake(self) -> "FakeAttestProxy":
        return self.server.fake  # type: ignore[attr-defined]

    def _write_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self._write_raw_json(status, body, receipt=None)

    def _write_raw_json(self, status: int, body: bytes, receipt: Optional[str]) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if receipt is not None:
            self.send_header("X-Adverserial-Receipt", receipt)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path in ("/attestation", "/.well-known/adverserial-attestation"):
            self._handle_attestation()
        elif path == "/healthz":
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._write_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if urlsplit(self.path).path != "/v1/chat/completions":
            self._write_json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        request_bytes = self.rfile.read(length)
        request = json.loads(request_bytes or b"{}")
        # WP-7: echo the client nonce, or generate one when absent.
        nonce = self.headers.get("X-Adverserial-Nonce") or _b64url(secrets.token_bytes(32))
        if request.get("stream"):
            self._handle_stream(request, request_bytes, nonce)
            return
        response = {
            "id": "chatcmpl-fake",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": request.get("model", "unknown"),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "fake completion"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
        }
        body = json.dumps(response).encode("utf-8")
        receipt: Optional[str] = None
        if self.fake.receipts:
            receipt = self.fake._request_receipt(
                request_bytes=request_bytes,
                response_hash="sha256:" + _b64url(hashlib.sha256(body).digest()),
                nonce=nonce,
                model=request.get("model", "unknown"),
            )
        if self.fake.tamper_response_body:
            body = body.replace(b"fake completion", b"EVIL completion")
        self._write_raw_json(200, body, receipt)

    def _handle_stream(self, request: Dict[str, Any], request_bytes: bytes, nonce: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        hasher = hashlib.sha256()
        for index, token in enumerate(("fake", " completion")):
            chunk = {
                "id": "chatcmpl-fake",
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": request.get("model", "unknown"),
                "choices": [
                    {
                        "index": index,
                        "delta": {"content": token},
                        "finish_reason": None,
                    }
                ],
            }
            payload = json.dumps(chunk).encode("utf-8")
            hasher.update(payload)
            wire = payload
            if self.fake.tamper_response_body and index == 0:
                wire = payload.replace(b"fake", b"EVIL")  # receipt commits to the original
            self.wfile.write(b"data: " + wire + b"\n\n")
            self.wfile.flush()
        if self.fake.receipts:
            hasher.update(b"[DONE]")
            receipt = self.fake._request_receipt(
                request_bytes=request_bytes,
                response_hash="sha256:" + _b64url(hasher.digest()),
                nonce=nonce,
                model=request.get("model", "unknown"),
            )
            chunk = json.dumps({"adverserial_receipt": receipt}).encode("utf-8")
            self.wfile.write(b"data: " + chunk + b"\n\n")
            self.wfile.flush()
        else:
            hasher.update(b"[DONE]")
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def _handle_attestation(self) -> None:
        fake = self.fake
        params = parse_qs(urlsplit(self.path).query)
        nonce_values = params.get("nonce")
        if not nonce_values or len(nonce_values) != 1 or not nonce_values[0]:
            self._write_json(400, {"error": "missing nonce parameter"})
            return
        nonce = nonce_values[0]

        now = int(time.time()) + fake.iat_offset
        expires = now + fake.lifetime
        evidence: Dict[str, Any] = {
            "version": 1,
            "nonce": nonce,
            "issued_at": _iso(now),
            "expires_at": _iso(expires),
            "tdx_quote": "4445565154453030" + "ab" * 32,  # synthetic DEVQTE00…
            "tdx_event_log": {"synthetic": True, "rtmr": ["ab" * 48]},
            "tls_spki_sha256": (
                fake.other_tls_spki_sha256 if fake.spki_lie else fake.tls_spki_sha256
            ),
            "tls_spki_der": _b64url(fake.tls_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)),
            "receipt_pubkey_jwk": fake.receipt_jwk,
            "attestation_state_digest": "sha256:" + _b64url(hashlib.sha256(b"fixture-state").digest()),
            "workload": {
                "policy_id": "adverserial-policy/dev",
                "model_id": fake.model_id,
                "proxy_version": "0.1.0",
                "compose_digest": "sha256:" + "11" * 32,
                "model_digest": "sha256:" + "22" * 32,
            },
            "gpu_evidence_ref": None,
        }
        if fake.dev:
            evidence["dev"] = True
        if fake.omit_event_log:
            evidence.pop("tdx_event_log")

        claims: Dict[str, Any] = {
            "iss": fake.issuer,
            "aud": fake.audience,
            "nonce": fake.nonce_override or nonce,
            "verdict": fake.verdict,
            "iat": now,
            "exp": expires,
            "evidence_sha256": evidence_digest(evidence),
            "model_id": fake.model_id,
            "endpoint": fake.endpoint,
        }
        if fake.model_digest_claim is not None:
            claims["model_digest"] = fake.model_digest_claim
        receipt = _mint_jws(
            fake.wrong_receipt_key if fake.sign_with_wrong_key else fake.receipt_key,
            fake.receipt_jwk["kid"],
            claims,
        )
        if fake.tamper_evidence:
            evidence["injected"] = "mutated after the receipt was minted"
        self._write_json(200, {"evidence": evidence, "verification_receipt": receipt})


class FakeAttestProxy:
    """Threaded TLS server speaking the attestation protocol.

    Failure knobs: model_id, verdict, nonce_override, iat_offset, lifetime,
    sign_with_wrong_key, tamper_evidence, spki_lie, omit_event_log, model_digest_claim,
    receipts, tamper_response_body, receipt_model_override, receipt_expired.
    """

    def __init__(
        self,
        *,
        dev: bool = True,
        model_id: str = "lordx64/cyberglm",
        issuer: str = "https://verify.adverserial.ai",
        audience: str = "https://chat.adverserial.ai",
        endpoint: Optional[str] = None,
        verdict: str = "verified",
        nonce_override: Optional[str] = None,
        iat_offset: int = 0,
        lifetime: int = 300,
        sign_with_wrong_key: bool = False,
        tamper_evidence: bool = False,
        spki_lie: bool = False,
        omit_event_log: bool = False,
        model_digest_claim: Optional[str] = None,
        receipts: bool = True,
        tamper_response_body: bool = False,
        receipt_model_override: Optional[str] = None,
        receipt_expired: bool = False,
    ) -> None:
        self.dev = dev
        self.model_id = model_id
        self.issuer = issuer
        self.audience = audience
        self._endpoint_override = endpoint
        self.verdict = verdict
        self.nonce_override = nonce_override
        self.iat_offset = iat_offset
        self.lifetime = lifetime
        self.sign_with_wrong_key = sign_with_wrong_key
        self.tamper_evidence = tamper_evidence
        self.spki_lie = spki_lie
        self.omit_event_log = omit_event_log
        self.model_digest_claim = model_digest_claim
        self.receipts = receipts
        self.tamper_response_body = tamper_response_body
        self.receipt_model_override = receipt_model_override
        self.receipt_expired = receipt_expired

        self.receipt_key = generate_private_key(SECP256R1())
        self.wrong_receipt_key = generate_private_key(SECP256R1())
        self.receipt_jwk = _public_jwk(self.receipt_key)

        self.tls_key = generate_private_key(SECP256R1())
        self.tls_cert = _self_signed_cert(self.tls_key)
        self.tls_spki_sha256 = self._spki_of(self.tls_cert)
        self.other_tls_spki_sha256 = self._spki_of(_self_signed_cert(generate_private_key(SECP256R1())))

        self._tmpdir = tempfile.TemporaryDirectory(prefix="adverserial-test-")
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def _spki_of(cert: x509.Certificate) -> str:
        spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return "sha256:" + _b64url(hashlib.sha256(spki).digest())

    @property
    def endpoint(self) -> str:
        return self._endpoint_override or self.base_url

    @property
    def base_url(self) -> str:
        assert self._httpd is not None
        return f"https://127.0.0.1:{self._httpd.server_address[1]}"

    @property
    def v1_url(self) -> str:
        return self.base_url + "/v1"

    @property
    def trusted_keys(self) -> Dict[str, Dict[str, Any]]:
        return {self.receipt_jwk["kid"]: self.receipt_jwk}

    def _request_receipt(
        self, *, request_bytes: bytes, response_hash: str, nonce: str, model: str
    ) -> str:
        """Mint a WP-7 per-request receipt (mirrors attest-proxy claims)."""
        now = int(time.time()) - (3600 if self.receipt_expired else 0)
        claims = {
            "v": 1,
            "iss": self.issuer,
            "aud": self.audience,
            "request_nonce": nonce,
            "request_body_hash": "sha256:" + _b64url(hashlib.sha256(request_bytes).digest()),
            "response_hash": response_hash,
            "model_id": self.receipt_model_override or model,
            "policy_id": "adverserial-policy/dev",
            "attestation_binding": {
                "tls_spki_sha256": self.tls_spki_sha256,
                "evidence_digest": "sha256:" + _b64url(hashlib.sha256(b"fixture-state").digest()),
            },
            "iat": now,
            "exp": now + 120,
            "usage": {"input_tokens": 1, "cached_tokens": 0, "output_tokens": 2},
        }
        return _mint_jws(self.receipt_key, self.receipt_jwk["kid"], claims)

    def start(self) -> "FakeAttestProxy":
        cert_path = self._tmpdir.name + "/cert.pem"
        key_path = self._tmpdir.name + "/key.pem"
        with open(cert_path, "wb") as handle:
            handle.write(self.tls_cert.public_bytes(Encoding.PEM))
        with open(key_path, "wb") as handle:
            handle.write(
                self.tls_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert_path, key_path)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.fake = self  # type: ignore[attr-defined]
        self._httpd.socket = context.wrap_socket(self._httpd.socket, server_side=True)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._tmpdir.cleanup()

    def __enter__(self) -> "FakeAttestProxy":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

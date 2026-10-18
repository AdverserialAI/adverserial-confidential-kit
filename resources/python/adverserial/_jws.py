"""ES256 compact-JWS verification against pinned JWK receipt keys.

Receipts are compact JWS tokens (header.payload.signature) where the ES256
signature is the raw 64-byte R||S concatenation per RFC 7518 section 3.4.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, Mapping, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    EllipticCurvePublicKey,
    EllipticCurvePublicNumbers,
)
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    raw = value.encode("ascii")
    padding = (-len(raw)) % 4
    return base64.urlsafe_b64decode(raw + b"=" * padding)


def jwk_to_public_key(jwk: Mapping[str, Any]) -> EllipticCurvePublicKey:
    """Rebuild a P-256 public key from a JWK mapping (kty/crv/x/y)."""
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError(f"unsupported JWK kty/crv {jwk.get('kty')!r}/{jwk.get('crv')!r}")
    try:
        x = int.from_bytes(b64url_decode(str(jwk["x"])), "big")
        y = int.from_bytes(b64url_decode(str(jwk["y"])), "big")
    except KeyError as exc:
        raise ValueError(f"JWK is missing coordinate {exc}") from exc
    numbers = EllipticCurvePublicNumbers(x, y, SECP256R1())
    return numbers.public_key()


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint of a P-256 public JWK."""
    from ._canonjson import canonical_json

    canonical = canonical_json(
        {"crv": "P-256", "kty": "EC", "x": str(jwk["x"]), "y": str(jwk["y"])}
    )
    import hashlib

    return b64url_encode(hashlib.sha256(canonical.encode("utf-8")).digest())


def parse_compact_jws(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], bytes, bytes]:
    """Split a compact JWS into (header, claims, signing_input, signature)."""
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise ValueError("the verification receipt is not a compact JWS")
    try:
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("the verification receipt has an invalid JSON payload") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError("the verification receipt has an invalid JSON payload")
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    signature = b64url_decode(parts[2])
    return header, claims, signing_input, signature


def verify_es256(jwk: Mapping[str, Any], signing_input: bytes, signature: bytes) -> None:
    """Verify a raw R||S ES256 signature; raise InvalidSignature on failure."""
    if len(signature) != 64:
        raise InvalidSignature("ES256 signature must be 64 bytes (raw R||S)")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    der_signature = encode_dss_signature(r, s)
    key = jwk_to_public_key(jwk)
    key.verify(der_signature, signing_input, ECDSA(SHA256()))

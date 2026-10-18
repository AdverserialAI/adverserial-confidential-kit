"""Canonical JSON encoding, byte-identical to the attest-proxy's Go
`internal/canonjson` package and to `canonicalize()` in the reference
TypeScript client (adverserial-webui src/lib/confidential/verification.ts).

Rules:
  - object keys sorted ascending (code-point order; the protocol's keys are
    ASCII, where this coincides with JS UTF-16 code-unit order),
  - no whitespace anywhere,
  - strings escaped exactly like JSON.stringify: only '"', '\\' and control
    characters < 0x20 are escaped (short forms \\b \\t \\n \\f \\r, otherwise
    lowercase \\u00xx). Non-ASCII, DEL (0x7f), U+2028/U+2029 and '<', '>',
    '&' are emitted raw,
  - integers in plain decimal; floats follow ECMA-262 Number-to-String
    (the attestation protocol itself only carries integers).
"""

from __future__ import annotations

import base64
import math
from decimal import Decimal
from hashlib import sha256
from typing import Any

_STRING_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def _encode_string(value: str) -> str:
    out = ['"']
    for char in value:
        escape = _STRING_ESCAPES.get(char)
        if escape is not None:
            out.append(escape)
        elif ord(char) < 0x20:
            out.append("\\u%04x" % ord(char))
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _encode_float(value: float) -> str:
    if math.isnan(value) or math.isinf(value):
        raise ValueError("canonjson: non-finite float")
    if value == 0:
        return "0"
    magnitude = abs(value)
    if 1e-6 <= magnitude < 1e21:
        if value.is_integer():
            return str(int(value))
        shortest = repr(value)
        if "e" in shortest or "E" in shortest:
            # repr() switches to exponent form for e.g. 1e16 inside the range
            # where JSON.stringify stays decimal; Decimal preserves the
            # shortest round-trip digits exactly.
            return format(Decimal(shortest), "f")
        return shortest
    # Exponential form with a JS-style exponent: no zero padding, explicit
    # sign (repr gives "1e-07" / "1e+21"; JSON.stringify gives "1e-7" / "1e+21").
    mantissa, _, exponent = repr(value).lower().partition("e")
    sign = ""
    if exponent.startswith(("+", "-")):
        sign, exponent = exponent[0], exponent[1:]
    exponent = exponent.lstrip("0") or "0"
    return f"{mantissa}e{sign}{exponent}"


def canonical_json(value: Any) -> str:
    """Encode *value* in the protocol's canonical JSON form."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _encode_float(value)
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        parts = []
        for key in sorted(value):
            if not isinstance(key, str):
                raise TypeError(f"canonjson: non-string object key {key!r}")
            parts.append(_encode_string(key) + ":" + canonical_json(value[key]))
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"canonjson: unsupported type {type(value).__name__}")


def evidence_digest(value: Any) -> str:
    """Return ``sha256:<base64url-no-padding>`` over the canonical UTF-8 form."""
    digest = sha256(canonical_json(value).encode("utf-8")).digest()
    return "sha256:" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

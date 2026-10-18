"""CLI: python -m adverserial verify <url> [--model ID] [--keys keys.json]

Prints a human-readable verdict table and exits 0 (verified) or 1 (failed).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Mapping, Optional

from ._jws import b64url_encode, jwk_thumbprint
from .verify import (
    VerificationError,
    VerifiedProof,
    fetch_attestation,
    verify_endpoint,
)

_DEFAULT_ISSUER = "https://verify.adverserial.ai"
_DEFAULT_AUDIENCE = "https://chat.adverserial.ai"
_DEFAULT_MODEL = "lordx64/cyberglm"

_DEV_WARNING = (
    "WARNING: DEV MODE — the evidence is synthetic (dev: true). This proof\n"
    "  demonstrates the plumbing (receipt signature, nonce binding, TLS SPKI\n"
    "  pinning) only. It does NOT prove the workload runs on genuine TDX/NVIDIA\n"
    "  hardware. Never send sensitive prompts to a dev-mode endpoint."
)

_TOFU_WARNING = (
    "WARNING: --trust-evidence-key trusts the receipt key published by the\n"
    "  endpoint itself (trust-on-first-use). Anyone terminating TLS can present\n"
    "  one. Use it for local development only; in production pin receipt keys\n"
    "  out-of-band via --keys."
)


def _load_keys(path: str) -> Dict[str, Mapping[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected a JSON object of {{kid: jwk}}")
    if "trusted_receipt_keys" in data:
        data = data["trusted_receipt_keys"]
    if not isinstance(data, dict) or not data:
        raise SystemExit(f"{path}: no trusted receipt keys found")
    for kid, jwk in data.items():
        if not isinstance(jwk, dict) or jwk.get("kty") != "EC":
            raise SystemExit(f"{path}: key {kid!r} is not an EC public JWK")
    return data


def _trust_evidence_key(url: str, timeout: float) -> Dict[str, Mapping[str, Any]]:
    import secrets

    nonce = b64url_encode(secrets.token_bytes(32))
    payload, _ = fetch_attestation(url, nonce, timeout)
    evidence = payload.get("evidence")
    jwk = evidence.get("receipt_pubkey_jwk") if isinstance(evidence, dict) else None
    if not isinstance(jwk, dict):
        raise SystemExit("the evidence does not publish a receipt_pubkey_jwk")
    kid = jwk.get("kid")
    if not isinstance(kid, str) or not kid:
        kid = jwk_thumbprint(jwk)
    print(_TOFU_WARNING, file=sys.stderr)
    return {kid: jwk}


def _print_row(label: str, value: Optional[str]) -> None:
    print(f"  {label:<16} {value if value is not None else '-'}")


def _print_proof(proof: VerifiedProof) -> None:
    print("Adverserial endpoint verification")
    _print_row("status", "VERIFIED")
    _print_row("model_id", proof.model_id)
    _print_row("endpoint", proof.endpoint)
    _print_row("issuer", proof.issuer)
    _print_row("audience", proof.audience)
    _print_row("receipt key", proof.receipt_key_id)
    _print_row("evidence", proof.evidence_digest)
    _print_row("TLS SPKI", proof.tls_spki_sha256)
    _print_row("receipt", proof.receipt_digest)
    _print_row("issued", proof.issued_at)
    _print_row("expires", proof.expires_at)
    _print_row("policy_id", proof.policy_id)
    _print_row("model_digest", proof.model_digest)
    _print_row("dev_mode", str(proof.dev_mode).lower())


def _cmd_verify(args: argparse.Namespace) -> int:
    print(
        "error: the CLI cannot verify raw TEE/GPU evidence without a configured "
        "independent hardware verifier. Use the SDK with hardware_verifier=...; "
        "it will not claim a hardware-verified result from a proxy receipt alone.",
        file=sys.stderr,
    )
    return 2

    # Retained below as the implementation skeleton for a future explicit,
    # audited verifier adapter. Do not make this path reachable until one is
    # configured; allowing it would create a misleading verification result.
    if args.trust_evidence_key:
        from .verify import _attestation_url_for

        attestation_url = _attestation_url_for(args.url)
        trusted_keys = _trust_evidence_key(attestation_url, args.timeout)
    elif args.keys:
        trusted_keys = _load_keys(args.keys)
    else:
        print(
            "error: provide --keys keys.json (production) or "
            "--trust-evidence-key (dev TOFU)",
            file=sys.stderr,
        )
        return 1

    try:
        proof = verify_endpoint(
            args.url,
            expected_model_id=args.model,
            trusted_receipt_keys=trusted_keys,
            issuer=args.issuer,
            audience=args.audience,
            expected_endpoint=args.endpoint,
            timeout=args.timeout,
        )
    except VerificationError as exc:
        print("Adverserial endpoint verification")
        _print_row("status", "FAILED")
        _print_row("reason", str(exc))
        return 1

    _print_proof(proof)
    if proof.dev_mode:
        print()
        print(_DEV_WARNING)
        if args.require_hardware:
            print("\n--require-hardware was given: failing on dev-mode evidence.")
            return 1
    return 0


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m adverserial",
        description="Adverserial confidential-inference verification SDK",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="verify an endpoint's attestation")
    verify.add_argument("url", help="endpoint base URL, e.g. https://host/v1")
    verify.add_argument("--model", default=_DEFAULT_MODEL, help="expected model ID")
    verify.add_argument(
        "--keys", help="JSON file of trusted receipt keys ({kid: jwk})"
    )
    verify.add_argument("--issuer", default=_DEFAULT_ISSUER)
    verify.add_argument("--audience", default=_DEFAULT_AUDIENCE)
    verify.add_argument("--endpoint", help="expected receipt endpoint claim")
    verify.add_argument(
        "--trust-evidence-key",
        action="store_true",
        help="DEV ONLY: trust the receipt key published in the evidence (TOFU)",
    )
    verify.add_argument(
        "--require-hardware",
        action="store_true",
        help="fail if the evidence is synthetic (dev: true)",
    )
    verify.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args(argv)
    if args.command == "verify":
        return _cmd_verify(args)
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())

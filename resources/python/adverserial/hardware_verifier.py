"""Fail-closed composition of independently maintained TDX and GPU verifiers.

This executable does not claim to interpret vendor evidence itself. It binds
raw evidence to the Adverserial protocol first, then invokes two separately
installed vendor adapters without a shell. Each adapter must return a strictly
checked JSON result. That keeps the client model- and GPU-agnostic while
ensuring a replacement adapter cannot silently omit nonce/TLS/event-log checks.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ._canonjson import canonical_json, evidence_digest
from ._jws import b64url_decode, jwk_to_public_key

_MAX_INPUT = 2 * 1024 * 1024
_MAX_OUTPUT = 64 * 1024
_PROTOCOL = "adverserial-hardware-verifier/v1"


class EvidenceError(ValueError):
    pass


def _fingerprint(data: bytes) -> str:
    return "sha256:" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def _need_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"missing {label}")
    return value


def _b64(value: str, label: str) -> bytes:
    try:
        return b64url_decode(value)
    except (ValueError, UnicodeError) as exc:
        raise EvidenceError(f"invalid base64url {label}") from exc


def protocol_bindings(request: Mapping[str, Any]) -> dict[str, Any]:
    evidence = request.get("evidence")
    if not isinstance(evidence, dict):
        raise EvidenceError("missing evidence")
    if evidence.get("dev") is True:
        raise EvidenceError("synthetic DEV_MODE evidence is never hardware verified")
    nonce = _need_string(request.get("nonce"), "nonce")
    if evidence.get("nonce") != nonce:
        raise EvidenceError("evidence nonce does not match verifier request")
    model = _need_string(request.get("model"), "model")
    workload = evidence.get("workload")
    if not isinstance(workload, dict) or workload.get("model_id") != model:
        raise EvidenceError("evidence model does not match verifier request")
    _need_string(evidence.get("tdx_quote"), "tdx_quote")
    if evidence.get("tdx_event_log") in (None, ""):
        raise EvidenceError("missing tdx_event_log")
    if evidence.get("gpu_evidence") in (None, ""):
        raise EvidenceError("missing gpu_evidence")
    tls_der = _b64(_need_string(evidence.get("tls_spki_der"), "tls_spki_der"), "tls_spki_der")
    if _fingerprint(tls_der) != _need_string(evidence.get("tls_spki_sha256"), "tls_spki_sha256"):
        raise EvidenceError("TLS SPKI public bytes do not match fingerprint")
    receipt_jwk = evidence.get("receipt_pubkey_jwk")
    if not isinstance(receipt_jwk, dict):
        raise EvidenceError("missing receipt_pubkey_jwk")
    try:
        receipt_der = jwk_to_public_key(receipt_jwk).public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    except (ValueError, TypeError) as exc:
        raise EvidenceError("invalid receipt_pubkey_jwk") from exc
    expected_report_data = hashlib.sha256(_b64(nonce, "nonce") + tls_der + receipt_der).digest() + b"\0" * 32
    return {
        "protocol": _PROTOCOL,
        "evidence": evidence,
        "expected": {
            "model": model,
            "endpoint": request.get("endpoint"),
            "report_data_hex": expected_report_data.hex(),
            "tdx_event_log_sha256": _fingerprint(canonical_json(evidence["tdx_event_log"]).encode("utf-8")),
            "gpu_evidence_sha256": _fingerprint(canonical_json(evidence["gpu_evidence"]).encode("utf-8")),
            "evidence_sha256": evidence_digest(evidence),
        },
    }


def _command(env_name: str) -> str:
    command = os.environ.get(env_name, "").strip()
    candidate = Path(command)
    if not command or not candidate.is_absolute():
        raise EvidenceError(f"{env_name} must be an absolute adapter executable path")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise EvidenceError(f"{env_name} could not be resolved") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise EvidenceError(f"{env_name} must name an executable file")
    return str(resolved)


def _run_adapter(env_name: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    try:
        command = _command(env_name)
        invocation = [sys.executable, command] if command.endswith('.py') else [command]
        completed = subprocess.run(
            invocation, input=json.dumps(payload, separators=(",", ":")).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvidenceError(f"{env_name} could not verify evidence") from exc
    if completed.returncode != 0 or len(completed.stdout) > _MAX_OUTPUT:
        raise EvidenceError(f"{env_name} rejected evidence")
    try:
        result = json.loads(completed.stdout)
    except ValueError as exc:
        raise EvidenceError(f"{env_name} emitted invalid JSON") from exc
    if not isinstance(result, dict) or result.get("verified") is not True or not isinstance(result.get("verifier"), str) or not result["verifier"].strip():
        raise EvidenceError(f"{env_name} did not return a verified vendor result")
    return result


def verify(request: Mapping[str, Any]) -> dict[str, Any]:
    payload = protocol_bindings(request)
    tdx = _run_adapter("ADVERSERIAL_TDX_VERIFIER_COMMAND", payload)
    expected = payload["expected"]
    if tdx.get("report_data_hex") != expected["report_data_hex"] or tdx.get("tdx_event_log_sha256") != expected["tdx_event_log_sha256"]:
        raise EvidenceError("TDX adapter did not validate report_data and event-log bindings")
    gpu = _run_adapter("ADVERSERIAL_GPU_VERIFIER_COMMAND", payload)
    if gpu.get("gpu_evidence_sha256") != expected["gpu_evidence_sha256"]:
        raise EvidenceError("GPU adapter did not validate the published GPU evidence")
    tee_name = _need_string(tdx.get("tee"), "TDX adapter tee")
    gpu_name = _need_string(gpu.get("gpu"), "GPU adapter gpu")
    return {"verified": True, "verifier": f"{tdx['verifier'].strip()} + {gpu['verifier'].strip()}", "tee": tee_name, "gpu": gpu_name}


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(_MAX_INPUT + 1)
        if len(raw) > _MAX_INPUT:
            raise EvidenceError("verifier input is too large")
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise EvidenceError("verifier input must be an object")
        print(json.dumps(verify(request), separators=(",", ":")))
        return 0
    except (EvidenceError, ValueError, UnicodeError):
        # Do not reveal inputs, quote contents, policy configuration, or vendor
        # stderr to an invoking client.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Subprocess bridge to the independently maintained hardware verifier."""
from __future__ import annotations

import json
import subprocess
from typing import Any, Mapping, Optional

from adverserial import HardwareVerification

_MAX_OUTPUT = 64 * 1024


def verifier_from_command(command: str):
    """Return an SDK hardware-verifier callback.

    The command is executed without a shell. It receives a JSON object with
    evidence and expected bindings on stdin and must return a JSON object whose
    `verified` is true and whose `verifier` contains a name/version.
    """
    def verify(evidence: Mapping[str, Any], nonce: str, model: str, endpoint: Optional[str]) -> HardwareVerification:
        request = json.dumps({"evidence": evidence, "nonce": nonce, "model": model, "endpoint": endpoint}, separators=(",", ":")).encode()
        try:
            completed = subprocess.run([command], input=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("hardware verifier could not run") from exc
        if len(completed.stdout) > _MAX_OUTPUT or completed.returncode != 0:
            raise RuntimeError("hardware verifier rejected the evidence")
        try:
            result = json.loads(completed.stdout)
        except ValueError as exc:
            raise RuntimeError("hardware verifier emitted invalid JSON") from exc
        if not isinstance(result, dict) or result.get("verified") is not True or not isinstance(result.get("verifier"), str) or not result["verifier"].strip():
            raise RuntimeError("hardware verifier rejected the evidence")
        return HardwareVerification(
            verified=True,
            verifier=result["verifier"].strip(),
            tee=result.get("tee") if isinstance(result.get("tee"), str) else None,
            gpu=result.get("gpu") if isinstance(result.get("gpu"), str) else None,
        )
    return verify

"""Configuration for the local confidential gateway.

The gateway deliberately binds loopback only. It handles a customer API key
solely between the local client and billing, then replaces it with a bounded
entitlement before contacting the confidential endpoint.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

CANONICAL_MODELS = frozenset({"lordx64/cyberglm", "lordx64/cyberkimi"})


class ConfigError(ValueError):
    pass


def _https_url(name: str, value: str, *, origin_only: bool = False) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigError(f"{name} must be a plain https URL without credentials, query, or fragment")
    if origin_only and parsed.path not in {"", "/"}:
        raise ConfigError(f"{name} must be an https origin without a path")
    return value.rstrip("/")


def _positive_int(name: str, value: str, maximum: int) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not 1 <= parsed <= maximum:
        raise ConfigError(f"{name} must be between 1 and {maximum}")
    return parsed


def _hardware_verifier_command(value: str) -> str:
    """Return a fixed executable path for the independent verifier.

    Verification must never fall back to PATH lookup.  A checkout, project
    hook, or other untrusted working directory can otherwise shadow a command
    such as ``adverserial-hardware-verify`` and forge a local "verified"
    verdict before any prompt is encrypted.  The documented configuration is
    already an absolute executable path; resolve it once at startup and pass
    that path directly to subprocess without a shell.
    """
    candidate = Path(value)
    if not candidate.is_absolute():
        raise ConfigError("ADVERSERIAL_HARDWARE_VERIFIER_COMMAND must be an absolute executable path")
    try:
        command = candidate.resolve(strict=True)
    except OSError as exc:
        raise ConfigError("ADVERSERIAL_HARDWARE_VERIFIER_COMMAND could not be resolved") from exc
    if not command.is_file() or not os.access(command, os.X_OK):
        raise ConfigError("ADVERSERIAL_HARDWARE_VERIFIER_COMMAND must name an executable file")
    return str(command)


@dataclass(frozen=True)
class Config:
    listen_host: str
    listen_port: int
    cc_api_url: str
    billing_url: str
    issuer: str
    audience: str
    receipt_keys: dict[str, dict[str, Any]]
    hardware_verifier_command: str
    max_input_tokens: int
    max_output_tokens: int

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Config":
        env = env or os.environ
        host = env.get("ADVERSERIAL_GATEWAY_HOST", "127.0.0.1")
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ConfigError("ADVERSERIAL_GATEWAY_HOST must be loopback; this gateway must not expose API keys on a network interface")
        port = _positive_int("ADVERSERIAL_GATEWAY_PORT", env.get("ADVERSERIAL_GATEWAY_PORT", "8787"), 65535)
        keys_path = env.get("ADVERSERIAL_RECEIPT_KEYS_FILE", "").strip()
        if not keys_path:
            raise ConfigError("ADVERSERIAL_RECEIPT_KEYS_FILE is required")
        try:
            data = json.loads(Path(keys_path).read_text())
        except Exception as exc:
            raise ConfigError("ADVERSERIAL_RECEIPT_KEYS_FILE could not be read as JSON") from exc
        if not isinstance(data, dict) or not data or not all(isinstance(k, str) and isinstance(v, dict) for k, v in data.items()):
            raise ConfigError("ADVERSERIAL_RECEIPT_KEYS_FILE must be a non-empty JSON object mapping kid to JWK")
        command = env.get("ADVERSERIAL_HARDWARE_VERIFIER_COMMAND", "").strip()
        if not command:
            raise ConfigError("ADVERSERIAL_HARDWARE_VERIFIER_COMMAND is required; proxy receipts alone are not hardware proof")
        return cls(
            listen_host=host,
            listen_port=port,
            cc_api_url=_https_url("ADVERSERIAL_CC_API_URL", env.get("ADVERSERIAL_CC_API_URL", "https://api.adverserial.ai/v1")),
            billing_url=_https_url(
                "ADVERSERIAL_BILLING_URL",
                env.get("ADVERSERIAL_BILLING_URL", "https://billing.adverserial.ai"),
                origin_only=True,
            ),
            issuer=env.get("ADVERSERIAL_ISSUER", "https://verify.adverserial.ai"),
            audience=env.get("ADVERSERIAL_AUDIENCE", "https://chat.adverserial.ai"),
            receipt_keys=data,
            hardware_verifier_command=_hardware_verifier_command(command),
            max_input_tokens=_positive_int("ADVERSERIAL_MAX_INPUT_TOKENS", env.get("ADVERSERIAL_MAX_INPUT_TOKENS", "6291456"), 6291456),
            max_output_tokens=_positive_int("ADVERSERIAL_MAX_OUTPUT_TOKENS", env.get("ADVERSERIAL_MAX_OUTPUT_TOKENS", "65536"), 65536),
        )

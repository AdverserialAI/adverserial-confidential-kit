"""Policy transparency for the Python SDK.

A verification policy is accepted only when the exact bytes that were served
carry a Sigstore bundle that

1. chains to the pinned Sigstore trusted root (Fulcio CA, CT log, Rekor,
   timestamp authority) with a verified transparency-log inclusion proof;
2. was issued to the one GitHub Actions workflow identity allowed to publish
   policies (workflow file, branch, repository, trigger); and
3. is not older than the newest policy this installation has accepted.

Verification is offline. The same rules, constants and pin file format are
implemented for Node in ``lib/policy-transparency.mjs``; the two share one pin
file under the ACK home, so a policy accepted by either runtime protects both.

The ack CLI and the gateway enforce this in the Node verifier. This module is
the optional equivalent for people who use the Python SDK on its own.

Two modes: ``warn`` (default in this release) checks and reports but never
blocks; ``enforce`` refuses a policy that is unsigned, unverifiable or older
than the one accepted before.

Requires the ``sigstore`` package (``pip install adverserial[transparency]``,
Python 3.11 or newer).
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

BUNDLE_SUFFIX = ".sigstore.json"
BUNDLED_TRUSTED_ROOT = Path(__file__).with_name("sigstore_trusted_root.json")
MAX_DOCUMENT_BYTES = 256 * 1024
PUBLISHED_AT_FUTURE_TOLERANCE_SECONDS = 600

# Keep identical to PRODUCTION_SIGNER in lib/policy-transparency.mjs.
PRODUCTION_SIGNER: Mapping[str, str] = {
    "san": "https://github.com/AdverserialAI/confidential-policy/.github/workflows/sign-policy.yml@refs/heads/main",
    "issuer": "https://token.actions.githubusercontent.com",
    "repository": "https://github.com/AdverserialAI/confidential-policy",
    "repositoryId": "1404762635",
    "ownerId": "158311530",
    "ref": "refs/heads/main",
    "trigger": "push",
    "runner": "github-hosted",
}
# Keep identical to POLICY_FLOOR in lib/policy-transparency.mjs.
POLICY_FLOOR: Mapping[str, str] = {"signedAt": "2026-11-19T14:41:23.000Z"}
DEFAULT_MODE = "warn"


class PolicyTransparencyError(Exception):
    """The policy must not be used. ``code`` says why."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def transparency_mode(env: Optional[Mapping[str, str]] = None) -> str:
    """ACK_POLICY_TRANSPARENCY, else the mode saved by ``ack policy enforce``, else the default."""
    env = env if env is not None else os.environ
    value = env.get("ACK_POLICY_TRANSPARENCY")
    if not value:
        try:
            value = (default_state_dir(env) / "policy-transparency-mode").read_text(encoding="utf-8").strip()
        except OSError:
            value = ""
    value = (value or DEFAULT_MODE).lower()
    if value not in ("warn", "enforce"):
        raise PolicyTransparencyError("CONFIG", 'The policy transparency mode must be "warn" or "enforce".')
    return value


def default_state_dir(env: Optional[Mapping[str, str]] = None) -> Path:
    env = env if env is not None else os.environ
    if env.get("ACK_HOME"):
        return Path(env["ACK_HOME"]).resolve()
    return Path(env.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "adverserial"


def _parse_time(text: Any) -> Optional[datetime]:
    if not isinstance(text, str):
        return None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else None


def _stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def verify_policy_signature(
    policy_bytes: bytes,
    bundle_json: str | bytes,
    *,
    signer: Mapping[str, str] = PRODUCTION_SIGNER,
    trusted_root: str | os.PathLike[str] = BUNDLED_TRUSTED_ROOT,
) -> dict[str, Any]:
    """Verify ``bundle_json`` over exactly ``policy_bytes``. Returns what was proven.

    Pass the bundle as the bytes that were served. If it is read from a file as
    text, read it as UTF-8: the Rekor checkpoint inside contains a non-ASCII
    character, and a platform default encoding corrupts it.
    """
    try:
        from sigstore.errors import Error as SigstoreError
        from sigstore.models import Bundle, TrustedRoot
        from sigstore.verify import Verifier, policy as sigstore_policy
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise PolicyTransparencyError("UNAVAILABLE", "Policy signatures need the 'sigstore' package: pip install 'adverserial[transparency]'.") from exc

    for field in ("san", "issuer", "repository", "ref", "trigger"):
        if not isinstance(signer.get(field), str) or not signer[field]:
            raise PolicyTransparencyError("CONFIG", f"Pinned signer is missing {field}.")
    try:
        document = json.loads(bundle_json)
        entries = document["verificationMaterial"]["tlogEntries"]
        bundle = Bundle.from_json(bundle_json)
    except Exception as exc:
        raise PolicyTransparencyError("BUNDLE_FORMAT", f"The policy signature bundle is not a valid Sigstore bundle ({exc}).") from exc
    if not isinstance(document.get("messageSignature"), dict):
        raise PolicyTransparencyError("BUNDLE_FORMAT", "The policy bundle must sign the policy bytes directly.")
    if len(entries) != 1 or not ((entries[0].get("inclusionProof") or {}).get("checkpoint") or {}).get("envelope"):
        # sigstore-python refuses such bundles too; this keeps the rule explicit.
        # A signed entry timestamp alone is a promise to log. Require the proof.
        raise PolicyTransparencyError("NOT_LOGGED", "The policy bundle has no transparency-log inclusion proof.")
    entry = entries[0]

    # Identity first, on its own, so that "valid signature, wrong signer" is
    # reported as such. The full verification below repeats it.
    optional = {
        "repositoryId": sigstore_policy.OIDCSourceRepositoryIdentifier,
        "ownerId": sigstore_policy.OIDCSourceRepositoryOwnerIdentifier,
        "runner": sigstore_policy.OIDCRunnerEnvironment,
    }
    identity = sigstore_policy.AllOf(
        [
            sigstore_policy.Identity(identity=signer["san"], issuer=signer["issuer"]),
            sigstore_policy.OIDCIssuerV2(signer["issuer"]),
            sigstore_policy.OIDCSourceRepositoryURI(signer["repository"]),
            sigstore_policy.OIDCSourceRepositoryRef(signer["ref"]),
            sigstore_policy.OIDCBuildTrigger(signer["trigger"]),
            *[check(signer[name]) for name, check in optional.items() if signer.get(name) is not None],
        ]
    )
    try:
        identity.verify(bundle.signing_certificate)
    except SigstoreError as exc:
        raise PolicyTransparencyError("WRONG_SIGNER", "The policy was not signed by the approved publishing workflow.") from exc
    try:
        verifier = Verifier(trusted_root=TrustedRoot.from_file(str(trusted_root)))
        verifier.verify_artifact(policy_bytes, bundle, identity)
        # Times that verify_artifact has just checked: the Rekor entry time is
        # covered by the signed entry timestamp, the RFC 3161 time by the
        # timestamp authority. The certificate was valid at each of them.
        times = []
        if entry.get("inclusionPromise"):
            times.append(datetime.fromtimestamp(int(entry["integratedTime"]), tz=timezone.utc))
        stamps = bundle.verification_material.timestamp_verification_data
        times.extend(response.tst_info.gen_time.astimezone(timezone.utc) for response in (stamps.rfc3161_timestamps if stamps else []))
    except PolicyTransparencyError:
        raise
    except Exception as exc:
        raise PolicyTransparencyError("SIGNATURE", f"The policy signature did not verify ({exc}).") from exc
    if not times:
        raise PolicyTransparencyError("SIGNATURE", "The policy bundle has no verified signing time.")

    return {
        "sha256": hashlib.sha256(policy_bytes).hexdigest(),
        "signedAt": _stamp(min(times)),
        "log": [{"logId": entry["logId"]["keyId"], "logIndex": str(entry["logIndex"]), "kind": f"{entry['kindVersion']['kind']}/{entry['kindVersion']['version']}"}],
        "signer": {"san": signer["san"], "issuer": signer["issuer"], "repository": signer["repository"], "ref": signer["ref"], "trigger": signer["trigger"]},
    }


def check_not_rolled_back(
    policy: Mapping[str, Any],
    verification: Mapping[str, Any],
    pin: Optional[Mapping[str, Any]] = None,
    floor: Optional[Mapping[str, str]] = POLICY_FLOOR,
) -> dict[str, Any]:
    """Order is the verified log time, which the signer cannot choose. Returns the new pin."""
    signed_at = _parse_time(verification["signedAt"])
    published_at = _parse_time(policy.get("published_at"))
    if published_at is None:
        raise PolicyTransparencyError("POLICY", "The signed policy has no published_at time.")
    assert signed_at is not None
    if (published_at - signed_at).total_seconds() > PUBLISHED_AT_FUTURE_TOLERANCE_SECONDS:
        raise PolicyTransparencyError("POLICY", "The policy claims to be published after it was signed.")
    floor_time = _parse_time((floor or {}).get("signedAt"))
    if floor_time and signed_at < floor_time:
        raise PolicyTransparencyError("ROLLBACK", "The policy is older than the minimum this release accepts.")
    pinned = _parse_time((pin or {}).get("signedAt"))
    if pin and pinned:
        if signed_at < pinned:
            raise PolicyTransparencyError("ROLLBACK", f"The policy was signed {verification['signedAt']}, before the policy already accepted here ({pin['signedAt']}).")
        if signed_at == pinned and pin.get("sha256") != verification["sha256"]:
            raise PolicyTransparencyError("ROLLBACK", "A different policy carries the same signing time as the accepted one.")
        pinned_published = _parse_time(pin.get("publishedAt"))
        if signed_at > pinned and pinned_published and published_at < pinned_published:
            raise PolicyTransparencyError("ROLLBACK", "A newer signature covers a policy with an older published_at than the accepted one.")
    log = verification["log"][0] if verification.get("log") else {}
    return {
        "signed": True,
        "sha256": verification["sha256"],
        "signedAt": verification["signedAt"],
        "publishedAt": policy["published_at"],
        "logIndex": log.get("logIndex"),
        "logId": log.get("logId"),
    }


def _pin_file(state_dir: os.PathLike[str] | str) -> Path:
    return Path(state_dir) / "policy-pins.json"


def read_pins(state_dir: Optional[os.PathLike[str] | str]) -> dict[str, Any]:
    if not state_dir:
        return {}
    try:
        text = _pin_file(state_dir).read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    try:
        pins = json.loads(text)
    except ValueError:
        pins = None
    if not isinstance(pins, dict):
        # A pin file that cannot be read is not the same as no pin.
        raise PolicyTransparencyError("PIN", f"The policy pin file is damaged: {_pin_file(state_dir)}. Remove it only if you accept re-pinning the published policy.")
    return pins


def write_pins(state_dir: os.PathLike[str] | str, pins: Mapping[str, Any]) -> None:
    directory = Path(state_dir)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    handle, temporary = tempfile.mkstemp(dir=directory, prefix="policy-pins.", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(pins, indent=2) + "\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, _pin_file(directory))
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


Fetcher = Callable[[str], Optional[bytes]]


def _https_get(timeout: float) -> Fetcher:
    def fetch(url: str) -> Optional[bytes]:
        request = urllib.request.Request(url, headers={"Accept": "application/json", "Cache-Control": "no-cache"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read(MAX_DOCUMENT_BYTES + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise
        if len(body) > MAX_DOCUMENT_BYTES:
            raise PolicyTransparencyError("FETCH", "A published policy document is larger than expected.")
        return body

    return fetch


def fetch_signed_policy(
    url: str,
    *,
    state_dir: Optional[os.PathLike[str] | str] = None,
    mode: Optional[str] = None,
    signer: Mapping[str, str] = PRODUCTION_SIGNER,
    trusted_root: str | os.PathLike[str] = BUNDLED_TRUSTED_ROOT,
    floor: Optional[Mapping[str, str]] = POLICY_FLOOR,
    fetch: Optional[Fetcher] = None,
    timeout: float = 15.0,
    decode: Callable[[bytes], Any] = json.loads,
) -> dict[str, Any]:
    """Fetch ``url`` and ``url + ".sigstore.json"``, verify, apply rollback
    protection and advance the pin in ``state_dir``.

    ``fetch(url)`` returns the body, or ``None`` for "not published" (404).
    Returns ``{"policy", "bytes", "status", "reason", "verification", "mode",
    "warnings"}``; status is "signed", or in warn mode "unsigned" or
    "unverifiable". Enforce mode raises instead of returning those two.
    """
    mode = mode or transparency_mode()
    if mode not in ("warn", "enforce"):
        raise PolicyTransparencyError("CONFIG", "Unknown policy transparency mode.")
    enforce = mode == "enforce"
    fetch = fetch or _https_get(timeout)
    warnings: list[str] = []
    pins: dict[str, Any] = {}
    pins_usable = True
    try:
        pins = read_pins(state_dir)
    except PolicyTransparencyError as exc:
        if enforce:
            raise
        pins_usable = False
        warnings.append(str(exc))
    pin = pins.get(url)
    verification = None
    status, reason = "unsigned", ""
    policy: Any = None
    policy_bytes = b""
    for attempt in (0, 1):
        verification = None
        try:
            body = fetch(url)
        except PolicyTransparencyError:
            raise
        except Exception as exc:
            raise PolicyTransparencyError("FETCH", "Could not fetch the published policy.") from exc
        if body is None:
            raise PolicyTransparencyError("FETCH", "Could not fetch the published policy (404).")
        policy_bytes = body
        try:
            policy = decode(policy_bytes)
        except ValueError as exc:
            raise PolicyTransparencyError("POLICY", "The published policy is not valid JSON.") from exc
        try:
            bundle = fetch(url + BUNDLE_SUFFIX)
            reason = "not published (404)" if bundle is None else ""
        except PolicyTransparencyError:
            raise
        except Exception as exc:
            bundle, reason = None, f"unreachable ({exc})"
        if bundle is None:
            if enforce:
                raise PolicyTransparencyError("UNSIGNED", f"The published policy has no transparency signature ({reason}); it is refused because policy transparency is enforced.")
            warnings.append(f"The published policy has no transparency signature ({reason}). It is used on HTTPS trust alone; a later release will refuse it.")
            break
        try:
            verification = verify_policy_signature(policy_bytes, bundle, signer=signer, trusted_root=trusted_root)
            next_pin = check_not_rolled_back(policy, verification, pin, floor)
            if state_dir and pins_usable and (not pin or pin.get("sha256") != next_pin["sha256"] or pin.get("signedAt") != next_pin["signedAt"]):
                write_pins(state_dir, {**pins, url: next_pin})
            status = "signed"
            break
        except PolicyTransparencyError as exc:
            # The two documents are separate requests; a deploy between them
            # looks like a signature over other bytes. Retry both once.
            if attempt == 0 and exc.code == "SIGNATURE":
                continue
            if enforce:
                raise
            status, reason = "unverifiable", str(exc)
            warnings.append(f"The published policy's transparency signature was NOT accepted: {exc} The policy is still used because policy transparency is in warn mode.")
            break
    return {"policy": policy, "bytes": policy_bytes, "status": status, "reason": reason, "verification": verification, "mode": mode, "warnings": warnings}

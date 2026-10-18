# adverserial (Python)

Client-side verification SDK for Adverserial confidential-inference
endpoints. See the [root README](../README.md) for the protocol and threat
model. Dependencies: Python ≥ 3.10, stdlib + `cryptography` only.

```python
from adverserial import verify_endpoint, VerifiedSession

proof = verify_endpoint(
    "https://host/v1",
    expected_model_id="lordx64/cyberglm",
    trusted_receipt_keys={kid: jwk},
    issuer="https://verify.adverserial.ai",
    audience="https://chat.adverserial.ai",
    hardware_verifier=verify_hardware_evidence,
)
session = VerifiedSession("https://host/v1", proof=proof, entitlement="<short-lived-JWS>")
resp = session.chat_completions(messages=[{"role": "user", "content": "hi"}])
```

- `verify_endpoint(...)` → `VerifiedProof` or raises `VerificationError`.
- `VerifiedSession` pins TLS to `proof.tls_spki_sha256`; a substituted
  certificate raises `TLSPinMismatchError` before any request bytes are sent.
- `proof.dev_mode == True` means synthetic evidence: plumbing, not hardware.
- CLI: `python -m adverserial verify …` → see `--help`.

## Hardware evidence is mandatory

`hardware_verifier` is required. It must independently verify the raw TEE and
GPU evidence against your pinned policy; the endpoint's signed receipt is not
hardware proof by itself. The callback makes the SDK model- and GPU-agnostic:
it receives `(evidence, nonce, expected_model_id, expected_endpoint)` and must
return `HardwareVerification(verified=True, verifier="...")`. Deployments
should provide a reviewed vendor-verifier adapter, such as a DCAP-QVL/TDX
verifier paired with the applicable GPU-attestation verifier.

## Official hardware-verifier runner

Install the Python package and configure `adverserial-hardware-verify` as the
gateway's `ADVERSERIAL_HARDWARE_VERIFIER_COMMAND`. It requires two absolute,
independently reviewed adapter paths: `ADVERSERIAL_TDX_VERIFIER_COMMAND` and
`ADVERSERIAL_GPU_VERIFIER_COMMAND`. Before either adapter runs, the runner
recomputes TDX `report_data = SHA-256(nonce || TLS-SPKI-DER || receipt-SPKI-DER)
|| 32 zero bytes`, validates the TLS public-key fingerprint, and canonicalizes
the TDX event log and GPU-evidence digests. It accepts only adapter outputs
that return those exact bindings. It rejects DEV_MODE and missing evidence.

Adapters are deployment-specific by design; the package does not substitute a
proxy receipt for Intel TDX/DCAP and GPU vendor verification. Their JSON input
is documented in `adverserial.hardware_verifier`; a real production adapter
must return a non-empty `verifier` name/version plus the verified binding
fields.

## Per-request receipts (WP-7)

Every chat completion through the proxy carries a signed enclave receipt
binding *this exact exchange* to the attested runtime — hashes only, never
content. Delivery: `X-Adverserial-Receipt` header on non-streaming responses;
a final `data: {"adverserial_receipt": "<jws>"}` SSE chunk just before the
upstream `[DONE]` on streams (upstream chunks are never dropped or
reordered).

```python
resp = session.chat_completions(messages=[...])              # non-stream
resp.receipt_verified   # True — receipt present and all checks passed
resp.receipt_claims     # verified claim dict (see below)

stream = session.chat_completions(messages=[...], stream=True)
for event in stream:    # content chunks
    ...
stream.receipt_verified # set when the stream ends ([DONE])
stream.receipt_claims
```

The session verifies, when a receipt is present: ES256 signature against the
attestation-proven receipt key (`proof.receipt_jwk`, thumbprint-checked
against the attestation receipt's `kid`); `request_nonce` echo (the SDK sends
a fresh `X-Adverserial-Nonce` per request; a server-generated nonce is
accepted when the client sent none); `request_body_hash` against the exact
bytes sent; `response_hash` against the exact bytes received (for streams:
SHA-256 over the concatenated SSE data payloads — one leading space after
`data:` stripped, `[DONE]` included, receipt chunk excluded); `model_id`,
`policy_id`, `iss`/`aud`; `exp`/`iat` freshness; and
`attestation_binding.tls_spki_sha256` against the live TLS pin. Any failure
raises `VerificationError` — for streams it raises at end-of-iteration, after
the content chunks (treat that as "the exchange failed verification"). A
missing receipt is not fatal: `receipt_verified` is `False`.

Receipt claims: `v:1`, `iss`, `aud`, `request_nonce`, `request_body_hash`,
`response_hash`, `model_id`, `policy_id`,
`attestation_binding: {tls_spki_sha256, evidence_digest}`, `iat`,
`exp` (iat+120 s), and `usage {input_tokens, cached_tokens, output_tokens}`
when the runtime reported usage.

## Tests

```sh
python -m pytest tests            # or: python -m unittest discover -s tests
```

`tests/fixture_server.py` is a threaded `http.server` speaking the real
protocol (self-signed TLS cert, ES256 receipts minted with `cryptography`,
canonical-JSON digests pinned against the TS/Go test vector in
attest-proxy `internal/canonjson/canonjson_test.go`).

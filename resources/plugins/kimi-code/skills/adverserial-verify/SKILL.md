---
name: adverserial-verify
description: Verify the attestation (TDX evidence + ES256 verification receipt) of the Adverserial confidential inference endpoint before trusting it with code, secrets, or prompts. Use when the user asks to verify or check the endpoint, asks about attestation/dev_mode, or wants to know whether it is currently safe to send data to the Adverserial API.
---

# Adverserial endpoint attestation

This plugin ships `adverserial-verify`, a small CLI that verifies the
attestation of the Adverserial confidential inference endpoint
(`ADVERSERIAL_API_URL`, default `https://api.adverserial.ai/v1`) using the
`@adverserial/sdk` verifier: it fetches fresh nonce-bound TDX evidence,
checks the ES256 verification receipt against pinned receipt keys, and binds
the receipt to the canonical evidence digest.

## How to run it

Via Bash (installed plugin — the managed copy):

```sh
node "$KIMI_CODE_HOME/plugins/managed/adverserial-verify/bin/adverserial-verify"
```

or from a source checkout of `adverserial-sdk`:

```sh
node /path/to/adverserial-sdk/plugins/kimi-code/bin/adverserial-verify
```

A `SessionStart` hook already runs this once per session when the plugin is
enabled; re-run it on demand whenever the user asks, or when the cached
verdict may be stale (the receipt TTL is minutes-scale). For a cheap
network-free check of the last result:

```sh
node …/bin/adverserial-verify --status      # cached verdict + age, exit 1 when stale
```

Exit codes: `0` = verified, `1` = failed / unpinned / stale / error.

## How to read the verdict

- `VERIFIED` — receipt signature, nonce binding, issuer/audience, model id,
  and evidence digest all checked out against **pinned** receipt keys.
- `VERIFIED — UNPINNED (TOFU dev mode)` — the receipt key was
  trust-on-first-use bootstrapped from the evidence itself
  (`--trust-evidence-key` / `ADVERSERIAL_TRUST_EVIDENCE_KEY=1`). This is a
  development convenience, not a security boundary: anyone terminating TLS
  could present that key. Never treat it as production-grade.
- `UNVERIFIED — no trusted receipt keys configured` — the tool refused to
  claim "verified". Pin keys via `ADVERSERIAL_RECEIPT_KEYS_JSON` or
  `ADVERSERIAL_RECEIPT_KEYS_FILE`. Production deployments pin the key set
  published at https://verify.adverserial.ai.
- `FAILED` — verification ran and was rejected; the `reason` line says why.

Two warnings matter when they appear:

- `dev_mode evidence (dev=true)` — the TDX quote is synthetic; the proof
  covers the plumbing (signatures, nonce, digests), NOT the hardware. Do not
  rely on it for confidentiality.
- `TLS certificate validation is DISABLED…` — loopback TOFU dev mode against
  a self-signed attest-proxy.

## Configuration (environment)

| Variable | Default | Purpose |
| --- | --- | --- |
| `ADVERSERIAL_API_URL` | `https://api.adverserial.ai/v1` | Endpoint base URL |
| `ADVERSERIAL_MODEL` | `lordx64/cyberglm` | Expected receipt `model_id` |
| `ADVERSERIAL_ISSUER` | `https://verify.adverserial.ai` | Expected receipt `iss` |
| `ADVERSERIAL_AUDIENCE` | `https://chat.adverserial.ai` | Expected receipt `aud` |
| `ADVERSERIAL_EXPECTED_ENDPOINT` | unset | Also pin the receipt `endpoint` claim |
| `ADVERSERIAL_RECEIPT_KEYS_JSON` | unset | Pinned keys: JSON map kid → public JWK |
| `ADVERSERIAL_RECEIPT_KEYS_FILE` | unset | Path to a JSON file with that map |
| `ADVERSERIAL_TRUST_EVIDENCE_KEY` | unset | `=1` enables the TOFU dev escape hatch |
| `ADVERSERIAL_CACHE_FILE` | `~/.cache/adverserial/verify.json` | `--status` cache location |

## Rules for the agent

- If the user is about to paste secrets, proprietary code, or customer data
  for the endpoint and no fresh `VERIFIED` verdict exists, offer to run the
  check first.
- Never paraphrase a FAILED or UNPINNED verdict as "verified". Report the
  exact status line.
- A `VERIFIED` verdict with the `dev_mode` warning is a plumbing proof only;
  say so.

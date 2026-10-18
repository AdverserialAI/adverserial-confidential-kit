---
name: adverserial-verify
description: Verify the attestation (TDX evidence + ES256 verification receipt) of the Adverserial confidential inference endpoint before trusting it with code, secrets, or prompts. Use when the user asks to verify or check the endpoint, asks about attestation/dev_mode, or wants to know whether it is currently safe to send data to the Adverserial API.
---

# Adverserial endpoint attestation

Verify the Adverserial confidential inference endpoint with the
`adverserial-verify` CLI: it fetches fresh nonce-bound TDX evidence, checks
the ES256 verification receipt against pinned receipt keys, and validates the
NVIDIA GPU EAT bundle through an independent hardware verifier.

## How to run it

The CLI is installed by the Adverserial SDK checkout:

```sh
node "$ADVERSERIAL_SDK/plugins/kimi-code/bin/adverserial-verify"
```

If the user installed the npm-bin wrapper, plain `adverserial-verify` also
works. For a network-free check of the last verdict:

```sh
node "$ADVERSERIAL_SDK/plugins/kimi-code/bin/adverserial-verify" --status
```

Exit codes: `0` = verified, `1` = failed / unpinned / stale / error.

## How to read the verdict

- `VERIFIED` with pinned receipt keys: the endpoint matched the published
  policy, fresh TDX + NVIDIA evidence, and the receipt key set.
- `UNPINNED (TOFU dev mode)`: plumbing proof only — never present it as
  verified and never send sensitive content.
- Any failure: the endpoint is unverified; do not send prompts, code,
  secrets, or customer data. Report the reason line verbatim.

If verification fails, show the error and stop. Do not retry with weaker
checks, do not suggest bypass flags, and do not treat a cached `VERIFIED`
older than its TTL as current.

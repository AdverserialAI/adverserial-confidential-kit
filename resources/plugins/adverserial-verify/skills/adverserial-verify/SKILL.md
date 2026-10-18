---
name: adverserial-verify
description: Verify an Adverserial confidential-inference endpoint before configuring or using it from Codex.
---

# Adverserial Verify

Use this skill when the user asks Codex to use, configure, or assess an Adverserial confidential endpoint. Users can invoke it explicitly with `$adverserial-verify`.

1. Run the bundled verifier before sending a prompt to a confidential endpoint. First use `adverserial-verify` if it is on `PATH`. Otherwise find the plugin bundle at `${CODEX_HOME:-$HOME/.codex}/plugins/cache/adverserial/adverserial-verify/*/bin/adverserial-verify.mjs` and run it with `node`. It must emit a fresh, pinned hardware-verified verdict; do not infer a result from cached prose or a proxy response.
2. A successful result requires all three checks: a pinned receipt key, fresh endpoint evidence, and an independent hardware verifier. Never treat TOFU, synthetic `dev=true` evidence, a proxy receipt by itself, or a missing hardware verifier as a verified TEE.
3. If verification fails, explain the failed check and do not present the endpoint as confidential. The user can still explicitly choose the normal `https://api.adverserial.ai/v1` service, which is separate from the confidential route.
4. Use canonical model IDs only: `lordx64/cyberglm` and `lordx64/cyberkimi`.
5. Keep API keys local. The confidential local gateway sends an API key to `billing.adverserial.ai` only to obtain a five-minute single-request entitlement. It must forward the entitlement, never the API key, to `api.adverserial.ai`.

## Required local configuration

Set these values before verification:

```sh
export ADVERSERIAL_API_URL='https://api.adverserial.ai/v1'
export ADVERSERIAL_MODEL='lordx64/cyberglm'
export ADVERSERIAL_RECEIPT_KEYS_FILE="$HOME/.config/adverserial/receipt-keys.json"
export ADVERSERIAL_HARDWARE_VERIFIER_COMMAND='/absolute/path/to/adverserial-hardware-verify'
```

The key file and hardware verifier must come from the signed, published policy at `https://verify.adverserial.ai`. Do not substitute an untrusted URL or a shell command.

## Security reporting

Please report security vulnerabilities privately to [security@adverserial.ai](mailto:security@adverserial.ai).

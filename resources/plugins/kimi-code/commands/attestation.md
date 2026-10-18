---
description: Verify the Adverserial confidential endpoint attestation and show the verdict
---

Run a fresh Adverserial attestation check and report the result:

1. Execute `node "$KIMI_PLUGIN_ROOT/bin/adverserial-verify"` (it prints a verdict table; exit 0 = verified, 1 = not).
2. Show the user the verdict table verbatim, then one sentence of interpretation.
3. Never paraphrase a failed, stale, or UNPINNED (TOFU) verdict as verified. If it fails, show the reason line and stop.
4. If the user passed arguments ($ARGUMENTS), treat them as a question about the verdict (e.g. "explain", "json") and answer from the CLI output (`--json` for raw fields).

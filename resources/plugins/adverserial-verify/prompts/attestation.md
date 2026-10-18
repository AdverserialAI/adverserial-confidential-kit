---
description: Verify the Adverserial confidential endpoint attestation and show the verdict
argument-hint: [explain | json]
---

Run a fresh Adverserial attestation check and report the result:

1. Run the verifier CLI: `adverserial-verify` when it is on PATH, otherwise `node <checkout>/plugins/kimi-code/bin/adverserial-verify` from a built confidential-sdk checkout (`npm install && npm run build` in its `plugins/` directory). It prints a verdict table; exit 0 = verified, 1 = not.
2. Show the user the verdict table verbatim, then one sentence of interpretation.
3. Never paraphrase a failed, stale, or UNPINNED (TOFU) verdict as verified. If it fails, show the reason line and stop. A proxy receipt alone is not hardware proof: a genuine VERIFIED verdict also requires pinned receipt keys and the independent verifier named by ADVERSERIAL_HARDWARE_VERIFIER_COMMAND.
4. If the user passed arguments ($ARGUMENTS), treat them as a question about the verdict (e.g. "explain", "json") and answer from the CLI output (`--json` for raw fields).

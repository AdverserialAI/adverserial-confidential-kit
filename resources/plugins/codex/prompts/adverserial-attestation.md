---
description: Run a fresh Adverserial confidential-runtime attestation check
argument-hint: [explain | json]
---

Run a fresh verification before claiming that the Adverserial confidential
runtime is safe for sensitive prompts.

Use the ACK launcher installed for this session:

```sh
"$ADVERSERIAL_ACK_CLI" attestation
```

If the user supplied `json`, append `--json`. Report the terminal verdict
exactly. A nonzero result, stale evidence, missing pinned receipt keys, or a
hardware-verifier failure means the runtime is **not verified**. Never expose
an API key, receipt, or prompt content.

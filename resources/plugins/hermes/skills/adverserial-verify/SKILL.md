---
name: adverserial-verify
description: Run a fresh pinned Adverserial confidential-runtime attestation check.
---

Run exactly this command using the shell tool:

```sh
node "$ADVERSERIAL_ACK_CLI" attestation
```

Report the exact verdict, endpoint, expected model, policy, evidence digest, expiry and trust state. A failed, stale, dev-mode or unpinned result is not verified. Never bypass verification or expose API keys. This command is installed by ACK; do not search PATH or invent a different location.

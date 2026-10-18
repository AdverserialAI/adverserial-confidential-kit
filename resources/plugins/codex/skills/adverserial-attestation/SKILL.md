---
name: adverserial-attestation
description: Verify the Adverserial confidential runtime before sensitive coding work or when the user asks for its attestation status.
---

Run a fresh verification with:

```sh
"$ADVERSERIAL_ACK_CLI" attestation
```

If `ADVERSERIAL_ACK_CLI` is unavailable, run:

```sh
node "$ADVERSERIAL_ACK_CLI" attestation
```

Report the terminal verdict exactly and do not claim the confidential runtime is verified if the command fails. The verification checks pinned receipt keys, the published policy, TEE and GPU evidence, the TLS binding, and the runtime receipt key. Never print API keys or copy their values into output.

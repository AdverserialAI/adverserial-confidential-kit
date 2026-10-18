# Pi confidential-inference extension

This Pi extension runs a fresh `adverserial-verify` check before registering
`adverserial-confidential/lordx64/cyberglm`. If the check fails, the model is
not registered. Once selected, Pi uses its normal OpenAI-compatible streaming
and tool loop against the loopback gateway. The gateway obtains a one-use
entitlement, verifies the live attestation and direct TLS binding, and accepts
an inference only when its signed receipt verifies.

## Install

Install the SDK verifier and start the local gateway first:

```sh
pip install ./python ./gateway
export ADVERSERIAL_RECEIPT_KEYS_FILE="$HOME/.config/adverserial/receipt-keys.json"
export ADVERSERIAL_HARDWARE_VERIFIER_COMMAND="/absolute/path/to/adverserial-hardware-verify"
export ADVERSERIAL_API_KEY='sk-…'
adverserial-confidential-gateway
```

Then launch Pi with the extension:

```sh
pi --extension /absolute/path/to/confidential-sdk/plugins/pi/adverserial-confidential.ts \
  --model adverserial-confidential/lordx64/cyberglm
```

The extension runs its checked-in verifier bundle with Node by default. To
use another verifier executable, set `ADVERSERIAL_VERIFY_COMMAND` to an
**absolute** executable path. Relative commands and `PATH` lookup are
intentionally rejected so a project checkout cannot replace the verifier.
The extension never stores or forwards the API key itself. Pi sends it only to
`127.0.0.1`; the gateway exchanges it with billing for a one-use entitlement.

Use `/adverserial-verify` or the `adverserial_verify` tool to force a fresh
attestation check during a session.

## Local swarm coordination

When Pi is launched through `ack code pi`, the extension also exposes
`adverserial_swarm_inbox` and `adverserial_swarm_post`. They coordinate with
tasks explicitly created by `ack swarm`:

```sh
ack swarm create review
ack swarm invite --to pi "Review the gateway cancellation path."
```

Pi can read the task with `adverserial_swarm_inbox`, then post a concise result
back to Claude or every participant with `adverserial_swarm_post`. The shared
room contains only messages deliberately added to it; it never copies a
harness’s private conversation or credentials.

Please report security vulnerabilities privately to security@adverserial.ai.

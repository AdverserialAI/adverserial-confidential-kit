# Hermes Agent — Adverserial confidential inference

Use CyberGLM through the Adverserial confidential gateway from
[Hermes Agent](https://hermes-agent.nousresearch.com) (CLI, TUI, and desktop
all read `~/.hermes/config.yaml`), plus an optional skill that lets the agent
verify the endpoint's attestation on request.

## 1. Route Hermes through the confidential gateway

Start the loopback gateway first (see the repo-root README: it verifies the
endpoint, exchanges your billing key for one-use entitlements, and encrypts
every request to the enclave):

```sh
adverserial-confidential-gateway   # listens on http://127.0.0.1:8787
```

Then declare a model alias in `~/.hermes/config.yaml`:

```yaml
model_aliases:
  cyberglm:
    model: lordx64/cyberglm
    provider: custom
    base_url: "http://127.0.0.1:8787/v1"
    key_env: ADVERSERIAL_API_KEY
```

with `ADVERSERIAL_API_KEY` set to your Adverserial billing key (`sk-…`) in the
environment. The key stays on your machine; the enclave receives only a
short-lived, single-request entitlement.

Use it in a session:

```text
/model cyberglm
```

or make it the default main model with `hermes model` (pick the custom
provider entry) or via `hermes config set`.

The same ready-to-merge configuration is available at
[`../../profiles/hermes.confidential.yaml`](../../profiles/hermes.confidential.yaml).
Hermes speaks OpenAI Chat Completions to the loopback gateway; tool turns are
carried as standard `tool_calls` and `tool` messages, then each completed
stream is accepted only after its runtime receipt verifies.

## 2. Optional: attestation skill

Hermes auto-discovers skills from `~/.hermes/skills/`:

```sh
mkdir -p ~/.hermes/skills/adverserial-verify
cp skills/adverserial-verify/SKILL.md ~/.hermes/skills/adverserial-verify/
```

The skill expects the verifier CLI from a confidential-sdk checkout; point
`ADVERSERIAL_SDK` at that checkout (the directory containing `plugins/`):

```sh
export ADVERSERIAL_SDK=/absolute/path/to/confidential-sdk
```

The CLI also needs the pinned receipt keys and the hardware verifier (see the
repo-root README): `ADVERSERIAL_RECEIPT_KEYS_FILE` and
`ADVERSERIAL_HARDWARE_VERIFIER_COMMAND` (the SDK ships
`typescript/bin/adverserial-hardware-verify.mjs` for the current Phala TDX +
NVIDIA deployment).

Then ask the agent to "verify the Adverserial endpoint" — the skill runs the
CLI and reports the verdict. A failed or unpinned verdict means do not send
content.

# Hermes Agent — Adverserial confidential inference

> **Bundled copy.** `ack code hermes` installs and configures this integration
> for you; the manual steps below are for using it without ACK. Paths such as
> `plugins/…`, `profiles/…` and `typescript/…` refer to the
> [confidential-sdk](https://github.com/AdverserialAI/confidential-sdk) layout;
> in this repository the same files live under `resources/`, and the hardware
> verifier is `resources/typescript/adverserial-hardware-verify.mjs`. The
> production model is `adverserial/cyberseek`. The published policy is fetched
> over HTTPS and is not signed; only the receipt keys are pinned locally. See
> [what ACK verifies and what it does not](../../../README.md#what-ack-verifies-and-what-it-does-not).

Use CyberSeek through the Adverserial confidential gateway from
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
  cyberseek:
    model: adverserial/cyberseek
    provider: custom
    base_url: "http://127.0.0.1:8787/v1"
    key_env: ADVERSERIAL_API_KEY
```

with `ADVERSERIAL_API_KEY` set to your Adverserial billing key (`sk-…`) in the
environment. The key stays on your machine; the enclave receives only a
short-lived, single-request entitlement.

Use it in a session:

```text
/model cyberseek
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

The bundled skill runs `node "$ADVERSERIAL_ACK_CLI" attestation`.
`ack code hermes` sets `ADVERSERIAL_ACK_CLI` to the installed ACK launcher,
which supplies the pinned receipt keys and the hardware verifier
(`resources/typescript/adverserial-hardware-verify.mjs`, for the current
Phala TDX + NVIDIA deployment). Without ACK, set `ADVERSERIAL_ACK_CLI` to the
absolute path of `bin/ack.mjs` in an initialized ACK installation.

Then ask the agent to "verify the Adverserial endpoint" — the skill runs the
CLI and reports the verdict. A failed or unpinned verdict means do not send
content.

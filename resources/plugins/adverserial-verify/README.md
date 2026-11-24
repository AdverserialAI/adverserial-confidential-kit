# Adverserial Verify — Codex plugin

> **Bundled copy.** `ack code codex` installs and configures this integration
> for you; the manual steps below are for using it without ACK. Paths such as
> `plugins/…`, `profiles/…` and `typescript/…` refer to the
> [confidential-sdk](https://github.com/AdverserialAI/confidential-sdk) layout;
> in this repository the same files live under `resources/`, and the hardware
> verifier is `resources/typescript/adverserial-hardware-verify.mjs`. The
> production model is `adverserial/cyberseek`. The published policy is fetched
> over HTTPS and is not signed; only the receipt keys are pinned locally. See
> [what ACK verifies and what it does not](../../../README.md#what-ack-verifies-and-what-it-does-not).

Verify the attestation of the Adverserial confidential inference endpoint
before trusting it with code, secrets, or prompts from
[Codex](https://developers.openai.com/codex) (Codex CLI and the Codex
desktop app — both share `~/.codex`).

A proxy receipt is not hardware proof. The bundled skill requires all three
checks before the endpoint may be called confidential: receipt keys pinned
from the policy published at `https://verify.adverserial.ai`, fresh nonce-bound
endpoint evidence that matches that policy, and an independent TDX/GPU verifier
named by
`ADVERSERIAL_HARDWARE_VERIFIER_COMMAND`. Missing any one of these is a
failure, never a "verified" result.

## Layout

```
adverserial-verify/
├── .codex-plugin/plugin.json         # Codex plugin manifest (skill)
├── skills/adverserial-verify/SKILL.md
└── prompts/attestation.md            # custom prompt → /prompts:attestation
```

## Install in Codex

Install the public GitHub marketplace, then add the plugin:

```sh
codex plugin marketplace add AdverserialAI/confidential-sdk --ref main
codex plugin add adverserial-verify@adverserial
```

Restart Codex so it loads the installed skill. In a chat, invoke
`$adverserial-verify` to request a fresh attestation check. This is the
supported command surface: Codex skills are the replacement for the older
custom-prompt slash-command mechanism.

The plugin includes the verifier executable. `$adverserial-verify` finds and
runs the installed bundle automatically. To run it directly from a repository
checkout, use:

```sh
plugins/adverserial-verify/bin/adverserial-verify
```

The command must produce a pinned, hardware-verified result before Codex
treats the endpoint as confidential.

## Legacy slash prompt

Custom prompts live in the Codex home directory and become slash commands
named after the file. Install once for both Codex CLI and the Codex desktop
app:

```sh
mkdir -p ~/.codex/prompts
cp prompts/attestation.md ~/.codex/prompts/
```

Restart Codex (new CLI session, or reopen the app chat) so it loads the
file, then invoke it as `/prompts:attestation`. It runs the verifier CLI and
reports the verdict table verbatim — a failed or UNPINNED (TOFU) verdict is
never paraphrased as verified. Use this only where an older Codex install does
not yet support skills.

Notes:

- The bundled `adverserial-verify` skill is the preferred explicit command
  (`$adverserial-verify`) and is also invoked implicitly for confidential
  endpoint setup.
- Some desktop builds have a known issue surfacing `~/.codex/prompts` files
  in the slash menu; the CLI is unaffected, and the skill works regardless.

## The skill

`skills/adverserial-verify/SKILL.md` teaches Codex the verification policy:
run the locally installed `adverserial-verify` CLI before using a
confidential endpoint, never treat TOFU mode, synthetic `dev=true` evidence,
a proxy receipt by itself, or a missing hardware verifier as a verified TEE,
and keep API keys local (the confidential gateway exchanges them for a
five-minute single-request entitlement at `billing.adverserial.ai` and
forwards only the entitlement).

The verifier CLI itself is built from this repository's plugins workspace
(`npm install && npm run build` in `plugins/`, then
`plugins/kimi-code/bin/adverserial-verify`; put it on PATH as
`adverserial-verify` for the smoothest experience).

## Send Codex through the confidential gateway

Copy [`../../profiles/codex.confidential.toml`](../../profiles/codex.confidential.toml)
to `~/.codex/confidential.config.toml` and start Codex with the profile after
the local gateway is running:

```sh
codex --profile confidential
```

The profile uses the native Responses endpoint and disables OpenAI-account
fallback for this model. It pins every request to `adverserial/cyberseek`; Codex
must not substitute an OpenAI model alias. The gateway preserves Responses
function calls and function-call outputs, streams function-argument events,
obtains a one-use billing entitlement, and requires the final runtime receipt
before a turn can complete.

## Environment

```sh
export ADVERSERIAL_API_URL='https://api.adverserial.ai/v1'             # default
export ADVERSERIAL_MODEL='adverserial/cyberseek'                       # default
export ADVERSERIAL_RECEIPT_KEYS_FILE="$HOME/.config/adverserial/receipt-keys.json"
export ADVERSERIAL_HARDWARE_VERIFIER_COMMAND='/absolute/path/to/adverserial-hardware-verify'
```

The keys file is a JSON object mapping key id → public EC P-256 JWK. The key
set comes from the policy published at
`https://verify.adverserial.ai/policies/production.json` (`ack init` and
`ack upgrade` write the file). That policy is served over HTTPS and is not
signed. The shipped `resources/typescript/adverserial-hardware-verify.mjs` in
this repository is the reference hardware verifier. Do not substitute an untrusted URL or a shell command.

## Security reporting

Please report security vulnerabilities privately to
[security@adverserial.ai](mailto:security@adverserial.ai).

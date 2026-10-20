<div align="center">

# ACK · Adverserial Confidential Kit

### Your coding agents. One confidential console.

[![Version](https://img.shields.io/badge/ACK-0.2.5-12b8a6)](package.json)
[![Runtime](https://img.shields.io/badge/Node.js-18%2B-43853d)](package.json)
[![Platform](https://img.shields.io/badge/key_vault-Keychain_%7C_Windows_DPAPI-555)](#requirements)
[![License](https://img.shields.io/badge/license-proprietary_source--available-6845bd)](LICENSE)

[Website](https://adverserial.ai) · [How confidentiality works](https://adverserial.ai/confidential/) · [Verify a runtime](https://verify.adverserial.ai) · [SDK](https://github.com/AdverserialAI/confidential-sdk) · [Security](mailto:security@adverserial.ai)

</div>

ACK prepares and manages the local confidential gateway, stores named API keys
in an encrypted vault, and connects your preferred coding harness to verified
Adverserial inference. Run it as a colorful interactive console or use ordinary
shell commands.

![ACK Confidential Console, version 0.2.3](docs/console-home.png)

**New in 0.2.5:** checks the hardware-verifier dependencies before launching a
coding session. Pi and Oh My Pi footers expire with the proof and clear their
verified state after a gateway verification failure. Linked source installations
must run `npm ci` in the checkout; `ack doctor` checks that the verifier can load.

**New in 0.2.4:** Hermes launches with its current supported CLI options; the
local URL comes from its isolated provider configuration. Failed native launches
keep their diagnostic output visible until you press Enter or Escape.

**New in 0.2.3:** run coding sessions in multiple terminal windows. Each session
gets its own local gateway and connection settings; closing one leaves the others
running. Runtime installation is coordinated across simultaneous launches.

[Get started on the website](https://adverserial.ai/documentation) ·
[Release validation](docs/TESTING.md)

## Install → initialize → code

Install the current public GitHub source:

```sh
npm install -g github:AdverserialAI/adverserial-confidential-kit
ack init
ack code
```

Enter your Adverserial API key when prompted. Input is masked. ACK fetches the
active verification policy, pins its receipt keys and installs an isolated
Python gateway runtime. Choose an installed harness and start working.

Run `ack` to open the full-screen console. Inside it, use `init`, `code`,
`models`, `keys`, `attestation` or the searchable command palette.

Once an npm registry release is published, the equivalent install command is
`npm install -g adverserial-confidential-kit`. The GitHub command above works
without waiting for that release.

### Requirements

- **macOS or Windows** for encrypted key storage through Keychain or Windows
  DPAPI (bound to your Windows account). Linux credential storage is not yet implemented.
- **Node.js 18+**, npm and **Python 3.10+** on PATH.
- An Adverserial API key with access to a currently published confidential model.
- The official CLI for each harness you want to use. ACK detects installed
  binaries and reports missing ones; it does not install every agent for you.
- Network access for installation, published policy, independent hardware
  verification, billing entitlements and confidential inference.

ACK keeps its own runtime under `~/.config/adverserial/venv`; it does not replace
your normal Python environment. Existing harness executables are reused. An upstream harness may show its own
first-run theme or workspace-trust dialog; ACK does not bypass those choices.

On Windows, run the same `ack init` and `ack code claude` / `ack code codex`
commands from PowerShell or Windows Terminal. ACK recognizes native `.exe`
launchers and npm `.cmd` shims, including per-user npm and `.local/bin` installs.
It also finds the CLI bundled under `%LOCALAPPDATA%/OpenAI/Codex/bin` when no
standalone Codex CLI is on PATH. `ack code codex` opens a CLI session; it does
not change the provider of an already-open desktop chat. Use `ack harnesses`
to see the selected executable, or `ACK_CODEX_BIN` / `ACK_CLAUDE_BIN` (and the
corresponding override for other harnesses) to choose a specific installation.

Windows settings default to `%USERPROFILE%/.config/adverserial` when `HOME`
is unset; `ACK_HOME` still overrides this location. The `storage-key.dpapi`
file contains only the Windows-protected storage key. Keep it with `ack.json`
when backing up the vault; it is not portable to a different Windows account.
Older Codex versions without `plugin add` use the bundled local attestation
skill. Other harnesses still require an upstream CLI that supports your OS.

## The Confidential Console

| Control | What it does |
| --- | --- |
| `/` or Ctrl+P | Search the command palette. |
| `code` or F2 | Search, number-select or arrow-select an installed coding harness. |
| `models` or F3 | Browse the public registry and activate a model with its matching active policy. |
| `keys` or F4 | Add, replace, activate and delete encrypted named API-key profiles. |
| `attestation` or F5 | Run a fresh independent hardware and pinned-receipt check. |
| `theme` or F6 | Choose Aurora, Ultraviolet, Ember or Glacier. |
| `swarm` | Select harness workers or manage a local collaboration room. |
| `doctor` / `status` | Inspect installed tools, runtime files, key pins and local configuration. |
| `motion off` / `motion on` | Disable or enable the activity animation. |

A compact five-line A appears beside the wordmark in a single accent color.
Narrow terminals use a three-line version.
Preferences persist locally. Tab completes commands, Up/Down browse in-memory
history, Escape returns or cancels, Page Up/Down scroll, and Ctrl+L redraws.
The console handles terminal resizing and restores itself after a harness exits.

Startup is local: no Keychain unlock or network fetch is required to draw the
first frame. The renderer has no additional UI dependencies and updates changed
rows. `NO_COLOR` disables colors; noninteractive terminals receive command help.

## Coding harnesses

Choose from nine integrations in the searchable picker. Missing executables are
clearly marked; install the official harness CLI before selecting it.

![ACK 0.2.3 harness picker showing all nine integrations and local installation status](docs/console-harnesses-0.2.3.png)

```sh
ack code claude
ack code codex
ack code opencode
ack code pi
ack code oh-my-pi
ack code zcode
ack code deepseek-harness
ack code hermes
ack code kimi
ack harnesses
```

| Harness | Binary | ACK integration |
| --- | --- | --- |
| Claude Code | `claude` | Bundled verification plugin, native attestation command and attestation status line. |
| Codex | `codex` | Confidential provider profile, published verification plugin, local skill and custom-prompt fallback. |
| OpenCode | `opencode` | Isolated provider configuration, local verifier plugin and attestation slash command. |
| Pi | `pi` | Verified provider extension, verification tool/command, footer and collaboration tools. |
| Oh My Pi | `omp` | Verified provider extension, verification tool/command, footer and collaboration tools. |
| ZCode | `zcode` | Versioned provider configuration and process-scoped gateway credential; billing key stays out of the provider file. |
| DeepSeek Harness | `dsh` | Confidential provider and default model; interactive Web profile and headless worker profile. |
| Hermes | `hermes` | ACK-owned provider configuration, environment credential reference and verification skill. |
| Kimi Code | `kimi` | Managed model alias, environment credential reference and verification skill. |

ACK configures each selected harness rather than changing the executable itself.
OpenCode and Hermes use ACK-owned configuration directories. Codex receives a
separate confidential profile and verification integrations in its selected
`CODEX_HOME`. Kimi's managed block preserves unrelated existing TOML settings.

For binaries outside PATH, set an absolute executable override, for example:

```sh
export ACK_CODEX_BIN=/absolute/path/to/codex
export ACK_OMP_BIN=/absolute/path/to/omp
export ACK_DSH_BIN=/absolute/path/to/dsh
ack code codex
```

Other overrides are `ACK_CLAUDE_BIN`, `ACK_OPENCODE_BIN`, `ACK_PI_BIN`,
`ACK_ZCODE_BIN`, `ACK_HERMES_BIN` and `ACK_KIMI_BIN`. Oh My Pi uses its own
agent state directory; `OMP_CODING_AGENT_DIR` can override it without reusing a
Pi-specific `PI_CODING_AGENT_DIR` setting.

## Attestation and verification

```sh
ack attestation
ack attestation --json
```

The verifier checks pinned receipt keys, fresh endpoint evidence, the expected
model and policy, independent hardware evidence, and the quote-bound transport
identity. The gateway verifies the confidential request path and signed final
inference receipt separately. Failed, stale, unpinned or synthetic evidence is
not a verified confidential runtime.

The console badge starts unchecked and expires with the evidence. Supported
harness interfaces expose verification as follows:

- **Claude:** `/adverserial-verify-claude:attestation`; the bottom status line
  displays the cached verdict and refuses expired or unpinned evidence.
- **Codex:** select the installed `adverserial-verify` plugin skill with
  `$adverserial-verify` or `/skills`. ACK also installs `$adverserial-attestation`
  and `/prompts:adverserial-attestation` for CLI versions supporting custom
  prompts. Restart Codex after installation. A Claude-style custom attestation
  status line is not provided by this integration.
- **OpenCode:** `/adverserial-attestation`, plus the `adverserial_verify` and
  `adverserial_status` tools.
- **Pi / Oh My Pi:** `/adverserial-verify`, the `adverserial_verify` tool and
  an attestation footer that expires with the proof and clears after verification errors.
- **Hermes / Kimi:** the supplied `adverserial-verify` skill invokes ACK's
  installed verifier through the harness shell tool.
- **Every harness:** `ack attestation` remains available from a normal terminal.
  ZCode and DeepSeek Harness do not currently install native attestation slash
  commands or custom attestation footers.

Commands, skills and footer capabilities vary by upstream CLI version; the
presence of a command is not evidence that verification succeeded.

## Encrypted API-key profiles

```sh
ack keys list
ack keys add personal
ack keys add security-team
ack keys modify security-team
ack keys use security-team
ack keys delete personal
```

Keys are encrypted with AES-256-GCM in `~/.config/adverserial/ack.json` using a
random storage key held in macOS Keychain or protected with Windows DPAPI. Key entry is masked; listings show
only a short masked identifier. Secret values are excluded from console history,
preferences and activity logs. ACK refuses to delete the active profile: select
another one first. Existing plaintext ACK state is migrated into encrypted
profiles when read.

Configuration files use mode `0600` and private directories use `0700`.
Credentials are decrypted into memory and passed to the selected local harness
and gateway for the session. ZCode's provider file contains only a random local
session token, not the billing key. Selected harnesses can access their own
process environment, so use trusted upstream CLIs and workspace tools.

## Models and runtime lifecycle

```sh
ack models
ack model lordx64/cyberglm
ack upgrade
ack doctor
ack status
```

Model discovery uses the public registry. Activation requires the matching active
policy and pinned receipt keys. For the production model, ACK uses the current
production policy even if a registry entry still points to an older template.
An unknown model or inactive policy cannot bypass verification.

ACK starts a separate loopback gateway for each coding session or swarm. The
operating system assigns a free port, and ACK passes that address to the selected
harness automatically. You can open multiple terminals and run `ack code` in each;
closing one stops only its own gateway.

Connection settings are isolated per session under
`~/.config/adverserial/sessions/`. Codex receives process-local provider overrides;
OpenCode, ZCode, Kimi and Hermes receive private connection configuration;
DeepSeek receives a per-invocation patch and a free Web UI port. Kimi links its
existing session/history directories. Hermes keeps its authority database private
to each profile, as required by upstream, while linking shared archives and
memories. Existing profiles and databases are not deleted.

ACK trusts readiness only from the gateway child it launched, through a private
pipe. It never adopts an unrelated local server based on its health response.
`ADVERSERIAL_GATEWAY_PORT` can specify a preferred port; if that port is occupied,
ACK leaves its owner untouched and allocates another port. Shared runtime upgrades
are serialized across windows, so two launches cannot run pip over the same venv
at once. Runtime files refresh automatically after an ACK version change.

The gateway exchanges the API key with billing for a scoped entitlement and
sends encrypted requests to the attested runtime. The model endpoint receives
the entitlement instead of the billing key. Completed streams require a signed
inference receipt.

To update ACK itself, reinstall the GitHub package, then refresh its runtime:

```sh
npm install -g github:AdverserialAI/adverserial-confidential-kit
ack upgrade
```

`ack upgrade` refreshes runtime files and policy; it does not replace the globally
installed npm package.

## Confidential swarms

Choose workers in the console or run:

```sh
ack swarm --agents claude,pi --workers 2 --lead claude \
  "review this repository and propose a minimal fix"
```

ACK shares a local brief, collects worker reports, and asks the lead to reconcile
the results. One verified gateway serves the job. Worker concurrency is bounded
from one to four; two is the default. All selected harnesses must be installed.
Use an explicit agent list to control usage. Reports remain under
`~/.config/adverserial/swarms/`.

Already-open agents can cooperate through a local room:

```sh
ack swarm create incident-review
ack swarm invite --to pi "Review cancellation and post your findings."
ack swarm inbox --agent pi
ack swarm post --from pi --to claude "Findings saved in the shared workspace."
```

An agent reads pending tasks on its next turn; ACK does not inject text into an
existing terminal or copy hidden conversation history. Claude, Pi and Oh My Pi
have collaboration integrations. Room artifacts live in
`~/.config/adverserial/swarm-rooms/`.

## Development and test coverage

```sh
npm ci
npm test
npm run test:terminal
npm run smoke
```

The terminal renderer is in `lib/console.mjs`, artwork in `lib/art.mjs`, and
vault, policy, runtime and harness operations in `lib/ack.mjs`. Regression tests
cover encrypted profile changes, masked input, cancellation, terminal handoff,
model policy activation, provider configuration, and attestation badge expiry.
Live harness verification is version-specific; see [the test report](docs/TESTING.md).

## Licensing

**Source-available proprietary software — not an open-source license.**

The [Adverserial Proprietary License](LICENSE) governs ACK's Adverserial-authored
material. A separate written agreement is required as described there. See
[LICENSING.md](LICENSING.md) for scope and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for retained dependency terms.
Upstream coding harnesses remain separate products under their own terms.

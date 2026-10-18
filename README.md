# Adverserial Confidential Kit

`adverserial-confidential-kit` turns the existing confidential SDK, gateway,
and harness integrations into one local command-line workflow.

```sh
# After the first npm release
npm install -g adverserial-confidential-kit

# Or install the current public GitHub source now
npm install -g github:AdverserialAI/adverserial-confidential-kit

ack
```

Running bare `ack` opens the Confidential Shell: a persistent local session with the Adverserial mark, an `ack ›` prompt, and commands for `init`, `upgrade`, `code`, `models`, `attestation`, and `swarm`. Setup phases use one animated status line that clears before returning to the shell or launching a harness.

`ack init` asks for an Adverserial API key once, downloads the active public
policy, pins its receipt keys in `~/.config/adverserial/receipt-keys.json`,
and prepares a private local confidential runtime in `~/.config/adverserial/venv`.
Both local config files use mode `0600`; the directory uses mode `0700`.

`ack code` handles the confidential runtime end to end: it starts it only for
the selected harness session, waits for it to become healthy, and stops it when
the harness exits. It refreshes the private runtime automatically after an
installed kit update. The runtime verifies fresh attestation and hardware
evidence, exchanges the API key with billing for a one-use entitlement,
encrypts requests to the runtime, and requires a signed inference receipt
before accepting a completed stream. The model endpoint never receives the
saved API key.

```sh
ack code claude
ack code codex
ack code opencode
ack code pi
ack code hermes
ack code kimi
ack models
ack attestation
ack upgrade
```

## Confidential swarms

Use `ack swarm` when a task benefits from independent coding-agent views. It starts one verified gateway for the whole job, limits workers to two by default, gives each worker a shared local brief, and asks a lead harness to reconcile their reports. Prompts and reports remain in the local swarm directory under `~/.config/adverserial/swarms/`.

```sh
ack swarm --agents claude,codex --workers 2 --lead claude \
  "audit this repository and propose a minimal fix"
```

The default selects every supported harness. Use `--agents` to choose a smaller group when you want to control usage or focus the review.

### Connecting already-open sessions

Harnesses do not expose a safe API for another process to inject text into an existing private conversation. Instead, `ack` provides a local file-backed room that active agents can explicitly join on their next turn:

```sh
ack swarm create incident-review
ack swarm invite --to pi "Review the streaming adapter and post the failure mode."
ack swarm inbox --agent pi
ack swarm post --from pi --to claude "Found the issue and saved a patch at …"
```

This lets a Claude session delegate work to an already-open Pi session, and lets Pi report back, without copying either session’s hidden conversation, credentials, or prompt history. The Claude integration recognizes explicit swarm requests, and the Pi integration exposes `adverserial_swarm_inbox` and `adverserial_swarm_post` tools when launched through `ack code pi`. An already-open Pi session receives the task on its next turn when it reads its inbox; the kit never injects text into a terminal in the background. All room artifacts are private local files under `~/.config/adverserial/swarm-rooms/`.

The target harness must already be installed. The kit creates an isolated
Codex profile and ephemeral OpenCode/Hermes config snippets; it does not
overwrite the user’s normal provider configuration. This repository is the source of the public `adverserial-confidential-kit` package. Before the first npm release, configure npm trusted publishing for this GitHub repository; the included release workflow then publishes the tagged package with provenance.

### Harness selection

Run `ack`, then `code`, to choose a colored launcher menu. ACK configures the
local receipt-verifying gateway and starts the selected installed harness.

Supported launchers are Claude Code, Codex, OpenCode, Pi, Oh My Pi (`omp`),
ZCode, DeepSeek Harness (`dsh`), Hermes, and Kimi Code. `ack code codex`
also installs the published `adverserial-verify` Codex plugin; invoke it in
Codex as `$adverserial-verify` or choose it from `/skills`. It also adds
the slash-prompt fallback `/prompts:adverserial-attestation` for Codex builds
that show custom prompts in their slash menu. Start a new Codex session after
installation so it loads either entry. Pi and Oh My Pi expose
`/adverserial-verify` and show the current attestation verdict in their footer.

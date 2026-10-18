# ACK 0.2.x validation

Validation performed on macOS (Apple Silicon), Node.js 26.5.0 and Python 3.14.4,
on October 17–18, 2026. The live model was `lordx64/cyberglm`, selected from the
public model registry and checked against the active production policy.

The 0.2.2 visual update replaces the large logo with a five-line mark (three
lines on narrow terminals). The 33 Node tests and PTY UI checks were rerun
after this layout change; inference and gateway behavior are unchanged.

## Fresh Hermes installation (0.2.4)

A fresh official Hermes install at `d923a5eb48` rejected the old `--base-url`
argument with exit status 2. ACK now supplies its loopback URL through the named
provider configuration and environment, without that unsupported argument.
The existing `6f46e2b9` test above did not cover this newer CLI revision.

The new installation completed a live `ack code hermes` model request and read
back a random value from a disposable local file through its terminal tool. A
fresh pinned hardware attestation returned `verified`. The 39 Node regression
tests include rejection of the removed flag and preservation of failed native
startup output until acknowledged. Native stdio remains attached to the TTY.
The installed npm archive also launched Hermes through the console picker,
generated the exact interactive test response, and restored ACK after exit.
A real PTY failure check confirmed diagnostics stay visible until Enter.

## Concurrent sessions (0.2.3)

- Two real `ack code` processes shared an installation and started real Python
  gateways on separate OS-assigned ports, with an unrelated listener occupying
  their preferred port. The listener was unchanged.
- Stopping the first process left the second gateway healthy; starting a
  replacement session also left the second one working.
- Private per-session connection files were checked for OpenCode, ZCode, Kimi,
  Hermes and DeepSeek; Codex uses command-line provider overrides.
- All nine harnesses were rechecked with real model requests and local file tools
  through dynamically assigned gateways.
- A live two-worker Pi/Oh My Pi swarm with a Claude lead completed with both
  worker reports successful and its gateway cleaned up. Pi and Oh My Pi use
  separate native state directories. Failed workers now produce a nonzero result.
- Two simultaneous first-run installers completed against one fresh venv. Lock
  regressions also cover a failing installer followed by successful recovery.
- A receipt-key source conflict discovered during Pi/Oh My Pi checks was fixed:
  the bound verifier clears the inherited file source when supplying pinned JSON.

## Live harness matrix

Each harness made real requests through an isolated local confidential gateway,
used a file-reading tool to recover a random value that existed only in a local
test file, and ran a fresh pinned hardware attestation through its verification
integration or shell tool. Test workspaces and configuration directories were
disposable. API keys were not included in prompts or the public report.

| Harness | Version / source tested | Model + file tool | Fresh attestation |
| --- | --- | --- | --- |
| Claude Code | 2.1.296 | Pass | Pass |
| Codex | 0.159.0 | Pass | Pass |
| OpenCode | 1.18.29 | Pass | Pass |
| Pi | 0.80.10 | Pass | Pass |
| Oh My Pi | 18.12.1 | Pass | Pass |
| ZCode CLI | 0.16.9, official source build at `aac4755` | Pass | Pass |
| DeepSeek Harness | 0.2.0-rc.2 | Pass | Pass |
| Hermes | Official source at `6f46e2b9`, isolated Python environment | Pass | Pass |
| Kimi Code | 2.2.0 | Pass | Pass |

Interactive launch checks used real pseudo-terminals and normal upstream
onboarding/trust dialogs. DeepSeek Harness launches its Web profile, not a
terminal UI. Pi and Oh My Pi exposed their verification footer and native
verification command. Claude's native `/adverserial-verify-claude:attestation`
command completed in its TUI and changed the footer to a verified verdict.
The installed npm archive also passed a fresh init/upgrade/key-management run.
Native command/skill availability differs by harness;
see the README rather than assuming every agent supports the same slash command.

## Workflow and regression coverage

- Fresh `init` with immediate masked key entry, actual Keychain encryption and
  a real private Python/runtime installation. A denied Keychain read cannot
  replace the existing encryption key.
- Key add, modify, activate, reactivate and delete; active-profile deletion
  refusal; legacy plaintext-state migration; absence of plaintext in saved state.
- `upgrade`, public model discovery, model activation and fresh verification.
  Production activation works even when the registry references an old template.
- Console command palette, harness search, hidden input, paste/cancel behavior,
  themes, diagnostics, resizing, scrolling and terminal restoration.
- A live Pi-worker / Claude-lead swarm recovered the file value through its
  shared brief and reports. Room invitation and reply flows have regression tests.
- Owned gateway normal exit and SIGTERM cleanup; occupied-port rejection without
  stopping or trusting the unrelated listener.
- Gateway streaming adapters, tool calls, signed-receipt requirements, admission
  bounds, request framing and exact session-token credential exchange.
- Packaged hardware-verifier paths, npm archive contents, license/notice inclusion
  and absence of configuration secrets, Python build output and caches.

Local automated checks:

```sh
npm ci
npm test                 # 38 Node tests (Keychain-denial case is macOS-only)
npm run test:terminal    # real PTY console checks
npm run smoke

# With the gateway's Python dependencies installed:
PYTHONPATH=resources/gateway:resources/python \
  python3 -m unittest discover -s resources/gateway/tests -q  # 35 tests
```

Console first-frame checks measured approximately 28–43 ms on this workstation.
This is a local UI measurement, not an inference-latency promise.

## Limits and observations

This report covers the versions above and the currently published CyberGLM
configuration. It does not assert that every upstream release, OS, terminal,
model, arbitrary plugin combination or possible swarm permutation was tested.
Linux and Windows encrypted credential stores are not implemented in this release.

Some live requests encountered temporary backend-warming 503 responses; the
harnesses retried and completed. A sandboxed Codex/DeepSeek shell may deny the
optional verdict-cache write outside its workspace even when fresh verification
succeeds. ACK binds public verification inputs into its verifier launcher so
scrubbed shell environments cannot silently discard the pinned key configuration.
No verification bypass was used.

The ZCode source build reported a missing optional built-in provider catalog;
its explicitly configured confidential provider and tool calls still passed.
Upstream first-run theme, telemetry and workspace-trust prompts remain upstream
choices; ACK does not disable them.

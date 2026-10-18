# @adverserial/kimi-code-plugin

Verify the attestation of the Adverserial confidential inference endpoint
from inside [Kimi Code CLI](https://www.kimi.com/code/docs/en/) — as a
session hook, an on-demand CLI, and an agent skill.

It wraps the TypeScript SDK (`@adverserial/sdk`, `../../typescript`) through
the shared core in `../shared`: fresh nonce-bound TDX evidence + ES256
verification receipt, checked against pinned receipt keys. Without pinned
keys it **refuses to claim "verified"**; the explicit escape hatch
(`--trust-evidence-key` / `ADVERSERIAL_TRUST_EVIDENCE_KEY=1`) TOFU-bootstraps
the ephemeral key from the evidence and the verdict reads **UNPINNED (TOFU
dev mode)**. Production deployments pin the key set published at
https://verify.adverserial.ai.

## Layout

```
kimi-code/
├── kimi.plugin.json                  # Kimi Code plugin manifest (skill + SessionStart hook)
├── bin/adverserial-verify            # executable shim → dist CLI
├── src/cli.ts                        # the CLI (prints the verdict table, exit 0/1)
├── skills/adverserial-verify/SKILL.md
└── dist/                             # self-contained build output (SDK + shared + CLI)
```

## Install

```sh
cd adverserial-sdk/plugins
npm install
npm run build            # tsc; output is self-contained (no runtime deps)
```

Then either install it as a Kimi Code plugin (recommended):

```
/plugins install /absolute/path/to/adverserial-sdk/plugins/kimi-code
/reload
```

The manifest registers the `adverserial-verify` skill and a `SessionStart`
hook that runs the CLI once per session. (Kimi Code copies the plugin into
`$KIMI_CODE_HOME/plugins/managed/adverserial-verify/`; the build output is
self-contained so the copy keeps working.)

…or wire the CLI directly in `~/.kimi-code/config.toml` without the plugin:

```toml
[[hooks]]
event = "SessionStart"
command = "node /absolute/path/to/adverserial-sdk/plugins/kimi-code/bin/adverserial-verify"
timeout = 30
```

Optional: to surface the cached state inside the conversation, a
`UserPromptSubmit` hook works too (its stdout is appended to context;
`--status` does no network I/O):

```toml
[[hooks]]
event = "UserPromptSubmit"
command = "node /absolute/path/to/adverserial-sdk/plugins/kimi-code/bin/adverserial-verify --status"
timeout = 10
```

## Usage

```sh
# fresh check, prints the verdict table, exit 0 = verified / 1 = not
node bin/adverserial-verify

# against a local DEV_MODE attest-proxy (synthetic evidence, self-signed TLS):
# the hardware verifier command is mandatory; for synthetic dev evidence use a
# dev double like ../opencode/test/dev-hardware-verifier.mjs (the shipped
# verifier only accepts genuine hardware evidence)
ADVERSERIAL_API_URL=https://127.0.0.1:8443/v1 \
ADVERSERIAL_HARDWARE_VERIFIER_COMMAND=/absolute/path/to/plugins/opencode/test/dev-hardware-verifier.mjs \
  node bin/adverserial-verify --trust-evidence-key

# network-free status of the last result (used by hooks)
node bin/adverserial-verify --status

# raw JSON verdict
node bin/adverserial-verify --json
```

Example output:

```
ADVERSERIAL ATTESTATION: VERIFIED — UNPINNED (TOFU dev mode)
  endpoint  https://127.0.0.1:51234/v1
  model     lordx64/cyberglm
  policy    adverserial-policy/dev
  evidence  sha256:…
  receipt   kid=… digest=sha256:…
  tls_spki  sha256:…
  issued    2026-10-04T07:00:00.000Z
  expires   2026-10-04T07:10:00.000Z (in 9m 32s)
  trust     UNPINNED (TOFU dev mode) — receipt key bootstrapped from the evidence itself
  WARNING: the receipt key was trust-on-first-use bootstrapped from the evidence;
           anyone terminating TLS could present it. Production deployments pin
           receipt keys from https://verify.adverserial.ai.
  WARNING: dev_mode evidence (dev=true) — the TDX quote is SYNTHETIC.
           This proves the plumbing (signatures, nonce, digests), NOT the hardware.
```

Inside a Kimi Code session, ask the agent to "verify the Adverserial
endpoint" — the skill teaches it to run `adverserial-verify`, interpret the
verdict (including `dev_mode` and UNPINNED states), and never paraphrase a
failed/unpinned verdict as verified.

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `ADVERSERIAL_API_URL` | `https://api.adverserial.ai/v1` | Endpoint base URL |
| `ADVERSERIAL_MODEL` | `lordx64/cyberglm` | Expected receipt `model_id` |
| `ADVERSERIAL_ISSUER` | `https://verify.adverserial.ai` | Expected receipt `iss` |
| `ADVERSERIAL_AUDIENCE` | `https://chat.adverserial.ai` | Expected receipt `aud` |
| `ADVERSERIAL_EXPECTED_ENDPOINT` | unset | Also pin the receipt `endpoint` claim |
| `ADVERSERIAL_RECEIPT_KEYS_JSON` | unset | Pinned keys: JSON map kid → public JWK |
| `ADVERSERIAL_RECEIPT_KEYS_FILE` | unset | Path to a JSON file with that map |
| `ADVERSERIAL_TRUST_EVIDENCE_KEY` | unset | `=1` enables the TOFU dev escape hatch |
| `ADVERSERIAL_HARDWARE_VERIFIER_COMMAND` | unset | Required executable that independently validates TDX/GPU evidence; no value means verification fails closed |
| `ADVERSERIAL_CACHE_FILE` | `~/.cache/adverserial/verify.json` | `--status` cache location |

Notes:

- The keys file is a JSON object mapping key id → public EC P-256 JWK, e.g.
  `{"<kid>": {"kty":"EC","crv":"P-256","x":"…","y":"…"}}`. Set only one of
  `ADVERSERIAL_RECEIPT_KEYS_JSON` / `ADVERSERIAL_RECEIPT_KEYS_FILE`.
- Against a DEV_MODE attest-proxy (self-signed TLS) on loopback, the TOFU
  escape additionally disables CA validation for the process, with a loud
  stderr warning. For a non-loopback self-signed endpoint, set
  `NODE_TLS_REJECT_UNAUTHORIZED=0` yourself (dev only).
- Node fetch cannot pin the TLS SPKI (see the SDK README); the CLI surfaces
  `tls_spki_sha256` in the verdict. For hard channel pinning use the Python
  SDK's `VerifiedSession`.

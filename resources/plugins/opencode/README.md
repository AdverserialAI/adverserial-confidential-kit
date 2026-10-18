# @adverserial/opencode-plugin

[opencode](https://opencode.ai) plugin that lets the agent verify the
attestation of the Adverserial confidential inference endpoint from inside
the coding session.

It wraps the TypeScript SDK (`@adverserial/sdk`, `../../typescript`) through
the shared core in `../shared`: fresh nonce-bound TDX evidence + ES256
verification receipt, checked against pinned receipt keys. Without pinned
keys the tools **refuse to claim "verified"**; the explicit escape hatch
(`ADVERSERIAL_TRUST_EVIDENCE_KEY=1`) TOFU-bootstraps the ephemeral key from
the evidence and the verdict reads **UNPINNED (TOFU dev mode)**. Production
deployments pin the key set published at https://verify.adverserial.ai.

## Tools

| Tool | Params | What it does |
| --- | --- | --- |
| `adverserial_verify` | none | Runs the attestation check and returns a compact verdict: `VERIFIED` / `FAILED` / unpinned refusal, with endpoint, model, policy, evidence digest, receipt key id, expiry, trust level, and a dev-mode warning when the evidence is synthetic. |
| `adverserial_status` | none | Shows the current verification state: the cached last verdict plus its age relative to the cache TTL. |

Verification runs **lazily on the first tool call** and is cached for
**5 minutes**; later calls within the TTL return the cached verdict (marked
as such).

## Install

```sh
cd adverserial-sdk/plugins
npm install
npm run build            # tsc; output is self-contained (SDK + shared + plugin)
```

## Send OpenCode through the confidential gateway

Merge [`../../profiles/opencode.jsonc`](../../profiles/opencode.jsonc) into
`~/.config/opencode/opencode.json` after starting the local gateway. Select
`adverserial/lordx64/cyberglm`. OpenCode uses normal OpenAI-compatible
streaming and function tools against `127.0.0.1`; the gateway sends only the
resulting one-use entitlement and encrypted request to the runtime.

Then register the built plugin with opencode — either project-local
(`.opencode/plugins/adverserial.ts` in the repo) or global
(`~/.config/opencode/plugins/adverserial.ts`). The file is a one-line shim
pointing at the build output:

```ts
// ~/.config/opencode/plugins/adverserial.ts
export { AdverserialPlugin as default } from "/absolute/path/to/adverserial-sdk/plugins/opencode/dist/plugins/opencode/src/index.js"
```

The dist tree is self-contained except for `@opencode-ai/plugin`, which
opencode resolves for plugin modules; if your setup loads the file outside
opencode's plugin loader, add a `package.json` next to your opencode config
with `"dependencies": { "@opencode-ai/plugin": "*" }` (opencode runs
`bun install` for it at startup) and keep `adverserial-sdk/plugins/node_modules`
in place.

## Usage inside a session

Ask the agent, e.g.:

> "Verify the Adversarial endpoint before I paste this config."
> "Is the confidential inference endpoint still attested? What's the evidence digest and expiry?"

The agent calls `adverserial_verify` (or `adverserial_status`) and reports
the verdict. Example tool output:

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

(fresh attestation check)
```

## No plugin slash commands in opencode

opencode plugins can contribute tools and event hooks, but they **cannot
register custom slash commands** — commands come from config, not plugins
([opencode plugin docs](https://opencode.ai/docs/plugins/)). The equivalent
of the other harnesses' `attestation` command is a user-level custom command
file; drop this into `~/.config/opencode/commands/attestation.md` (global)
or `.opencode/commands/attestation.md` (per-project) to get `/attestation`:

```md
---
description: Verify the Adverserial confidential endpoint attestation and show the verdict
---

Use the adverserial_verify tool to run a fresh Adverserial attestation check
(or adverserial_status for the cached state) and report the result:

1. Show the user the tool's verdict output verbatim, then one sentence of
   interpretation.
2. Never paraphrase a failed, stale, or UNPINNED (TOFU) verdict as verified.
   If it fails, show the reason line and stop.
```

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

Notes:

- The keys file is a JSON object mapping key id → public EC P-256 JWK, e.g.
  `{"<kid>": {"kty":"EC","crv":"P-256","x":"…","y":"…"}}`. Set only one of
  `ADVERSERIAL_RECEIPT_KEYS_JSON` / `ADVERSERIAL_RECEIPT_KEYS_FILE`.
- Set the env in the environment you launch `opencode` from; the plugin
  reads it once, lazily, on the first tool call.
- Against a DEV_MODE attest-proxy (self-signed TLS) on loopback, the TOFU
  escape additionally disables CA validation for the opencode process, with
  a loud warning in the tool output and plugin log. For a non-loopback
  self-signed endpoint, export `NODE_TLS_REJECT_UNAUTHORIZED=0` before
  launching opencode (dev only).
- Node/Bun fetch cannot pin the TLS SPKI (see the SDK README); the verdict
  surfaces `tls_spki_sha256`. For hard channel pinning use the Python SDK's
  `VerifiedSession`.

## Smoke test

With a DEV_MODE attest-proxy running on loopback
(`cd ../../../attest-proxy && DEV_MODE=1 AUTH_REQUIRED=0 LISTEN_ADDR=127.0.0.1:0 go run ./cmd/attest-proxy`):

```sh
cd adverserial-sdk/plugins/opencode
export ADVERSERIAL_API_URL=https://127.0.0.1:<port>/v1
ADVERSERIAL_TRUST_EVIDENCE_KEY=1 \
  ADVERSERIAL_HARDWARE_VERIFIER_COMMAND="$PWD/test/dev-hardware-verifier.mjs" \
  npm test
npm test -- --expect-unpinned
```

The hardware verifier command is mandatory (verification fails closed
without it); `test/dev-hardware-verifier.mjs` is a fixture that accepts only
synthetic DEV_MODE evidence, mirroring the SDK's own dev test double. Real
evidence must go through the shipped
`typescript/bin/adverserial-hardware-verify.mjs`.

This drives the exact tool code path (plugin module + tools + TTL cache)
under plain Node, without the opencode runtime.

# Adverserial confidential gateway

A loopback-only gateway for the confidential endpoint. It accepts the native
wire protocol used by coding agents and refuses to send a prompt unless the
endpoint attestation, pinned receipt key, TLS SPKI, and independent TDX/GPU
verifier all pass.

The endpoint is [attest-proxy](https://github.com/AdverserialAI/attest-proxy)
(v0.1.0-rc.33 at the time of writing) in front of an SGLang model server on a
VM-internal network. All server private keys are generated inside the enclave;
the operator holds none of them. What the kit checks, and what it does not, is
listed in the [root README](../../README.md#what-ack-verifies-and-what-it-does-not).
An independent verifier and attestation history are published at
[AdverserialAI/cyberseek-transparency](https://github.com/AdverserialAI/cyberseek-transparency).

## Data path

```
coding agent → 127.0.0.1 gateway → billing.adverserial.ai /cc/entitlements
                                  → configured direct TLS endpoint (CVM)
```

The raw `sk-…` key ends at billing. The gateway receives an opaque five-minute,
single-request entitlement and sends that to `ADVERSERIAL_CC_API_URL`; the
model request never passes through a general-purpose application relay.

## Install

`ack init` installs and configures the gateway; `ack code` starts one per
session on an OS-assigned port. To run it by hand from this repository:

```sh
npm ci                                  # dependencies of the Node hardware verifier
pip install ./resources/python ./resources/gateway
export ADVERSERIAL_RECEIPT_KEYS_FILE="$HOME/.config/adverserial/receipt-keys.json"
export ADVERSERIAL_HARDWARE_VERIFIER_COMMAND="$PWD/resources/typescript/adverserial-hardware-verify.mjs"
export ADVERSERIAL_NODE_EXECUTABLE="$(command -v node)"
adverserial-confidential-gateway
```

`ADVERSERIAL_HARDWARE_VERIFIER_COMMAND` must be an absolute path; it is never
looked up on `PATH`. The bundled `adverserial-hardware-verify.mjs` is the
verifier ACK uses: it verifies the Intel TDX quote with `@phala/dcap-qvl`
(requiring an `UpToDate` TCB status), checks the quote's `report_data` binding,
replays the event log, compares measurements with the published policy and
verifies the NVIDIA NRAS tokens. A `.mjs` or `.js` verifier is run with
`ADVERSERIAL_NODE_EXECUTABLE`.

The receipt-key file is the `receipt_keys` object of the policy published at
`https://verify.adverserial.ai/policies/production.json` (`ack init` and
`ack upgrade` write it). The policy is fetched over HTTPS and is not signed; the
receipt keys are the only values pinned locally. Do not use this gateway until
the policy identifies a live production endpoint.

Configure an OpenAI client with `base_url=http://127.0.0.1:8787/v1` (the
default port when the gateway is started by hand), your
normal Adverserial API key, and the canonical model ID `adverserial/cyberseek`.
CyberKimi and CyberGLM are available only on request.

## Supported coding-agent protocols

It handles OpenAI Chat Completions, Anthropic Messages, and OpenAI Responses,
including receipt-verified SSE and structured function calls. Each adapter
converts locally to a canonical OpenAI-compatible request, then follows the
same attestation → entitlement → pinned direct-TLS → signed-receipt path:

- OpenAI: `POST /v1/chat/completions`
- Claude-compatible clients: `POST /v1/messages`
- Codex-compatible clients: `POST /v1/responses`

Function definitions, function calls, function call outputs, and streamed
function argument deltas are preserved across Claude Messages and Responses.
Codex's local function tools are forwarded normally. Optional hosted
`web_search`, `image_generation`, and multi-agent namespace declarations are
omitted from the model request: they cannot execute through a private,
direct-only runtime. An explicit hosted-tool choice is still rejected, as is
`tool_choice: required` when no supported local function remains.
Image/document blocks, other hosted provider tools, and provider-side
conversation state are rejected deliberately. The caller must resend complete
text and function-call history; this avoids keeping prompt history at the
provider.

## Prefix-cache salt

Each gateway process creates one random 32-byte `cache_salt` (unpadded
base64url) and adds it to every request it forwards, for all three local
protocols. The gateway keeps no conversation state, so the salt is stable for
the life of the process — one `ack code` session or swarm — and separates that
session's prefix cache inside the enclave. It is random, never logged and never
written to disk.

- A client `cache_salt` matching `^[A-Za-z0-9_-]{32,128}$` is forwarded by the
  gateway unchanged.
- Any other `cache_salt` value is replaced with the session salt (the proxy
  answers a malformed salt with HTTP 400).
- A client `extra_key` is removed; the proxy rejects it with HTTP 400.
- The salt is part of the body the entitlement's input bound is computed from
  (`2 × bytes + 4096`).

The proxy never hands the salt to the model server as sent. It always replaces
it with `HMAC-SHA256(k, account id || 0x00 || salt)`, where `k` is drawn at
every proxy start and kept in memory only, and the account id comes from the
billing-signed entitlement. Two accounts therefore never share prefix-cache
entries, whatever salt either sends; the gateway's salt only separates sessions
of the same account.

## Enclave restarts and key rotation

The enclave generates a new EHBP key at every boot and keeps it in memory only;
it is never a fixed or operator-supplied key. The receipt key is generated in
the enclave on first boot and changes only when the enclave's key state is
rebuilt. A cached proof is dropped and
the endpoint is verified again from scratch — attestation, published policy,
pinned receipt key and hardware evidence — when:

- the TLS handshake presents a different key, the endpoint is unreachable, or the
  proof cannot be used (nothing was sent);
- the enclave answers with the EHBP key-configuration problem document
  (`422 application/problem+json`, type `urn:ietf:params:ehbp:error:key-config`);
- the enclave rejects the request with 400, 401, 403 or 422 before generating
  and the cached proof is at least 30 seconds old.

The request is then retried exactly once, and only if nothing was sent or the
newly verified proof carries a different EHBP key (so the enclave cannot have
opened the first attempt). 5xx responses, timeouts, broken streams and receipt failures
are never retried: the request may have run. No key is ever taken from an error
response.

The pinned receipt keys are re-read when `ADVERSERIAL_RECEIPT_KEYS_FILE` changes,
so `ack upgrade` reaches a running gateway. A missing or malformed file leaves
the loaded pins untouched.

After a server key rotation run `ack upgrade`, then `ack attestation`, then
start a new session; see
[After a server key rotation](../../README.md#after-a-server-key-rotation).

See [`../profiles/`](../profiles/) for Claude Code, Codex, OpenCode and Hermes
profiles.

Please report security vulnerabilities privately to security@adverserial.ai.

### Claude MCP tool search

The attested proxy has a 64-active-tool limit. ACK launches Claude Code with
`ENABLE_TOOL_SEARCH=true`; the local Anthropic adapter honors `defer_loading`
and hydrates schemas named by `tool_reference` blocks returned by Claude's
local ToolSearch. All lookups are restricted to the current request's catalog.
The gateway never executes a tool or shares discovery state between sessions.
A catalog with more than 64 active tools is rejected locally with an actionable
message rather than silently truncated. This requires no proxy/CVM update.

After upgrading ACK, exit old Claude sessions and run `ack code claude` again.
A live test with 80 synthetic MCP tools completed search, execution and a final
answer through encrypted CyberSeek inference with verified receipts.

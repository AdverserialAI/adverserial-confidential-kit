# Adverserial confidential gateway

A loopback-only gateway for the confidential endpoint. It accepts the native
wire protocol used by coding agents and refuses to send a prompt unless the
endpoint attestation, pinned receipt key, TLS SPKI, and independent TDX/GPU
verifier all pass.

## Data path

```
coding agent → 127.0.0.1 gateway → billing.adverserial.ai /cc/entitlements
                                  → configured direct TLS endpoint (CVM)
```

The raw `sk-…` key ends at billing. The gateway receives an opaque five-minute,
single-request entitlement and sends that to `ADVERSERIAL_CC_API_URL`; the
model request never passes through a general-purpose application relay.

## Install

```sh
pip install ./python ./gateway
export ADVERSERIAL_RECEIPT_KEYS_FILE="$HOME/.config/adverserial/receipt-keys.json"
export ADVERSERIAL_HARDWARE_VERIFIER_COMMAND='/absolute/path/to/adverserial-hardware-verify'
export ADVERSERIAL_TDX_VERIFIER_COMMAND='/absolute/path/to/your-intel-tdx-adapter'
export ADVERSERIAL_GPU_VERIFIER_COMMAND='/absolute/path/to/your-gpu-attestation-adapter'
adverserial-confidential-gateway
```

`adverserial-hardware-verify` validates protocol bindings then invokes both configured vendor adapters; it fails closed unless each validates its portion of raw evidence. The receipt keys and hardware verifier must be obtained from the signed policy
published at `https://verify.adverserial.ai`. Do not use this gateway until the
policy identifies a live production endpoint and the independent verifier is
available.

Configure an OpenAI client with `base_url=http://127.0.0.1:8787/v1`, your
normal Adverserial API key, and canonical model IDs only:
`lordx64/cyberglm` or `lordx64/cyberkimi`.

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
Image/document blocks, hosted provider tools, and provider-side conversation
state are rejected deliberately. The caller must resend complete text and
function-call history; this avoids keeping prompt history at the provider.

See [`../profiles/`](../profiles/) for Claude Code, Codex, OpenCode, Pi, and
Hermes setup.

Please report security vulnerabilities privately to security@adverserial.ai.

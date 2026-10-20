# Gateway abuse and attestation freshness regressions

These tests use local HTTP/TLS servers, synthetic evidence, fixture signing keys
and mocked hardware verification. They do not attack hosted billing or inference
services and do not make paid requests.

Run the normal Node, SDK and gateway suites described in `STRESS_TESTING.md`.
Additional regression coverage checks:

- Session gateways reject credentials other than their random session token or
  configured API key before reading the request body or dispatching verification
  and billing work. Standalone gateways retain caller-supplied API-key support.
- Requests for multiple completions are rejected before reserving a single
  output allowance. This is a local policy restriction, not evidence of a
  demonstrated bypass in the hosted billing service.
- Request-line/header and body deadlines survive clients trickling bytes faster
  than the socket idle timeout. Admission remains bounded to 16 connections.
- Client-controlled paths and validation-error details do not enter gateway logs.
- Python sessions reject expired proofs before opening a connection and after
  the TLS handshake, before credentials/request bytes are sent. Pre-dispatch TLS
  and freshness failures leave the reservation eligible for release.
- Python and every bundled JavaScript verifier reject evidence that expires
  during the verification operation. Signed per-inference receipts retain their
  separate signature, nonce, content-binding and expiry checks.
- The console, Claude/Kimi status lines, shared status helpers and both bundled
  CLI `--status --json` commands reject expired, future-dated, old, unpinned,
  synthetic and incomplete cache entries. A current verified status requires
  both unexpired evidence and a verification age below five minutes.
- OpenCode refreshes cached evidence at its proof expiry even when the cache TTL
  has not elapsed. A failed gateway refresh never falls back to an expired proof.

Freshness is checked before starting an inference. A long-running inference may
finish after its initial attestation expires; its response still must pass its
own signed receipt checks. A later request requires a current proof.

Status caches are informational local files, not a substitute for cryptographic
verification or a security boundary against a process that controls the same OS
account. The gateway performs its own verification before confidential dispatch.

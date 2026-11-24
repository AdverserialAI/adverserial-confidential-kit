# Sigstore test fixtures

Real, public Sigstore bundles. Nobody outside the publishing workflow can make a
signature from the production policy identity, so the verification code is
tested against signatures other projects made with the same mechanism.

| File | Source | Size |
|---|---|---|
| `goreleaser-v2.20.3-checksums.txt` | https://github.com/goreleaser/goreleaser/releases/download/v2.20.3/checksums.txt | 5271 bytes, sha256 `0cb9bc49…6aaf` |
| `goreleaser-v2.20.3-checksums.txt.sigstore.json` | https://github.com/goreleaser/goreleaser/releases/download/v2.20.3/checksums.txt.sigstore.json | 10315 bytes |
| `rekor2/a.txt` | https://github.com/sigstore/sigstore-conformance/blob/e275ffb5aab734681fe82b919cc4a9a1dd27fa2c/test/assets/bundle-verify/a.txt | 109 bytes |
| `rekor2/a.txt.sigstore.json` | …/test/assets/bundle-verify/rekor2-happy-path/bundle.sigstore.json (same commit) | 10123 bytes |
| `rekor2/trusted_root.staging.json` | …/test/assets/bundle-verify/rekor2-happy-path/trusted_root.json (same commit) | 6824 bytes |

The goreleaser bundle is a production Sigstore signature from a GitHub Actions
release workflow (Fulcio certificate, Rekor v1 entry with inclusion proof and
signed entry timestamp, RFC 3161 timestamp). It verifies against the trusted
root this kit ships, `resources/sigstore/trusted_root.json`.

The `rekor2` bundle is the Sigstore conformance suite's Rekor v2 case
(`hashedrekord` 0.0.2, no integrated time, time from the timestamp authority
only), signed on Sigstore *staging*. It verifies only against the staging root
next to it and must be refused under the production root.

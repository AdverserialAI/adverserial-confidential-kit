# Third-party notices

The Adverserial Proprietary License covers Adverserial-authored ACK material;
it does not replace licenses attached to third-party components.

- **EHBP:** the JavaScript `ehbp` 0.3.3 and Python `tinfoil-ehbp` 0.3.2
  reference implementations come from the [Tinfoil Encrypted HTTP Body Protocol
  project](https://github.com/tinfoilsh/encrypted-http-body-protocol) under MIT.
- **Hardware evidence:** `@phala/dcap-qvl` 0.6.5 is licensed under Apache-2.0.
- **JavaScript dependencies:** dependency manifests identify exact versions.
  Copies of the installed packages' license and notice files are preserved in
  [`resources/licenses/`](resources/licenses/), including libraries incorporated
  into verifier bundles. Installed npm dependencies also carry their own notices.
- **Python runtime:** pip installs the gateway's dependencies into a private
  environment; those distributions retain their own package metadata and licenses.
- **Bundled integrations:** notices and license declarations already present in
  integration files remain applicable to those components.
- **Coding harnesses:** Claude Code, Codex, OpenCode, Pi, Oh My Pi, ZCode,
  DeepSeek Harness, Hermes and Kimi Code are separate upstream products. ACK
  does not bundle their executables or grant rights to them.

Report security issues privately to [security@adverserial.ai](mailto:security@adverserial.ai).

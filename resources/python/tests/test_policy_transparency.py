"""Offline tests for the policy transparency check (Python runtime).

Nobody outside the publishing workflow can produce a signature from the
production identity, so the cryptographic path is exercised with a real public
Sigstore bundle: the checksums file of goreleaser v2.20.3, signed by that
project's GitHub Actions release workflow and logged in Rekor.
  https://github.com/goreleaser/goreleaser/releases/download/v2.20.3/checksums.txt                (5271 bytes)
  https://github.com/goreleaser/goreleaser/releases/download/v2.20.3/checksums.txt.sigstore.json  (10315 bytes)
The same two files are the fixtures of test/policy-transparency.test.mjs.

Run: python -m pytest tests/test_policy_transparency.py   (needs the 'transparency' extra)
"""
from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adverserial import policy_transparency as pt  # noqa: E402

try:
    import sigstore  # noqa: F401
    HAVE_SIGSTORE = True
except ImportError:  # pragma: no cover
    HAVE_SIGSTORE = False

KIT = Path(__file__).resolve().parents[3]
FIXTURES = KIT / "test" / "fixtures" / "sigstore"
ARTIFACT = (FIXTURES / "goreleaser-v2.20.3-checksums.txt").read_bytes()
BUNDLE = (FIXTURES / "goreleaser-v2.20.3-checksums.txt.sigstore.json").read_text()
FIXTURE_SIGNER = {
    "san": "https://github.com/goreleaser/goreleaser/.github/workflows/release.yml@refs/tags/v2.20.3",
    "issuer": "https://token.actions.githubusercontent.com",
    "repository": "https://github.com/goreleaser/goreleaser",
    "repositoryId": "77071454",
    "ownerId": "24697112",
    "ref": "refs/tags/v2.20.3",
    "trigger": "push",
    "runner": "github-hosted",
}
SIGNED_AT = "2026-11-20T04:21:30.000Z"
URL = "https://verify.example.test/policies/production.json"
SIGNED_SITE = {URL: ARTIFACT, URL + ".sigstore.json": BUNDLE.encode()}


def verify(artifact=ARTIFACT, bundle=BUNDLE, signer=FIXTURE_SIGNER, **extra):
    return pt.verify_policy_signature(artifact, bundle, signer=signer, **extra)


def site(routes, seen=None):
    def fetch(url):
        if seen is not None:
            seen.append(url)
        return routes.get(url)
    return fetch


def decode(_bytes):
    # The signed fixture is not a policy document; supply the field the rollback rule reads.
    return {"published_at": "2026-11-20T04:00:00.000Z"}


def flip(b64):
    raw = bytearray(base64.b64decode(b64))
    raw[-1] ^= 1
    return base64.b64encode(bytes(raw)).decode()


class Refuses:
    def assertRefused(self, code, call, *args, **kwargs):
        with self.assertRaises(pt.PolicyTransparencyError) as caught:
            call(*args, **kwargs)
        self.assertEqual(caught.exception.code, code, str(caught.exception))


@unittest.skipUnless(HAVE_SIGSTORE, "needs the 'transparency' extra (sigstore)")
class SignatureTests(Refuses, unittest.TestCase):
    def test_real_bundle_verifies_offline_against_the_shipped_root(self):
        result = verify()
        self.assertEqual(result["sha256"], "0cb9bc491aed89a6bed88d89a61cd0bbf97f30d0906ac6e99ecb5b2d9d4d6aaf")
        self.assertEqual(result["signedAt"], SIGNED_AT)
        self.assertEqual(result["log"], [{"logId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=", "logIndex": "4016955355", "kind": "hashedrekord/0.0.1"}])

    def test_same_valid_bundle_is_refused_for_the_production_identity(self):
        self.assertRefused("WRONG_SIGNER", verify, signer=pt.PRODUCTION_SIGNER)

    def test_every_pinned_identity_field_is_compared_exactly(self):
        variants = {
            "san": FIXTURE_SIGNER["san"][:-1],
            "issuer": "https://accounts.google.com",
            "repository": "https://github.com/goreleaser/goreleaser-pro",
            "repositoryId": "1",
            "ownerId": "1",
            "ref": "refs/heads/main",
            "trigger": "workflow_dispatch",
            "runner": "self-hosted",
        }
        for field, value in variants.items():
            with self.subTest(field=field):
                self.assertRefused("WRONG_SIGNER", verify, signer={**FIXTURE_SIGNER, field: value})
        self.assertRefused("WRONG_SIGNER", verify, signer={**FIXTURE_SIGNER, "san": "https://github.com/goreleaser/.*"})

    def test_one_flipped_byte_in_the_policy_is_refused(self):
        for index in (0, 1234, len(ARTIFACT) - 1):
            tampered = bytearray(ARTIFACT)
            tampered[index] ^= 1
            with self.subTest(index=index):
                self.assertRefused("SIGNATURE", verify, artifact=bytes(tampered))
        self.assertRefused("SIGNATURE", verify, artifact=ARTIFACT + b"\n")

    def test_a_tampered_bundle_is_refused(self):
        def mutated(change):
            bundle = json.loads(BUNDLE)
            change(bundle)
            return json.dumps(bundle)

        def signature(b): b["messageSignature"]["signature"] = flip(b["messageSignature"]["signature"])
        def proof(b): b["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["hashes"][0] = flip(b["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["hashes"][0])
        def promise(b): b["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"]["signedEntryTimestamp"] = flip(b["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"]["signedEntryTimestamp"])
        def time(b): b["verificationMaterial"]["tlogEntries"][0]["integratedTime"] = str(int(b["verificationMaterial"]["tlogEntries"][0]["integratedTime"]) + 3600)
        for change in (signature, proof, promise, time):
            with self.subTest(change=change.__name__):
                self.assertRefused("SIGNATURE", verify, bundle=mutated(change))

    def test_a_bundle_without_an_inclusion_proof_is_refused(self):
        bundle = json.loads(BUNDLE)
        del bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
        with self.assertRaises(pt.PolicyTransparencyError) as caught:
            verify(bundle=json.dumps(bundle))
        self.assertIn(caught.exception.code, ("NOT_LOGGED", "BUNDLE_FORMAT"))
        self.assertRefused("BUNDLE_FORMAT", verify, bundle='{"not": "a bundle"}')

    def test_a_root_that_does_not_know_the_log_or_the_ca_refuses_the_bundle(self):
        root = json.loads(pt.BUNDLED_TRUSTED_ROOT.read_text())
        with tempfile.TemporaryDirectory() as scratch:
            for removed in ("tlogs", "certificateAuthorities"):
                path = Path(scratch) / f"no-{removed}.json"
                path.write_text(json.dumps({**root, removed: []}))
                with self.subTest(removed=removed):
                    self.assertRefused("SIGNATURE", verify, trusted_root=path)

    # Rekor v2: no integrated time and no signed entry timestamp; the signing
    # time comes from the RFC 3161 timestamp alone. Sigstore staging signature
    # from the conformance suite, with the staging root it was made under.
    V2 = FIXTURES / "rekor2"
    V2_SIGNER = {
        "san": "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main",
        "issuer": "https://token.actions.githubusercontent.com",
        "repository": "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon",
        "repositoryId": "632596897",
        "ownerId": "131804563",
        "ref": "refs/heads/main",
        "trigger": "workflow_dispatch",
        "runner": "github-hosted",
    }

    def test_rekor_v2_bundle_verifies_with_time_from_the_timestamp_authority(self):
        artifact, bundle, root = (self.V2 / "a.txt").read_bytes(), (self.V2 / "a.txt.sigstore.json").read_text(), self.V2 / "trusted_root.staging.json"
        result = verify(artifact, bundle, self.V2_SIGNER, trusted_root=root)
        self.assertEqual(result["log"][0]["kind"], "hashedrekord/0.0.2")
        self.assertRegex(result["signedAt"], r"^2025-06-12T12:0\d:\d\d\.000Z$")
        tampered = bytearray(artifact)
        tampered[3] ^= 1
        self.assertRefused("SIGNATURE", verify, bytes(tampered), bundle, self.V2_SIGNER, trusted_root=root)
        self.assertRefused("WRONG_SIGNER", verify, artifact, bundle, {**self.V2_SIGNER, "trigger": "push"}, trusted_root=root)

    def test_staging_signature_is_refused_under_the_shipped_production_root(self):
        self.assertRefused("SIGNATURE", verify, (self.V2 / "a.txt").read_bytes(), (self.V2 / "a.txt.sigstore.json").read_text(), self.V2_SIGNER)

    def test_fetch_accepts_pins_and_accepts_again(self):
        with tempfile.TemporaryDirectory() as home:
            seen = []
            result = pt.fetch_signed_policy(URL, state_dir=home, mode="enforce", signer=FIXTURE_SIGNER, floor=None, fetch=site(SIGNED_SITE, seen), decode=decode)
            self.assertEqual(seen, [URL, URL + ".sigstore.json"])
            self.assertEqual((result["status"], result["verification"]["signedAt"]), ("signed", SIGNED_AT))
            self.assertEqual(result["warnings"], [])
            pins = pt.read_pins(home)
            self.assertEqual(pins[URL]["sha256"], result["verification"]["sha256"])
            pt.fetch_signed_policy(URL, state_dir=home, mode="enforce", signer=FIXTURE_SIGNER, floor=None, fetch=site(SIGNED_SITE), decode=decode)
            self.assertEqual(pt.read_pins(home), pins)

    def test_fetch_wrong_bundle_is_refused_in_enforce_and_reported_in_warn(self):
        tampered = bytearray(ARTIFACT)
        tampered[10] ^= 1
        bad_site = {**SIGNED_SITE, URL: bytes(tampered)}
        with tempfile.TemporaryDirectory() as home:
            seen = []
            self.assertRefused("SIGNATURE", pt.fetch_signed_policy, URL, state_dir=home, mode="enforce", signer=FIXTURE_SIGNER, floor=None, fetch=site(bad_site, seen), decode=decode)
            self.assertEqual(len(seen), 4, "both files are fetched once more before giving up")
            self.assertRefused("WRONG_SIGNER", pt.fetch_signed_policy, URL, state_dir=home, mode="enforce", floor=None, fetch=site(SIGNED_SITE), decode=decode)
            warned = pt.fetch_signed_policy(URL, state_dir=home, mode="warn", signer=FIXTURE_SIGNER, floor=None, fetch=site(bad_site), decode=decode)
            self.assertEqual((warned["status"], warned["bytes"]), ("unverifiable", bytes(tampered)))
            self.assertIn("NOT accepted", warned["warnings"][0])
            self.assertEqual(pt.read_pins(home), {}, "nothing unverified is ever pinned")

    def test_fetch_rollback_is_refused_in_enforce_and_reported_in_warn(self):
        newer = {"signed": True, "sha256": "ff" * 32, "signedAt": "2026-11-22T00:00:00.000Z", "publishedAt": "2026-11-21T23:00:00.000Z", "logIndex": "4020000000"}
        with tempfile.TemporaryDirectory() as home:
            pt.write_pins(home, {URL: newer})
            self.assertRefused("ROLLBACK", pt.fetch_signed_policy, URL, state_dir=home, mode="enforce", signer=FIXTURE_SIGNER, floor=None, fetch=site(SIGNED_SITE), decode=decode)
            warned = pt.fetch_signed_policy(URL, state_dir=home, mode="warn", signer=FIXTURE_SIGNER, floor=None, fetch=site(SIGNED_SITE), decode=decode)
            self.assertEqual(warned["status"], "unverifiable")
            self.assertEqual(pt.read_pins(home)[URL], newer)
        self.assertRefused("ROLLBACK", pt.fetch_signed_policy, URL, mode="enforce", signer=FIXTURE_SIGNER, floor={"signedAt": "2026-11-22T00:00:00.000Z"}, fetch=site(SIGNED_SITE), decode=decode)

    def test_a_pin_written_by_the_node_runtime_is_honoured(self):
        # Same file name and fields as lib/policy-transparency.mjs writes.
        node_pin = {"signed": True, "sha256": "ab" * 32, "signedAt": "2026-11-23T10:00:00.000Z", "publishedAt": "2026-11-23T09:00:00.000Z", "logIndex": "1", "logId": "x"}
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / "policy-pins.json").write_text(json.dumps({URL: node_pin}, indent=2) + "\n")
            self.assertRefused("ROLLBACK", pt.fetch_signed_policy, URL, state_dir=home, mode="enforce", signer=FIXTURE_SIGNER, floor=None, fetch=site(SIGNED_SITE), decode=decode)


class RuleTests(Refuses, unittest.TestCase):
    """No cryptography: these run without the sigstore package."""

    VERIFICATION = {"sha256": "0c" * 32, "signedAt": SIGNED_AT, "log": [{"logId": "id", "logIndex": "7", "kind": "hashedrekord/0.0.1"}]}
    POLICY = {"published_at": "2026-11-20T04:00:00.000Z"}

    def test_rollback_rules(self):
        pin = pt.check_not_rolled_back(self.POLICY, self.VERIFICATION, None, None)
        self.assertEqual(pin, {"signed": True, "sha256": "0c" * 32, "signedAt": SIGNED_AT, "publishedAt": self.POLICY["published_at"], "logIndex": "7", "logId": "id"})
        pt.check_not_rolled_back(self.POLICY, self.VERIFICATION, pin, None)
        self.assertRefused("ROLLBACK", pt.check_not_rolled_back, self.POLICY, self.VERIFICATION, {**pin, "signedAt": "2026-11-21T00:00:00.000Z"}, None)
        self.assertRefused("ROLLBACK", pt.check_not_rolled_back, self.POLICY, self.VERIFICATION, {**pin, "sha256": "00" * 32}, None)
        self.assertRefused("ROLLBACK", pt.check_not_rolled_back, self.POLICY, self.VERIFICATION, {**pin, "signedAt": "2026-11-19T00:00:00.000Z", "publishedAt": "2026-11-20T04:10:00.000Z"}, None)
        self.assertRefused("ROLLBACK", pt.check_not_rolled_back, self.POLICY, self.VERIFICATION, None, {"signedAt": "2026-11-21T00:00:00.000Z"})
        self.assertRefused("POLICY", pt.check_not_rolled_back, {"published_at": "2026-11-20T05:00:00.000Z"}, self.VERIFICATION, None, None)
        self.assertRefused("POLICY", pt.check_not_rolled_back, {}, self.VERIFICATION, None, None)

    def test_enforce_refuses_unsigned_and_warn_accepts_with_a_warning(self):
        with tempfile.TemporaryDirectory() as home:
            self.assertRefused("UNSIGNED", pt.fetch_signed_policy, URL, state_dir=home, mode="enforce", fetch=site({URL: b"{}"}))
            result = pt.fetch_signed_policy(URL, state_dir=home, mode="warn", fetch=site({URL: b'{"status": "active"}'}))
            self.assertEqual(result["status"], "unsigned")
            self.assertIsNone(result["verification"])
            self.assertIn("no transparency signature", result["warnings"][0])
            self.assertEqual(pt.read_pins(home), {})

    def test_damaged_pin_file_is_an_error_not_an_empty_pin(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / "policy-pins.json").write_text("{broken")
            self.assertRefused("PIN", pt.fetch_signed_policy, URL, state_dir=home, mode="enforce", fetch=site({URL: b"{}"}))
            warned = pt.fetch_signed_policy(URL, state_dir=home, mode="warn", fetch=site({URL: b"{}"}))
            self.assertIn("pin file is damaged", warned["warnings"][0])
            self.assertEqual((Path(home) / "policy-pins.json").read_text(), "{broken")

    def test_mode_and_constants_match_the_node_runtime(self):
        with tempfile.TemporaryDirectory() as home:
            env = {"ACK_HOME": home}
            self.assertEqual(pt.transparency_mode(env), "warn")
            self.assertEqual(pt.transparency_mode({**env, "ACK_POLICY_TRANSPARENCY": "enforce"}), "enforce")
            self.assertRefused("CONFIG", pt.transparency_mode, {**env, "ACK_POLICY_TRANSPARENCY": "off"})
            # The file `ack policy enforce` writes.
            (Path(home) / "policy-transparency-mode").write_text("enforce\n")
            self.assertEqual(pt.transparency_mode(env), "enforce")
            self.assertEqual(pt.transparency_mode({**env, "ACK_POLICY_TRANSPARENCY": "warn"}), "warn")
        node = (KIT / "lib" / "policy-transparency.mjs").read_text()
        for value in list(pt.PRODUCTION_SIGNER.values()) + [pt.POLICY_FLOOR["signedAt"]]:
            self.assertIn(f"'{value}'", node)
        self.assertEqual(pt.BUNDLED_TRUSTED_ROOT.read_bytes(), (KIT / "resources" / "sigstore" / "trusted_root.json").read_bytes())


if __name__ == "__main__":
    unittest.main()

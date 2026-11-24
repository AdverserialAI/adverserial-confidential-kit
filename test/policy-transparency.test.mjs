// Offline tests for the policy transparency check.
//
// Nobody outside the publishing workflow can produce a signature from the
// production identity, so the cryptographic path is exercised with a real
// public Sigstore bundle: the checksums file of goreleaser v2.20.3, signed by
// that project's GitHub Actions release workflow and logged in Rekor.
//   https://github.com/goreleaser/goreleaser/releases/download/v2.20.3/checksums.txt                (5271 bytes)
//   https://github.com/goreleaser/goreleaser/releases/download/v2.20.3/checksums.txt.sigstore.json  (10315 bytes)
// The trusted root is resources/sigstore/trusted_root.json, the one shipped.
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PRODUCTION_SIGNER, PolicyTransparencyError, checkNotRolledBack, describePolicyStatus, fetchSignedPolicy, loadTrustedRoot,
  nodeSupportsSigstore, readPins, saveTransparencyMode, transparencyMode, verifyPolicySignature
} from '../lib/policy-transparency.mjs';

// Tests that run the Sigstore verifier need a Node.js it supports (see README).
const sig = (name, run) => test(name, { skip: nodeSupportsSigstore() ? false : `Node ${process.versions.node} cannot run the Sigstore verifier` }, run);
const fixture = (name) => fileURLToPath(new URL(`./fixtures/sigstore/${name}`, import.meta.url));
const ARTIFACT = readFileSync(fixture('goreleaser-v2.20.3-checksums.txt'));
const BUNDLE = readFileSync(fixture('goreleaser-v2.20.3-checksums.txt.sigstore.json'), 'utf8');
const FIXTURE_SIGNER = Object.freeze({
  san: 'https://github.com/goreleaser/goreleaser/.github/workflows/release.yml@refs/tags/v2.20.3',
  issuer: 'https://token.actions.githubusercontent.com',
  repository: 'https://github.com/goreleaser/goreleaser',
  repositoryId: '77071454',
  ownerId: '24697112',
  ref: 'refs/tags/v2.20.3',
  trigger: 'push',
  runner: 'github-hosted'
});
const SIGNED_AT = '2026-11-20T04:21:30.000Z';
const code = (expected) => (error) => error instanceof PolicyTransparencyError && error.code === expected;
const verify = (overrides = {}) => verifyPolicySignature({ policyBytes: ARTIFACT, bundleJson: BUNDLE, signer: FIXTURE_SIGNER, ...overrides });

sig('a real GitHub Actions Sigstore bundle verifies offline against the shipped trusted root', async () => {
  const result = await verify();
  assert.equal(result.sha256, '0cb9bc491aed89a6bed88d89a61cd0bbf97f30d0906ac6e99ecb5b2d9d4d6aaf');
  assert.equal(result.signedAt, SIGNED_AT);
  assert.equal(result.signer.san, FIXTURE_SIGNER.san);
  assert.equal(result.signer.trigger, 'push');
  assert.equal(result.signer.commit, 'a6edafaafe0fd15a4725e917beac26305ba67738');
  assert.deepEqual(result.log, [{ logId: 'wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=', logIndex: '4016955355', kind: 'hashedrekord/0.0.1' }]);
});

sig('the same valid bundle is refused for the production identity', async () => {
  await assert.rejects(() => verify({ signer: PRODUCTION_SIGNER }), code('WRONG_SIGNER'));
});

sig('every pinned identity field is compared exactly', async () => {
  const variants = {
    // A prefix of the real identity: an unanchored pattern match would accept it.
    san: 'https://github.com/goreleaser/goreleaser/.github/workflows/release.yml@refs/tags/v2.20',
    issuer: 'https://accounts.google.com',
    repository: 'https://github.com/goreleaser/goreleaser-pro',
    repositoryId: '1',
    ownerId: '1',
    ref: 'refs/heads/main',
    trigger: 'workflow_dispatch',
    runner: 'self-hosted'
  };
  for (const [field, value] of Object.entries(variants)) {
    await assert.rejects(() => verify({ signer: { ...FIXTURE_SIGNER, [field]: value } }), code('WRONG_SIGNER'), field);
  }
  // Regular-expression metacharacters in the pin are literals.
  await assert.rejects(() => verify({ signer: { ...FIXTURE_SIGNER, san: 'https://github.com/goreleaser/.*' } }), code('WRONG_SIGNER'));
});

sig('one flipped byte in the policy is refused', async () => {
  for (const index of [0, 1234, ARTIFACT.length - 1]) {
    const tampered = Buffer.from(ARTIFACT);
    tampered[index] ^= 0x01;
    await assert.rejects(() => verify({ policyBytes: tampered }), code('SIGNATURE'), `byte ${index}`);
  }
  await assert.rejects(() => verify({ policyBytes: Buffer.concat([ARTIFACT, Buffer.from('\n')]) }), code('SIGNATURE'));
});

sig('a tampered bundle is refused', async () => {
  const mutate = (change) => { const bundle = JSON.parse(BUNDLE); change(bundle); return bundle; };
  const flip = (base64) => { const bytes = Buffer.from(base64, 'base64'); bytes[bytes.length - 1] ^= 0x01; return bytes.toString('base64'); };
  // Signature over the artifact.
  await assert.rejects(() => verify({ bundleJson: mutate((b) => { b.messageSignature.signature = flip(b.messageSignature.signature); }) }), code('SIGNATURE'));
  // Merkle inclusion proof.
  await assert.rejects(() => verify({ bundleJson: mutate((b) => { const p = b.verificationMaterial.tlogEntries[0].inclusionProof; p.hashes[0] = flip(p.hashes[0]); }) }), code('SIGNATURE'));
  // Signed entry timestamp.
  await assert.rejects(() => verify({ bundleJson: mutate((b) => { const p = b.verificationMaterial.tlogEntries[0].inclusionPromise; p.signedEntryTimestamp = flip(p.signedEntryTimestamp); }) }), code('SIGNATURE'));
  // Log time moved outside the certificate's ten-minute validity.
  await assert.rejects(() => verify({ bundleJson: mutate((b) => { b.verificationMaterial.tlogEntries[0].integratedTime = String(Number(b.verificationMaterial.tlogEntries[0].integratedTime) + 3600); }) }), code('SIGNATURE'));
});

sig('a bundle without an inclusion proof or without a log entry is refused', async () => {
  const bundle = JSON.parse(BUNDLE);
  delete bundle.verificationMaterial.tlogEntries[0].inclusionProof;
  await assert.rejects(() => verify({ bundleJson: bundle }), (error) => ['NOT_LOGGED', 'BUNDLE_FORMAT'].includes(error.code));
  const none = JSON.parse(BUNDLE);
  none.verificationMaterial.tlogEntries = [];
  await assert.rejects(() => verify({ bundleJson: none }), (error) => ['NOT_LOGGED', 'BUNDLE_FORMAT'].includes(error.code));
  await assert.rejects(() => verify({ bundleJson: '{"not":"a bundle"}' }), code('BUNDLE_FORMAT'));
});

sig('a trusted root that does not know the log or the CA refuses the bundle', async () => {
  const withoutLogs = { ...loadTrustedRoot(), tlogs: [] };
  await assert.rejects(() => verify({ trustedRoot: withoutLogs }), code('SIGNATURE'));
  const withoutCA = { ...loadTrustedRoot(), certificateAuthorities: [] };
  await assert.rejects(() => verify({ trustedRoot: withoutCA }), code('SIGNATURE'));
});

// Rekor v2: no integrated time and no signed entry timestamp; the signing time
// comes from the RFC 3161 timestamp alone. Sigstore staging signature from the
// conformance suite, with the staging trusted root it was made under.
const V2_ARTIFACT = readFileSync(fixture('rekor2/a.txt'));
const V2_BUNDLE = readFileSync(fixture('rekor2/a.txt.sigstore.json'), 'utf8');
const V2_ROOT = JSON.parse(readFileSync(fixture('rekor2/trusted_root.staging.json'), 'utf8'));
const V2_SIGNER = Object.freeze({
  san: 'https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main',
  issuer: 'https://token.actions.githubusercontent.com',
  repository: 'https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon',
  repositoryId: '632596897',
  ownerId: '131804563',
  ref: 'refs/heads/main',
  trigger: 'workflow_dispatch',
  runner: 'github-hosted'
});

sig('a Rekor v2 bundle verifies, with the signing time taken from the timestamp authority', async () => {
  const result = await verifyPolicySignature({ policyBytes: V2_ARTIFACT, bundleJson: V2_BUNDLE, signer: V2_SIGNER, trustedRoot: V2_ROOT });
  assert.deepEqual(result.log.map((entry) => entry.kind), ['hashedrekord/0.0.2']);
  assert.match(result.signedAt, /^2025-06-12T12:0\d:\d\d\.000Z$/);
  const tampered = Buffer.from(V2_ARTIFACT);
  tampered[3] ^= 0x01;
  await assert.rejects(() => verifyPolicySignature({ policyBytes: tampered, bundleJson: V2_BUNDLE, signer: V2_SIGNER, trustedRoot: V2_ROOT }), code('SIGNATURE'));
  // The production pin requires the push trigger: a manually dispatched run of
  // the right workflow on the right branch is still refused.
  await assert.rejects(() => verifyPolicySignature({ policyBytes: V2_ARTIFACT, bundleJson: V2_BUNDLE, signer: { ...V2_SIGNER, trigger: 'push' }, trustedRoot: V2_ROOT }), code('WRONG_SIGNER'));
});

sig('a Sigstore staging signature is refused under the shipped production root', async () => {
  await assert.rejects(() => verifyPolicySignature({ policyBytes: V2_ARTIFACT, bundleJson: V2_BUNDLE, signer: V2_SIGNER }), code('SIGNATURE'));
});

sig('rollback: an older signature, an equal-time different policy and a back-dated policy are refused', async () => {
  const verification = await verify();
  const policy = { published_at: '2026-11-20T04:00:00.000Z' };
  const pin = checkNotRolledBack({ policy, verification, pin: null, floor: null });
  assert.deepEqual(pin, { signed: true, sha256: verification.sha256, signedAt: SIGNED_AT, publishedAt: policy.published_at, logIndex: '4016955355', logId: 'wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=' });
  // The same policy again is fine.
  checkNotRolledBack({ policy, verification, pin, floor: null });
  // The installation has already accepted something newer.
  assert.throws(() => checkNotRolledBack({ policy, verification, pin: { ...pin, signedAt: '2026-11-21T00:00:00.000Z' }, floor: null }), code('ROLLBACK'));
  assert.throws(() => checkNotRolledBack({ policy, verification, pin: { ...pin, sha256: '00'.repeat(32) }, floor: null }), code('ROLLBACK'));
  assert.throws(() => checkNotRolledBack({ policy, verification, pin: { ...pin, signedAt: '2026-11-19T00:00:00.000Z', publishedAt: '2026-11-20T04:10:00.000Z' }, floor: null }), code('ROLLBACK'));
  // The release floor applies on a machine with no pin at all.
  assert.throws(() => checkNotRolledBack({ policy, verification, pin: null, floor: { signedAt: '2026-11-21T00:00:00.000Z' } }), code('ROLLBACK'));
  // published_at cannot be later than the log time.
  assert.throws(() => checkNotRolledBack({ policy: { published_at: '2026-11-20T05:00:00.000Z' }, verification, pin: null, floor: null }), code('POLICY'));
  assert.throws(() => checkNotRolledBack({ policy: {}, verification, pin: null, floor: null }), code('POLICY'));
});

// fetchSignedPolicy end to end. The signed fixture is a checksums file, not a
// policy document, so `decode` supplies the one field the rollback rule reads.
const URL_ = 'https://verify.example.test/policies/production.json';
const SIGNED_ROUTES = { [URL_]: ARTIFACT, [`${URL_}.sigstore.json`]: BUNDLE };
const decode = () => ({ published_at: '2026-11-20T04:00:00.000Z' });
const responder = (routes, seen = []) => async (url) => {
  seen.push(String(url));
  const body = routes[String(url)];
  if (body === undefined) return { ok: false, status: 404, arrayBuffer: async () => new ArrayBuffer(0) };
  const bytes = Buffer.from(body);
  return { ok: true, status: 200, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length) };
};
const withHome = async (run) => {
  const home = await mkdtemp(join(tmpdir(), 'ack-policy-'));
  try { await run(home); } finally { await rm(home, { recursive: true, force: true }); }
};
const options = (home, extra = {}) => ({ url: URL_, stateDir: home, mode: 'enforce', signer: FIXTURE_SIGNER, floor: null, decode, ...extra });

sig('fetch: a signed policy is accepted, pinned, and accepted again', () => withHome(async (home) => {
  const seen = [];
  const result = await fetchSignedPolicy(options(home, { fetchImpl: responder(SIGNED_ROUTES, seen) }));
  assert.deepEqual(seen, [URL_, `${URL_}.sigstore.json`]);
  assert.equal(result.status, 'signed');
  assert.equal(result.verification.signedAt, SIGNED_AT);
  assert.deepEqual(result.warnings, []);
  assert.ok(result.bytes.equals(ARTIFACT));
  const pins = await readPins(home);
  assert.equal(pins[URL_].sha256, result.verification.sha256);
  assert.equal(pins[URL_].signed, true);
  await fetchSignedPolicy(options(home, { fetchImpl: responder(SIGNED_ROUTES) }));
  assert.deepEqual(await readPins(home), pins);
}));

test('fetch: enforce refuses an unsigned policy; warn uses it, says "unsigned" and writes no pin', () => withHome(async (home) => {
  const fetchImpl = responder({ [URL_]: ARTIFACT });
  await assert.rejects(() => fetchSignedPolicy(options(home, { fetchImpl })), code('UNSIGNED'));
  const result = await fetchSignedPolicy(options(home, { fetchImpl, mode: 'warn' }));
  assert.equal(result.status, 'unsigned');
  assert.equal(result.verification, null);
  assert.match(result.warnings[0], /no transparency signature/);
  assert.match(describePolicyStatus(result), /^unsigned \(not published \(404\)\)/);
  assert.deepEqual(await readPins(home), {});
}));

sig('fetch: a wrong bundle is refused in enforce mode and reported, never blocking, in warn mode', () => withHome(async (home) => {
  const tampered = Buffer.from(ARTIFACT);
  tampered[10] ^= 0x01;
  const seen = [];
  const tamperedSite = () => responder({ ...SIGNED_ROUTES, [URL_]: tampered }, seen);
  await assert.rejects(() => fetchSignedPolicy(options(home, { fetchImpl: tamperedSite() })), code('SIGNATURE'));
  assert.equal(seen.length, 4, 'both files are fetched once more before giving up');
  await assert.rejects(() => fetchSignedPolicy(options(home, { signer: PRODUCTION_SIGNER, fetchImpl: responder(SIGNED_ROUTES) })), code('WRONG_SIGNER'));

  const warned = await fetchSignedPolicy(options(home, { mode: 'warn', fetchImpl: tamperedSite() }));
  assert.equal(warned.status, 'unverifiable');
  assert.ok(warned.bytes.equals(tampered), 'warn mode still hands back the served policy');
  assert.match(warned.warnings[0], /NOT accepted/);
  const wrongSigner = await fetchSignedPolicy(options(home, { mode: 'warn', signer: PRODUCTION_SIGNER, fetchImpl: responder(SIGNED_ROUTES) }));
  assert.equal(wrongSigner.status, 'unverifiable');
  assert.match(describePolicyStatus(wrongSigner), /^unverifiable: The policy was not signed by the approved publishing workflow/);
  assert.deepEqual(await readPins(home), {}, 'nothing unverified is ever pinned');
}));

sig('fetch: a validly signed but older policy is a rollback: refused in enforce, reported in warn, pin unmoved', () => withHome(async (home) => {
  const newer = { signed: true, sha256: 'ff'.repeat(32), signedAt: '2026-11-22T00:00:00.000Z', publishedAt: '2026-11-21T23:00:00.000Z', logIndex: '4020000000' };
  await writeFile(join(home, 'policy-pins.json'), JSON.stringify({ [URL_]: newer }));
  await assert.rejects(() => fetchSignedPolicy(options(home, { fetchImpl: responder(SIGNED_ROUTES) })), code('ROLLBACK'));
  const warned = await fetchSignedPolicy(options(home, { mode: 'warn', fetchImpl: responder(SIGNED_ROUTES) }));
  assert.equal(warned.status, 'unverifiable');
  assert.match(warned.reason, /before the policy already accepted here/);
  assert.deepEqual((await readPins(home))[URL_], newer);
  // With no local pin, the floor shipped in the release still applies.
  await assert.rejects(() => fetchSignedPolicy(options(undefined, { floor: { signedAt: '2026-11-22T00:00:00.000Z' }, fetchImpl: responder(SIGNED_ROUTES) })), code('ROLLBACK'));
}));

sig('fetch: a damaged pin file is an error in enforce mode; warn mode reports it and leaves the file alone', () => withHome(async (home) => {
  await writeFile(join(home, 'policy-pins.json'), '{broken');
  await assert.rejects(() => fetchSignedPolicy(options(home, { fetchImpl: responder(SIGNED_ROUTES) })), code('PIN'));
  const warned = await fetchSignedPolicy(options(home, { mode: 'warn', fetchImpl: responder(SIGNED_ROUTES) }));
  assert.equal(warned.status, 'signed');
  assert.match(warned.warnings[0], /pin file is damaged/);
  assert.equal(await readFile(join(home, 'policy-pins.json'), 'utf8'), '{broken');
}));

test('a Node too old for the Sigstore verifier: warn says so and continues, enforce refuses', () => withHome(async (home) => {
  for (const [version, supported] of [['18.20.4', false], ['20.19.0', false], ['22.11.0', false], ['22.22.2', true], ['23.9.0', false], ['24.15.0', true], ['26.5.0', true]]) {
    assert.equal(nodeSupportsSigstore(version), supported, version);
  }
  const old = { nodeVersion: '20.19.0', fetchImpl: responder(SIGNED_ROUTES) };
  const warned = await fetchSignedPolicy(options(home, { ...old, mode: 'warn' }));
  assert.equal(warned.status, 'unverifiable');
  assert.match(warned.warnings[0], /policy signature not checked \(Node too old\)/);
  assert.ok(warned.bytes.equals(ARTIFACT));
  await assert.rejects(() => fetchSignedPolicy(options(home, old)), code('UNAVAILABLE'));
  assert.deepEqual(await readPins(home), {});
}));

sig('describePolicyStatus names the signer, the log index and the integrated time', () => withHome(async (home) => {
  const result = await fetchSignedPolicy(options(home, { fetchImpl: responder(SIGNED_ROUTES) }));
  assert.equal(describePolicyStatus(result), `signed by ${FIXTURE_SIGNER.san}; Rekor log index 4016955355; logged ${SIGNED_AT}; sha256:0cb9bc491aed89a6bed88d89a61cd0bbf97f30d0906ac6e99ecb5b2d9d4d6aaf`);
}));

test('the mode comes from ACK_POLICY_TRANSPARENCY, then from `ack policy enforce`, then the default', () => withHome(async (home) => {
  const env = { ACK_HOME: home };
  assert.equal(transparencyMode(env), 'warn');
  await saveTransparencyMode('enforce', env);
  assert.equal(transparencyMode(env), 'enforce');
  assert.equal(transparencyMode({ ...env, ACK_POLICY_TRANSPARENCY: 'warn' }), 'warn');
  await saveTransparencyMode('warn', env);
  assert.equal(transparencyMode(env), 'warn');
  assert.equal(transparencyMode({ ...env, ACK_POLICY_TRANSPARENCY: 'enforce' }), 'enforce');
  assert.throws(() => transparencyMode({ ...env, ACK_POLICY_TRANSPARENCY: 'off' }), code('CONFIG'));
  await assert.rejects(() => saveTransparencyMode('off', env), code('CONFIG'));
}));

test('the production pin names one workflow on one branch of one repository', async () => {
  assert.match(PRODUCTION_SIGNER.san, /^https:\/\/github\.com\/AdverserialAI\/[a-z-]+\/\.github\/workflows\/[a-z-]+\.yml@refs\/heads\/main$/);
  assert.equal(PRODUCTION_SIGNER.issuer, 'https://token.actions.githubusercontent.com');
  assert.ok(PRODUCTION_SIGNER.san.startsWith(`${PRODUCTION_SIGNER.repository}/`));
  const root = JSON.parse(await readFile(new URL('../resources/sigstore/trusted_root.json', import.meta.url), 'utf8'));
  assert.equal(root.mediaType, 'application/vnd.dev.sigstore.trustedroot+json;version=0.1');
});

import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { evidenceDigest } from '../resources/typescript/dist/canonjson.js';
import { activateModel, receiptPinStatus, receiptPinsMatch } from '../lib/ack.mjs';

const productionURL = 'https://verify.adverserial.ai/policies/production.json';
const oldKeys = { 'old-kid': { kty: 'EC', crv: 'P-256', x: 'old-x', y: 'old-y' } };
const newKeys = { 'new-kid': { kty: 'EC', crv: 'P-256', x: 'new-x', y: 'new-y' } };
const policy = (receipt_keys) => ({ status: 'active', model_id: 'adverserial/cyberseek', receipt_keys });
// A policy site that publishes no Sigstore bundle (signed paths: policy-transparency.test.mjs).
const serving = (document) => async (url) => {
  if (url === `${productionURL}.sigstore.json`) return { ok: false, status: 404, arrayBuffer: async () => new ArrayBuffer(0) };
  assert.equal(url, productionURL);
  const bytes = Buffer.from(JSON.stringify(document));
  return { ok: true, status: 200, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length) };
};

test('pins match only when every published receipt key is pinned unchanged', () => {
  assert.equal(receiptPinsMatch(newKeys, newKeys), true);
  assert.equal(receiptPinsMatch(oldKeys, newKeys), false);
  assert.equal(receiptPinsMatch({ ...oldKeys, ...newKeys }, newKeys), false, 'a retired pin must not linger');
  assert.equal(receiptPinsMatch(newKeys, { ...oldKeys, ...newKeys }), false, 'an overlap-period key must be pinned too');
  assert.equal(receiptPinsMatch({ 'new-kid': { ...newKeys['new-kid'], x: 'other' } }, newKeys), false, 'same kid, different key');
  assert.equal(receiptPinsMatch(null, newKeys), false);
  assert.equal(receiptPinsMatch({}, newKeys), false);
});

test('after the service rotates its keys, doctor says so and the re-pin path used by ack upgrade recovers', async () => {
  const home = await mkdtemp(join(tmpdir(), 'ack-rotation-'));
  try {
    const env = { ACK_HOME: home, HOME: home, ACK_QUIET: '1', NODE_ENV: 'test', ACK_TEST_STORAGE_KEY: Buffer.alloc(32, 9).toString('base64url') };
    await writeFile(join(home, 'ack.json'), JSON.stringify({ version: 1, model: 'adverserial/cyberseek', endpoint: 'https://api.adverserial.ai/v1', apiKey: 'private-test-key-for-rotation' }));
    await writeFile(join(home, 'receipt-keys.json'), JSON.stringify(oldKeys));

    const before = await receiptPinStatus(env, { fetchImpl: serving(policy(newKeys)), model: 'adverserial/cyberseek' });
    assert.equal(before.ok, false);
    assert.match(before.detail, /rotated its keys/);
    assert.match(before.detail, /ack upgrade/);
    // Checking never re-pins: only an explicit command replaces the trust anchor.
    assert.deepEqual(JSON.parse(await readFile(join(home, 'receipt-keys.json'), 'utf8')), oldKeys);

    await activateModel('adverserial/cyberseek', env, { models: [{ id: 'adverserial/cyberseek' }], fetchImpl: serving(policy(newKeys)) });
    assert.deepEqual(JSON.parse(await readFile(join(home, 'receipt-keys.json'), 'utf8')), newKeys);
    const after = await receiptPinStatus(env, { fetchImpl: serving(policy(newKeys)), model: 'adverserial/cyberseek' });
    assert.equal(after.ok, true);
    assert.match(after.detail, /Match the published policy/);
  } finally { await rm(home, { recursive: true, force: true }); }
});

test('the pin check degrades safely offline, before init, and with damaged pins', async () => {
  const home = await mkdtemp(join(tmpdir(), 'ack-rotation-'));
  try {
    const env = { ACK_HOME: home, HOME: home, ACK_QUIET: '1' };
    assert.deepEqual(await receiptPinStatus(env, { fetchImpl: serving(policy(newKeys)) }), { ok: false, detail: 'Run init to fetch the published policy' });
    await writeFile(join(home, 'receipt-keys.json'), '{}');
    assert.match((await receiptPinStatus(env, { fetchImpl: serving(policy(newKeys)) })).detail, /incomplete\. Run ack upgrade/);
    await writeFile(join(home, 'receipt-keys.json'), JSON.stringify(oldKeys));
    const offline = await receiptPinStatus(env, { fetchImpl: async () => { throw new Error('offline'); } });
    assert.equal(offline.ok, true);
    assert.match(offline.detail, /could not be reached/);
  } finally { await rm(home, { recursive: true, force: true }); }
});

// A service whose receipt key differs from the one this machine pinned.
function rotatedService() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const stale = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'rotated' };
  const der = publicKey.export({ format: 'der', type: 'spki' });
  const evidence = { dev: false, tdx_quote: 'fixture-quote', tdx_event_log: [], tls_spki_der: der.toString('base64url'), tls_spki_sha256: 'sha256:' + createHash('sha256').update(der).digest('base64url'), receipt_pubkey_jwk: jwk, attestation_state_digest: 'sha256:fixture-state' };
  let hardwareCalls = 0;
  const options = {
    expectedModelId: 'fixture', issuer: 'fixture-issuer', audience: 'fixture-audience',
    trustedReceiptKeys: { previous: { ...stale, kid: 'previous' } },
    verifyHardwareEvidence: async () => { hardwareCalls++; return { verified: true, verifier: 'fixture-only' }; },
    fetchImpl: async (url) => {
      const now = Math.floor(Date.now() / 1000);
      const claims = { iat: now, exp: now + 30, iss: 'fixture-issuer', aud: 'fixture-audience', model_id: 'fixture', endpoint: 'https://fixture.invalid', nonce: new URL(url).searchParams.get('nonce'), verdict: 'verified', evidence_sha256: await evidenceDigest(evidence) };
      const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
      const input = encode({ alg: 'ES256', kid: 'rotated' }) + '.' + encode(claims);
      const signature = sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
      return new Response(JSON.stringify({ evidence, verification_receipt: input + '.' + signature }), { status: 200 });
    }
  };
  return { options, jwk, hardwareCalls: () => hardwareCalls };
}

test('every bundled JS verifier rejects a rotated receipt key and names ack upgrade', async (t) => {
  const home = await mkdtemp(join(tmpdir(), 'ack-rotation-verifier-'));
  t.after(() => rm(home, { recursive: true, force: true }));
  const modules = [
    await import('../resources/typescript/dist/verify.js'),
    await import('../resources/plugins/opencode/dist/typescript/src/verify.js'),
    await import('../resources/plugins/kimi-code/dist/typescript/src/verify.js')
  ];
  const bundles = ['claude-code/bin/adverserial-verify-cli.mjs', 'adverserial-verify/bin/adverserial-verify.mjs'];
  for (const [index, relative] of bundles.entries()) {
    const source = await readFile(new URL('../resources/plugins/' + relative, import.meta.url), 'utf8');
    assert.ok(source.includes('process.exitCode = await main();'));
    const path = join(home, `bundle-${index}.mjs`);
    await writeFile(path, source.replace('process.exitCode = await main();', 'export { verifyEndpoint };'));
    modules.push(await import(pathToFileURL(path)));
  }
  const kimi = await readFile(new URL('../resources/plugins/kimi-code/dist/adverserial-verify.bundle.mjs', import.meta.url), 'utf8');
  assert.match(kimi, /The service rotated its keys: .*Run `ack upgrade`/);
  for (const module of modules) {
    const service = rotatedService();
    const rejected = await module.verifyEndpoint('https://fixture.invalid/v1', service.options);
    assert.equal(rejected.status, 'failed');
    assert.match(rejected.reason, /The service rotated its keys/);
    assert.match(rejected.reason, /Run `ack upgrade`/);
    assert.equal(service.hardwareCalls(), 0, 'an unknown signer is rejected before hardware verification');
    // A key id that only exists on Object.prototype is not a pin.
    const inherited = await module.verifyEndpoint('https://fixture.invalid/v1', { ...service.options, trustedReceiptKeys: Object.create({ rotated: service.jwk }) });
    assert.equal(inherited.status, 'failed');
    // Re-pinning (what ack upgrade does) is the only thing that makes it verify.
    const repinned = await module.verifyEndpoint('https://fixture.invalid/v1', { ...service.options, trustedReceiptKeys: { rotated: service.jwk } });
    assert.equal(repinned.status, 'verified');
  }
});

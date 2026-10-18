import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { activateModel, publishedModelPolicy } from '../lib/ack.mjs';

const productionURL = 'https://verify.adverserial.ai/policies/production.json';
const currentKeys = { current: { kty: 'EC', crv: 'P-256', x: 'current-x', y: 'current-y' } };
const production = { status: 'active', model_id: 'lordx64/cyberglm', receipt_keys: currentKeys };
const models = [{ id: 'lordx64/cyberglm', policyRef: 'policies/lordx64-cyberglm.json' }];
function fetchFixture(documents, requested = []) {
  return async (url) => {
    requested.push(url);
    assert.ok(url in documents, `Unexpected policy request: ${url}`);
    return { ok: true, json: async () => structuredClone(documents[url]) };
  };
}

test('model activation uses the current production policy despite a stale registry template reference', async () => {
  const home = await mkdtemp(join(tmpdir(), 'ack-activation-'));
  const requested = [];
  const apiKey = 'private-test-key-for-model-activation';
  try {
    await writeFile(join(home, 'ack.json'), JSON.stringify({ version: 1, model: 'lordx64/cyberglm', endpoint: 'https://api.adverserial.ai/v1', apiKey }));
    const env = { ACK_HOME: home, HOME: home, NODE_ENV: 'test', ACK_TEST_STORAGE_KEY: Buffer.alloc(32, 8).toString('base64url') };
    await activateModel('lordx64/cyberglm', env, { models, fetchImpl: fetchFixture({
      [productionURL]: production,
      'https://verify.adverserial.ai/policies/lordx64-cyberglm.json': { status: 'template-not-production', model_id: 'lordx64/cyberglm', receipt_keys: { obsolete: currentKeys.current } }
    }, requested) });
    assert.deepEqual(requested, [productionURL]);
    const stateText = await readFile(join(home, 'ack.json'), 'utf8');
    const state = JSON.parse(stateText);
    assert.equal(state.model, production.model_id);
    assert.equal(state.policyUrl, productionURL);
    assert.equal(stateText.includes(apiKey), false);
    assert.deepEqual(JSON.parse(await readFile(join(home, 'receipt-keys.json'), 'utf8')), currentKeys);
  } finally { await rm(home, { recursive: true, force: true }); }
});

test('a different model still needs its own active matching policy and receipt keys', async () => {
  const other = { id: 'lordx64/cyberkimi', policyRef: 'policies/lordx64-cyberkimi.json' };
  const otherURL = 'https://verify.adverserial.ai/policies/lordx64-cyberkimi.json';
  for (const invalid of [
    { ...production, model_id: other.id, status: 'template-not-production' },
    production,
    { ...production, model_id: other.id, receipt_keys: {} }
  ]) {
    await assert.rejects(() => publishedModelPolicy(other.id, { models: [other], fetchImpl: fetchFixture({ [productionURL]: production, [otherURL]: invalid }) }), /complete active/);
  }
  const active = { ...production, model_id: other.id };
  const result = await publishedModelPolicy(other.id, { models: [other], fetchImpl: fetchFixture({ [productionURL]: production, [otherURL]: active }) });
  assert.equal(result.policy.model_id, other.id);
  assert.equal(result.url, otherURL);
});

test('inactive or unpinned production policy cannot activate the production model', async () => {
  for (const invalid of [{ ...production, status: 'revoked' }, { ...production, receipt_keys: {} }]) {
    await assert.rejects(() => publishedModelPolicy(production.model_id, { models, fetchImpl: fetchFixture({ [productionURL]: invalid }) }), /incomplete/);
  }
});

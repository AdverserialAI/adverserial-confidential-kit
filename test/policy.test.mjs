import assert from 'node:assert/strict';
import test from 'node:test';
import { fetchProductionPolicy } from '../lib/ack.mjs';

test('rejects a policy without pinned receipt keys', async () => {
  await assert.rejects(
    () => fetchProductionPolicy({ fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'active', model_id: 'lordx64/cyberglm', receipt_keys: {} }) }) }),
    /incomplete/
  );
});

test('accepts an active P-256 receipt-key policy', async () => {
  const result = await fetchProductionPolicy({ fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'active', model_id: 'lordx64/cyberglm', receipt_keys: { kid: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } } }) }) });
  assert.equal(result.model_id, 'lordx64/cyberglm');
});

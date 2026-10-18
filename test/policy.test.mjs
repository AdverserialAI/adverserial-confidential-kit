import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { resolveHarnessBinary } from '../lib/ack.mjs';
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

test('the packaged hardware verifier resolves its bundled runtime', async () => {
  const source = await readFile(join(process.cwd(), 'resources', 'typescript', 'adverserial-hardware-verify.mjs'), 'utf8');
  assert.match(source, /from '\.\/dist\/phala\.js'/);
});

test('finds an explicitly configured harness binary without relying on PATH', () => {
  assert.equal(resolveHarnessBinary('codex', { PATH: '', ACK_CODEX_BIN: '/bin/sh' }), '/bin/sh');
});

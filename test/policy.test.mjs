import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { configureKimi, configureOpenCode, resolveHarnessBinary } from '../lib/ack.mjs';
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

test('creates and refreshes an isolated managed Kimi model alias', async () => {
  const home = await mkdtemp(join(tmpdir(), 'ack-kimi-'));
  const kimiHome = join(home, '.kimi-code');
  try {
    await writeFile(join(home, 'preserved.toml'), '');
    const env = { HOME: home, KIMI_CODE_HOME: kimiHome, ADVERSERIAL_GATEWAY_PORT: '8766' };
    const state = { apiKey: 'test-key', model: 'lordx64/cyberglm' };
    assert.equal(await configureKimi(state, env), 'adverserial_confidential');
    let config = await readFile(join(kimiHome, 'config.toml'), 'utf8');
    assert.match(config, /\[models\.adverserial_confidential\]/);
    assert.match(config, /model = "lordx64\/cyberglm"/);
    assert.match(config, /base_url = "http:\/\/127\.0\.0\.1:8766\/v1"/);
    await configureKimi({ ...state, model: 'lordx64/cyberkimi' }, env);
    config = await readFile(join(kimiHome, 'config.toml'), 'utf8');
    assert.equal((config.match(/BEGIN ADVERSERIAL CONFIDENTIAL KIT/g) || []).length, 1);
    assert.match(config, /model = "lordx64\/cyberkimi"/);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('installs OpenCode verifier plugin files locally and gives the slash command a bundled fallback', async () => {
  const home = await mkdtemp(join(tmpdir(), 'ack-opencode-'));
  try {
    const env = { HOME: home, ADVERSERIAL_GATEWAY_PORT: '8766' };
    const state = { apiKey: 'test-key', model: 'lordx64/cyberglm' };
    const configured = await configureOpenCode(state, env);
    const root = join(configured.XDG_CONFIG_HOME, 'opencode');
    const wrapper = await readFile(join(root, 'plugins', 'adverserial.ts'), 'utf8');
    const command = await readFile(join(root, 'commands', 'adverserial-attestation.md'), 'utf8');
    const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
    assert.match(wrapper, /\.\/adverserial-dist\/plugins\/opencode\/src\/index\.js/);
    assert.equal((await stat(join(root, 'plugins', 'adverserial-dist', 'plugins', 'opencode', 'src', 'index.js'))).isFile(), true);
    assert.match(command, /adverserial-verify-cli\.mjs/);
    assert.doesNotMatch(command, /adverserial_verify/);
    assert.deepEqual(manifest.dependencies, {
      '@opencode-ai/plugin': '*',
      '@phala/dcap-qvl': '0.6.5',
      ehbp: '0.3.3'
    });
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

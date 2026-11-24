import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { configureKimi, configureOpenCode, harnessCommand, resolveHarnessBinary } from '../lib/ack.mjs';
import { fetchProductionPolicy } from '../lib/ack.mjs';

// An unsigned policy site: the document exists, its Sigstore bundle does not.
// The signed paths are covered in policy-transparency.test.mjs.
const unsignedSite = (document) => async (url) => {
  if (String(url).endsWith('.sigstore.json')) return { ok: false, status: 404, arrayBuffer: async () => new ArrayBuffer(0) };
  const bytes = Buffer.from(JSON.stringify(document));
  return { ok: true, status: 200, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length) };
};
const scratchEnv = async (extra = {}) => ({ ACK_HOME: await mkdtemp(join(tmpdir(), 'ack-policy-home-')), ACK_QUIET: '1', ...extra });

test('rejects a policy without pinned receipt keys', async () => {
  const env = await scratchEnv();
  try {
    await assert.rejects(
      () => fetchProductionPolicy({ env, fetchImpl: unsignedSite({ status: 'active', model_id: 'adverserial/cyberseek', receipt_keys: {} }) }),
      /incomplete/
    );
  } finally { await rm(env.ACK_HOME, { recursive: true, force: true }); }
});

test('accepts an active P-256 receipt-key policy while unsigned policies are still tolerated', async () => {
  const env = await scratchEnv();
  try {
    const result = await fetchProductionPolicy({ env, fetchImpl: unsignedSite({ status: 'active', model_id: 'adverserial/cyberseek', receipt_keys: { kid: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } } }) });
    assert.equal(result.model_id, 'adverserial/cyberseek');
  } finally { await rm(env.ACK_HOME, { recursive: true, force: true }); }
});

test('refuses an unsigned production policy once enforcement is on', async () => {
  const env = await scratchEnv({ ACK_POLICY_TRANSPARENCY: 'enforce' });
  try {
    await assert.rejects(
      () => fetchProductionPolicy({ env, fetchImpl: unsignedSite({ status: 'active', model_id: 'adverserial/cyberseek', receipt_keys: { kid: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } } }) }),
      /no transparency signature/
    );
  } finally { await rm(env.ACK_HOME, { recursive: true, force: true }); }
});

test('the packaged hardware verifier resolves its bundled runtime', async () => {
  const { hardwareRuntimeStatus } = await import('../lib/ack.mjs');
  assert.equal((await hardwareRuntimeStatus()).ok, true);
});

test('finds an explicitly configured harness binary without relying on PATH', () => {
  assert.equal(resolveHarnessBinary('codex', { PATH: '', ACK_CODEX_BIN: process.execPath }), process.execPath);
});

test('launches Oh My Pi with the Node-backed bundled verifier', async () => {
  const selected = await harnessCommand('oh-my-pi', { apiKey: 'test-key', model: 'adverserial/cyberseek' }, {
    HOME: tmpdir(), PATH: '', ACK_OMP_BIN: process.execPath
  });
  assert.equal(selected.command, process.execPath);
  assert.match(selected.env.ADVERSERIAL_VERIFY_COMMAND, /plugins[\\/]adverserial-verify[\\/]bin[\\/]adverserial-verify\.mjs$/);
  assert.match(selected.args.join(' '), /adverserial-confidential\/adverserial\/cyberseek/);
});

test('creates and refreshes an isolated managed Kimi model alias', async () => {
  const home = await mkdtemp(join(tmpdir(), 'ack-kimi-'));
  const kimiHome = join(home, '.kimi-code');
  try {
    await writeFile(join(home, 'preserved.toml'), '');
    const env = { HOME: home, KIMI_CODE_HOME: kimiHome, ADVERSERIAL_GATEWAY_PORT: '8766' };
    const state = { apiKey: 'test-key', model: 'adverserial/cyberseek' };
    assert.equal(await configureKimi(state, env), 'adverserial_confidential');
    let config = await readFile(join(kimiHome, 'config.toml'), 'utf8');
    assert.match(config, /\[models\.adverserial_confidential\]/);
    assert.match(config, /model = "adverserial\/cyberseek"/);
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
    const state = { apiKey: 'test-key', model: 'adverserial/cyberseek' };
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

test('policy transparency status reports unsigned, unreachable and refused without throwing', async () => {
  const { policyTransparencyStatus } = await import('../lib/ack.mjs');
  const document = { status: 'active', model_id: 'adverserial/cyberseek', receipt_keys: { kid: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } } };
  const env = await scratchEnv();
  try {
    const unsigned = await policyTransparencyStatus(env, { fetchImpl: unsignedSite(document) });
    assert.equal(unsigned.status, 'unsigned');
    assert.equal(unsigned.ok, false);
    assert.match(unsigned.detail, /^unsigned \(not published \(404\)\); used on HTTPS trust alone \[mode: warn\]$/);
    const down = await policyTransparencyStatus(env, { fetchImpl: async () => { throw new Error('offline'); } });
    assert.equal(down.status, 'unreachable');
    const enforced = await policyTransparencyStatus({ ...env, ACK_POLICY_TRANSPARENCY: 'enforce' }, { fetchImpl: unsignedSite(document) });
    assert.equal(enforced.status, 'refused');
    assert.match(enforced.detail, /no transparency signature/);
  } finally { await rm(env.ACK_HOME, { recursive: true, force: true }); }
});

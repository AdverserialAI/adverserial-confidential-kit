import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile, readFile, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { linuxStorageKey } from '../lib/linux-vault.mjs';

const skip = process.platform === 'win32';
const names = { service: 'test.service', account: 'test-account' };

// A stand-in `secret-tool` with the real CLI's contract: `store` reads the
// secret from stdin, `lookup` prints it, and a missing item exits 1 silently.
const FAKE = `#!/bin/sh
echo "$@" >> "$FAKE_STORE/argv.log"
[ -n "$FAKE_FAIL" ] && { echo "secret-tool: Cannot autolaunch D-Bus" >&2; exit 1; }
case "$1" in
  store) cat > "$FAKE_STORE/secret" ;;
  lookup) [ -f "$FAKE_STORE/secret" ] && cat "$FAKE_STORE/secret" || exit 1 ;;
  *) exit 2 ;;
esac
`;

async function fixture(t, extra = {}) {
  const root = await mkdtemp(join(tmpdir(), 'ack linux vault '));
  t.after(() => rm(root, { recursive: true, force: true }));
  const bin = join(root, 'bin');
  const store = join(root, 'store');
  const home = join(root, 'home');
  await Promise.all([bin, store, home].map((path) => mkdir(path)));
  await writeFile(join(bin, 'secret-tool'), FAKE, { mode: 0o700 });
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, FAKE_STORE: store, ...extra };
  return { root, home, store, env };
}

test('Secret Service key is created once, reused, and never passed in arguments', { skip }, async (t) => {
  const { home, store, env } = await fixture(t);
  const [a, b] = await Promise.all([linuxStorageKey(home, env, names), linuxStorageKey(home, env, names)]);
  assert.equal(a.length, 32);
  assert.deepEqual(a, b);
  assert.deepEqual(await linuxStorageKey(home, env, names), a);
  assert.equal((await readFile(join(store, 'argv.log'), 'utf8')).includes(a.toString('base64url')), false);
  assert.equal((await readFile(join(store, 'argv.log'), 'utf8')).match(/^store /gm).length, 1);
});

test('a failing or locked keyring never creates or replaces a key', { skip }, async (t) => {
  const { home, store, env } = await fixture(t, { FAKE_FAIL: '1' });
  await assert.rejects(linuxStorageKey(home, env, names), /existing keys were not replaced/);
  assert.equal((await readFile(join(store, 'argv.log'), 'utf8')).includes('store'), false);
});

test('a missing key with encrypted profiles is refused, not regenerated', { skip }, async (t) => {
  const { home, store, env } = await fixture(t);
  await writeFile(join(home, 'ack.json'), JSON.stringify({ apiKeyProfiles: { default: { encryptedKey: {} } } }));
  await assert.rejects(linuxStorageKey(home, env, names), /existing profiles were not replaced/);
  assert.equal((await readFile(join(store, 'argv.log'), 'utf8')).includes('store'), false);
});

test('an invalid stored key is rejected', { skip }, async (t) => {
  const { home, store, env } = await fixture(t);
  await writeFile(join(store, 'secret'), 'dG9vLXNob3J0');
  await assert.rejects(linuxStorageKey(home, env, names), /invalid/);
});

test('a missing secret-tool explains how to proceed', { skip }, async (t) => {
  const { home } = await fixture(t);
  await assert.rejects(linuxStorageKey(home, { PATH: join(home, 'nowhere') }, names), /libsecret-tools/);
});

test('file mode is opt-in, round-trips, and never replaces a damaged file', { skip }, async (t) => {
  const { home, env: base } = await fixture(t);
  const env = { ...base, ACK_LINUX_KEYSTORE: 'file', ACK_KEYSTORE_PASSPHRASE: 'correct horse' };
  const [a, b] = await Promise.all([linuxStorageKey(home, env, names), linuxStorageKey(home, env, names)]);
  assert.equal(a.length, 32);
  assert.deepEqual(a, b);
  const path = join(home, 'storage-key.enc');
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  assert.equal((await readFile(path, 'utf8')).includes(a.toString('base64url')), false);
  await assert.rejects(linuxStorageKey(home, { ...env, ACK_KEYSTORE_PASSPHRASE: 'wrong' }, names), /existing keys were not replaced/);
  await writeFile(path, 'damaged');
  await assert.rejects(linuxStorageKey(home, env, names), /existing keys were not replaced/);
  assert.equal(await readFile(path, 'utf8'), 'damaged');
});

test('file mode requires a passphrase and refuses to regenerate for existing profiles', { skip }, async (t) => {
  const { home, env: base } = await fixture(t);
  const env = { ...base, ACK_LINUX_KEYSTORE: 'file' };
  await assert.rejects(linuxStorageKey(home, env, names), /passphrase is required/);
  await writeFile(join(home, 'ack.json'), JSON.stringify({ apiKeyProfiles: { default: { encryptedKey: {} } } }));
  await assert.rejects(linuxStorageKey(home, { ...env, ACK_KEYSTORE_PASSPHRASE: 'x' }, names), /existing profiles were not replaced/);
});

test('an unknown keystore mode is rejected', { skip }, async (t) => {
  const { home, env } = await fixture(t);
  await assert.rejects(linuxStorageKey(home, { ...env, ACK_LINUX_KEYSTORE: 'auto' }, names), /secret-service" or "file/);
});

test('Linux key-profile migration encrypts through the real CLI without the test override', { skip: process.platform !== 'linux' }, async (t) => {
  const { home, env: base } = await fixture(t);
  const secret = 'fake-key-for-linux-vault-regression-only';
  const path = join(home, 'ack.json');
  await writeFile(path, JSON.stringify({ version: 1, apiKey: secret, model: 'lordx64/cyberglm', endpoint: 'https://api.adverserial.ai/v1' }));
  const env = { ...base, ACK_HOME: home, ACK_QUIET: '1' };
  delete env.ACK_TEST_STORAGE_KEY;
  const cli = fileURLToPath(new URL('../bin/ack.mjs', import.meta.url));
  for (let i = 0; i < 2; i++) {
    const result = spawnSync(process.execPath, [cli, 'keys', 'list'], { env, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.ok(!result.stdout.includes(secret));
    assert.ok(!(await readFile(path, 'utf8')).includes(secret));
  }
});

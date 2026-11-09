import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile, readFile, rm, stat, utimes, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
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
  store) sleep 0.2; cat > "$FAKE_STORE/secret" ;;
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
  const run = join(root, 'run');
  await Promise.all([bin, store, home, run].map((path) => mkdir(path)));
  await writeFile(join(bin, 'secret-tool'), FAKE, { mode: 0o700 });
  // Start from a clean keystore configuration so results never depend on the developer's vault settings.
  const inherited = { ...process.env };
  delete inherited.ACK_LINUX_KEYSTORE;
  delete inherited.ACK_KEYSTORE_PASSPHRASE;
  const env = { ...inherited, PATH: `${bin}:${process.env.PATH}`, FAKE_STORE: store, XDG_RUNTIME_DIR: run, ...extra };
  return { root, home, store, run, env };
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

// Drives the real CLI on a pseudo-terminal, answering each hidden prompt with `answer`.
const PTY = `
import os, pty, sys, select, time
answer = sys.argv[1].encode() + b"\\r"
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[2], sys.argv[2:])
out = b""; prompts = 0; deadline = time.time() + 60
while time.time() < deadline:
    ready, _, _ = select.select([fd], [], [], 0.2)
    if ready:
        try: chunk = os.read(fd, 4096)
        except OSError: break
        if not chunk: break
        out += chunk
        while out.count(b"(input hidden)") > prompts:
            prompts += 1
            os.write(fd, answer)
_, status = os.waitpid(pid, 0)
print(prompts, os.waitstatus_to_exitcode(status))
`;

function viaPty(answer, env, args) {
  const cli = fileURLToPath(new URL('../bin/ack.mjs', import.meta.url));
  const result = spawnSync('python3', ['-c', PTY, answer, process.execPath, cli, ...args], { env, encoding: 'utf8' });
  const [prompts, status] = result.stdout.trim().split(' ').map(Number);
  return { prompts, status, stderr: result.stderr };
}

const havePty = process.platform === 'linux' && spawnSync('python3', ['-c', 'import pty']).status === 0;

test('a passphrase with surrounding spaces typed at the masked prompt matches the environment variable', { skip: !havePty }, async (t) => {
  const { home, env: base } = await fixture(t);
  await writeFile(join(home, 'ack.json'), JSON.stringify({ version: 1, apiKey: 'fake-key-for-linux-vault-regression-only', model: 'lordx64/cyberglm', endpoint: 'https://api.adverserial.ai/v1' }));
  const env = { ...base, ACK_HOME: home, ACK_QUIET: '1', ACK_LINUX_KEYSTORE: 'file' };
  delete env.ACK_TEST_STORAGE_KEY;
  const created = viaPty('  spaced pass  ', env, ['keys', 'list']);
  assert.equal(created.status, 0, created.stderr);
  const unlocked = spawnSync(process.execPath, [fileURLToPath(new URL('../bin/ack.mjs', import.meta.url)), 'keys', 'list'], { env: { ...env, ACK_KEYSTORE_PASSPHRASE: '  spaced pass  ' }, encoding: 'utf8' });
  assert.equal(unlocked.status, 0, unlocked.stderr);
});

test('interactive file creation prompts once plus confirmation, then existing files prompt once', { skip }, async (t) => {
  const { home, env: base } = await fixture(t);
  const env = { ...base, ACK_LINUX_KEYSTORE: 'file' };
  const labels = [];
  const askPassphrase = async (label) => { labels.push(label); return ' pass '; };
  const key = await linuxStorageKey(home, env, { ...names, askPassphrase });
  assert.deepEqual(labels, ['Key-store passphrase', 'Confirm passphrase']);
  labels.length = 0;
  assert.deepEqual(await linuxStorageKey(home, env, { ...names, askPassphrase }), key);
  assert.deepEqual(labels, ['Key-store passphrase']);
});

const lockFile = (run) => join(run, `ack-storage-key-${createHash('sha256').update(`${names.service}\0${names.account}`).digest('hex').slice(0, 16)}.lock`);

test('vaults in different homes share one keyring identity, so they share one lock and one key', { skip }, async (t) => {
  const { root, store, env } = await fixture(t);
  const homes = await Promise.all(['a', 'b', 'c'].map(async (name) => { const home = join(root, name); await mkdir(home); return home; }));
  const keys = await Promise.all(homes.map((home) => linuxStorageKey(home, env, names)));
  assert.deepEqual(keys[1], keys[0]);
  assert.deepEqual(keys[2], keys[0]);
  assert.equal((await readFile(join(store, 'argv.log'), 'utf8')).match(/^store /gm).length, 1);
  assert.deepEqual((await readdir(env.XDG_RUNTIME_DIR)).filter((name) => name.startsWith('ack-storage-key-')), []);
});

test('a stale lock left by a crashed process is reclaimed', { skip }, async (t) => {
  const { home, store, run, env } = await fixture(t);
  await writeFile(lockFile(run), 'dead-owner');
  const old = new Date(Date.now() - 120000);
  await utimes(lockFile(run), old, old);
  assert.equal((await linuxStorageKey(home, env, names)).length, 32);
  assert.equal((await readFile(join(store, 'argv.log'), 'utf8')).match(/^store /gm).length, 1);
  assert.deepEqual((await readdir(run)).filter((name) => name.startsWith('ack-storage-key-')), []);
});

test('a live lock is never reclaimed and is left intact for its owner', { skip }, async (t) => {
  const { home, store, run, env } = await fixture(t);
  await writeFile(lockFile(run), 'live-owner');
  const pending = linuxStorageKey(home, env, names);
  await new Promise((done) => setTimeout(done, 600));
  await assert.rejects(readFile(join(store, 'argv.log'), 'utf8').then((log) => { if (/^store /m.test(log)) throw new Error('stored under a live lock'); return Promise.reject(new Error('ok')); }), /ok/);
  assert.equal(await readFile(lockFile(run), 'utf8'), 'live-owner');
  await rm(lockFile(run));
  assert.equal((await pending).length, 32);
});

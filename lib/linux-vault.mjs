import { createCipheriv, createDecipheriv, createHash, randomBytes, scrypt } from 'node:crypto';
import { readFile, writeFile, link, unlink, open, stat, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from './platform.mjs';

const TIMEOUT_MS = 15000;
const LOCK_STALE_MS = 30000;
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

// Runs a fixed command. Secrets travel only on stdin/stdout, never in arguments.
function run(binary, args, input, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('Linux credential store timed out; existing keys were not replaced.')); }, TIMEOUT_MS);
    child.stdout.on('data', (part) => { stdout += part; });
    child.stderr.on('data', (part) => { stderr += part; });
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error.code === 'ENOENT'
        ? new Error('Linux credential storage needs `secret-tool` (package libsecret-tools) and an unlocked Secret Service such as GNOME Keyring. Install it, or set ACK_LINUX_KEYSTORE=file to use a passphrase-protected key file.')
        : error);
    });
    child.stdin.on('error', () => {});
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
    child.stdin.end(input ?? '');
  });
}

// Never create a key when encrypted profiles already depend on the missing one.
async function refuseIfProfilesExist(home, what) {
  try {
    const state = JSON.parse(await readFile(join(home, 'ack.json'), 'utf8'));
    if (Object.values(state.apiKeyProfiles || {}).some((profile) => profile.encryptedKey)) {
      throw new Error(`The Linux ${what} is missing; existing profiles were not replaced. Restore it from backup.`);
    }
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
}

function decodeKey(text) {
  const key = Buffer.from(text.trim(), 'base64url');
  if (key.length !== 32) throw new Error('The Linux credential-store key is invalid; existing keys were not replaced.');
  return key;
}

async function lookup(attributes, env) {
  const result = await run('secret-tool', ['lookup', ...attributes], '', env);
  if (result.code === 0 && result.stdout.trim()) return decodeKey(result.stdout);
  // secret-tool exits 1 with no output for a missing item; anything printed is a real failure.
  if (result.code === 1 && !result.stderr.trim() && !result.stdout.trim()) return null;
  throw new Error('Could not unlock the Linux Secret Service storage key. Unlock your keyring and retry; existing keys were not replaced.');
}

// Lock protocol. Every operation that removes a lock file (stale reclamation and
// release) runs under a short-lived mutex, and re-reads the lock's owner token
// under that mutex first. A caller can therefore never delete a lock that a
// different owner created after the caller last looked.
async function readLock(path) {
  try { return { token: await readFile(path, 'utf8'), mtimeMs: (await stat(path)).mtimeMs }; }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

async function withMutex(path, action) {
  const mutex = `${path}.mutex`;
  const deadline = Date.now() + TIMEOUT_MS;
  for (;;) {
    try { await (await open(mutex, 'wx')).close(); break; }
    catch (error) {
      if (error.code !== 'EEXIST') throw error;
      // The mutex is held for milliseconds; only a crashed holder leaves it behind.
      try { if (Date.now() - (await stat(mutex)).mtimeMs > LOCK_STALE_MS) await unlink(mutex); } catch { /* raced */ }
      if (Date.now() > deadline) throw new Error('Timed out waiting for another ack process to release the storage-key lock.');
      await sleep(10);
    }
  }
  try { return await action(); } finally { await unlink(mutex).catch(() => {}); }
}

// Returns the owner token when the lock was taken, otherwise null.
async function takeLock(path) {
  const token = randomBytes(16).toString('hex');
  const temporary = `${path}.${token}.tmp`;
  // The token is written before the lock becomes visible, so it is never empty.
  await writeFile(temporary, token, { flag: 'wx', mode: 0o600 });
  try { await link(temporary, path); return token; }
  catch (error) { if (error.code !== 'EEXIST') throw error; }
  finally { await unlink(temporary).catch(() => {}); }
  const observed = await readLock(path);
  if (observed && Date.now() - observed.mtimeMs > LOCK_STALE_MS) {
    await withMutex(path, async () => {
      const current = await readLock(path);
      if (current && current.token === observed.token) await unlink(path).catch(() => {});
    });
  }
  return null;
}

async function releaseLock(path, token) {
  await withMutex(path, async () => {
    const current = await readLock(path);
    if (current && current.token === token) await unlink(path).catch(() => {});
  });
}

// The Secret Service item is shared by every ACK_HOME of this user, so the lock
// is scoped to that identity (service + account), not to a vault directory.
async function lockPath(env, service, account) {
  const directory = env.XDG_RUNTIME_DIR || join(tmpdir(), `ack-${process.getuid?.() ?? 'user'}`);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const scope = createHash('sha256').update(`${service}\0${account}`).digest('hex').slice(0, 16);
  return join(directory, `ack-storage-key-${scope}.lock`);
}

async function secretServiceKey(home, env, service, account) {
  const attributes = ['service', service, 'account', account];
  const existing = await lookup(attributes, env);
  if (existing) return existing;
  await refuseIfProfilesExist(home, 'Secret Service storage key');
  const lock = await lockPath(env, service, account);
  const deadline = Date.now() + TIMEOUT_MS;
  let token;
  while (!(token = await takeLock(lock))) {
    // Another ack process is creating the key; wait for it instead of racing it.
    await sleep(100);
    const created = await lookup(attributes, env);
    if (created) return created;
    if (Date.now() > deadline) throw new Error('Timed out waiting for another ack process to create the storage key.');
  }
  try {
    const raced = await lookup(attributes, env);
    if (raced) return raced;
    const encoded = randomBytes(32).toString('base64url');
    const stored = await run('secret-tool', ['store', '--label=Adverserial Confidential Kit storage key', ...attributes], encoded, env);
    if (stored.code !== 0) throw new Error('Could not save the storage key to the Linux Secret Service; nothing was replaced.');
    const verified = await lookup(attributes, env);
    if (!verified || !verified.equals(Buffer.from(encoded, 'base64url'))) throw new Error('The Secret Service did not return the key it just stored; nothing was replaced.');
    return verified;
  } finally { await releaseLock(lock, token); }
}

const derive = (passphrase, salt, params) => new Promise((resolve, reject) => {
  scrypt(passphrase, salt, 32, params, (error, key) => (error ? reject(error) : resolve(key)));
});

async function wrapKey(key, passphrase) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', await derive(passphrase, salt, SCRYPT), iv);
  const ciphertext = Buffer.concat([cipher.update(key), cipher.final()]);
  return JSON.stringify({ version: 1, kdf: 'scrypt', N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, salt: salt.toString('base64url'), iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'), ciphertext: ciphertext.toString('base64url') });
}

async function unwrapKey(text, passphrase) {
  try {
    const value = JSON.parse(text);
    if (value.version !== 1 || value.kdf !== 'scrypt') throw new Error('unsupported');
    const params = { N: value.N, r: value.r, p: value.p, maxmem: SCRYPT.maxmem };
    const decipher = createDecipheriv('aes-256-gcm', await derive(passphrase, Buffer.from(value.salt, 'base64url'), params), Buffer.from(value.iv, 'base64url'));
    decipher.setAuthTag(Buffer.from(value.tag, 'base64url'));
    const key = Buffer.concat([decipher.update(Buffer.from(value.ciphertext, 'base64url')), decipher.final()]);
    if (key.length === 32) return key;
  } catch { /* fall through to one non-revealing message */ }
  throw new Error('Could not unlock the Linux key file (wrong passphrase or damaged storage-key.enc); existing keys were not replaced.');
}

async function fileKey(home, env, askPassphrase) {
  const path = join(home, 'storage-key.enc');
  const passphrase = async (confirm) => {
    const first = env.ACK_KEYSTORE_PASSPHRASE || (askPassphrase ? await askPassphrase('Key-store passphrase') : '');
    if (!first) throw new Error('A key-store passphrase is required: set ACK_KEYSTORE_PASSPHRASE or run from a terminal.');
    if (confirm && !env.ACK_KEYSTORE_PASSPHRASE && askPassphrase && (await askPassphrase('Confirm passphrase')) !== first) throw new Error('Passphrases did not match. Nothing was saved.');
    return first;
  };
  let wrapped;
  let created = null; // confirmed passphrase, reused below instead of prompting again
  try { wrapped = await readFile(path, 'utf8'); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    await refuseIfProfilesExist(home, 'key file storage-key.enc');
    const key = randomBytes(32);
    const temporary = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
    created = await passphrase(true);
    await writeFile(temporary, await wrapKey(key, created), { flag: 'wx', mode: 0o600 });
    try { await link(temporary, path); }
    catch (linkError) { if (linkError.code !== 'EEXIST') throw linkError; }
    finally { await unlink(temporary); }
    wrapped = await readFile(path, 'utf8');
  }
  return unwrapKey(wrapped, created ?? await passphrase(false));
}

// Default: Secret Service (GNOME Keyring, KWallet, ...) through `secret-tool`.
// Opt-in only: ACK_LINUX_KEYSTORE=file, a passphrase-wrapped key file.
export async function linuxStorageKey(home, env = process.env, { service, account, askPassphrase } = {}) {
  const mode = env.ACK_LINUX_KEYSTORE || 'secret-service';
  if (mode === 'file') return fileKey(home, env, askPassphrase);
  if (mode !== 'secret-service') throw new Error('ACK_LINUX_KEYSTORE must be "secret-service" or "file".');
  return secretServiceKey(home, env, service, account);
}

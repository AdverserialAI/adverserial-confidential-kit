import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'node:crypto';
import { readFile, writeFile, link, unlink, open, stat } from 'node:fs/promises';
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

async function takeLock(path) {
  try { await (await open(path, 'wx')).close(); return true; }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    try { if (Date.now() - (await stat(path)).mtimeMs > LOCK_STALE_MS) { await unlink(path); return takeLock(path); } } catch { /* raced */ }
    return false;
  }
}

async function secretServiceKey(home, env, service, account) {
  const attributes = ['service', service, 'account', account];
  const existing = await lookup(attributes, env);
  if (existing) return existing;
  await refuseIfProfilesExist(home, 'Secret Service storage key');
  const lock = join(home, 'storage-key.lock');
  const deadline = Date.now() + TIMEOUT_MS;
  while (!(await takeLock(lock))) {
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
  } finally { await unlink(lock).catch(() => {}); }
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
  try { wrapped = await readFile(path, 'utf8'); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    await refuseIfProfilesExist(home, 'key file storage-key.enc');
    const key = randomBytes(32);
    const temporary = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
    await writeFile(temporary, await wrapKey(key, await passphrase(true)), { flag: 'wx', mode: 0o600 });
    try { await link(temporary, path); }
    catch (linkError) { if (linkError.code !== 'EEXIST') throw linkError; }
    finally { await unlink(temporary); }
    wrapped = await readFile(path, 'utf8');
  }
  return unwrapKey(wrapped, await passphrase(false));
}

// Default: Secret Service (GNOME Keyring, KWallet, ...) through `secret-tool`.
// Opt-in only: ACK_LINUX_KEYSTORE=file, a passphrase-wrapped key file.
export async function linuxStorageKey(home, env = process.env, { service, account, askPassphrase } = {}) {
  const mode = env.ACK_LINUX_KEYSTORE || 'secret-service';
  if (mode === 'file') return fileKey(home, env, askPassphrase);
  if (mode !== 'secret-service') throw new Error('ACK_LINUX_KEYSTORE must be "secret-service" or "file".');
  return secretServiceKey(home, env, service, account);
}

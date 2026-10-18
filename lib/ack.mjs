import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { chmod, cp, mkdir, mkdtemp, readdir, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { accessSync, constants, existsSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { delimiter, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MARK } from './art.mjs';
import { runConsole, THEMES, isTheme } from './console.mjs';

const here = dirname(fileURLToPath(import.meta.url));
export const PACKAGE_ROOT = resolve(here, '..');
const POLICY_URL = 'https://verify.adverserial.ai/policies/production.json';
const MODELS_URL = 'https://verify.adverserial.ai/registry/models.json';
const DEFAULT_ENDPOINT = 'https://api.adverserial.ai/v1';
const STATE_VERSION = 2;
const KEYCHAIN_SERVICE = 'ai.adverserial.confidential-kit.storage.v1';
const KEYCHAIN_ACCOUNT = 'ack-storage-key';
const HARNESS_NAMES = ['claude', 'codex', 'opencode', 'pi', 'oh-my-pi', 'zcode', 'deepseek-harness', 'hermes', 'kimi'];
const HARNESS_LABELS = {
  claude: 'Claude Code', codex: 'Codex', opencode: 'OpenCode', pi: 'Pi',
  'oh-my-pi': 'Oh My Pi', zcode: 'ZCode', 'deepseek-harness': 'DeepSeek Harness',
  hermes: 'Hermes', kimi: 'Kimi Code'
};
const localGatewayTokens = new WeakMap();
const KIMI_MODEL_ALIAS = 'adverserial_confidential';
const KIMI_CONFIG_BEGIN = '# BEGIN ADVERSERIAL CONFIDENTIAL KIT (managed by ack)';
const KIMI_CONFIG_END = '# END ADVERSERIAL CONFIDENTIAL KIT';
function coloredMark(line, enabled = true) {
  return enabled ? `\x1b[38;5;81m${line}\x1b[0m` : line;
}

function banner() {
  const lines = MARK.split('\n');
  const width = Math.max(...lines.map((line) => line.length));
  const titleRow = Math.floor(lines.length / 2) - 1;
  const output = lines.map((line, index) => {
    const mark = coloredMark(line, !('NO_COLOR' in process.env));
    // Pad before styling so ANSI sequences cannot shift the wordmark column.
    const gap = ' '.repeat(width - line.length + 3);
    if (index === titleRow) return `${mark}${gap}\x1b[1mADVERSERIAL CONFIDENTIAL\x1b[0m`;
    if (index === titleRow + 1) return `${mark}${gap}\x1b[2mConfidential coding kit\x1b[0m`;
    return mark;
  });
  process.stdout.write(`${output.join('\n')}\n\n`);
}

const resource = (...parts) => join(PACKAGE_ROOT, 'resources', ...parts);
const appHome = (env = process.env) => env.ACK_HOME ? resolve(env.ACK_HOME) : join(env.XDG_CONFIG_HOME || join(env.HOME || process.cwd(), '.config'), 'adverserial');
const statePath = (env) => join(appHome(env), 'ack.json');
const keysPath = (env) => join(appHome(env), 'receipt-keys.json');
const gatewayMarkerPath = (env) => join(appHome(env), 'gateway.json');
const venvBin = (env) => join(appHome(env), 'venv', process.platform === 'win32' ? 'Scripts' : 'bin');
const executable = (env, name) => join(venvBin(env), process.platform === 'win32' ? `${name}.exe` : name);
const fail = (message) => { throw new Error(message); };

const bundledHarnessPaths = {
  codex: [
    '/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex',
    '/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex'
  ],
  claude: ['/opt/homebrew/bin/claude', '/usr/local/bin/claude'],
  pi: ['/opt/homebrew/bin/pi', '/usr/local/bin/pi'],
  'oh-my-pi': ['/opt/homebrew/bin/omp', '/usr/local/bin/omp'],
  zcode: [],
  'deepseek-harness': [],
  opencode: [],
  kimi: [],
  hermes: []
};

function isExecutable(path) {
  try { accessSync(path, constants.X_OK); return true; } catch { return false; }
}

export function resolveHarnessBinary(name, env = process.env) {
  const binaryName = name === 'oh-my-pi' ? 'omp' : name === 'deepseek-harness' ? 'dsh' : name;
  const override = env[`ACK_${binaryName.toUpperCase()}_BIN`];
  if (override) {
    if (isExecutable(override)) return override;
    fail(`ACK_${binaryName.toUpperCase()}_BIN is not an executable file: ${override}`);
  }
  for (const directory of (env.PATH || '').split(delimiter)) {
    const candidate = join(directory || '.', binaryName);
    if (isExecutable(candidate)) return candidate;
  }
  for (const candidate of bundledHarnessPaths[name] || []) if (isExecutable(candidate)) return candidate;
  fail(`${HARNESS_LABELS[name] || name} is not installed. Install its official CLI, or set ACK_${binaryName.toUpperCase()}_BIN to its absolute executable path.`);
}

function usage() {
  return `Adverserial Confidential Kit

Usage:
  ack                      Open the interactive Confidential Console
  ack init                 Save your first API key and prepare confidential coding
  ack keys …               Add, modify, delete, list, or activate API-key profiles
  ack upgrade              Refresh the confidential runtime and pinned policy
  ack models               List models published in the policy registry
  ack model <id>           Select a model and its published verification policy
  ack harnesses            Show installed coding harnesses
  ack status               Show local configuration without unlocking your vault
  ack doctor               Check this workstation
  ack theme <name>         Choose aurora, ultraviolet, ember, or glacier
  ack attestation [--json] Run a fresh hardware and receipt verification
  ack code [harness]       Start a verified coding harness (or choose from a colored menu)
  ack swarm [options] task Run selected harnesses as confidential workers
  ack swarm create [name]  Create a room for already-open agent sessions
  ack swarm invite --to pi task  Assign an existing agent a shared task
  ack swarm inbox --agent pi  Read pending shared tasks
  ack swarm post --from pi message  Post a result for other agents

Harnesses: ${HARNESS_NAMES.join(', ')}

Examples:
  npm install -g adverserial-confidential-kit
  ack init
  ack code claude
  ack swarm --agents claude,codex "review this repository"
  ack swarm create incident-review
  ack swarm invite --to pi "review the streaming adapter"
  ack attestation

API-key profiles are stored only in ${appHome()}/ack.json (mode 0600). The
active key is passed only to the selected local harness and loopback gateway,
never to the model endpoint.`;
}

async function privateDirectory(dir) {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  try { await chmod(dir, 0o700); } catch { /* Windows ACLs are OS-managed. */ }
}

async function privateJson(path, value) {
  await privateDirectory(dirname(path));
  const temporary = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  try { await chmod(temporary, 0o600); } catch { /* Windows ACLs are OS-managed. */ }
  await rename(temporary, path);
  try { await chmod(path, 0o600); } catch { /* Windows ACLs are OS-managed. */ }
}

async function privateText(path, value) {
  await privateDirectory(dirname(path));
  const temporary = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  await writeFile(temporary, value, { mode: 0o600 });
  try { await chmod(temporary, 0o600); } catch { /* Windows ACLs are OS-managed. */ }
  await rename(temporary, path);
  try { await chmod(path, 0o600); } catch { /* Windows ACLs are OS-managed. */ }
}

// Upsert KEY=VALUE lines in a dotenv file (atomic, mode 0600, unrelated lines
// preserved). Returns true when the file changed, so callers can hint about
// restarts without repeating themselves on every launch.
export async function upsertDotenv(path, vars) {
  let lines;
  try { lines = (await readFile(path, 'utf8')).split(/\r?\n/); }
  catch (error) { if (error.code !== 'ENOENT') throw error; lines = []; }
  while (lines.length && lines[lines.length - 1].trim() === '') lines.pop();
  let changed = false;
  for (const [key, value] of Object.entries(vars)) {
    const line = `${key}=${value}`;
    const pattern = new RegExp(`^(?:export\\s+)?${key}=`);
    const at = lines.findIndex((existing) => pattern.test(existing));
    if (at >= 0) { if (lines[at] !== line) { lines[at] = line; changed = true; } }
    else { if (lines.length) lines.push(''); lines.push(line); changed = true; }
  }
  if (changed) await privateText(path, `${lines.join('\n')}\n`);
  return changed;
}

async function readState(env = process.env) {
  let value;
  try { value = JSON.parse(await readFile(statePath(env), 'utf8')); }
  catch { fail('Not initialized. Run `ack init` first.'); }
  if (!value || ![1, STATE_VERSION].includes(value.version) || typeof value.model !== 'string' || typeof value.endpoint !== 'string') {
    fail('Local configuration is incomplete. Run `ack init` again.');
  }
  const { profiles, activeKeyProfile } = keyProfiles(value);
  const migrationRequired = value.version !== STATE_VERSION || typeof value.apiKey === 'string' || Object.values(profiles).some((profile) => typeof profile.apiKey === 'string');
  const storage = await encryptedStorageKey(env);
  for (const profile of Object.values(profiles)) {
    if (typeof profile.apiKey === 'string') {
      profile.encryptedKey = encryptApiKey(profile.apiKey, storage);
      profile.mask = maskApiKey(profile.apiKey);
      delete profile.apiKey;
    }
    if (!validEncryptedKey(profile.encryptedKey)) fail('An encrypted API-key profile is incomplete. Run `ack init` again.');
    if (typeof profile.mask !== 'string') profile.mask = maskApiKey(decryptApiKey(profile.encryptedKey, storage));
  }
  const state = {
    ...value,
    version: STATE_VERSION,
    apiKey: decryptApiKey(profiles[activeKeyProfile].encryptedKey, storage),
    apiKeyProfiles: profiles,
    activeKeyProfile
  };
  if (migrationRequired) await writeState(state, env);
  return state;
}

function validateProfileName(value) {
  const name = value.trim().toLowerCase();
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(name)) {
    fail('Profile names must start with a letter and use only lowercase letters, numbers, hyphens, or underscores (up to 32 characters).');
  }
  return name;
}

function maskApiKey(value) {
  if (value.length <= 6) return `${value.slice(0, 1)}••••${value.slice(-1)}`;
  return `${value.slice(0, 3)}••••••••${value.slice(-3)}`;
}

function validEncryptedKey(value) {
  return value && typeof value === 'object' && value.version === 1 &&
    typeof value.iv === 'string' && typeof value.tag === 'string' && typeof value.ciphertext === 'string';
}

function keyProfiles(value) {
  if (value?.apiKeyProfiles && typeof value.apiKeyProfiles === 'object' && !Array.isArray(value.apiKeyProfiles)) {
    const profiles = {};
    for (const [rawName, profile] of Object.entries(value.apiKeyProfiles)) {
      const name = validateProfileName(rawName);
      if (!profile || typeof profile !== 'object' || (typeof profile.apiKey !== 'string' && !validEncryptedKey(profile.encryptedKey))) {
        fail('An API-key profile is incomplete. Run `ack init` again.');
      }
      profiles[name] = {
        ...(typeof profile.apiKey === 'string' ? { apiKey: profile.apiKey } : {}),
        ...(validEncryptedKey(profile.encryptedKey) ? { encryptedKey: profile.encryptedKey } : {}),
        ...(typeof profile.mask === 'string' ? { mask: profile.mask } : {}),
        createdAt: profile.createdAt,
        updatedAt: profile.updatedAt
      };
    }
    const activeKeyProfile = typeof value.activeKeyProfile === 'string' ? validateProfileName(value.activeKeyProfile) : '';
    if (!activeKeyProfile || !profiles[activeKeyProfile]) fail('The active API-key profile is missing. Run `ack keys use <profile>.');
    return { profiles, activeKeyProfile };
  }
  if (typeof value?.apiKey !== 'string' || !value.apiKey) fail('Local configuration is incomplete. Run `ack init` again.');
  return {
    profiles: { default: { apiKey: value.apiKey, createdAt: value.updatedAt, updatedAt: value.updatedAt } },
    activeKeyProfile: 'default'
  };
}

async function encryptedStorageKey(env) {
  const testKey = env.ACK_TEST_STORAGE_KEY;
  if (testKey && env.NODE_ENV === 'test') {
    const decoded = Buffer.from(testKey, 'base64url');
    if (decoded.length === 32) return decoded;
    fail('ACK_TEST_STORAGE_KEY must encode exactly 32 bytes.');
  }
  if (process.platform !== 'darwin') {
    fail('Encrypted API-key storage requires an operating-system credential store. This ACK build currently supports the macOS Keychain.');
  }
  try {
    const encoded = (await commandOutput('security', ['find-generic-password', '-a', KEYCHAIN_ACCOUNT, '-s', KEYCHAIN_SERVICE, '-w'])).trim();
    const decoded = Buffer.from(encoded, 'base64url');
    if (decoded.length === 32) return decoded;
    fail('The encrypted credential-store key is invalid. Remove it from Keychain and run `ack init` again.');
  } catch (error) {
    if (error instanceof Error && /invalid/.test(error.message)) throw error;
    if (!(error instanceof Error) || !/exited with status 44(?:\D|$)/.test(error.message)) {
      fail('Could not unlock the macOS Keychain storage key. Unlock Keychain and retry; the existing key was not replaced.');
    }
    const encoded = randomBytes(32).toString('base64url');
    // The API key never appears in a process argument. This is a random AES
    // storage key, immediately placed in the macOS Keychain.
    await command('security', ['add-generic-password', '-U', '-a', KEYCHAIN_ACCOUNT, '-s', KEYCHAIN_SERVICE, '-w', encoded]);
    return Buffer.from(encoded, 'base64url');
  }
}

function encryptApiKey(value, key) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return { version: 1, iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'), ciphertext: ciphertext.toString('base64url') };
}

function decryptApiKey(value, key) {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(value.iv, 'base64url'));
    decipher.setAuthTag(Buffer.from(value.tag, 'base64url'));
    return Buffer.concat([decipher.update(Buffer.from(value.ciphertext, 'base64url')), decipher.final()]).toString('utf8');
  } catch {
    fail('Could not decrypt an API-key profile. The macOS Keychain key may have been removed. Run `ack init` again.');
  }
}

async function writeState(state, env) {
  const { profiles, activeKeyProfile } = keyProfiles(state);
  const storage = await encryptedStorageKey(env);
  for (const profile of Object.values(profiles)) {
    if (typeof profile.apiKey === 'string') {
      profile.encryptedKey = encryptApiKey(profile.apiKey, storage);
      profile.mask = maskApiKey(profile.apiKey);
      delete profile.apiKey;
    }
    if (!validEncryptedKey(profile.encryptedKey)) fail('An encrypted API-key profile is incomplete.');
  }
  const { apiKey, ...safe } = state;
  await privateJson(statePath(env), { ...safe, version: STATE_VERSION, apiKeyProfiles: profiles, activeKeyProfile });
}

async function promptApiKey(label = 'Adverserial API key') {
  if (!process.stdin.isTTY) fail('Interactive API-key entry requires a terminal. Run this command from a terminal.');
  return new Promise((resolvePrompt, rejectPrompt) => {
    let value = '';
    const input = process.stdin;
    input.setRawMode(true); input.resume(); input.setEncoding('utf8');
    const done = () => {
      input.setRawMode(false); input.pause(); input.removeListener('data', onData);
      process.stdout.write('\n'); resolvePrompt(value.trim());
    };
    const onData = (chunk) => {
      for (const character of chunk) {
        if (character === '\u0003') { input.setRawMode(false); input.pause(); input.removeListener('data', onData); process.stdout.write('\n'); rejectPrompt(new Error('Cancelled.')); return; }
        if (character === '\r' || character === '\n') { done(); return; }
        if (character === '\u007f') {
          if (value) { value = value.slice(0, -1); process.stdout.write('\b \b'); }
          continue;
        }
        if (character >= ' ') { value += character; process.stdout.write('•'); }
      }
    };
    input.on('data', onData);
    process.stdout.write(`\x1b[38;5;81m${label}\x1b[0m \x1b[2m(input hidden)\x1b[0m: `);
  });
}

function validKeys(value) {
  return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length > 0 &&
    Object.entries(value).every(([kid, key]) => typeof kid === 'string' && key && typeof key === 'object' && key.kty === 'EC' && key.crv === 'P-256');
}

async function fetchJson(url, fetchImpl = fetch) {
  const response = await fetchImpl(url, { headers: { accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(10_000) });
  if (!response.ok) fail(`Could not fetch published configuration (${response.status}).`);
  return response.json();
}

export async function fetchProductionPolicy({ fetchImpl = fetch } = {}) {
  const policy = await fetchJson(POLICY_URL, fetchImpl);
  if (!policy || policy.status !== 'active' || typeof policy.model_id !== 'string' || !validKeys(policy.receipt_keys)) {
    fail('Published production policy is incomplete; refusing to configure confidential inference.');
  }
  return policy;
}

class StatusLine {
  constructor(env = process.env, stream = process.stdout) {
    this.stream = stream;
    this.enabled = !env.ACK_QUIET && Boolean(stream.isTTY);
    this.frames = ['◐', '◓', '◑', '◒'];
    this.frame = 0;
    this.message = '';
    this.timer = null;
  }

  render() {
    if (!this.enabled) return;
    this.stream.write(`\r\x1b[2K${this.frames[this.frame++ % this.frames.length]} ${this.message}`);
  }

  start(message) {
    this.message = message;
    this.render();
    this.timer = setInterval(() => this.render(), 110);
    this.timer.unref?.();
  }

  update(message) {
    this.message = message;
    this.render();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    if (this.enabled) this.stream.write('\r\x1b[2K');
  }
}

async function withStatus(message, env, work) {
  const status = new StatusLine(env);
  status.start(message);
  try { return await work((next) => status.update(next)); }
  finally { status.stop(); }
}

function command(commandName, args, options = {}) {
  return new Promise((resolveCommand, rejectCommand) => {
    const child = spawn(commandName, args, { stdio: ['ignore', 'pipe', 'pipe'], ...options });
    let tail = '';
    const collect = (chunk) => {
      tail = `${tail}${chunk}`.slice(-2048);
    };
    child.stdout?.on('data', collect);
    child.stderr?.on('data', collect);
    child.once('error', (error) => rejectCommand(new Error(`Could not run ${commandName}: ${error.message}`)));
    child.once('exit', (code) => {
      if (code === 0) return resolveCommand();
      const detail = tail.trim().split(/\r?\n/).filter(Boolean).at(-1);
      rejectCommand(new Error(`${commandName} exited with status ${code ?? 'unknown'}${detail ? `: ${detail}` : ''}.`));
    });
  });
}

function commandOutput(commandName, args, options = {}) {
  return new Promise((resolveCommand, rejectCommand) => {
    const child = spawn(commandName, args, { stdio: ['ignore', 'pipe', 'pipe'], ...options });
    let output = '';
    let errorOutput = '';
    child.stdout?.on('data', (chunk) => { output += chunk; });
    child.stderr?.on('data', (chunk) => { errorOutput += chunk; });
    child.once('error', (error) => rejectCommand(new Error(`Could not run ${commandName}: ${error.message}`)));
    child.once('exit', (code) => {
      if (code === 0) return resolveCommand(output);
      const detail = errorOutput.trim().split(/\r?\n/).filter(Boolean).at(-1);
      rejectCommand(new Error(`${commandName} exited with status ${code ?? 'unknown'}${detail ? `: ${detail}` : ''}.`));
    });
  });
}

function python() {
  for (const candidate of ['python3', 'python']) {
    const result = spawnSync(candidate, ['--version'], { encoding: 'utf8' });
    if (result.status === 0 && /Python 3\.(1[0-9]|[2-9][0-9])/.test(`${result.stdout}${result.stderr}`)) return candidate;
  }
  fail('Python 3.10 or later is required to install the local confidential gateway.');
}

async function kitRevision() {
  const manifest = JSON.parse(await readFile(join(PACKAGE_ROOT, 'package.json'), 'utf8'));
  return `${manifest.name}@${manifest.version}`;
}

export async function installGateway(env = process.env, progress = () => {}, { force = true } = {}) {
  await privateDirectory(appHome(env));
  progress('Preparing isolated confidential runtime');
  await command(python(), [resource('install-runtime.py'), appHome(env), resource('python'), resource('gateway'), await kitRevision(), ...(force ? ['--force'] : [])]);
  progress('Finalizing hardware verification');
  try { await chmod(resource('typescript', 'adverserial-hardware-verify.mjs'), 0o755); } catch { /* Npm preserves mode on Unix. */ }
}

async function ensureGateway(env = process.env) {
  let marker;
  try { marker = JSON.parse(await readFile(gatewayMarkerPath(env), 'utf8')); } catch { marker = null; }
  if (!existsSync(executable(env, 'adverserial-confidential-gateway')) || marker?.revision !== await kitRevision()) {
    await withStatus('Preparing confidential runtime', env, (progress) => installGateway(env, progress, { force: false }));
  }
}

async function saveSetup(apiKey, policy, env, prior = null, policyUrl = POLICY_URL) {
  const profileState = prior ? keyProfiles(prior) : {
    profiles: { default: { apiKey, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() } },
    activeKeyProfile: 'default'
  };
  // A legacy state may be upgraded by init/upgrade. Keep every existing
  // profile, but make the selected profile authoritative for API access.
  profileState.profiles[profileState.activeKeyProfile].apiKey = apiKey;
  profileState.profiles[profileState.activeKeyProfile].updatedAt = new Date().toISOString();
  await privateJson(keysPath(env), policy.receipt_keys);
  await writeState({
    version: STATE_VERSION,
    apiKey,
    apiKeyProfiles: profileState.profiles,
    activeKeyProfile: profileState.activeKeyProfile,
    model: policy.model_id,
    endpoint: DEFAULT_ENDPOINT,
    policyUrl,
    policyDigest: `sha256:${createHash('sha256').update(JSON.stringify(policy)).digest('hex')}`,
    updatedAt: new Date().toISOString()
  }, env);
}

async function init(env) {
  const prior = existsSync(statePath(env)) ? await readState(env) : null;
  const apiKey = prior ? prior.apiKey : await promptApiKey();
  if (!apiKey) fail('An API key is required. Nothing was saved.');
  const policy = await withStatus('Checking signed production policy', env, () => fetchProductionPolicy());
  await withStatus('Saving pinned verification policy', env, () => saveSetup(apiKey, policy, env, prior));
  await withStatus('Preparing confidential runtime', env, (progress) => installGateway(env, progress));
}

async function upgrade(env) {
  const prior = await readState(env);
  const { policy, url } = await withStatus('Refreshing selected model policy', env, () => publishedModelPolicy(prior.model));
  await withStatus('Saving pinned verification policy', env, () => saveSetup(prior.apiKey, policy, env, prior, url));
  await withStatus('Preparing confidential runtime', env, (progress) => installGateway(env, progress));
}

function verifiedEnvironment(state, env) {
  if (!localGatewayTokens.has(state)) localGatewayTokens.set(state, randomBytes(32).toString('base64url'));
  return {
    ...env,
    ADVERSERIAL_LOCAL_GATEWAY_TOKEN: localGatewayTokens.get(state),
    ADVERSERIAL_UPSTREAM_API_KEY: state.apiKey,
    ADVERSERIAL_ACK_CLI: join(PACKAGE_ROOT, 'bin', 'ack.mjs'),
    ADVERSERIAL_API_KEY: state.apiKey,
    ADVERSERIAL_API_URL: state.endpoint,
    ADVERSERIAL_CC_API_URL: state.endpoint,
    ADVERSERIAL_GATEWAY_URL: localGatewayUrl(env),
    ADVERSERIAL_MODEL: state.model,
    ADVERSERIAL_RECEIPT_KEYS_FILE: keysPath(env),
    // Pi and Oh My Pi load extensions under Bun, where process.execPath is
    // Bun rather than Node. Point them at the executable launcher so a fresh
    // attestation always uses Node to run the bundled verifier.
    ADVERSERIAL_VERIFY_COMMAND: resource('plugins', 'adverserial-verify', 'bin', 'adverserial-verify'),
    ADVERSERIAL_HARDWARE_VERIFIER_COMMAND: resource('typescript', 'adverserial-hardware-verify.mjs'),
    ADVERSERIAL_ISSUER: 'https://verify.adverserial.ai',
    ADVERSERIAL_AUDIENCE: 'https://chat.adverserial.ai'
  };
}

function waitFor(child) {
  return new Promise((resolveChild, rejectChild) => {
    child.once('error', rejectChild);
    child.once('exit', (code, signal) => resolveChild({ code: code ?? 1, signal }));
  });
}

export async function startSessionGateway(state, env) {
  // The child binds port 0 itself: no find-free-port/rebind race, and no
  // possibility of accepting another process's health response as readiness.
  const port = env.ADVERSERIAL_GATEWAY_PORT ? Number(env.ADVERSERIAL_GATEWAY_PORT) : 0;
  if (port) localGatewayOrigin(env);
  else if (env.ADVERSERIAL_GATEWAY_PORT) fail('ADVERSERIAL_GATEWAY_PORT must be an integer between 1 and 65535.');
  const sessions = join(appHome(env), 'sessions');
  await privateDirectory(sessions);
  const sessionHome = await mkdtemp(join(sessions, 'coding-'));
  const child = spawn(executable(env, 'adverserial-confidential-gateway'), ['--port', String(port), '--fallback-port', '--ready-fd', '3'], {
    env: { ...verifiedEnvironment(state, env), ADVERSERIAL_GATEWAY_PORT: String(port || 8787) }, stdio: ['ignore', 'ignore', 'pipe', 'pipe']
  });
  // Drain stderr without forwarding content/credentials from a local runtime.
  child.stderr.on('data', () => {});
  try {
    const boundPort = await new Promise((resolveReady, rejectReady) => {
      let data = '';
      const finish = (error, readyPort) => {
        clearTimeout(timer);
        child.removeListener('error', failed); child.removeListener('exit', exited);
        child.stdio[3].removeListener('data', received); child.stdio[3].removeListener('end', ended);
        if (error) rejectReady(error); else resolveReady(readyPort);
      };
      const failed = () => finish(new Error('The local confidential runtime could not start. Run ack upgrade and retry.'));
      const exited = () => finish(new Error(port ? `Could not bind the requested gateway port ${port}. Choose a different ADVERSERIAL_GATEWAY_PORT or unset it for automatic allocation.` : 'The local confidential runtime stopped during startup. Run ack upgrade and retry.'));
      const ended = () => { if (!data.includes('\n')) exited(); };
      const received = (part) => {
        data += part;
        if (data.length > 1024) return failed();
        if (!data.includes('\n')) return;
        try {
          const ready = JSON.parse(data.slice(0, data.indexOf('\n')));
          if (ready.pid !== child.pid || !Number.isInteger(ready.port) || ready.port < 1 || ready.port > 65535 || child.exitCode !== null) return failed();
          finish(null, ready.port);
        } catch { failed(); }
      };
      const timer = setTimeout(failed, 15000);
      child.once('error', failed); child.once('exit', exited);
      child.stdio[3].on('data', received); child.stdio[3].once('end', ended);
    });
    return { child, env: { ...env, ACK_SESSION_HOME: sessionHome, ADVERSERIAL_GATEWAY_PORT: String(boundPort) } };
  } catch (error) {
    child.kill('SIGTERM');
    throw error;
  }
}

async function scopedHarnessHome(base, target, configName, sharedDirectories = [], shareOnly = false) {
  await privateDirectory(base); await privateDirectory(target);
  for (const name of sharedDirectories) await privateDirectory(join(base, name));
  for (const entry of await readdir(base, { withFileTypes: true })) {
    if (shareOnly && !sharedDirectories.includes(entry.name)) continue;
    if (entry.name === configName || entry.name.startsWith(`${configName}.`) || entry.name === '.env' || entry.name === 'skills') continue;
    try { await symlink(join(base, entry.name), join(target, entry.name)); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
  }
  return target;
}
const harnessConfigHome = (env) => env.ACK_SESSION_HOME || appHome(env);

function normalizeHarness(value) {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'omp') return 'oh-my-pi';
  if (normalized === 'dsh' || normalized === 'deepseek') return 'deepseek-harness';
  return normalized;
}

async function chooseHarness() {
  if (!process.stdin.isTTY) fail(`Choose a harness explicitly: ack code <${HARNESS_NAMES.join('|')}>`);
  const colors = [81, 213, 120, 214, 39, 141, 220, 75, 207];
  process.stdout.write('\n\x1b[1m  Select a verified coding harness\x1b[0m\n');
  HARNESS_NAMES.forEach((name, index) => {
    const color = colors[index % colors.length];
    process.stdout.write(`  \x1b[38;5;${color}m${String(index + 1).padStart(2, '0')}\x1b[0m  \x1b[1m${HARNESS_LABELS[name]}\x1b[0m  \x1b[2m${name}\x1b[0m\n`);
  });
  const line = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  const answer = await new Promise((resolveAnswer) => line.question('\n\x1b[38;5;81mack\x1b[0m \x1b[2m/ code ›\x1b[0m ', resolveAnswer));
  line.close();
  const selectedNumber = Number(answer.trim());
  const harness = Number.isInteger(selectedNumber) && selectedNumber >= 1 && selectedNumber <= HARNESS_NAMES.length
    ? HARNESS_NAMES[selectedNumber - 1]
    : normalizeHarness(answer);
  if (!HARNESS_NAMES.includes(harness)) fail(`Unknown harness ${JSON.stringify(harness)}.`);
  return harness;
}

async function codexProfile(env, binary, state) {
  const codexHome = env.CODEX_HOME || join(env.HOME || process.cwd(), '.codex');
  await privateDirectory(codexHome);
  const profile = (await readFile(resource('profiles', 'codex.confidential.toml'), 'utf8'))
    .replace('http://127.0.0.1:8787/v1', localGatewayUrl(env))
    .replaceAll('lordx64/cyberglm', state.model);
  await privateText(join(codexHome, 'confidential.config.toml'), profile);
  const skill = join(codexHome, 'skills', 'adverserial-attestation', 'SKILL.md');
  await privateText(skill, await readFile(resource('plugins', 'codex', 'skills', 'adverserial-attestation', 'SKILL.md'), 'utf8'));
  // Codex Skills are available from `/skills` or the `$` prefix. Keep a
  // custom-prompt counterpart for CLI builds that surface user prompts in the
  // slash menu, under the stable `/prompts:adverserial-attestation` command.
  const prompt = join(codexHome, 'prompts', 'adverserial-attestation.md');
  await privateText(prompt, await readFile(resource('plugins', 'codex', 'prompts', 'adverserial-attestation.md'), 'utf8'));

  // A copied skill alone is not a Codex plugin and is not shown in its plugin
  // picker. Install the public, signed marketplace plugin as part of Codex
  // setup. Both Codex commands are idempotent, including after an upgrade.
  await command(binary, ['plugin', 'marketplace', 'add', 'AdverserialAI/confidential-sdk', '--ref', 'main'], { env });
  await command(binary, ['plugin', 'add', 'adverserial-verify@adverserial'], { env });
}

export async function configureOpenCode(state, env) {
  // OpenCode has no --config flag. It discovers config at
  // $XDG_CONFIG_HOME/opencode/, so give it an isolated ACK-owned config home
  // rather than modifying the user's existing OpenCode installation.
  const xdgConfigHome = join(harnessConfigHome(env), 'opencode');
  const config = join(xdgConfigHome, 'opencode', 'opencode.json');
  const plugin = join(xdgConfigHome, 'opencode', 'plugins', 'adverserial.ts');
  const commandFile = join(xdgConfigHome, 'opencode', 'commands', 'adverserial-attestation.md');
  const profile = (await readFile(resource('profiles', 'opencode.jsonc'), 'utf8'))
    .replace('http://127.0.0.1:8787/v1', localGatewayUrl(env))
    .replaceAll('lordx64/cyberglm', state.model);
  const pluginDist = join(xdgConfigHome, 'opencode', 'plugins', 'adverserial-dist');
  const verifier = resource('plugins', 'claude-code', 'bin', 'adverserial-verify-cli.mjs');
  await privateText(config, profile);
  // OpenCode detects this file and runs `bun install` before loading local
  // plugins. The verifier's shared runtime uses EHBP and DCAP verification in
  // addition to OpenCode's plugin helper, so declare the complete runtime.
  await privateJson(join(xdgConfigHome, 'opencode', 'package.json'), {
    private: true,
    type: 'module',
    dependencies: {
      '@opencode-ai/plugin': '*',
      '@phala/dcap-qvl': '0.6.5',
      ehbp: '0.3.3'
    }
  });
  // OpenCode resolves package imports from the plugin file's directory. A
  // wrapper that re-exported the copy inside ACK's global npm directory made
  // `@opencode-ai/plugin` invisible, so the slash command loaded but its tools
  // did not. Keep a local, self-contained copy beneath OpenCode's config root.
  await privateDirectory(dirname(plugin));
  await cp(resource('plugins', 'opencode', 'dist'), pluginDist, { recursive: true, force: true });
  await privateText(plugin, 'export { AdverserialPlugin as default } from "./adverserial-dist/plugins/opencode/src/index.js";\n');
  // A slash command is a prompt, not a native OpenCode action. Use an absolute
  // bundled verifier invocation so the command remains useful even if a future
  // OpenCode release declines to load an optional plugin.
  const verifierCommand = `${JSON.stringify(process.execPath)} ${JSON.stringify(verifier)}`;
  await privateText(commandFile, `---\ndescription: Run a fresh Adverserial confidential-runtime attestation check\n---\n\nRun a fresh verification with the Bash tool by executing exactly:\n\n\`${verifierCommand}\`\n\nDo not search PATH for a verifier and do not substitute another command. Report the verdict exactly, including the endpoint, policy, evidence digest, expiry, and trust state. A failure, stale verdict, or unpinned result is not verified.\n`);
  return { ...verifiedEnvironment(state, env), XDG_CONFIG_HOME: xdgConfigHome };
}

export async function configureZCode(state, env) {
  const home = join(appHome(env), 'zcode');
  const config = join(harnessConfigHome(env), 'zcode', 'providers.json');
  const legacy = join(home, 'cli', 'config.json');
  try {
    const previous = JSON.parse(await readFile(legacy, 'utf8'));
    if (previous.$schema === 'zcode.config.v1' && previous.provider?.zai?.name === 'Adverserial Confidential') await rm(legacy);
  } catch (error) { if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error; }
  const base = verifiedEnvironment(state, env);
  // ZCode's provider file does not support environment credential references.
  // Persist only a random, process-scoped loopback token, never the billing key.
  await privateJson(config, {
    schemaVersion: 1,
    config: {
      providerOrder: ['adverserial-confidential'],
      providerConfigRules: { providerRules: [{
        providerId: 'adverserial-confidential', providerName: 'Adverserial Confidential',
        config: {
          group: 'standard-personal',
          access: { type: 'api-key', apiKey: base.ADVERSERIAL_LOCAL_GATEWAY_TOKEN },
          api: { type: 'openai-chat-completions', baseUrl: localGatewayUrl(env) },
          personalModelIds: [state.model], modelOrder: [state.model]
        }
      }] },
      modelConfigRules: { providerModelRules: [{
        providerId: 'adverserial-confidential', modelId: state.model,
        config: { properties: { contextWindow: 1048576 } }
      }], manualProviderModelRules: [] },
      defaultModelSelection: { providerId: 'adverserial-confidential', modelId: state.model }
    }
  });
  return { ...base, ZCODE_DATA_BASE_DIR: home, ZCODE_PERSONAL_PROVIDER_CONFIG_FILE: config };
}

async function configureDeepSeekHarness(state, env) {
  const home = join(appHome(env), 'deepseek-harness');
  const patch = join(harnessConfigHome(env), 'deepseek-harness', 'cordis.patch.yml');
  const content = `# Managed by Adverserial Confidential Kit.\n- id: agent-default-model\n  config:\n    provider: adverserial-confidential\n    model: ${state.model}\n- id: llm-pi-ai\n  config:\n    providers:\n      adverserial-confidential:\n        apiKeyEnv: ADVERSERIAL_API_KEY\n        api: openai-completions\n        baseURL: ${localGatewayUrl(env)}\n        compat:\n          supportsDeveloperRole: false\n        models:\n          - id: ${state.model}\n            name: CyberGLM — verified confidential runtime\n            input: [text]\n            contextWindow: 1048576\n            maxTokens: 65536\n`;
  await privateText(patch, content);
  return { ...verifiedEnvironment(state, env), DSH_HOME: home, ACK_DSH_PATCH: patch };
}

function kimiConfigPath(env) {
  return join(env.KIMI_CODE_HOME || join(env.HOME || process.cwd(), '.kimi-code'), 'config.toml');
}

function tomlString(value) {
  // JSON basic strings are also valid TOML basic strings for API keys and model IDs.
  return JSON.stringify(value);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function localGatewayUrl(env) {
  return `${localGatewayOrigin(env)}/v1`;
}

function localGatewayOrigin(env) {
  const port = Number(env.ADVERSERIAL_GATEWAY_PORT || '8787');
  if (!Number.isInteger(port) || port < 1 || port > 65535) fail('ADVERSERIAL_GATEWAY_PORT must be an integer between 1 and 65535.');
  return `http://127.0.0.1:${port}`;
}

export async function configureKimi(state, env = process.env) {
  const path = kimiConfigPath(env);
  let existing = '';
  try { existing = await readFile(path, 'utf8'); } catch { /* Kimi has not been configured yet. */ }
  const managed = `${KIMI_CONFIG_BEGIN}\n[providers.${KIMI_MODEL_ALIAS}]\ntype = "openai"\nbase_url = ${tomlString(localGatewayUrl(env))}\napi_key_env = "ADVERSERIAL_API_KEY"\n\n[models.${KIMI_MODEL_ALIAS}]\nprovider = "${KIMI_MODEL_ALIAS}"\nmodel = ${tomlString(state.model)}\nmax_context_size = 1048576\ncapabilities = ["thinking", "always_thinking", "tool_use"]\ndisplay_name = "CyberGLM — verified confidential runtime"\n${KIMI_CONFIG_END}\n`;
  const block = new RegExp(`\\n?${escapeRegExp(KIMI_CONFIG_BEGIN)}[\\s\\S]*?${escapeRegExp(KIMI_CONFIG_END)}\\n?`, 'g');
  let preserved = existing.replace(block, '').trimEnd();
  // Kimi validates a root default before applying the --model override.
  const root = preserved.split(/^\s*\[/m, 1)[0];
  if (!/^\s*default_model\s*=/m.test(root)) preserved = `default_model = "${KIMI_MODEL_ALIAS}"\n${preserved}`.trimEnd();
  await privateText(path, `${preserved ? `${preserved}\n\n` : ''}${managed}`);
  return KIMI_MODEL_ALIAS;
}

async function bindHarnessVerifier(state, base) {
  let pins;
  try { pins = JSON.parse(await readFile(keysPath(base), 'utf8')); } catch { return base; }
  if (!validKeys(pins)) fail('Pinned receipt keys are incomplete. Run ack upgrade.');
  // Some harness shell sandboxes scrub provider environment variables. Bind
  // public verification inputs into an executable, with no API credential.
  const publicConfig = {
    ADVERSERIAL_API_URL: state.endpoint || DEFAULT_ENDPOINT,
    ADVERSERIAL_MODEL: state.model,
    ADVERSERIAL_RECEIPT_KEYS_JSON: JSON.stringify(pins),
    ADVERSERIAL_RECEIPT_KEYS_FILE: '',
    ADVERSERIAL_HARDWARE_VERIFIER_COMMAND: resource('typescript', 'adverserial-hardware-verify.mjs'),
    ADVERSERIAL_ISSUER: 'https://verify.adverserial.ai',
    ADVERSERIAL_AUDIENCE: 'https://chat.adverserial.ai'
  };
  const id = createHash('sha256').update(JSON.stringify(publicConfig)).digest('hex').slice(0, 16);
  const wrapper = join(appHome(base), 'bin', `verify-${id}.mjs`);
  await privateText(wrapper, `#!${process.execPath}\nObject.assign(process.env, ${JSON.stringify(publicConfig)});\nawait import(${JSON.stringify(new URL('../resources/plugins/claude-code/bin/adverserial-verify-cli.mjs', import.meta.url).href)});\n`);
  await chmod(wrapper, 0o700);
  return { ...base, ADVERSERIAL_VERIFY_COMMAND: wrapper };
}

export async function harnessCommand(name, state, env) {
  const base = await bindHarnessVerifier(state, verifiedEnvironment(state, env));
  const binary = resolveHarnessBinary(name, base);
  if (name === 'claude') {
    return { command: binary, args: ['--plugin-dir', resource('plugins', 'claude-code'), '--settings', JSON.stringify({ statusLine: { type: 'command', command: `${JSON.stringify(process.execPath)} ${JSON.stringify(resource('plugins', 'claude-code', 'bin', 'adverserial-statusline.mjs'))}` } })], env: { ...base,
      ANTHROPIC_BASE_URL: localGatewayOrigin(base), ANTHROPIC_AUTH_TOKEN: state.apiKey, ANTHROPIC_API_KEY: '',
      ANTHROPIC_MODEL: state.model, ANTHROPIC_DEFAULT_OPUS_MODEL: state.model, ANTHROPIC_DEFAULT_SONNET_MODEL: state.model,
      ANTHROPIC_DEFAULT_HAIKU_MODEL: state.model, ANTHROPIC_DEFAULT_FABLE_MODEL: state.model, ANTHROPIC_SMALL_FAST_MODEL: state.model,
      ANTHROPIC_CUSTOM_MODEL_OPTION: state.model, ANTHROPIC_CUSTOM_MODEL_OPTION_NAME: 'CyberGLM — verified confidential runtime',
      CLAUDE_CODE_ENABLE_FINE_GRAINED_TOOL_STREAMING: '1', CLAUDE_CODE_MAX_CONTEXT_TOKENS: '1048576'
    }};
  }
  if (name === 'codex') { await codexProfile(base, binary, state); return { command: binary, args: ['--profile', 'confidential', '-c', `model_providers.adverserial_confidential.base_url=${JSON.stringify(localGatewayUrl(base))}`, '-c', `model=${JSON.stringify(state.model)}`], env: base }; }
  if (name === 'pi') return { command: binary, args: ['--extension', resource('plugins', 'pi', 'adverserial-confidential.ts'), '--model', `adverserial-confidential/${state.model}`], env: base };
  if (name === 'oh-my-pi') return { command: binary, args: ['--extension', resource('plugins', 'oh-my-pi', 'adverserial-confidential.ts'), '--model', `adverserial-confidential/${state.model}`], env: { ...base, PI_CODING_AGENT_DIR: env.OMP_CODING_AGENT_DIR || join(env.HOME || process.cwd(), '.omp', 'agent') } };
  if (name === 'zcode') return { command: binary, args: [], env: { ...await configureZCode(state, base), ADVERSERIAL_VERIFY_COMMAND: base.ADVERSERIAL_VERIFY_COMMAND } };
  if (name === 'deepseek-harness') {
    const configured = { ...await configureDeepSeekHarness(state, base), ADVERSERIAL_VERIFY_COMMAND: base.ADVERSERIAL_VERIFY_COMMAND };
    return { command: binary, args: ['--profile', 'web', '--patch', configured.ACK_DSH_PATCH, '--port', '0'], env: configured };
  }
  if (name === 'kimi') {
    if (base.ACK_SESSION_HOME) {
      const original = dirname(kimiConfigPath(base));
      base.KIMI_CODE_HOME = await scopedHarnessHome(original, join(base.ACK_SESSION_HOME, 'kimi'), 'config.toml', ['sessions', 'user-history', 'workspace-trust', 'file-history', 'cache', 'logs']);
      try { await privateText(kimiConfigPath(base), await readFile(join(original, 'config.toml'), 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    const alias = await configureKimi(state, base);
    return { command: binary, args: ['--skills-dir', resource('plugins', 'kimi-code', 'skills'), '--model', alias], env: base };
  }
  if (name === 'opencode') return { command: binary, args: [], env: { ...await configureOpenCode(state, base), ADVERSERIAL_VERIFY_COMMAND: base.ADVERSERIAL_VERIFY_COMMAND } };
  if (name === 'hermes') {
    const original = join(appHome(env), 'hermes');
    await privateDirectory(original);
    const home = base.ACK_SESSION_HOME ? await scopedHarnessHome(original, join(base.ACK_SESSION_HOME, 'hermes'), 'config.yaml', ['sessions', 'memories', 'cache', 'logs'], true) : original;
    await privateDirectory(home);
    await privateText(join(home, 'config.yaml'), `model:\n  default: ${state.model}\n  provider: adverserial-confidential\nproviders:\n  adverserial-confidential:\n    base_url: ${localGatewayUrl(env)}\n    key_env: ADVERSERIAL_API_KEY\n    api_mode: chat_completions\n    context_length: 1048576\nauxiliary:\n  title_generation:\n    model_upgrade_enabled: false\n`);
    if (home !== original) {
      try { await cp(join(original, 'skills'), join(home, 'skills'), { recursive: true }); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    await cp(resource('plugins', 'hermes', 'skills'), join(home, 'skills'), { recursive: true, force: true });
    // A Hermes gateway the user runs against this home (a launchd/systemd
    // service, `hermes gateway`, any chat platform) does not inherit this
    // process's environment, so persist the ACK CLI path into the Hermes env
    // file. Agent shells inside those gateway sessions can then run
    // `node "$ADVERSERIAL_ACK_CLI" attestation` exactly as the skill expects.
    const ackEnv = { ADVERSERIAL_ACK_CLI: join(PACKAGE_ROOT, 'bin', 'ack.mjs') };
    let exported = await upsertDotenv(join(home, '.env'), ackEnv);
    if (home !== original && await upsertDotenv(join(original, '.env'), ackEnv)) exported = true;
    if (exported) process.stderr.write('ack: exported ADVERSERIAL_ACK_CLI into the Hermes env — restart Hermes gateways to load it.\n');
    return { command: binary, args: ['chat', '--provider', 'adverserial-confidential', '--model', state.model],
      env: { ...base, HERMES_HOME: home, OPENAI_BASE_URL: localGatewayUrl(env), OPENAI_API_KEY: state.apiKey } };
  }
  fail(`Unsupported harness ${name}.`);
}

function handleTermination(stop) {
  const terminate = () => { process.exitCode = 143; stop(); };
  const hangup = () => { process.exitCode = 129; stop(); };
  process.once('SIGTERM', terminate);
  process.once('SIGHUP', hangup);
  return () => { process.removeListener('SIGTERM', terminate); process.removeListener('SIGHUP', hangup); };
}

async function code(arguments_, env) {
  const state = await readState(env);
  const name = arguments_[0] ? normalizeHarness(arguments_[0]) : await chooseHarness();
  if (!HARNESS_NAMES.includes(name)) fail(`Unknown harness ${JSON.stringify(name)}. Choose ${HARNESS_NAMES.join(', ')}.`);
  resolveHarnessBinary(name, env);
  await ensureGateway(env);
  const session = await startSessionGateway(state, env);
  const gateway = session.child;
  env = session.env;
  let harness;
  const removeSignalHandlers = handleTermination(() => { harness?.kill('SIGTERM'); gateway.kill('SIGTERM'); });
  try {
    const selected = await harnessCommand(name, state, env);
    const launchStatus = new StatusLine(env);
    launchStatus.start(`Launching ${name} with verified confidential inference`);
    harness = spawn(selected.command, selected.args, { env: selected.env, stdio: 'inherit' });
    launchStatus.stop();
    const result = await waitFor(harness);
    if (result.code !== 0) process.exitCode = result.code;
  } finally {
    removeSignalHandlers();
    if (!gateway.killed) gateway.kill('SIGTERM');
  }
}

function parseSwarm(arguments_) {
  const options = { agents: [...HARNESS_NAMES], workers: 2, lead: null, task: '' };
  const task = [];
  for (let index = 0; index < arguments_.length; index += 1) {
    const value = arguments_[index];
    if (value === '--agents') { options.agents = (arguments_[++index] || '').split(',').map((item) => item.trim().toLowerCase()).filter(Boolean); continue; }
    if (value === '--workers') { options.workers = Number(arguments_[++index]); continue; }
    if (value === '--lead') { options.lead = (arguments_[++index] || '').trim().toLowerCase(); continue; }
    task.push(value);
  }
  options.task = task.join(' ').trim();
  if (!options.task) fail('Usage: ack swarm [--agents claude,codex] [--workers 2] [--lead claude] "task"');
  if (!Number.isInteger(options.workers) || options.workers < 1 || options.workers > 4) fail('--workers must be an integer between 1 and 4.');
  if (!options.agents.length || options.agents.some((agent) => !HARNESS_NAMES.includes(agent))) fail(`--agents must contain only: ${HARNESS_NAMES.join(', ')}.`);
  options.agents = [...new Set(options.agents)];
  options.lead ||= options.agents[0];
  if (!options.agents.includes(options.lead)) fail('--lead must be one of the selected agents.');
  return options;
}

export async function headlessCommand(name, state, env, prompt) {
  const selected = await harnessCommand(name, state, env);
  if (name === 'claude') return { ...selected, args: [...selected.args, '-p', prompt] };
  if (name === 'codex') return { ...selected, args: [...selected.args, 'exec', prompt] };
  if (name === 'opencode') return { ...selected, args: [...selected.args, 'run', prompt] };
  if (name === 'kimi') return { ...selected, args: [...selected.args, '-p', prompt] };
  if (name === 'pi' || name === 'oh-my-pi') return { ...selected, args: [...selected.args, '--print', prompt] };
  if (name === 'zcode') return { ...selected, args: ['--prompt', prompt], env: selected.env };
  if (name === 'deepseek-harness') return { ...selected, args: ['--profile', 'headless', '--patch', selected.env.ACK_DSH_PATCH, prompt], env: selected.env };
  if (name === 'hermes') return { ...selected, args: [...selected.args, '-q', prompt, '--oneshot'] };
  fail(`Unsupported headless harness ${name}.`);
}

function captureWorker(commandName, args, env, cwd, { signal, timeoutMs = 0 } = {}) {
  return new Promise((resolveWorker) => {
    const child = spawn(commandName, args, { env, cwd, signal, stdio: ['ignore', 'pipe', 'pipe'] });
    const timeout = timeoutMs ? setTimeout(() => child.kill('SIGTERM'), timeoutMs) : null;
    const finish = (result) => { if (timeout) clearTimeout(timeout); resolveWorker(result); };
    const chunks = [];
    let size = 0;
    const append = (chunk) => {
      if (size >= 2 * 1024 * 1024) return;
      const slice = chunk.subarray ? chunk.subarray(0, 2 * 1024 * 1024 - size) : Buffer.from(String(chunk));
      chunks.push(slice); size += slice.length;
    };
    child.stdout.on('data', append); child.stderr.on('data', append);
    child.once('error', (error) => finish({ code: 1, output: signal?.aborted ? 'Verification cancelled.\n' : `Worker could not start: ${error.message}\n` }));
    child.once('close', (code) => finish({ code: code ?? 1, output: Buffer.concat(chunks).toString('utf8') }));
  });
}

async function runPool(items, limit, run) {
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const item = items[cursor++];
      await run(item);
    }
  }));
}

async function runSwarm(arguments_, env) {
  const options = parseSwarm(arguments_);
  for (const agent of options.agents) resolveHarnessBinary(agent, env);
  const state = await readState(env);
  await ensureGateway(env);
  const job = join(appHome(env), 'swarms', `${new Date().toISOString().replace(/[:.]/g, '-')}-${process.pid}`);
  const results = join(job, 'results');
  await privateDirectory(results);
  const brief = join(job, 'brief.md');
  await writeFile(brief, `# Confidential swarm brief\n\n${options.task}\n\nAll worker output remains in this local directory. Do not place API keys, credentials, or private data in a report.\n`, { mode: 0o600 });
  const session = await startSessionGateway(state, env);
  const gateway = session.child;
  env = session.env;
  const cancelled = new AbortController();
  const removeSignalHandlers = handleTermination(() => { cancelled.abort(); gateway.kill('SIGTERM'); });
  try {
    let failedWorkers = 0;
    const workers = options.agents.filter((agent) => agent !== options.lead);
    process.stdout.write(`Starting ${workers.length} confidential workers; results stay in ${job}.\n`);
    await runPool(workers, options.workers, async (agent) => {
      if (cancelled.signal.aborted) return;
      const prompt = `You are the ${agent} worker in a confidential coding swarm. Work on this task:\n${options.task}\n\nRead the shared brief at ${brief}. Return a concise, concrete report with findings, proposed edits, and verification steps. Other workers will read your report from the shared local directory.`;
      const selected = await headlessCommand(agent, state, env, prompt);
      const result = await captureWorker(selected.command, selected.args, selected.env, process.cwd(), { signal: cancelled.signal });
      if (result.code !== 0) failedWorkers++;
      await writeFile(join(results, `${agent}.md`), `# ${agent} worker (exit ${result.code})\n\n${result.output}`, { mode: 0o600 });
    });
    if (cancelled.signal.aborted) return;
    const handoff = join(job, 'handoff.md');
    const reportList = options.agents.filter((agent) => agent !== options.lead).map((agent) => `- ${join(results, `${agent}.md`)}`).join('\n') || '- No additional worker reports';
    await writeFile(handoff, `# Swarm handoff\n\nTask: ${options.task}\n\nWorker reports:\n${reportList}\n`, { mode: 0o600 });
    const leadPrompt = `You are the lead (${options.lead}) in a confidential coding swarm. Complete this task: ${options.task}\n\nRead ${handoff} and every worker report it lists. Reconcile the findings, inspect the current workspace where needed, then produce the final implementation or review. Do not treat unverified worker claims as facts.`;
    const lead = await headlessCommand(options.lead, state, env, leadPrompt);
    const result = await captureWorker(lead.command, lead.args, lead.env, process.cwd(), { signal: cancelled.signal });
    const finalReport = join(job, 'lead.md');
    await writeFile(finalReport, `# ${options.lead} lead (exit ${result.code})\n\n${result.output}`, { mode: 0o600 });
    process.stdout.write(`Swarm complete. Lead report: ${finalReport}\n`);
    if (failedWorkers) process.stdout.write(`${failedWorkers} worker(s) failed; review their reports before relying on the lead result.\n`);
    if (result.code !== 0 || failedWorkers) process.exitCode = result.code || 1;
  } finally {
    cancelled.abort();
    removeSignalHandlers();
    if (!gateway.killed) gateway.kill('SIGTERM');
  }
}

const roomRoot = (env) => join(appHome(env), 'swarm-rooms');
const activeRoomPath = (env) => join(roomRoot(env), 'active-room');
const roomName = (value) => {
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/i.test(value)) fail('Room names may contain letters, numbers, and hyphens only.');
  return value;
};

async function activeRoom(env) {
  try { return roomName((await readFile(activeRoomPath(env), 'utf8')).trim()); }
  catch { fail('No active swarm room. Create one with `ack swarm create <name>`.'); }
}

async function ensureRoom(name, env) {
  const room = join(roomRoot(env), roomName(name));
  const events = join(room, 'events');
  await privateDirectory(events);
  if (!existsSync(join(room, 'room.json'))) {
    await privateJson(join(room, 'room.json'), { version: 1, name, createdAt: new Date().toISOString() });
  }
  await privateDirectory(roomRoot(env));
  await writeFile(activeRoomPath(env), `${name}\n`, { mode: 0o600 });
  return room;
}

function swarmFlag(arguments_, flag) {
  const index = arguments_.indexOf(flag);
  if (index === -1) return null;
  const value = arguments_[index + 1];
  if (!value || value.startsWith('--')) fail(`${flag} requires a value.`);
  return value;
}

function swarmMessage(arguments_, flags) {
  const ignored = new Set();
  for (const flag of flags) {
    const index = arguments_.indexOf(flag);
    if (index >= 0) { ignored.add(index); ignored.add(index + 1); }
  }
  const message = arguments_.filter((_value, index) => !ignored.has(index)).join(' ').trim();
  if (!message) fail('A task or message is required.');
  return message;
}

async function appendRoomEvent(room, event) {
  const directory = join(room, 'events');
  const id = `${Date.now()}-${process.pid}-${Math.random().toString(16).slice(2)}`;
  await writeFile(join(directory, `${id}.json`), `${JSON.stringify({ id, createdAt: new Date().toISOString(), ...event })}\n`, { mode: 0o600, flag: 'wx' });
}

async function roomEvents(room) {
  const { readdir } = await import('node:fs/promises');
  const files = (await readdir(join(room, 'events'))).filter((file) => file.endsWith('.json')).sort();
  const events = [];
  for (const file of files) {
    try { events.push(JSON.parse(await readFile(join(room, 'events', file), 'utf8'))); } catch { /* Ignore a partial/corrupt local event. */ }
  }
  return events;
}

async function swarmCreate(arguments_, env) {
  const name = roomName(arguments_[0] || `room-${Date.now()}`);
  const room = await ensureRoom(name, env);
  process.stdout.write(`Swarm room ${name} is ready.\nInvite an existing agent: ack swarm invite --to pi "task"\nLocal room: ${room}\n`);
}

async function swarmInvite(arguments_, env) {
  const recipient = (swarmFlag(arguments_, '--to') || '').toLowerCase();
  if (!HARNESS_NAMES.includes(recipient)) fail(`--to must be one of: ${HARNESS_NAMES.join(', ')}.`);
  const name = swarmFlag(arguments_, '--room') || await activeRoom(env);
  const room = await ensureRoom(name, env);
  const task = swarmMessage(arguments_, ['--to', '--room']);
  await appendRoomEvent(room, { type: 'task', from: 'user-or-agent', to: recipient, task });
  process.stdout.write(`Assigned a confidential swarm task to ${recipient} in room ${name}.\n${recipient} can read it with: ack swarm inbox --agent ${recipient} --room ${name}\n`);
}

async function swarmInbox(arguments_, env) {
  const agent = (swarmFlag(arguments_, '--agent') || '').toLowerCase();
  if (!HARNESS_NAMES.includes(agent)) fail(`--agent must be one of: ${HARNESS_NAMES.join(', ')}.`);
  const name = swarmFlag(arguments_, '--room') || await activeRoom(env);
  const events = (await roomEvents(join(roomRoot(env), roomName(name)))).filter((event) => event.to === agent || event.to === 'all');
  if (arguments_.includes('--json')) { process.stdout.write(`${JSON.stringify(events)}\n`); return; }
  if (!events.length) { process.stdout.write(`No pending messages for ${agent} in ${name}.\n`); return; }
  for (const event of events) process.stdout.write(`[${event.createdAt}] ${event.from} → ${agent}\n${event.task || event.message || ''}\n\n`);
}

async function swarmPost(arguments_, env) {
  const from = (swarmFlag(arguments_, '--from') || '').toLowerCase();
  if (!HARNESS_NAMES.includes(from)) fail(`--from must be one of: ${HARNESS_NAMES.join(', ')}.`);
  const recipient = (swarmFlag(arguments_, '--to') || 'all').toLowerCase();
  if (recipient !== 'all' && !HARNESS_NAMES.includes(recipient)) fail(`--to must be one of: all, ${HARNESS_NAMES.join(', ')}.`);
  const name = swarmFlag(arguments_, '--room') || await activeRoom(env);
  const room = await ensureRoom(name, env);
  const message = swarmMessage(arguments_, ['--from', '--to', '--room']);
  await appendRoomEvent(room, { type: 'result', from, to: recipient, message });
  process.stdout.write(`Posted ${from}'s update to ${recipient} in room ${name}.\n`);
}

async function swarmCommand(arguments_, env) {
  const subcommand = arguments_[0];
  if (subcommand === '--help' || subcommand === '-h' || subcommand === 'help') {
    process.stdout.write('Usage: ack swarm [--agents claude,pi] [--workers 2] [--lead claude] "task"\n       ack swarm create <room>\n       ack swarm invite --to <harness> "task"\n       ack swarm inbox --agent <harness> [--json]\n       ack swarm post --from <harness> [--to <harness>|all] "result"\n');
    return;
  }
  if (subcommand === 'create') return swarmCreate(arguments_.slice(1), env);
  if (subcommand === 'invite') return swarmInvite(arguments_.slice(1), env);
  if (subcommand === 'inbox') return swarmInbox(arguments_.slice(1), env);
  if (subcommand === 'post') return swarmPost(arguments_.slice(1), env);
  return runSwarm(arguments_, env);
}

async function attestation(arguments_, env) {
  const state = await readState(env);
  const args = [resource('plugins', 'claude-code', 'bin', 'adverserial-verify-cli.mjs')];
  if (arguments_.includes('--json')) args.push('--json');
  const result = await waitFor(spawn(process.execPath, args, { env: verifiedEnvironment(state, env), stdio: 'inherit' }));
  if (result.code !== 0) process.exitCode = result.code;
}

async function promptProfileName() {
  if (!process.stdin.isTTY) fail('Specify a profile name: ack keys add <name>.');
  const line = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  const answer = await new Promise((resolveAnswer) => line.question('\x1b[38;5;81mProfile name\x1b[0m \x1b[2m(e.g. personal or work)\x1b[0m: ', resolveAnswer));
  line.close();
  return validateProfileName(answer);
}

function printKeyProfiles(state) {
  const { profiles, activeKeyProfile } = keyProfiles(state);
  const names = Object.keys(profiles).sort();
  process.stdout.write('\n\x1b[1m  API-key profiles\x1b[0m  \x1b[2m(keys are masked)\x1b[0m\n');
  names.forEach((name, index) => {
    const active = name === activeKeyProfile;
    const number = String(index + 1).padStart(2, '0');
    const marker = active ? '\x1b[38;5;120m● active\x1b[0m' : '\x1b[2m○ saved\x1b[0m';
    process.stdout.write(`  \x1b[38;5;${[81, 213, 120, 214, 39, 141][index % 6]}m${number}\x1b[0m  \x1b[1m${name}\x1b[0m  \x1b[2m${profiles[name].mask}\x1b[0m  ${marker}\n`);
  });
  process.stdout.write('\n');
  return names;
}

async function chooseKeyProfile(state) {
  if (!process.stdin.isTTY) fail('Choose a profile explicitly: ack keys use <name>.');
  const names = printKeyProfiles(state);
  const line = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  const answer = await new Promise((resolveAnswer) => line.question('\x1b[38;5;81mack\x1b[0m \x1b[2m/ keys use ›\x1b[0m ', resolveAnswer));
  line.close();
  const number = Number(answer.trim());
  const chosen = Number.isInteger(number) && number >= 1 && number <= names.length ? names[number - 1] : answer;
  return validateProfileName(chosen);
}

async function keysCommand(arguments_, env) {
  const [rawAction = 'list', rawName] = arguments_;
  const action = rawAction.toLowerCase();
  const state = await readState(env);
  const { profiles, activeKeyProfile } = keyProfiles(state);

  if (action === 'help' || action === '--help' || action === '-h') {
    process.stdout.write('Usage: ack keys [list]\n       ack keys add [name]\n       ack keys modify <name>\n       ack keys use [name]\n       ack keys delete <name>\n\nProfiles are stored locally with mode 0600. Key values are hidden while entered and masked when listed.\n');
    return;
  }
  if (action === 'list') { printKeyProfiles(state); return; }

  if (action === 'add' || action === 'modify') {
    const name = rawName ? validateProfileName(rawName) : await promptProfileName();
    if (action === 'add' && profiles[name]) fail(`Profile ${JSON.stringify(name)} already exists. Use \`ack keys modify ${name}\` to replace its key.`);
    if (action === 'modify' && !profiles[name]) fail(`Profile ${JSON.stringify(name)} does not exist. Use \`ack keys add ${name}\` first.`);
    const apiKey = await promptApiKey(`API key for ${name}`);
    if (!apiKey) fail('An API key is required. Nothing was saved.');
    const now = new Date().toISOString();
    profiles[name] = { apiKey, createdAt: profiles[name]?.createdAt || now, updatedAt: now };
    const next = { ...state, apiKeyProfiles: profiles, activeKeyProfile, apiKey: name === activeKeyProfile ? apiKey : state.apiKey, updatedAt: now };
    await writeState(next, env);
    process.stdout.write(`\x1b[38;5;120m✓\x1b[0m ${action === 'add' ? 'Added' : 'Updated'} profile \x1b[1m${name}\x1b[0m (${maskApiKey(apiKey)}).\n`);
    return;
  }

  if (action === 'use') {
    const name = rawName ? validateProfileName(rawName) : await chooseKeyProfile(state);
    if (!profiles[name]) fail(`Profile ${JSON.stringify(name)} does not exist. Run \`ack keys list\` to see saved profiles.`);
    if (name === activeKeyProfile) {
      process.stdout.write(`\x1b[38;5;120m✓\x1b[0m Profile \x1b[1m${name}\x1b[0m is already active.\n`);
      return;
    }
    const now = new Date().toISOString();
    const activeApiKey = decryptApiKey(profiles[name].encryptedKey, await encryptedStorageKey(env));
    await writeState({ ...state, apiKeyProfiles: profiles, activeKeyProfile: name, apiKey: activeApiKey, updatedAt: now }, env);
    process.stdout.write(`\x1b[38;5;120m✓\x1b[0m Active profile: \x1b[1m${name}\x1b[0m (${profiles[name].mask}).\n`);
    return;
  }

  if (action === 'delete') {
    if (!rawName) fail('Specify a profile: ack keys delete <name>.');
    const name = validateProfileName(rawName);
    if (!profiles[name]) fail(`Profile ${JSON.stringify(name)} does not exist.`);
    if (name === activeKeyProfile) fail('Cannot delete the active profile. Activate another saved profile first with `ack keys use <name>`.');
    delete profiles[name];
    const now = new Date().toISOString();
    await writeState({ ...state, apiKeyProfiles: profiles, activeKeyProfile, apiKey: state.apiKey, updatedAt: now }, env);
    process.stdout.write(`\x1b[38;5;120m✓\x1b[0m Deleted profile \x1b[1m${name}\x1b[0m.\n`);
    return;
  }
  fail(`Unknown keys command ${JSON.stringify(rawAction)}. Run \`ack keys help\`.`);
}

// Read only non-secret metadata for the console. Opening ACK should neither
// unlock the vault nor contact a remote endpoint.
export async function consoleSnapshot(env = process.env) {
  let state = {};
  try { state = JSON.parse(await readFile(statePath(env), 'utf8')); } catch { /* First run. */ }
  const profiles = state.apiKeyProfiles && typeof state.apiKeyProfiles === 'object' ? state.apiKeyProfiles : {};
  return {
    version: JSON.parse(await readFile(join(PACKAGE_ROOT, 'package.json'), 'utf8')).version,
    configured: Boolean(state.version && state.model),
    model: typeof state.model === 'string' ? state.model : null,
    activeProfile: typeof state.activeKeyProfile === 'string' ? state.activeKeyProfile : state.version === 1 ? 'default' : null,
    profiles: Object.entries(profiles).filter(([, profile]) => profile && typeof profile === 'object').map(([name, profile]) => ({
      name, mask: typeof profile.mask === 'string' ? profile.mask : '••••••••', active: name === state.activeKeyProfile
    })),
    runtime: existsSync(executable(env, 'adverserial-confidential-gateway')),
    endpoint: typeof state.endpoint === 'string' ? state.endpoint : DEFAULT_ENDPOINT
  };
}

const HARNESS_INFO = {
  claude: ['claude', 'Install the official Claude Code CLI, then run code claude.'],
  codex: ['codex', 'Install the official OpenAI Codex CLI, then run code codex.'],
  opencode: ['opencode', 'Install the official OpenCode CLI, then run code opencode.'],
  pi: ['pi', 'Install the official Pi CLI, then run code pi.'],
  'oh-my-pi': ['omp', 'Install the official Oh My Pi CLI, then run code oh-my-pi.'],
  zcode: ['zcode', 'Install the official ZCode CLI, then run code zcode.'],
  'deepseek-harness': ['dsh', 'Install the official DeepSeek Harness CLI, then run code deepseek-harness.'],
  hermes: ['hermes', 'Install the official Hermes CLI, then run code hermes.'],
  kimi: ['kimi', 'Install the official Kimi Code CLI, then run code kimi.']
};

export function harnessInventory(env = process.env) {
  return HARNESS_NAMES.map((id) => {
    let path = null;
    try { path = resolveHarnessBinary(id, env); } catch { /* Show it as unavailable. */ }
    return { id, label: HARNESS_LABELS[id], available: Boolean(path), path, binary: HARNESS_INFO[id][0], install: HARNESS_INFO[id][1] };
  });
}

export async function consolePreferences(env = process.env) {
  try {
    const saved = JSON.parse(await readFile(join(appHome(env), 'console.json'), 'utf8'));
    return { theme: isTheme(saved.theme) ? saved.theme : 'aurora', motion: saved.motion !== false };
  } catch { return { theme: 'aurora', motion: true }; }
}

async function saveConsolePreferences(patch, env) {
  const current = await consolePreferences(env);
  await privateJson(join(appHome(env), 'console.json'), {
    theme: isTheme(patch.theme) ? patch.theme : current.theme,
    motion: typeof patch.motion === 'boolean' ? patch.motion : current.motion
  });
}

let cachedModels = null;
export async function publishedModels() {
  if (cachedModels && Date.now() - cachedModels.at < 60_000) return cachedModels.models;
  let registry;
  try { registry = await fetchJson(MODELS_URL); } catch { /* Active policy remains the fallback. */ }
  const entries = Array.isArray(registry) ? registry : registry?.models;
  let models = Array.isArray(entries) ? entries.map((entry) => typeof entry === 'string' ? { id: entry } : entry)
    .filter((entry) => entry && typeof (entry.id || entry.model_id) === 'string')
    .map((entry) => ({
      id: entry.id || entry.model_id,
      name: entry.display_name || entry.name || entry.id || entry.model_id,
      description: entry.description || '',
      policyRef: entry.policy_ref
    })) : [];
  if (!models.length) {
    const policy = await fetchProductionPolicy();
    models = [{ id: policy.model_id, name: policy.model_id, description: policy.description || 'Confidential inference' }];
  }
  cachedModels = { at: Date.now(), models };
  return models;
}

export function modelPolicyURL(reference) {
  const url = new URL(reference, 'https://verify.adverserial.ai/');
  if (url.origin !== 'https://verify.adverserial.ai' || !url.pathname.startsWith('/policies/') || url.search || url.hash || url.username || url.password) {
    fail('Published model has an invalid verification-policy reference.');
  }
  return url.href;
}

export async function publishedModelPolicy(id, { models, fetchImpl = fetch } = {}) {
  const model = (models || await publishedModels()).find((entry) => entry.id === id);
  if (!model) fail('That model is not in the published Adverserial registry. Run `ack models`.');
  // The deployment policy is authoritative for the model it names. Registry
  // policy references may still name historical template documents with old
  // keys; they must not override a complete, active production policy.
  const production = await fetchProductionPolicy({ fetchImpl });
  if (production.model_id === id) return { policy: production, url: POLICY_URL };
  if (!model.policyRef) fail('The selected model does not have a published verification policy.');
  const url = modelPolicyURL(model.policyRef);
  const policy = await fetchJson(url, fetchImpl);
  if (!policy || policy.status !== 'active' || policy.model_id !== id || !validKeys(policy.receipt_keys)) {
    fail('The selected model does not have a complete active verification policy.');
  }
  return { policy, url };
}

export async function activateModel(id, env = process.env, dependencies) {
  const { policy, url } = await publishedModelPolicy(id, dependencies);
  const state = await readState(env);
  // The model's receipt-key pins must change together with the selected model.
  await saveSetup(state.apiKey, policy, env, state, url);
}

async function saveConsoleKey(rawName, apiKey, modify, env) {
  const name = validateProfileName(rawName);
  if (typeof apiKey !== 'string' || !apiKey.trim()) fail('An API key is required. Nothing was saved.');
  const state = await readState(env);
  const { profiles, activeKeyProfile } = keyProfiles(state);
  if (!modify && profiles[name]) fail('That profile already exists. Choose Replace this key.');
  if (modify && !profiles[name]) fail('That profile does not exist. Add it first.');
  const now = new Date().toISOString();
  profiles[name] = { apiKey: apiKey.trim(), createdAt: profiles[name]?.createdAt || now, updatedAt: now };
  await writeState({ ...state, apiKeyProfiles: profiles, activeKeyProfile, apiKey: activeKeyProfile === name ? apiKey.trim() : state.apiKey }, env);
}

async function capturedVerification(env, signal) {
  const state = await readState(env);
  const { formatVerdict } = await import('./../resources/plugins/opencode/dist/plugins/shared/src/format.js');
  const result = await captureWorker(process.execPath, [resource('plugins', 'claude-code', 'bin', 'adverserial-verify-cli.mjs'), '--json'], verifiedEnvironment(state, env), process.cwd(), { signal, timeoutMs: 60_000 });
  let verdict;
  try { verdict = JSON.parse(result.output); }
  catch { fail(result.output.trim() || 'The verification process did not return a verdict.'); }
  return { ...verdict, report: formatVerdict(verdict) };
}

async function workstationChecks(env) {
  const snapshot = await consoleSnapshot(env);
  const checks = [
    { label: 'Node.js', ok: Number(process.versions.node.split('.')[0]) >= 18, detail: process.version },
    { label: 'Encrypted vault', ok: snapshot.configured, detail: snapshot.configured ? `${snapshot.profiles.length} saved profile(s)` : 'Run init to save your first key' },
    { label: 'Gateway runtime', ok: snapshot.runtime, detail: snapshot.runtime ? 'Prepared; launched and stopped with coding sessions' : 'Run init or upgrade' },
    { label: 'Hardware verifier', ok: existsSync(resource('typescript', 'dist', 'phala.js')), detail: 'Bundled independent hardware verifier' },
    { label: 'Receipt-key pins', ok: existsSync(keysPath(env)), detail: existsSync(keysPath(env)) ? 'Configured; run attestation to verify fresh evidence' : 'Run init to fetch the published policy' }
  ];
  for (const harness of harnessInventory(env)) checks.push({ label: harness.label, ok: harness.available, detail: harness.path || harness.install });
  return checks;
}

export function consoleBackend(env = process.env) {
  return {
    cwd: process.cwd().replace(env.HOME || '\0', '~'),
    snapshot: () => consoleSnapshot(env),
    preferences: () => consolePreferences(env),
    savePreferences: (patch) => saveConsolePreferences(patch, env),
    harnesses: () => harnessInventory(env),
    models: publishedModels,
    useModel: (id) => activateModel(id, env),
    verify: (signal) => capturedVerification(env, signal),
    doctor: () => workstationChecks(env),
    keyAction: async (action, rawName) => {
      const name = validateProfileName(rawName);
      const state = await readState(env);
      const { profiles, activeKeyProfile } = keyProfiles(state);
      if (!profiles[name]) fail('That key profile does not exist.');
      if (action === 'delete') {
        if (name === activeKeyProfile) fail('Activate another key before deleting this profile.');
        delete profiles[name];
        await writeState({ ...state, apiKeyProfiles: profiles }, env); return;
      }
      if (action !== 'use') fail('Unknown key-profile action.');
      const apiKey = decryptApiKey(profiles[name].encryptedKey, await encryptedStorageKey(env));
      await writeState({ ...state, apiKeyProfiles: profiles, activeKeyProfile: name, apiKey }, env);
    },
    saveKey: (name, key, modify) => saveConsoleKey(name, key, modify, env),
    initialize: async (apiKey, progress) => {
      if (!apiKey.trim()) fail('An API key is required.');
      progress('Fetching the active verification policy');
      const policy = await fetchProductionPolicy();
      await saveSetup(apiKey, policy, env);
      await installGateway(env, progress);
    },
    upgrade: async (progress) => {
      const prior = await readState(env);
      progress('Refreshing published receipt-key pins');
      const { policy, url } = await publishedModelPolicy(prior.model);
      await saveSetup(prior.apiKey, policy, env, prior, url);
      await installGateway(env, progress);
    },
    capture: async (tokens) => {
      const result = await captureWorker(process.execPath, [join(PACKAGE_ROOT, 'bin', 'ack.mjs'), ...tokens], { ...env, ACK_QUIET: '1', ACK_SHELL: '1' }, process.cwd());
      if (result.code) fail(result.output.trim() || `Command exited with status ${result.code}.`);
      return result.output;
    },
    run: async (tokens) => {
      const result = await waitFor(spawn(process.execPath, [join(PACKAGE_ROOT, 'bin', 'ack.mjs'), ...tokens], {
        env: { ...env, ACK_SHELL: '1' }, stdio: 'inherit'
      }));
      if (result.code) fail(`${tokens[0] === 'code' && tokens[1] ? HARNESS_LABELS[tokens[1]] || tokens[1] : tokens[0]} exited with status ${result.code}.`);
    }
  };
}

async function shell(env, initialCommand = '') {
  if (!process.stdin.isTTY || !process.stdout.isTTY || env.TERM === 'dumb') {
    process.stdout.write(`${usage()}\n`); return;
  }
  return runConsole(consoleBackend(env), { env, initialCommand });
}

async function models() {
  for (const model of await publishedModels()) process.stdout.write(`${model.id}\t${model.name}\n`);
}

export async function main(arguments_, env = process.env) {
  const [action, ...rest] = arguments_;
  if (!action) return shell(env);
  if (!env.ACK_QUIET && !env.ACK_SHELL && (action === '--help' || action === '-h' || action === 'help')) banner();
  if (action === '--help' || action === '-h' || action === 'help') { process.stdout.write(`${usage()}\n`); return; }
  if (action === 'init') return init(env);
  if (action === 'upgrade') return upgrade(env);
  if (action === 'models' && rest[0] === 'use') return activateModel(rest[1], env);
  if (action === 'model') return activateModel(rest[0], env);
  if (action === 'models') return models();
  if (action === 'harnesses') {
    for (const harness of harnessInventory(env)) process.stdout.write(`${harness.available ? '✓' : '○'} ${harness.label.padEnd(18)} ${harness.available ? harness.path : 'not installed'}\n`);
    return;
  }
  if (action === 'status') {
    const snapshot = await consoleSnapshot(env);
    process.stdout.write(`${JSON.stringify(snapshot, null, 2)}\n`); return;
  }
  if (action === 'doctor') {
    for (const check of await workstationChecks(env)) process.stdout.write(`${check.ok ? 'PASS' : 'CHECK'}  ${check.label.padEnd(20)} ${check.detail}\n`);
    return;
  }
  if (action === 'theme') {
    if (!isTheme(rest[0])) fail(`Choose a theme: ${Object.keys(THEMES).join(', ')}.`);
    await saveConsolePreferences({ theme: rest[0] }, env); return;
  }
  if (action === 'shell') return shell(env);
  if (action === 'keys') return keysCommand(rest, env);
  if (action === 'attestation') return attestation(rest, env);
  if (action === 'code' && !rest.length && process.stdin.isTTY && process.stdout.isTTY) return shell(env, 'code');
  if (action === 'code') return code(rest, env);
  if (action === 'swarm') return swarmCommand(rest, env);
  fail(`Unknown command ${JSON.stringify(action)}.\n\n${usage()}`);
}

import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { accessSync, constants, existsSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { delimiter, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

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
const KIMI_MODEL_ALIAS = 'adverserial_confidential';
const KIMI_CONFIG_BEGIN = '# BEGIN ADVERSERIAL CONFIDENTIAL KIT (managed by ack)';
const KIMI_CONFIG_END = '# END ADVERSERIAL CONFIDENTIAL KIT';
// Terminal rendition of the upper A/X mark from the supplied Adverserial
// artwork. It retains the broad left blade, open centre, crossbar, and right
// descending blade; do not replace this with a generic letter “A”.
const MARK = String.raw`              #######
             ########
            #######.+#.
           #######.+###.
          ####### +#####.
         #######  .#####+    .++.
        #######    .#####+++###+
      #######      .#########+
     ########     .++######+.
    ########   .++####+#####.
   ######## .+###++..  +#####.
  ############.        +#####.
 ########.             ######.
 #######                 .+####.
`;

const MARK_COLORS = { '.': 250, '+': 254, '#': 255 };

function coloredMark() {
  return MARK.replace(/[.+#]/g, (character) => `\x1b[38;5;${MARK_COLORS[character]}m${character}\x1b[0m`);
}

function banner() {
  const lines = coloredMark().trimEnd().split('\n');
  const titleRow = Math.floor(lines.length / 2) - 1;
  const output = lines.map((line, index) => {
    if (index === titleRow) return `${line}  \x1b[1mADVERSERIAL CONFIDENTIAL\x1b[0m`;
    if (index === titleRow + 1) return `${line}  \x1b[2mConfidential coding kit\x1b[0m`;
    return line;
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
  ack init                 Save your first API key and prepare confidential coding
  ack keys …               Add, modify, delete, list, or activate API-key profiles
  ack upgrade              Refresh the confidential runtime and pinned policy
  ack models               List models published in the policy registry
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
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  try { await chmod(temporary, 0o600); } catch { /* Windows ACLs are OS-managed. */ }
  await rename(temporary, path);
  try { await chmod(path, 0o600); } catch { /* Windows ACLs are OS-managed. */ }
}

async function privateText(path, value) {
  await privateDirectory(dirname(path));
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, value, { mode: 0o600 });
  try { await chmod(temporary, 0o600); } catch { /* Windows ACLs are OS-managed. */ }
  await rename(temporary, path);
  try { await chmod(path, 0o600); } catch { /* Windows ACLs are OS-managed. */ }
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
  process.stdout.write(`\x1b[38;5;81m${label}\x1b[0m \x1b[2m(input hidden)\x1b[0m: `);
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
        if (character === '\u0003') { input.setRawMode(false); process.stdout.write('\n'); rejectPrompt(new Error('Cancelled.')); return; }
        if (character === '\r' || character === '\n') { done(); return; }
        if (character === '\u007f') {
          if (value) { value = value.slice(0, -1); process.stdout.write('\b \b'); }
          continue;
        }
        if (character >= ' ') { value += character; process.stdout.write('•'); }
      }
    };
    input.on('data', onData);
  });
}

function validKeys(value) {
  return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length > 0 &&
    Object.entries(value).every(([kid, key]) => typeof kid === 'string' && key && typeof key === 'object' && key.kty === 'EC' && key.crv === 'P-256');
}

async function fetchJson(url, fetchImpl = fetch) {
  const response = await fetchImpl(url, { headers: { accept: 'application/json' }, redirect: 'error' });
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

export async function installGateway(env = process.env, progress = () => {}) {
  await privateDirectory(appHome(env));
  const interpreter = python();
  const venv = join(appHome(env), 'venv');
  if (!existsSync(executable(env, 'python'))) {
    progress('Creating isolated confidential runtime');
    await command(interpreter, ['-m', 'venv', venv]);
  }
  progress('Installing verified client runtime');
  await command(executable(env, 'pip'), ['install', '--disable-pip-version-check', '--no-input', '--no-deps', '--force-reinstall', resource('python')]);
  progress('Installing confidential gateway');
  await command(executable(env, 'pip'), ['install', '--disable-pip-version-check', '--no-input', resource('gateway')]);
  progress('Finalizing hardware verification');
  try { await chmod(resource('typescript', 'adverserial-hardware-verify.mjs'), 0o755); } catch { /* Npm preserves mode on Unix. */ }
  await privateJson(gatewayMarkerPath(env), { revision: await kitRevision(), installedAt: new Date().toISOString() });
}

async function ensureGateway(env = process.env) {
  let marker;
  try { marker = JSON.parse(await readFile(gatewayMarkerPath(env), 'utf8')); } catch { marker = null; }
  if (!existsSync(executable(env, 'adverserial-confidential-gateway')) || marker?.revision !== await kitRevision()) {
    await withStatus('Preparing confidential runtime', env, (progress) => installGateway(env, progress));
  }
}

async function saveSetup(apiKey, policy, env, prior = null) {
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
    policyUrl: POLICY_URL,
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
  const policy = await withStatus('Checking signed production policy', env, () => fetchProductionPolicy());
  await withStatus('Saving pinned verification policy', env, () => saveSetup(prior.apiKey, policy, env, prior));
  await withStatus('Preparing confidential runtime', env, (progress) => installGateway(env, progress));
}

function verifiedEnvironment(state, env) {
  return {
    ...env,
    ADVERSERIAL_ACK_CLI: join(PACKAGE_ROOT, 'bin', 'ack.mjs'),
    ADVERSERIAL_API_KEY: state.apiKey,
    ADVERSERIAL_API_URL: state.endpoint,
    ADVERSERIAL_CC_API_URL: state.endpoint,
    ADVERSERIAL_GATEWAY_URL: localGatewayUrl(env),
    ADVERSERIAL_MODEL: state.model,
    ADVERSERIAL_RECEIPT_KEYS_FILE: keysPath(env),
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

async function gatewayAlreadyRunning(env) {
  try { return (await fetch(`${localGatewayOrigin(env)}/healthz`, { signal: AbortSignal.timeout(300) })).ok; }
  catch { return false; }
}

async function waitForGateway(child, startupError, env) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (startupError.error) fail(`The local confidential runtime could not start: ${startupError.error.message}`);
    if (child.exitCode !== null) fail('The local confidential runtime stopped during startup. Run `ack upgrade` and retry.');
    try {
      const response = await fetch(`${localGatewayOrigin(env)}/healthz`, { signal: AbortSignal.timeout(500) });
      if (response.ok) return;
    } catch { /* Gateway is still starting. */ }
    await new Promise((resolveSleep) => setTimeout(resolveSleep, 150));
  }
  fail('The local confidential gateway did not become ready. Run `ack upgrade` and retry.');
}

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

async function codexProfile(env, binary) {
  const codexHome = env.CODEX_HOME || join(env.HOME || process.cwd(), '.codex');
  await privateDirectory(codexHome);
  const profile = (await readFile(resource('profiles', 'codex.confidential.toml'), 'utf8'))
    .replace('http://127.0.0.1:8787/v1', localGatewayUrl(env));
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
  await command(binary, ['plugin', 'marketplace', 'add', 'AdverserialAI/confidential-sdk', '--ref', 'main']);
  await command(binary, ['plugin', 'add', 'adverserial-verify@adverserial']);
}

async function harnessConfig(name, env) {
  const dir = join(appHome(env), 'harness-config');
  await privateDirectory(dir);
  const file = 'hermes.confidential.yaml';
  const target = join(dir, file);
  await writeFile(target, await readFile(resource('profiles', file)), { mode: 0o600 });
  return target;
}

async function configureOpenCode(state, env) {
  // OpenCode has no --config flag. It discovers config at
  // $XDG_CONFIG_HOME/opencode/, so give it an isolated ACK-owned config home
  // rather than modifying the user's existing OpenCode installation.
  const xdgConfigHome = join(appHome(env), 'opencode');
  const config = join(xdgConfigHome, 'opencode', 'opencode.json');
  const plugin = join(xdgConfigHome, 'opencode', 'plugins', 'adverserial.ts');
  const commandFile = join(xdgConfigHome, 'opencode', 'commands', 'adverserial-attestation.md');
  const profile = (await readFile(resource('profiles', 'opencode.jsonc'), 'utf8'))
    .replace('http://127.0.0.1:8787/v1', localGatewayUrl(env))
    .replaceAll('lordx64/cyberglm', state.model);
  const pluginPath = resource('plugins', 'opencode', 'dist', 'plugins', 'opencode', 'src', 'index.js');
  await privateText(config, profile);
  await privateText(plugin, `export { AdverserialPlugin as default } from ${JSON.stringify(pluginPath)};\n`);
  await privateText(commandFile, `---\ndescription: Run a fresh Adverserial confidential-runtime attestation check\n---\n\nUse the \`adverserial_verify\` tool to run a fresh check. Report its verdict exactly, including the endpoint, policy, evidence digest, expiry, and trust state. A failure, stale verdict, or unpinned result is not verified.\n`);
  return { ...verifiedEnvironment(state, env), XDG_CONFIG_HOME: xdgConfigHome };
}

async function configureZCode(state, env) {
  const home = join(appHome(env), 'zcode');
  const config = join(home, 'cli', 'config.json');
  await privateJson(config, {
    $schema: 'zcode.config.v1',
    provider: {
      zai: {
        kind: 'openai-compatible',
        name: 'Adverserial Confidential',
        options: { baseURL: localGatewayUrl(env), apiKey: state.apiKey, apiKeyRequired: true },
        models: {
          [state.model]: {
            name: 'CyberGLM — verified confidential runtime', contextWindow: 1048576,
            maxOutputTokens: 65536, supportsToolCall: true, supportsReasoning: true, supportsImages: false
          }
        }
      }
    },
    model: { main: `zai/${state.model}`, lite: `zai/${state.model}` }
  });
  return { ...verifiedEnvironment(state, env), ZCODE_DATA_BASE_DIR: home };
}

async function configureDeepSeekHarness(state, env) {
  const home = join(appHome(env), 'deepseek-harness');
  const patch = join(home, 'cordis.patch.yml');
  const content = `# Managed by Adverserial Confidential Kit.\n- id: llm-pi-ai\n  config:\n    providers:\n      adverserial-confidential:\n        apiKeyEnv: ADVERSERIAL_API_KEY\n        api: openai-completions\n        baseURL: ${localGatewayUrl(env)}\n        compat:\n          supportsDeveloperRole: false\n        models:\n          - id: ${state.model}\n            name: CyberGLM — verified confidential runtime\n            input: [text]\n`;
  await privateText(patch, content);
  return { ...verifiedEnvironment(state, env), DSH_HOME: home };
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
  const managed = `${KIMI_CONFIG_BEGIN}\n[providers.${KIMI_MODEL_ALIAS}]\ntype = "openai"\nbase_url = ${tomlString(localGatewayUrl(env))}\napi_key = ${tomlString(state.apiKey)}\n\n[models.${KIMI_MODEL_ALIAS}]\nprovider = "${KIMI_MODEL_ALIAS}"\nmodel = ${tomlString(state.model)}\nmax_context_size = 1048576\ncapabilities = ["thinking", "always_thinking", "tool_use"]\ndisplay_name = "CyberGLM — verified confidential runtime"\n${KIMI_CONFIG_END}\n`;
  const block = new RegExp(`\\n?${escapeRegExp(KIMI_CONFIG_BEGIN)}[\\s\\S]*?${escapeRegExp(KIMI_CONFIG_END)}\\n?`, 'g');
  const preserved = existing.replace(block, '').trimEnd();
  await privateText(path, `${preserved ? `${preserved}\n\n` : ''}${managed}`);
  return KIMI_MODEL_ALIAS;
}

export async function harnessCommand(name, state, env) {
  const base = verifiedEnvironment(state, env);
  const binary = resolveHarnessBinary(name, base);
  if (name === 'claude') {
    return { command: binary, args: ['--plugin-dir', resource('plugins', 'claude-code')], env: { ...base,
      ANTHROPIC_BASE_URL: localGatewayOrigin(base), ANTHROPIC_AUTH_TOKEN: state.apiKey, ANTHROPIC_API_KEY: state.apiKey,
      ANTHROPIC_MODEL: state.model, ANTHROPIC_DEFAULT_OPUS_MODEL: state.model, ANTHROPIC_DEFAULT_SONNET_MODEL: state.model,
      ANTHROPIC_DEFAULT_HAIKU_MODEL: state.model, ANTHROPIC_DEFAULT_FABLE_MODEL: state.model, ANTHROPIC_SMALL_FAST_MODEL: state.model,
      ANTHROPIC_CUSTOM_MODEL_OPTION: state.model, ANTHROPIC_CUSTOM_MODEL_OPTION_NAME: 'CyberGLM — verified confidential runtime',
      CLAUDE_CODE_ENABLE_FINE_GRAINED_TOOL_STREAMING: '1'
    }};
  }
  if (name === 'codex') { await codexProfile(base, binary); return { command: binary, args: ['--profile', 'confidential'], env: base }; }
  if (name === 'pi') return { command: binary, args: ['--extension', resource('plugins', 'pi', 'adverserial-confidential.ts'), '--model', `adverserial-confidential/${state.model}`], env: base };
  if (name === 'oh-my-pi') return { command: binary, args: ['--extension', resource('plugins', 'oh-my-pi', 'adverserial-confidential.ts'), '--model', `adverserial-confidential/${state.model}`], env: base };
  if (name === 'zcode') return { command: binary, args: [], env: await configureZCode(state, env) };
  if (name === 'deepseek-harness') return { command: binary, args: ['--profile', 'web'], env: await configureDeepSeekHarness(state, env) };
  if (name === 'kimi') {
    const alias = await configureKimi(state, base);
    return { command: binary, args: ['--skills-dir', resource('plugins', 'kimi-code', 'skills'), '--model', alias], env: base };
  }
  if (name === 'opencode') return { command: binary, args: [], env: await configureOpenCode(state, base) };
  const config = await harnessConfig(name, env);
  return { command: binary, args: ['--config', config], env: base };
}

async function code(arguments_, env) {
  const state = await readState(env);
  const name = arguments_[0] ? normalizeHarness(arguments_[0]) : await chooseHarness();
  if (!HARNESS_NAMES.includes(name)) fail(`Unknown harness ${JSON.stringify(name)}. Choose ${HARNESS_NAMES.join(', ')}.`);
  await ensureGateway(env);
  if (await gatewayAlreadyRunning(env)) fail('A process is already listening on the confidential loopback port. Stop it before running `ack code`, so the kit never sends prompts through an unknown local process.');
  const gateway = spawn(executable(env, 'adverserial-confidential-gateway'), [], { env: verifiedEnvironment(state, env), stdio: ['ignore', 'ignore', 'ignore'] });
  const startupError = { error: null };
  gateway.once('error', (error) => { startupError.error = error; });
  try {
    await waitForGateway(gateway, startupError, env);
    const selected = await harnessCommand(name, state, env);
    const launchStatus = new StatusLine(env);
    launchStatus.start(`Launching ${name} with verified confidential inference`);
    const harness = spawn(selected.command, selected.args, { env: selected.env, stdio: 'inherit' });
    launchStatus.stop();
    const result = await waitFor(harness);
    if (result.code !== 0) process.exitCode = result.code;
  } finally {
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

async function headlessCommand(name, state, env, prompt) {
  const selected = await harnessCommand(name, state, env);
  if (name === 'claude') return { ...selected, args: ['-p', prompt] };
  if (name === 'codex') return { ...selected, args: ['--profile', 'confidential', 'exec', prompt] };
  if (name === 'opencode') return { ...selected, args: [...selected.args, 'run', prompt] };
  if (name === 'kimi') return { ...selected, args: [...selected.args, '-p', prompt] };
  if (name === 'pi' || name === 'oh-my-pi') return { ...selected, args: [...selected.args, '--print', prompt] };
  if (name === 'zcode') return { ...selected, args: ['--prompt', prompt], env: selected.env };
  if (name === 'deepseek-harness') return { ...selected, args: ['--profile', 'headless', prompt], env: selected.env };
  return { ...selected, args: [...selected.args, '--print', prompt] };
}

function captureWorker(commandName, args, env, cwd) {
  return new Promise((resolveWorker) => {
    const child = spawn(commandName, args, { env, cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    const chunks = [];
    let size = 0;
    const append = (chunk) => {
      if (size >= 2 * 1024 * 1024) return;
      const slice = chunk.subarray ? chunk.subarray(0, 2 * 1024 * 1024 - size) : Buffer.from(String(chunk));
      chunks.push(slice); size += slice.length;
    };
    child.stdout.on('data', append); child.stderr.on('data', append);
    child.once('error', (error) => resolveWorker({ code: 1, output: `Worker could not start: ${error.message}\n` }));
    child.once('exit', (code) => resolveWorker({ code: code ?? 1, output: Buffer.concat(chunks).toString('utf8') }));
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
  const state = await readState(env);
  await ensureGateway(env);
  if (await gatewayAlreadyRunning(env)) fail('A process is already listening on the confidential loopback port. Stop it before running `ack swarm`, so the kit never sends prompts through an unknown local process.');
  const job = join(appHome(env), 'swarms', `${new Date().toISOString().replace(/[:.]/g, '-')}-${process.pid}`);
  const results = join(job, 'results');
  await privateDirectory(results);
  const brief = join(job, 'brief.md');
  await writeFile(brief, `# Confidential swarm brief\n\n${options.task}\n\nAll worker output remains in this local directory. Do not place API keys, credentials, or private data in a report.\n`, { mode: 0o600 });
  const gateway = spawn(executable(env, 'adverserial-confidential-gateway'), [], { env: verifiedEnvironment(state, env), stdio: ['ignore', 'ignore', 'ignore'] });
  const startupError = { error: null };
  gateway.once('error', (error) => { startupError.error = error; });
  try {
    await waitForGateway(gateway, startupError, env);
    const workers = options.agents.filter((agent) => agent !== options.lead);
    process.stdout.write(`Starting ${workers.length} confidential workers; results stay in ${job}.\n`);
    await runPool(workers, options.workers, async (agent) => {
      const prompt = `You are the ${agent} worker in a confidential coding swarm. Work on this task:\n${options.task}\n\nRead the shared brief at ${brief}. Return a concise, concrete report with findings, proposed edits, and verification steps. Other workers will read your report from the shared local directory.`;
      const selected = await headlessCommand(agent, state, env, prompt);
      const result = await captureWorker(selected.command, selected.args, selected.env, process.cwd());
      await writeFile(join(results, `${agent}.md`), `# ${agent} worker (exit ${result.code})\n\n${result.output}`, { mode: 0o600 });
    });
    const handoff = join(job, 'handoff.md');
    const reportList = options.agents.filter((agent) => agent !== options.lead).map((agent) => `- ${join(results, `${agent}.md`)}`).join('\n') || '- No additional worker reports';
    await writeFile(handoff, `# Swarm handoff\n\nTask: ${options.task}\n\nWorker reports:\n${reportList}\n`, { mode: 0o600 });
    const leadPrompt = `You are the lead (${options.lead}) in a confidential coding swarm. Complete this task: ${options.task}\n\nRead ${handoff} and every worker report it lists. Reconcile the findings, inspect the current workspace where needed, then produce the final implementation or review. Do not treat unverified worker claims as facts.`;
    const lead = await headlessCommand(options.lead, state, env, leadPrompt);
    const result = await captureWorker(lead.command, lead.args, lead.env, process.cwd());
    const finalReport = join(job, 'lead.md');
    await writeFile(finalReport, `# ${options.lead} lead (exit ${result.code})\n\n${result.output}`, { mode: 0o600 });
    process.stdout.write(`Swarm complete. Lead report: ${finalReport}\n`);
    if (result.code !== 0) process.exitCode = result.code;
  } finally {
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

function shellTokens(line) {
  const tokens = [];
  const matcher = /"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|([^\s]+)/g;
  for (const match of line.matchAll(matcher)) {
    const raw = match[1] ?? match[2] ?? match[3];
    tokens.push(raw.replace(/\\([\\"'])/g, '$1'));
  }
  return tokens;
}

function shellHelp() {
  return `
Commands
  init                 Save an API key and prepare confidential coding
  keys …               Add, modify, delete, list, or activate API-key profiles
  upgrade              Refresh the signed policy and local runtime
  code [harness]       Launch a verified coding harness from the colored selector
  models               List available confidential models
  attestation          Run a fresh independent verification
  swarm …              Coordinate verified coding harnesses
  clear                Clear this shell
  exit                 Close the shell

Use quoted text for a multi-word swarm task.`;
}

function shellPrompt() {
  return new Promise((resolvePrompt) => {
    const line = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    line.question('\x1b[38;5;81mack\x1b[0m \x1b[2m›\x1b[0m ', (answer) => {
      line.close();
      resolvePrompt(answer);
    });
    line.once('SIGINT', () => { line.close(); resolvePrompt('exit'); });
  });
}

async function shell(env) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  banner();
  process.stdout.write('\x1b[2mConfidential shell ready. Type help to see commands.\x1b[0m\n\n');
  while (true) {
    const input = (await shellPrompt()).trim();
    const tokens = shellTokens(input);
    const action = tokens[0]?.toLowerCase();
    if (!action) continue;
    if (action === 'exit' || action === 'quit') break;
    if (action === 'clear') { process.stdout.write('\x1b[2J\x1b[H'); banner(); continue; }
    if (action === 'help') { process.stdout.write(`${shellHelp()}\n\n`); continue; }
    try {
      await main(tokens, { ...env, ACK_SHELL: '1' });
      if (process.exitCode) process.exitCode = 0;
    } catch (error) {
      process.stderr.write(`ack: ${error instanceof Error ? error.message : String(error)}\n`);
    }
  }
}

async function models() {
  try {
    const registry = await fetchJson(MODELS_URL);
    const entries = Array.isArray(registry) ? registry : registry?.models;
    if (Array.isArray(entries)) {
      for (const value of entries) process.stdout.write(`${typeof value === 'string' ? value : value.model_id || value.id || JSON.stringify(value)}\n`);
      return;
    }
  } catch { /* Fall back to the active policy. */ }
  const policy = await fetchProductionPolicy();
  process.stdout.write(`${policy.model_id}\tactive\t${policy.description || 'confidential inference'}\n`);
}

export async function main(arguments_, env = process.env) {
  const [action, ...rest] = arguments_;
  if (!action) return shell(env);
  if (!env.ACK_QUIET && !env.ACK_SHELL && (action === '--help' || action === '-h' || action === 'help')) banner();
  if (action === '--help' || action === '-h' || action === 'help') { process.stdout.write(`${usage()}\n`); return; }
  if (action === 'init') return init(env);
  if (action === 'upgrade') return upgrade(env);
  if (action === 'models') return models();
  if (action === 'keys') return keysCommand(rest, env);
  if (action === 'attestation') return attestation(rest, env);
  if (action === 'code') return code(rest, env);
  if (action === 'swarm') return swarmCommand(rest, env);
  fail(`Unknown command ${JSON.stringify(action)}.\n\n${usage()}`);
}

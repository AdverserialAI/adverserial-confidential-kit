import { createHash } from 'node:crypto';
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
const STATE_VERSION = 1;
const HARNESS_NAMES = ['claude', 'codex', 'opencode', 'pi', 'hermes', 'kimi'];
const MARK = String.raw`
          ⣰⣶⣶⣶⠂
        ⢀⣼⣿⣿⡿⠁⣰⣧
       ⢠⣾⣿⣿⠟ ⢸⣿⣿⣧        ADVERSERIAL CONFIDENTIAL
      ⣰⣿⣿⣿⠋   ⢻⣿⣿⣧⣀⣤⣶⡾⠁    Confidential coding kit
     ⣴⣿⣿⡿⠁    ⣀⣽⣿⣿⣿⠛⠉
   ⢀⣾⣿⣿⠟  ⣀⣤⠶⠟⠛⠉⠻⣿⣿⣷⡀
  ⣠⡿⠟⠋⣁⠤⠖⠋⠉      ⠹⣿⣿⣷⡀
  ⠁  ⠉            ⠙⠛⠛⠓
`;

function banner() {
  process.stdout.write(`${MARK}\n\n`);
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
  opencode: [],
  kimi: [],
  hermes: []
};

function isExecutable(path) {
  try { accessSync(path, constants.X_OK); return true; } catch { return false; }
}

export function resolveHarnessBinary(name, env = process.env) {
  const override = env[`ACK_${name.toUpperCase()}_BIN`];
  if (override) {
    if (isExecutable(override)) return override;
    fail(`ACK_${name.toUpperCase()}_BIN is not an executable file: ${override}`);
  }
  for (const directory of (env.PATH || '').split(delimiter)) {
    const candidate = join(directory || '.', name);
    if (isExecutable(candidate)) return candidate;
  }
  for (const candidate of bundledHarnessPaths[name] || []) if (isExecutable(candidate)) return candidate;
  fail(`${name} is not installed. Install the official ${name} CLI, or set ACK_${name.toUpperCase()}_BIN to its absolute executable path.`);
}

function usage() {
  return `Adverserial Confidential Kit

Usage:
  ack init                 Save your API key once and prepare confidential coding
  ack upgrade              Refresh the confidential runtime and pinned policy
  ack models               List models published in the policy registry
  ack attestation [--json] Run a fresh hardware and receipt verification
  ack code [harness]       Start a verified coding harness
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

The API key is stored only in ${appHome()}/ack.json (mode 0600). It is passed
only to the selected local harness and loopback gateway, never to the model endpoint.`;
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

async function readState(env = process.env) {
  let value;
  try { value = JSON.parse(await readFile(statePath(env), 'utf8')); }
  catch { fail('Not initialized. Run `ack init` first.'); }
  if (!value || value.version !== STATE_VERSION || typeof value.apiKey !== 'string' || !value.apiKey || typeof value.model !== 'string' || typeof value.endpoint !== 'string') {
    fail('Local configuration is incomplete. Run `ack init` again.');
  }
  return value;
}

async function promptApiKey() {
  if (!process.stdin.isTTY) fail('Interactive API-key entry requires a terminal. Run `ack init` from a terminal.');
  process.stdout.write('Adverserial API key (stored locally, input hidden): ');
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
        if (character === '\u007f') { value = value.slice(0, -1); continue; }
        if (character >= ' ') value += character;
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

async function saveSetup(apiKey, policy, env) {
  await privateJson(keysPath(env), policy.receipt_keys);
  await privateJson(statePath(env), {
    version: STATE_VERSION,
    apiKey,
    model: policy.model_id,
    endpoint: DEFAULT_ENDPOINT,
    policyUrl: POLICY_URL,
    policyDigest: `sha256:${createHash('sha256').update(JSON.stringify(policy)).digest('hex')}`,
    updatedAt: new Date().toISOString()
  });
}

async function init(env) {
  const prior = existsSync(statePath(env)) ? await readState(env) : null;
  const apiKey = prior ? prior.apiKey : await promptApiKey();
  if (!apiKey) fail('An API key is required. Nothing was saved.');
  const policy = await withStatus('Checking signed production policy', env, () => fetchProductionPolicy());
  await withStatus('Saving pinned verification policy', env, () => saveSetup(apiKey, policy, env));
  await withStatus('Preparing confidential runtime', env, (progress) => installGateway(env, progress));
}

async function upgrade(env) {
  const prior = await readState(env);
  const policy = await withStatus('Checking signed production policy', env, () => fetchProductionPolicy());
  await withStatus('Saving pinned verification policy', env, () => saveSetup(prior.apiKey, policy, env));
  await withStatus('Preparing confidential runtime', env, (progress) => installGateway(env, progress));
}

function verifiedEnvironment(state, env) {
  return {
    ...env,
    ADVERSERIAL_ACK_CLI: join(PACKAGE_ROOT, 'bin', 'ack.mjs'),
    ADVERSERIAL_API_KEY: state.apiKey,
    ADVERSERIAL_API_URL: state.endpoint,
    ADVERSERIAL_CC_API_URL: state.endpoint,
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

async function gatewayAlreadyRunning() {
  try { return (await fetch('http://127.0.0.1:8787/healthz', { signal: AbortSignal.timeout(300) })).ok; }
  catch { return false; }
}

async function waitForGateway(child, startupError) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (startupError.error) fail(`The local confidential runtime could not start: ${startupError.error.message}`);
    if (child.exitCode !== null) fail('The local confidential runtime stopped during startup. Run `ack upgrade` and retry.');
    try {
      const response = await fetch('http://127.0.0.1:8787/healthz', { signal: AbortSignal.timeout(500) });
      if (response.ok) return;
    } catch { /* Gateway is still starting. */ }
    await new Promise((resolveSleep) => setTimeout(resolveSleep, 150));
  }
  fail('The local confidential gateway did not become ready. Run `ack upgrade` and retry.');
}

async function chooseHarness() {
  if (!process.stdin.isTTY) fail(`Choose a harness explicitly: ack code <${HARNESS_NAMES.join('|')}>`);
  const line = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise((resolveAnswer) => line.question(`Choose a harness (${HARNESS_NAMES.join(', ')}): `, resolveAnswer));
  line.close();
  const harness = answer.trim().toLowerCase();
  if (!HARNESS_NAMES.includes(harness)) fail(`Unknown harness ${JSON.stringify(harness)}.`);
  return harness;
}

async function codexProfile(env) {
  const codexHome = env.CODEX_HOME || join(env.HOME || process.cwd(), '.codex');
  await mkdir(codexHome, { recursive: true, mode: 0o700 });
  await writeFile(join(codexHome, 'confidential.config.toml'), await readFile(resource('profiles', 'codex.confidential.toml')));
}

async function harnessConfig(name, env) {
  const dir = join(appHome(env), 'harness-config');
  await privateDirectory(dir);
  const file = name === 'opencode' ? 'opencode.jsonc' : 'hermes.confidential.yaml';
  const target = join(dir, file);
  await writeFile(target, await readFile(resource('profiles', file)), { mode: 0o600 });
  return target;
}

export async function harnessCommand(name, state, env) {
  const base = verifiedEnvironment(state, env);
  const binary = resolveHarnessBinary(name, base);
  if (name === 'claude') {
    return { command: binary, args: ['--plugin-dir', resource('plugins', 'claude-code')], env: { ...base,
      ANTHROPIC_BASE_URL: 'http://127.0.0.1:8787', ANTHROPIC_AUTH_TOKEN: state.apiKey, ANTHROPIC_API_KEY: state.apiKey,
      ANTHROPIC_MODEL: state.model, ANTHROPIC_DEFAULT_OPUS_MODEL: state.model, ANTHROPIC_DEFAULT_SONNET_MODEL: state.model,
      ANTHROPIC_DEFAULT_HAIKU_MODEL: state.model, ANTHROPIC_DEFAULT_FABLE_MODEL: state.model, ANTHROPIC_SMALL_FAST_MODEL: state.model,
      ANTHROPIC_CUSTOM_MODEL_OPTION: state.model, ANTHROPIC_CUSTOM_MODEL_OPTION_NAME: 'CyberGLM — verified confidential runtime',
      CLAUDE_CODE_ENABLE_FINE_GRAINED_TOOL_STREAMING: '1'
    }};
  }
  if (name === 'codex') { await codexProfile(env); return { command: binary, args: ['--profile', 'confidential'], env: base }; }
  if (name === 'pi') return { command: binary, args: ['--extension', resource('plugins', 'pi', 'adverserial-confidential.ts'), '--model', `adverserial-confidential/${state.model}`], env: base };
  if (name === 'kimi') return { command: binary, args: ['--skills-dir', resource('plugins', 'kimi-code', 'skills'), '--model', state.model], env: base };
  const config = await harnessConfig(name, env);
  if (name === 'opencode') return { command: binary, args: ['--config', config], env: base };
  return { command: binary, args: ['--config', config], env: base };
}

async function code(arguments_, env) {
  const state = await readState(env);
  const name = arguments_[0]?.toLowerCase() || await chooseHarness();
  if (!HARNESS_NAMES.includes(name)) fail(`Unknown harness ${JSON.stringify(name)}. Choose ${HARNESS_NAMES.join(', ')}.`);
  await ensureGateway(env);
  if (await gatewayAlreadyRunning()) fail('A process is already listening on the confidential loopback port. Stop it before running `ack code`, so the kit never sends prompts through an unknown local process.');
  const gateway = spawn(executable(env, 'adverserial-confidential-gateway'), [], { env: verifiedEnvironment(state, env), stdio: ['ignore', 'ignore', 'ignore'] });
  const startupError = { error: null };
  gateway.once('error', (error) => { startupError.error = error; });
  try {
    await waitForGateway(gateway, startupError);
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
  if (name === 'pi') return { ...selected, args: [...selected.args, '--print', prompt] };
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
  if (await gatewayAlreadyRunning()) fail('A process is already listening on the confidential loopback port. Stop it before running `ack swarm`, so the kit never sends prompts through an unknown local process.');
  const job = join(appHome(env), 'swarms', `${new Date().toISOString().replace(/[:.]/g, '-')}-${process.pid}`);
  const results = join(job, 'results');
  await privateDirectory(results);
  const brief = join(job, 'brief.md');
  await writeFile(brief, `# Confidential swarm brief\n\n${options.task}\n\nAll worker output remains in this local directory. Do not place API keys, credentials, or private data in a report.\n`, { mode: 0o600 });
  const gateway = spawn(executable(env, 'adverserial-confidential-gateway'), [], { env: verifiedEnvironment(state, env), stdio: ['ignore', 'ignore', 'ignore'] });
  const startupError = { error: null };
  gateway.once('error', (error) => { startupError.error = error; });
  try {
    await waitForGateway(gateway, startupError);
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
  if (!env.ACK_QUIET && (!action || action === '--help' || action === '-h' || action === 'help')) banner();
  if (!action || action === '--help' || action === '-h' || action === 'help') { process.stdout.write(`${usage()}\n`); return; }
  if (action === 'init') return init(env);
  if (action === 'upgrade') return upgrade(env);
  if (action === 'models') return models();
  if (action === 'attestation') return attestation(rest, env);
  if (action === 'code') return code(rest, env);
  if (action === 'swarm') return swarmCommand(rest, env);
  fail(`Unknown command ${JSON.stringify(action)}.\n\n${usage()}`);
}

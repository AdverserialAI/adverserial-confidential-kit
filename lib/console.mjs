import { emitKeypressEvents } from 'node:readline';
import { MARK, COMPACT_MARK } from './art.mjs';

export const THEMES = {
  aurora: { label: 'Aurora', accent: 87, second: 141, good: 120, warn: 221, bad: 203, palette: [51, 87, 117, 141, 177, 213] },
  ultraviolet: { label: 'Ultraviolet', accent: 183, second: 99, good: 121, warn: 221, bad: 204, palette: [63, 99, 135, 171, 207, 219] },
  ember: { label: 'Ember', accent: 215, second: 203, good: 156, warn: 221, bad: 196, palette: [196, 202, 208, 214, 220, 223] },
  glacier: { label: 'Glacier', accent: 117, second: 75, good: 122, warn: 221, bad: 203, palette: [33, 39, 45, 81, 117, 159] }
};

export const isTheme = (value) => typeof value === 'string' && Object.hasOwn(THEMES, value);

export const COMMANDS = [
  { id: 'code', label: 'Launch a coding harness', detail: 'Claude, Codex, OpenCode, Pi, Oh My Pi + more', key: 'c' },
  { id: 'models', label: 'Explore confidential models', detail: 'Published registry and active model', key: 'm' },
  { id: 'keys', label: 'Open the encrypted key vault', detail: 'Add, edit, activate and remove profiles', key: 'k' },
  { id: 'attestation', label: 'Verify the confidential runtime', detail: 'Fresh hardware evidence and pinned receipt keys', key: 'v' },
  { id: 'swarm', label: 'Coordinate a coding swarm', detail: 'Launch workers or connect existing sessions', key: 's' },
  { id: 'doctor', label: 'Check this workstation', detail: 'Harnesses, local runtime and configuration', key: 'd' },
  { id: 'status', label: 'Show workspace status', detail: 'Selected model, key profile and local runtime' },
  { id: 'theme', label: 'Change console colors', detail: 'Aurora / Ultraviolet / Ember / Glacier', key: 't' },
  { id: 'init', label: 'Set up confidential coding', detail: 'Save your first key and prepare the local runtime' },
  { id: 'upgrade', label: 'Refresh the confidential runtime', detail: 'Update pinned policy and local dependencies' },
  { id: 'help', label: 'Command reference', detail: 'Shortcuts, commands and session controls', key: '?' },
  { id: 'exit', label: 'Leave ACK', detail: 'Return to your terminal' }
];

// Treat all registry, filesystem and child-process text as terminal data.
export function clean(value) {
  return String(value ?? '').replace(/\x1b\][\s\S]*?(?:\x07|\x1b\\)/g, '')
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '').replace(/[\x00-\x1f\x7f-\x9f]/g, '');
}
const ansi = /\x1b\[[0-?]*[ -/]*[@-~]/g;
export const visibleLength = (value) => Array.from(String(value).replace(ansi, '')).length;
export function fit(value, width) {
  // Keep styling while clipping visible cells. UI glyphs are all one cell wide.
  let out = '', cells = 0;
  for (const part of String(value).split(/(\x1b\[[0-?]*[ -/]*[@-~])/g)) {
    if (ansi.test(part)) { ansi.lastIndex = 0; out += part; continue; }
    ansi.lastIndex = 0;
    for (const character of part) { if (cells++ >= width) return `${out}\x1b[0m`; out += character; }
  }
  return out;
}
const pad = (text, width) => `${text}${' '.repeat(Math.max(0, width - visibleLength(text)))}`;
const paint = (text, color, enabled = true) => enabled ? `\x1b[38;5;${color}m${text}\x1b[0m` : text;
const bold = (text, enabled = true) => enabled ? `\x1b[1m${text}\x1b[0m` : text;

export function tokenize(input) {
  const tokens = [];
  let token = '', quote = '', escaped = false, started = false;
  for (const character of input) {
    if (escaped) { token += character; escaped = false; started = true; continue; }
    if (character === '\\') { escaped = true; continue; }
    if (quote) { if (character === quote) quote = ''; else token += character; started = true; continue; }
    if (character === '"' || character === "'") { quote = character; started = true; continue; }
    if (/\s/.test(character)) { if (started) tokens.push(token); token = ''; started = false; continue; }
    token += character; started = true;
  }
  if (escaped) token += '\\';
  if (quote) throw new Error('Close the quoted text before running this command.');
  if (started) tokens.push(token);
  return tokens;
}

function wrapText(text, width) {
  const result = [];
  let remaining = clean(text);
  while (remaining.length > width) {
    let end = remaining.lastIndexOf(' ', width);
    if (end < width / 2) end = width;
    result.push(remaining.slice(0, end));
    remaining = remaining.slice(end).trimStart();
  }
  result.push(remaining);
  return result;
}

export function filterItems(items, query) {
  const terms = query.toLowerCase().trim().split(/\s+/).filter(Boolean);
  return items.filter((item) => terms.every((term) => `${item.id} ${item.label} ${item.detail || ''}`.toLowerCase().includes(term)));
}

export function verificationLabel(verdict, now = Date.now()) {
  if (!verdict) return { text: 'Not checked this session', tone: 'warn' };
  if (verdict.status !== 'verified' || verdict.trust !== 'pinned' || verdict.proof?.devMode) return { text: 'Verification needs attention', tone: 'bad' };
  const expires = Number(verdict.proof?.expiresEpoch) * 1000;
  if (!Number.isFinite(expires) || !Number.isFinite(verdict.verifiedAt) || verdict.verifiedAt > now + 5000 || expires <= now || now - verdict.verifiedAt >= 300_000) return { text: 'Evidence expired · verify again', tone: 'warn' };
  return { text: `Verified · ${Math.ceil((expires - now) / 1000)}s remaining`, tone: 'good' };
}

export class AckConsole {
  constructor(backend, { input = process.stdin, output = process.stdout, env = process.env, initialCommand = '' } = {}) {
    this.backend = backend; this.input = input; this.output = output; this.env = env; this.initialCommand = initialCommand;
    this.theme = 'aurora'; this.motion = true; this.snapshot = {}; this.view = 'home';
    this.items = []; this.query = ''; this.selection = 0; this.command = ''; this.cursor = 0;
    this.messages = []; this.history = []; this.historyIndex = 0; this.savedInput = '';
    this.verdict = null; this.busy = ''; this.frame = 0; this.lastFrame = []; this.scroll = 0;
    this.running = false; this.suspended = false; this.form = null;
    this.color = !('NO_COLOR' in env) && env.TERM !== 'dumb';
    this.onKey = (text, key) => { void this.handleKey(text, key).catch((error) => this.error(error)); };
    this.onResize = () => { this.lastFrame = []; this.render(); };
    this.onSignal = () => this.close();
  }

  async start() {
    const preferences = await this.backend.preferences();
    this.theme = isTheme(preferences.theme) ? preferences.theme : 'aurora';
    this.motion = preferences.motion !== false;
    this.snapshot = await this.backend.snapshot();
    emitKeypressEvents(this.input, { escapeCodeTimeout: 35 });
    this.running = true;
    this.enter();
    process.once('SIGTERM', this.onSignal);
    process.once('SIGHUP', this.onSignal);
    // Only busy indicators and evidence expiry change while idle; unchanged
    // terminal rows are never repainted. No network or Keychain read at boot.
    this.timer = setInterval(() => { this.frame++; if (this.busy || (this.frame % 10 === 0 && this.verdict)) this.render(); }, 100);
    this.timer.unref?.();
    const finished = new Promise((resolve) => { this.finished = resolve; });
    if (this.initialCommand) await this.execute(this.initialCommand);
    return finished;
  }

  enter() {
    this.suspended = false;
    this.output.write('\x1b[?1049h\x1b[?2004h\x1b[?25l\x1b[2J\x1b[H');
    this.input.setRawMode(true); this.input.resume();
    this.input.on('keypress', this.onKey); this.output.on('resize', this.onResize);
    this.lastFrame = []; this.render();
  }

  leave() {
    this.suspended = true;
    this.input.removeListener('keypress', this.onKey); this.output.removeListener('resize', this.onResize);
    this.input.setRawMode(false); this.input.pause();
    this.output.write('\x1b[0m\x1b[?25h\x1b[?2004l\x1b[?1049l');
  }

  close() {
    if (!this.running) return;
    if (this.busy) { this.exitRequested = true; return; }
    this.running = false; this.command = ''; this.form = null; clearInterval(this.timer);
    if (!this.suspended) this.leave();
    process.removeListener('SIGTERM', this.onSignal); process.removeListener('SIGHUP', this.onSignal);
    this.output.write('ACK · See you on the other side.\n');
    this.finished?.();
  }

  error(error) {
    this.busy = ''; this.form = null;
    this.log(error instanceof Error ? error.message : String(error), 'bad'); this.render();
  }

  log(text, tone = 'muted') {
    for (const line of String(text).split(/\r?\n/)) if (line.trim()) this.messages.push({ text: clean(line).slice(0, 4000), tone });
    this.messages = this.messages.slice(-300); this.scroll = 0;
    if (tone === 'bad' || tone === 'warn') this.notice = { text: clean(String(text).split(/\r?\n/)[0]), tone, until: Date.now() + 10_000 };
  }

  c(text, tone = 'accent') {
    const theme = THEMES[this.theme];
    return paint(text, theme[tone] || (tone === 'muted' ? 244 : tone === 'text' ? 252 : 238), this.color);
  }

  async task(label, work, { cancellable = false } = {}) {
    if (this.busy) return;
    this.busy = label; this.controller = cancellable ? new AbortController() : null; this.render();
    try { await work((message) => { this.busy = message; this.render(); }, this.controller?.signal); }
    finally { this.busy = ''; this.controller = null; this.snapshot = await this.backend.snapshot(); if (this.exitRequested) this.close(); else this.render(); }
  }

  async external(tokens) {
    // Child TUIs and secret-entry prompts get sole ownership of the terminal.
    // Always restore raw mode, the screen and handlers when they return.
    this.leave();
    try { await this.backend.run(tokens); }
    finally {
      this.snapshot = await this.backend.snapshot();
      this.enter();
    }
    this.log(`${tokens[0] === 'code' ? 'Session ended' : 'Completed'} · ${tokens.join(' ')}`, 'good');
    this.render();
  }

  picker(title, items, onSelect) {
    this.view = title; this.items = items; this.query = ''; this.selection = 0; this.onSelect = onSelect;
    this.command = ''; this.cursor = 0;
    this.form = null; this.multi = null; this.render();
  }

  formInput(title, label, onSubmit, { secret = false, initial = '' } = {}) {
    this.view = title; this.items = []; this.query = '';
    this.form = { label, secret, submit: onSubmit };
    this.command = initial; this.cursor = initial.length; this.render();
  }

  home() {
    this.view = 'home'; this.items = []; this.form = null; this.command = ''; this.cursor = 0; this.query = ''; this.scroll = 0; this.render();
  }

  async launchPicker() {
    const harnesses = this.backend.harnesses();
    this.picker('CODING HARNESSES', harnesses.map((h) => ({
      id: h.id, label: h.label, detail: h.available ? 'Installed · confidential gateway managed by ACK' : `Install first · ${h.binary}`, available: h.available
    })), async (item) => {
      if (!item.available) { this.log(`${item.label} is not installed. ${harnesses.find((h) => h.id === item.id).install}`, 'warn'); this.render(); return; }
      this.home(); await this.external(['code', item.id]);
    });
  }

  async modelsPicker() {
    await this.task('Fetching the published model registry', async () => {
      const models = await this.backend.models();
      this.picker('CONFIDENTIAL MODELS', models.map((model) => ({
        id: model.id, label: model.name, detail: `${model.id}${model.id === this.snapshot.model ? ' · active' : ''} · ${model.description || 'Confidential inference'}`
      })), async (item) => {
        await this.task(`Configuring ${item.label}`, async () => {
          await this.backend.useModel(item.id); this.verdict = null;
          this.log(`Active model · ${item.id}. Run attestation for fresh evidence.`, 'good'); this.home();
        });
      });
    });
  }

  keyMenu() {
    this.picker('ENCRYPTED KEY VAULT', [
      ...(this.snapshot.profiles || []).map((p) => ({ id: p.name, label: p.name, detail: `${p.mask} · ${p.active ? 'ACTIVE' : 'encrypted'} · manage profile`, profile: true })),
      { id: '+', label: 'Add an API-key profile', detail: 'Hidden input · AES-256-GCM encrypted storage' }
    ], (item) => {
      if (!item.profile) return this.addKey();
      this.picker(`KEY / ${item.label}`, [
        { id: 'use', label: 'Activate this key', detail: 'Use it for your next coding session' },
        { id: 'modify', label: 'Replace this key', detail: 'Enter a replacement with hidden input' },
        { id: 'delete', label: 'Delete this profile', detail: 'Active profiles must be switched before deletion' }
      ], async (action) => {
        if (action.id === 'modify') return this.keySecret(item.id, true);
        if (action.id === 'delete') return this.formInput('DELETE KEY PROFILE', `Type ${item.id} to delete`, async (answer) => {
          if (answer !== item.id) throw new Error('Profile name did not match. Nothing was deleted.');
          await this.backend.keyAction('delete', item.id); this.snapshot = await this.backend.snapshot(); this.log(`Deleted profile · ${item.id}`, 'good'); this.keyMenu();
        });
        await this.task('Activating encrypted key profile', async () => {
          await this.backend.keyAction('use', item.id); this.verdict = null;
          this.snapshot = await this.backend.snapshot(); this.log(`Active key profile · ${item.id}`, 'good'); this.keyMenu();
        });
      });
    });
  }

  addKey(name) {
    if (name) return this.keySecret(name, false);
    this.formInput('ADD KEY PROFILE', 'Profile name · e.g. personal or work', (answer) => this.keySecret(answer, false));
  }

  keySecret(name, modify) {
    this.formInput(modify ? 'REPLACE API KEY' : 'ADD API KEY', `API key for ${name} · hidden input`, async (secret) => {
      await this.task('Encrypting API key in your local vault', async () => {
        await this.backend.saveKey(name, secret, modify); secret = '';
        this.log(`${modify ? 'Updated' : 'Added'} encrypted profile · ${name}`, 'good');
        this.snapshot = await this.backend.snapshot(); this.keyMenu();
      });
    }, { secret: true });
  }

  themePicker() {
    this.picker('CONSOLE THEMES', Object.entries(THEMES).map(([id, theme]) => ({ id, label: theme.label, detail: id === this.theme ? 'Active palette' : 'Preview and apply this palette' })), async (item) => {
      this.theme = item.id; await this.backend.savePreferences({ theme: item.id }); this.log(`${item.label} palette activated`, 'good'); this.home();
    });
  }

  swarmMenu() {
    this.picker('CONFIDENTIAL SWARMS', [
      { id: 'launch', label: 'Launch a multi-agent task', detail: 'Select installed harnesses, then enter a shared brief' },
      { id: 'create', label: 'Create a shared room', detail: 'Coordinate already-open coding sessions' },
      { id: 'help', label: 'Swarm command reference', detail: 'Invite / inbox / post / lead and worker controls' }
    ], (item) => {
      if (item.id === 'help') { this.home(); this.log('swarm --agents claude,pi --lead claude "review this repository"'); this.log('swarm create review-room'); this.log('swarm invite --to pi "inspect the streaming adapter"'); return this.render(); }
      if (item.id === 'create') return this.formInput('NEW SWARM ROOM', 'Room name', async (name) => { await this.task('Creating a local swarm room', async () => { this.log(await this.backend.capture(['swarm', 'create', name]), 'good'); this.home(); }); });
      const installed = this.backend.harnesses().filter((h) => h.available);
      if (installed.length < 2) throw new Error('Install at least two coding harnesses to launch a swarm.');
      const selected = new Set();
      const items = installed.map((h) => ({ id: h.id, label: h.label, detail: 'Space to toggle · Enter to continue' }));
      this.picker('SWARM / SELECT HARNESSES', items, () => {
        if (selected.size < 2) throw new Error('Select at least two harnesses with Space.');
        this.formInput('SWARM / TASK BRIEF', 'What should the agents work on?', async (brief) => {
          const agents = [...selected]; this.home();
          await this.external(['swarm', '--agents', agents.join(','), '--lead', agents[0], brief]);
        });
      });
      this.multi = selected;
    });
  }

  help() {
    this.home();
    const rows = [
      'code [harness]      Launch or pick a coding harness',
      'models             Browse models; Enter activates one',
      'model <id>         Activate a published model and its policy',
      'keys               Manage encrypted API-key profiles',
      'attestation        Run fresh hardware and receipt verification',
      'status / doctor    Local status / workstation checks',
      'init / upgrade     First-time setup / refresh runtime',
      'swarm              Multi-agent task and shared-room controls',
      'theme [name]       Aurora, Ultraviolet, Ember or Glacier',
      'motion on|off      Toggle animated activity indicators',
      'clear / exit       Clear activity / return to your terminal',
      'Ctrl+P  palette    Tab  complete    Esc  back    Ctrl+C  cancel',
      'F2 code / F3 models / F4 keys / F5 verify / F6 theme',
      'Up/Down  history   PgUp/PgDn  activity   Ctrl+L  redraw'
    ];
    rows.forEach((row) => this.log(row)); this.render();
  }

  async execute(raw) {
    const tokens = tokenize(raw.replace(/^\//, '').trim());
    if (!tokens.length) return;
    const [action, ...args] = tokens;
    // Never record secrets or opaque key input in command history.
    const safe = !/\b(?:sk-|api[_-]?key|token=)/i.test(raw);
    const known = COMMANDS.some((item) => item.id === action) || ['harnesses', 'model', 'verify', 'home', 'quit', 'motion'].includes(action);
    if (safe && known && this.history.at(-1) !== raw) this.history.push(raw);
    this.history = this.history.slice(-100); this.historyIndex = this.history.length;
    this.command = ''; this.cursor = 0; this.multi = null;
    if (action === 'exit' || action === 'quit') return this.close();
    if (action === 'clear' || action === 'home') { this.messages = []; return this.home(); }
    if (action === 'help' || action === '?') return this.help();
    if (action === 'code') { if (!args.length) return this.launchPicker(); this.home(); return this.external(['code', ...args]); }
    if (action === 'harnesses') return this.launchPicker();
    if (action === 'models' && !args.length) return this.modelsPicker();
    if (action === 'model' || (action === 'models' && args[0] === 'use')) {
      const id = action === 'model' ? args[0] : args[1];
      if (!id) return this.modelsPicker();
      return this.task('Configuring selected model', async () => { await this.backend.useModel(id); this.verdict = null; this.log(`Active model · ${id}`, 'good'); this.home(); });
    }
    if (action === 'keys' && !args.length) return this.keyMenu();
    if (action === 'keys' && args[0] === 'add') return this.addKey(args[1]);
    if (action === 'keys' && args[0] === 'modify' && args[1]) return this.keySecret(args[1], true);
    if (action === 'theme') {
      if (!args.length) return this.themePicker();
      if (!isTheme(args[0])) throw new Error(`Choose a theme: ${Object.keys(THEMES).join(', ')}.`);
      this.theme = args[0]; await this.backend.savePreferences({ theme: this.theme }); this.render(); return;
    }
    if (action === 'motion') {
      if (!['on', 'off'].includes(args[0])) throw new Error('Use motion on or motion off.');
      this.motion = args[0] === 'on'; await this.backend.savePreferences({ motion: this.motion }); this.render(); return;
    }
    if (action === 'attestation' || action === 'verify') return this.task('Verifying hardware, evidence and pinned receipt keys', async (_progress, signal) => {
      this.verdict = null;
      const result = await this.backend.verify(signal); this.verdict = result;
      this.log(result.report, result.status === 'verified' && result.trust === 'pinned' && !result.proof?.devMode ? 'good' : 'bad');
    }, { cancellable: true });
    if (action === 'status') {
      this.snapshot = await this.backend.snapshot(); this.home();
      this.log(`Model · ${this.snapshot.model || 'not configured'}`);
      this.log(`Key profile · ${this.snapshot.activeProfile || 'not configured'} · ${this.snapshot.profiles?.length || 0} saved`);
      this.log(`Runtime · ${this.snapshot.runtime ? 'prepared; starts with your coding session' : 'run init to prepare'}`);
      this.log(`Attestation · ${verificationLabel(this.verdict).text}`); return this.render();
    }
    if (action === 'doctor') return this.task('Checking this workstation', async () => {
      for (const check of await this.backend.doctor()) this.log(`${check.ok ? 'PASS' : 'CHECK'}  ${check.label} · ${check.detail}`, check.ok ? 'good' : 'warn');
    });
    if (action === 'swarm' && !args.length) return this.swarmMenu();
    if (action === 'upgrade') return this.task('Refreshing confidential runtime', async (progress) => { await this.backend.upgrade(progress); this.verdict = null; this.log('Pinned policy and local runtime refreshed', 'good'); });
    if (action === 'init') {
      if (this.snapshot.configured) return this.execute('upgrade');
      return this.formInput('WELCOME TO CONFIDENTIAL CODING', 'Adverserial API key · hidden input', async (secret) => {
        await this.task('Preparing confidential coding', async (progress) => { await this.backend.initialize(secret, progress); secret = ''; this.log('Ready. Open code to choose your harness.', 'good'); this.home(); });
      }, { secret: true });
    }
    if (action === 'keys') {
      if (args[0] === 'list' || args[0] === 'help' || !args[1]) return this.keyMenu();
      if (args[0] === 'delete') return this.formInput('DELETE KEY PROFILE', `Type ${args[1]} to delete`, async (answer) => {
        if (answer !== args[1]) throw new Error('Profile name did not match. Nothing was deleted.');
        await this.backend.keyAction('delete', answer); this.log(`Deleted profile · ${answer}`, 'good'); this.snapshot = await this.backend.snapshot(); this.home();
      });
      if (args[0] === 'use') return this.task('Activating encrypted key profile', async () => { await this.backend.keyAction('use', args[1]); this.verdict = null; this.log(`Active key profile · ${args[1]}`, 'good'); this.home(); });
      throw new Error('Use keys add, keys modify, keys use or keys delete.');
    }
    if (action === 'swarm') {
      if (['create', 'invite', 'inbox', 'post', 'help', '--help'].includes(args[0])) return this.task('Updating local swarm room', async () => this.log(await this.backend.capture(tokens)));
      this.home(); return this.external(tokens);
    }
    throw new Error('Unknown command. Press Ctrl+P to explore ACK.');
  }

  async handleKey(text = '', key = {}) {
    if (!this.running || this.suspended) return;
    if (key.name === 'paste-start') { this.pasting = true; return; }
    if (key.name === 'paste-end') { this.pasting = false; return; }
    if (this.pasting && ['return', 'enter'].includes(key.name)) {
      if (!this.form?.secret && !this.items.length) { this.command += ' '; this.cursor = this.command.length; }
      this.render(); return;
    }
    if (this.busy) {
      if (key.ctrl && key.name === 'c' && this.controller) { this.controller.abort(); this.busy = 'Cancelling verification'; this.render(); }
      return;
    }
    if (key.ctrl && key.name === 'c') {
      if (this.view !== 'home' || this.command) { this.multi = null; return this.home(); }
      return this.close();
    }
    if (key.ctrl && key.name === 'd') return this.close();
    const functionActions = { f1: 'help', f2: 'code', f3: 'models', f4: 'keys', f5: 'attestation', f6: 'theme' };
    if (functionActions[key.name] && !this.form) return this.execute(functionActions[key.name]);
    if (key.ctrl && key.name === 'l') { this.lastFrame = []; return this.render(); }
    if (key.ctrl && key.name === 'p') { this.multi = null; return this.picker('COMMAND PALETTE', COMMANDS, (item) => this.execute(item.id)); }
    if (key.name === 'escape') { this.multi = null; return this.home(); }
    if (['pageup', 'pagedown'].includes(key.name)) { this.scroll = Math.max(0, Math.min(this.scrollMax || this.messages.length, this.scroll + (key.name === 'pageup' ? 5 : -5))); return this.render(); }
    if (this.items.length) {
      const filtered = filterItems(this.items, this.query);
      if (this.view === 'CODING HARNESSES' && !this.query && /^[1-9]$/.test(text)) {
        const selected = filtered[Number(text) - 1]; if (selected) await this.onSelect(selected);
      } else if (key.name === 'up' || key.name === 'down') {
        this.selection = (this.selection + (key.name === 'up' ? -1 : 1) + Math.max(filtered.length, 1)) % Math.max(filtered.length, 1);
      } else if (text === ' ' && this.multi) {
        const selected = filtered[this.selection]; if (selected) { if (this.multi.has(selected.id)) this.multi.delete(selected.id); else this.multi.add(selected.id); }
      } else if (key.name === 'return') {
        const selected = filtered[this.selection]; if (selected) await this.onSelect(selected);
      } else if (key.name === 'backspace') { this.query = this.query.slice(0, -1); this.selection = 0; }
      else if (text && !key.ctrl && !key.meta && !/[\x00-\x1f\x7f]/.test(text)) { this.query = (this.query + text).slice(0, 80); this.selection = 0; }
      this.render(); return;
    }
    if (key.name === 'return') {
      if (this.form) {
        const answer = this.command; const submit = this.form.submit;
        this.command = ''; this.cursor = 0; this.form = null;
        if (!answer.trim()) throw new Error('Enter a value or press Escape to go back.');
        await submit(answer.trim());
      } else await this.execute(this.command);
    } else if (key.name === 'tab' && !this.form) {
      const matches = COMMANDS.filter((item) => item.id.startsWith(this.command.replace(/^\//, '')));
      if (matches.length === 1) { this.command = `${matches[0].id} `; this.cursor = this.command.length; }
      else if (matches.length > 1) this.picker('COMMAND PALETTE', matches, (item) => this.execute(item.id));
    } else if (key.name === 'up' && !this.form) {
      if (this.historyIndex === this.history.length) this.savedInput = this.command;
      this.historyIndex = Math.max(0, this.historyIndex - 1); this.command = this.history[this.historyIndex] || ''; this.cursor = this.command.length;
    } else if (key.name === 'down' && !this.form) {
      this.historyIndex = Math.min(this.history.length, this.historyIndex + 1); this.command = this.historyIndex === this.history.length ? this.savedInput : this.history[this.historyIndex]; this.cursor = this.command.length;
    } else if (key.name === 'left') this.cursor = Math.max(0, this.cursor - 1);
    else if (key.name === 'right') this.cursor = Math.min(this.command.length, this.cursor + 1);
    else if (key.name === 'home' || (key.ctrl && key.name === 'a')) this.cursor = 0;
    else if (key.name === 'end' || (key.ctrl && key.name === 'e')) this.cursor = this.command.length;
    else if (key.ctrl && key.name === 'u') { this.command = this.command.slice(this.cursor); this.cursor = 0; }
    else if (key.name === 'backspace' && this.cursor > 0) { this.command = this.command.slice(0, this.cursor - 1) + this.command.slice(this.cursor); this.cursor--; }
    else if (key.name === 'delete') this.command = this.command.slice(0, this.cursor) + this.command.slice(this.cursor + 1);
    else if (text && !key.ctrl && !key.meta && !/[\x00-\x1f\x7f]/.test(text)) {
      this.command = (this.command.slice(0, this.cursor) + text + this.command.slice(this.cursor)).slice(0, this.form?.secret ? 4096 : 2048);
      this.cursor = Math.min(this.command.length, this.cursor + text.length);
      if (!this.form && this.command === '/') { this.command = ''; this.cursor = 0; this.picker('COMMAND PALETTE', COMMANDS, (item) => this.execute(item.id)); }
    }
    this.render();
  }

  render() {
    if (!this.running || this.suspended) return;
    const width = Math.max(24, this.output.columns || 80);
    const height = Math.max(12, this.output.rows || 30);
    const inside = width - 4; const lines = [];
    const add = (text = '') => lines.push(`  ${fit(text, inside)}`);
    const version = this.snapshot.version || '0.2';
    add(`${this.c('◆', 'second')} ${bold('ACK', this.color)} ${this.c('/ CONFIDENTIAL CONSOLE', 'muted')}  ${this.c(`v${version}`, 'muted')}`);
    add(this.c('─'.repeat(inside), 'border'));
    if (this.view === 'home' && !this.messages.length && height >= 25) {
      const art = (width >= 75 ? MARK : COMPACT_MARK).split('\n');
      const artWidth = Math.max(...art.map((line) => line.length));
      const copy = [
        this.c('A D V E R S E R I A L', 'second'), bold('Your terminal. Amplified.', this.color),
        this.c('Confidential AI, at your command.', 'muted'), '',
        `${this.c('F2')} code   ${this.c('F3', 'second')} models   ${this.c('F4')} keys   ${this.c('F5', 'second')} verify`
      ];
      art.forEach((row, y) => {
        add(`${pad(this.c(row), artWidth)}${width >= 75 ? `    ${copy[y] || ''}` : ''}`);
      });
      if (width < 75) add(bold('Your terminal. Amplified.', this.color));
      add();
    }
    const attestation = verificationLabel(this.verdict);
    add(`${this.c('●', attestation.tone)} ${this.c(attestation.text, attestation.tone)}${width >= 85 ? `   ${this.c('VAULT', 'muted')} ${this.c(this.snapshot.activeProfile || 'not set up', 'second')}` : ''}`);
    add(`${this.c('MODEL', 'muted')} ${this.c(clean(this.snapshot.model || 'run init to get started'), 'text')}  ${width >= 70 ? `${this.c('RUNTIME', 'muted')} ${this.c(this.snapshot.runtime ? 'on demand' : 'not prepared', 'muted')}` : ''}`);
    add(this.c('─'.repeat(inside), 'border'));
    const reservedBottom = 6;
    const slots = Math.max(1, height - lines.length - reservedBottom);
    if (this.items.length) {
      add(`${this.c(this.view, 'second')}  ${this.c('↑↓ navigate · Enter select · Esc back', 'muted')}`);
      const filtered = filterItems(this.items, this.query);
      this.selection = Math.min(this.selection, Math.max(0, filtered.length - 1));
      const count = Math.max(1, Math.floor((slots - 2) / 2));
      const start = Math.max(0, Math.min(this.selection - Math.floor(count / 2), filtered.length - count));
      for (let i = start; i < Math.min(filtered.length, start + count); i++) {
        const item = filtered[i], active = i === this.selection;
        const marker = this.multi ? this.multi.has(item.id) ? '[●]' : '[ ]' : active ? '›' : ' ';
        add(`${this.c(marker, active ? 'accent' : 'muted')} ${this.c(String(i + 1).padStart(2, '0'), 'muted')} ${active ? bold(this.c(clean(item.label)), this.color) : this.c(clean(item.label), 'text')}${item.available === false ? this.c('  not installed', 'warn') : ''}`);
        add(`    ${this.c(clean(item.detail || ''), 'muted')}`);
      }
      if (!filtered.length) add(this.c('No matches. Backspace to broaden your search.', 'warn'));
    } else if (this.form) {
      add(this.c(this.view, 'second')); add(); add(this.c(this.form.label, 'text'));
      if (this.form.secret) add(this.c('Hidden input · stored encrypted · never kept in shell history', 'muted'));
    } else {
      add(`${this.c('WORKSPACE', 'second')}${this.scroll ? this.c(` · ${this.scroll} lines above latest`, 'muted') : ''}`);
      const available = Math.max(1, slots - 1);
      if (this.messages.length) {
        const activity = this.messages.flatMap((row) => wrapText(row.text, inside).map((text) => ({ text, tone: row.tone })));
        this.scrollMax = Math.max(0, activity.length - available);
        this.scroll = Math.min(this.scroll, this.scrollMax);
        const end = Math.max(0, activity.length - this.scroll);
        for (const row of activity.slice(Math.max(0, end - available), end)) add(this.c(row.text, row.tone));
      } else {
        add(this.c('Type a command or press / to explore.', 'muted'));
        if (available >= 2) add(this.c('Start with init, then code. Everything else is one keystroke away.', 'muted'));
      }
    }
    const footerAt = height - 4;
    while (lines.length < footerAt) add();
    lines.splice(footerAt);
    add(this.c('─'.repeat(inside), 'border'));
    const spinner = this.motion ? ['◐', '◓', '◑', '◒'][this.frame % 4] : '·';
    const suggestions = !this.form && !this.items.length && this.command ? COMMANDS.filter((item) => item.id.startsWith(this.command)).slice(0, 3).map((item) => item.id).join('  ') : '';
    const notice = this.notice && this.notice.until > Date.now() ? this.notice : null;
    add(this.busy ? this.c(`${spinner} ${clean(this.busy)}${this.controller ? ' · Ctrl+C cancel' : ''}`) : notice ? this.c(notice.text, notice.tone) : this.c(suggestions || (this.form ? 'Enter save · Esc cancel' : this.items.length ? `${filterItems(this.items, this.query).length ? this.selection + 1 : 0}/${filterItems(this.items, this.query).length} · type to filter${this.multi ? ' · Space toggles' : ''}` : `${clean(this.backend.cwd)} · ${THEMES[this.theme].label}`), 'muted'));
    const prompt = this.items.length ? 'find › ' : this.form ? this.form.secret ? 'key › ' : 'input › ' : 'ack ❯ ';
    const value = this.items.length ? this.query : this.form?.secret ? '•'.repeat(this.command.length) : this.command;
    const valueCursor = this.items.length ? this.query.length : this.cursor;
    const room = Math.max(1, inside - prompt.length - 1);
    const offset = Math.max(0, valueCursor - room + 1);
    add(`${this.c(prompt)}${this.c(clean(value.slice(offset, offset + room)), 'text')}`);
    add(this.c('Ctrl+P palette   Tab complete   Esc back   Ctrl+C cancel / exit', 'muted'));
    this.output.write('\x1b[?25l');
    for (let i = 0; i < height; i++) {
      const row = lines[i] || '';
      if (row !== this.lastFrame[i]) this.output.write(`\x1b[${i + 1};1H\x1b[2K${fit(row, width - 1)}`);
    }
    this.lastFrame = lines;
    if (!this.busy) this.output.write(`\x1b[${height - 1};${Math.min(width - 1, 3 + prompt.length + valueCursor - offset)}H\x1b[?25h`);
  }
}

export async function runConsole(backend, options) {
  const app = new AckConsole(backend, options);
  try { return await app.start(); }
  finally { if (app.running) { app.busy = ''; app.close(); } }
}

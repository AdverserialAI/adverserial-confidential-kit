import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { AckConsole, clean, filterItems, tokenize, verificationLabel, visibleLength } from '../lib/console.mjs';

test('Windows console preserves drive paths, UNC shares and trailing separators', () => {
  const options = { platform: 'win32' };
  assert.deepEqual(tokenize('swarm "inspect C:\\Users\\Adam\\my project\\"', options), ['swarm', 'inspect C:\\Users\\Adam\\my project\\']);
  assert.deepEqual(tokenize('swarm \\\\server\\share\\file.py', options), ['swarm', '\\\\server\\share\\file.py']);
  assert.deepEqual(tokenize('swarm C:\\Users\\Adam\\file.py', options), ['swarm', 'C:\\Users\\Adam\\file.py']);
  assert.deepEqual(tokenize('swarm review\\ file', { platform: 'linux' }), ['swarm', 'review file']);
});
import { consoleBackend, consoleSnapshot } from '../lib/ack.mjs';

function fakeTerminal(columns = 100, rows = 36) {
  const input = new EventEmitter();
  input.setRawMode = (raw) => { input.raw = raw; };
  input.resume = () => {};
  input.pause = () => {};
  const output = new EventEmitter();
  Object.assign(output, { columns, rows, data: '', write(text) { this.data += text; } });
  return { input, output };
}
function fakeBackend(overrides = {}) {
  return {
    cwd: '~/workspace',
    preferences: async () => ({ theme: 'aurora', motion: false }),
    snapshot: async () => ({ model: 'lordx64/cyberglm', configured: true, profiles: [], runtime: true, version: '0.2.0' }),
    harnesses: () => [{ id: 'pi', label: 'Pi', available: true, binary: 'pi', install: 'Install Pi' }],
    savePreferences: async () => {},
    ...overrides
  };
}

test('command parsing preserves quoted swarm tasks and rejects incomplete quotes', () => {
  assert.deepEqual(tokenize('swarm --agents claude,pi "review the adapter"'), ['swarm', '--agents', 'claude,pi', 'review the adapter']);
  assert.deepEqual(tokenize("keys add 'client-team'"), ['keys', 'add', 'client-team']);
  assert.throws(() => tokenize('swarm "unfinished'), /Close the quoted/);
});

test('verification badge expires and never treats unpinned or synthetic evidence as verified', () => {
  const now = Date.now();
  const verdict = { status: 'verified', trust: 'pinned', verifiedAt: now, proof: { devMode: false, expiresEpoch: now / 1000 + 60 } };
  assert.equal(verificationLabel(verdict, now).tone, 'good');
  assert.equal(verificationLabel(verdict, now + 61_000).tone, 'warn');
  assert.equal(verificationLabel({ ...verdict, trust: 'tofu' }, now).tone, 'bad');
  assert.equal(verificationLabel({ ...verdict, proof: { ...verdict.proof, devMode: true } }, now).tone, 'bad');
});

test('external terminal control sequences cannot escape the console renderer', () => {
  assert.equal(clean('\x1b]0;evil\x07hello\x1b[2J\r\nworld'), 'helloworld');
  assert.equal(filterItems([{ id: 'omp', label: 'Oh My Pi', detail: 'Installed' }], 'pi installed').length, 1);
});

test('console startup is local, keyboard picker launches the harness and raw mode restores on exit', async () => {
  const terminal = fakeTerminal();
  let launched;
  const app = new AckConsole(fakeBackend({ run: async (tokens) => { launched = tokens; assert.equal(terminal.input.raw, false); } }), terminal);
  const finished = app.start();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(terminal.input.raw, true);
  await app.execute('code');
  await app.handleKey('', { name: 'return' });
  assert.deepEqual(launched, ['code', 'pi']);
  assert.equal(terminal.input.raw, true);
  for (const width of [40, 60, 80, 120]) {
    terminal.output.columns = width; app.lastFrame = []; app.render();
    assert.ok(app.lastFrame.every((row) => visibleLength(row) <= width));
  }
  app.close(); await finished;
  assert.equal(terminal.input.raw, false);
  assert.equal(terminal.input.listenerCount('keypress'), 0);
  assert.ok(terminal.output.data.endsWith('ACK · See you on the other side.\n'));
});

test('secret entry is masked, absent from history and handed only to encrypted storage', async () => {
  const terminal = fakeTerminal();
  let stored;
  const app = new AckConsole(fakeBackend({ saveKey: async (...args) => { stored = args; } }), terminal);
  const finished = app.start(); await new Promise((resolve) => setImmediate(resolve));
  await app.execute('keys add work');
  const secret = 'sk-super-secret-987654';
  await app.handleKey(secret, {});
  assert.equal(terminal.output.data.includes(secret), false);
  await app.handleKey('', { name: 'return' });
  assert.deepEqual(stored, ['work', secret, false]);
  assert.equal(app.history.some((entry) => entry.includes(secret)), false);
  assert.equal(app.command, '');
  app.close(); await finished;
});

test('snapshot and console preferences never expose secret key data or unlock the vault', async () => {
  const home = await mkdtemp(join(tmpdir(), 'ack-console-'));
  try {
    const secret = 'NEVER_RENDER_THIS_KEY';
    await writeFile(join(home, 'ack.json'), JSON.stringify({ version: 2, model: 'lordx64/cyberglm', apiKey: secret,
      activeKeyProfile: 'work', apiKeyProfiles: { work: { encryptedKey: { ciphertext: secret }, mask: 'sk-••••987' } } }));
    const env = { ACK_HOME: home, HOME: home };
    const snapshot = await consoleSnapshot(env);
    assert.equal(JSON.stringify(snapshot).includes(secret), false);
    assert.equal(snapshot.profiles[0].active, true);
    const backend = consoleBackend(env);
    await backend.savePreferences({ theme: 'ember', apiKey: secret });
    const saved = await readFile(join(home, 'console.json'), 'utf8');
    assert.equal(saved.includes(secret), false);
    assert.equal(JSON.parse(saved).theme, 'ember');
  } finally { await rm(home, { recursive: true, force: true }); }
});

test('model policy references remain on the verifier origin and inside the policy directory', async () => {
  const { modelPolicyURL } = await import('../lib/ack.mjs');
  assert.equal(modelPolicyURL('policies/lordx64-cyberglm.json'), 'https://verify.adverserial.ai/policies/lordx64-cyberglm.json');
  for (const ref of ['https://evil.example/policies/key.json', 'http://verify.adverserial.ai/policies/key.json', '/registry/models.json', '/policies/../../other.json', '/policies/key.json?redirect=1']) {
    assert.throws(() => modelPolicyURL(ref));
  }
});

test('console vault actions encrypt new keys and switch/delete profiles without revealing them', async () => {
  const home = await mkdtemp(join(tmpdir(), 'ack-console-vault-'));
  try {
    const first = 'first-private-key-123';
    const next = 'second-private-key-456';
    await writeFile(join(home, 'ack.json'), JSON.stringify({ version: 1, model: 'lordx64/cyberglm', endpoint: 'https://api.adverserial.ai/v1', apiKey: first }));
    const backend = consoleBackend({ HOME: home, ACK_HOME: home, NODE_ENV: 'test', ACK_TEST_STORAGE_KEY: Buffer.alloc(32, 9).toString('base64url') });
    await backend.saveKey('work', next, false);
    await backend.keyAction('use', 'work');
    let saved = await readFile(join(home, 'ack.json'), 'utf8');
    assert.ok(!saved.includes(first) && !saved.includes(next));
    assert.equal(JSON.parse(saved).activeKeyProfile, 'work');
    await assert.rejects(() => backend.keyAction('delete', 'work'), /Activate another key/);
    await backend.keyAction('delete', 'default');
    saved = JSON.parse(await readFile(join(home, 'ack.json'), 'utf8'));
    assert.deepEqual(Object.keys(saved.apiKeyProfiles), ['work']);
  } finally { await rm(home, { recursive: true, force: true }); }
});

test('verification can be cancelled without leaving the terminal stuck in raw mode', async () => {
  const terminal = fakeTerminal();
  const app = new AckConsole(fakeBackend({ verify: (signal) => new Promise((resolve, reject) => {
    signal.addEventListener('abort', () => reject(new Error('Verification cancelled.')), { once: true });
  }) }), terminal);
  const finished = app.start(); await new Promise((resolve) => setImmediate(resolve));
  const pending = app.execute('attestation');
  await app.handleKey('', { ctrl: true, name: 'c' });
  await assert.rejects(pending, /cancelled/);
  assert.equal(app.busy, '');
  assert.equal(app.verdict, null);
  app.close(); await finished;
  assert.equal(terminal.input.raw, false);
});

test('pasted newlines cannot submit a key and cancelling a secret cannot leak it into the palette', async () => {
  const terminal = fakeTerminal();
  let calls = 0;
  const app = new AckConsole(fakeBackend({ saveKey: async () => { calls++; } }), terminal);
  const finished = app.start(); await new Promise((resolve) => setImmediate(resolve));
  await app.execute('keys add work');
  await app.handleKey('', { name: 'paste-start' });
  await app.handleKey('private-pasted-value', {});
  await app.handleKey('', { name: 'return' });
  await app.handleKey('', { name: 'paste-end' });
  assert.equal(calls, 0);
  await app.handleKey('', { ctrl: true, name: 'p' });
  assert.equal(app.command, '');
  assert.equal(terminal.output.data.includes('private-pasted-value'), false);
  app.close(); await finished;
});

test('failed native harness output stays visible until acknowledged, then restores the console', async () => {
  const terminal = fakeTerminal();
  terminal.input.isTTY = terminal.output.isTTY = true;
  const failure = new Error('Hermes exited with status 2.');
  const app = new AckConsole(fakeBackend({ run: async () => {
    terminal.output.write('hermes: error: unrecognized arguments: --example\n');
    throw failure;
  } }), terminal);
  const finished = app.start(); await new Promise(resolve => setImmediate(resolve));
  const pending = assert.rejects(app.external(['code', 'hermes']), error => error === failure);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(app.suspended, true);
  assert.ok(terminal.output.data.includes('hermes: error: unrecognized arguments: --example'));
  assert.ok(terminal.output.data.includes('Press Enter or Esc to return to ACK'));
  terminal.input.emit('keypress', 'x', {name: 'x'});
  assert.equal(app.suspended, true);
  terminal.input.emit('keypress', '', {name: 'return'});
  await pending;
  assert.equal(app.suspended, false);
  assert.equal(terminal.input.raw, true);
  assert.equal(terminal.input.listenerCount('keypress'), 1);
  app.close(); await finished;
  assert.equal(terminal.input.listenerCount('keypress'), 0);
});

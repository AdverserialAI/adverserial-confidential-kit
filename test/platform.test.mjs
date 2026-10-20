import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { findBinary, spawnSync, userHome } from '../lib/platform.mjs';
import { resolveHarnessBinary, harnessCommand } from '../lib/ack.mjs';
import { windowsStorageKey } from '../lib/windows-vault.mjs';

async function fixture(t) {
  const home = await mkdtemp(join(tmpdir(), 'ack platform & spaces '));
  t.after(() => rm(home, { recursive: true, force: true }));
  return home;
}

test('home fallback uses USERPROFILE, not the current project', () => {
  assert.equal(userHome({ USERPROFILE: tmpdir() }), tmpdir());
});

test('binary overrides reject directories', () => {
  assert.throws(() => resolveHarnessBinary('codex', { ACK_CODEX_BIN: tmpdir() }), /not an executable file/);
});

test('Windows discovery finds native CLIs, npm shims and desktop Codex without PATH', { skip: process.platform !== 'win32' }, async t => {
  const home = await fixture(t);
  const local = join(home, 'Local');
  const roaming = join(home, 'Roaming');
  const native = join(home, '.local', 'bin');
  const desktop = join(local, 'OpenAI', 'Codex', 'bin', 'version');
  await Promise.all([native, desktop, join(roaming, 'npm')].map(path => mkdir(path, { recursive: true })));
  await writeFile(join(native, 'claude.exe'), '');
  await writeFile(join(roaming, 'npm', 'pi.cmd'), '');
  await writeFile(join(desktop, 'codex.exe'), '');
  const env = { USERPROFILE: home, LOCALAPPDATA: local, APPDATA: roaming, Path: '' };
  assert.equal(resolveHarnessBinary('claude', env), join(native, 'claude.exe'));
  assert.equal(resolveHarnessBinary('pi', env), join(roaming, 'npm', 'pi.cmd'));
  assert.equal(resolveHarnessBinary('codex', env), join(desktop, 'codex.exe'));
  assert.equal(findBinary('claude', { Path: `"${native}"`, USERPROFILE: home }), join(native, 'claude.exe'));
});

test('Windows cmd launcher preserves spaces, quotes and metacharacters as arguments', { skip: process.platform !== 'win32' }, async t => {
  const home = await fixture(t);
  const script = join(home, 'args.cjs');
  const shim = join(home, 'harness.cmd');
  await writeFile(script, 'console.log(JSON.stringify(process.argv.slice(2)))');
  await writeFile(shim, `@echo off\r\n"${process.execPath}" "${script}" %*\r\n`);
  const args = ['hello world', 'a"quoted"value', 'a&echo injected', 'x|echo injected', '(parentheses)', '%PATH%', 'bang!'];
  const result = spawnSync(shim, args, { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), args);
});

test('Windows DPAPI survives concurrent creation and never replaces damaged keys', { skip: process.platform !== 'win32' }, async t => {
  const home = await fixture(t);
  const [a, b] = await Promise.all([windowsStorageKey(home), windowsStorageKey(home)]);
  assert.equal(a.length, 32);
  assert.deepEqual(a, b);
  const path = join(home, 'storage-key.dpapi');
  assert.equal((await readFile(path)).includes(a), false);
  assert.deepEqual(await windowsStorageKey(home), a);
  await writeFile(path, 'damaged DPAPI blob');
  await assert.rejects(windowsStorageKey(home), /existing keys were not replaced/);
  assert.equal(await readFile(path, 'utf8'), 'damaged DPAPI blob');
  await rm(path);
  await writeFile(join(home, 'ack.json'), JSON.stringify({ apiKeyProfiles: { default: { encryptedKey: {} } } }));
  await assert.rejects(windowsStorageKey(home), /existing profiles were not replaced/);
});

test('Windows key-profile migration uses real DPAPI without the test storage override', { skip: process.platform !== 'win32' }, async t => {
  const home = await fixture(t);
  const secret = 'fake-key-for-local-dpapi-regression-only';
  const path = join(home, 'ack.json');
  await writeFile(path, JSON.stringify({ version: 1, apiKey: secret, model: 'lordx64/cyberglm', endpoint: 'https://api.adverserial.ai/v1' }));
  const env = { ...process.env, ACK_HOME: home, ACK_QUIET: '1' };
  delete env.ACK_TEST_STORAGE_KEY;
  const cli = fileURLToPath(new URL('../bin/ack.mjs', import.meta.url));
  for (let i = 0; i < 2; i++) {
    const result = spawnSync(process.execPath, [cli, 'keys', 'list'], { env, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.ok(!result.stdout.includes(secret));
    assert.ok(!(await readFile(path, 'utf8')).includes(secret));
  }
});

test('Codex without plugin add gets a local skill and a complete inline provider', async t => {
  const home = await fixture(t);
  const binary = join(home, process.platform === 'win32' ? 'codex.cmd' : 'codex');
  await writeFile(binary, process.platform === 'win32' ? '@echo off\r\necho Commands:\r\necho   marketplace  Manage marketplaces\r\n' : '#!/bin/sh\nprintf "Commands:\\n  marketplace  Manage marketplaces\\n"\n', { mode: 0o700 });
  const launch = await harnessCommand('codex', { apiKey: 'secret', model: 'lordx64/cyberglm' }, { ...process.env, ACK_HOME: home, CODEX_HOME: join(home, 'codex-home'), ACK_CODEX_BIN: binary });
  assert.ok(!launch.args.includes('--profile'));
  assert.ok(launch.args.includes('model_provider="adverserial_confidential"'));
  assert.match(launch.args.join(' '), /wire_api = "responses"/);
  assert.match(launch.args.join(' '), /requires_openai_auth = false/);
  assert.ok(!launch.args.join(' ').includes('secret'));
  assert.match(await readFile(join(home, 'codex-home', 'skills', 'adverserial-attestation', 'SKILL.md'), 'utf8'), /attestation/i);
});

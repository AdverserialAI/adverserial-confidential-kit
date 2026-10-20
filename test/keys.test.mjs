import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { createCipheriv } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const root = fileURLToPath(new URL('..', import.meta.url));
const cli = join(root, 'bin', 'ack.mjs');
const storageKey = Buffer.alloc(32, 7);
const storageKeyText = storageKey.toString('base64url');

function encrypt(value) {
  const iv = Buffer.alloc(12, 4);
  const cipher = createCipheriv('aes-256-gcm', storageKey, iv);
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return {
    version: 1,
    iv: iv.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
    ciphertext: ciphertext.toString('base64url')
  };
}

function run(home, ...args) {
  return spawnSync(process.execPath, [cli, ...args], {
    encoding: 'utf8',
    env: {
      ...process.env,
      ACK_HOME: home,
      ACK_QUIET: '1',
      NODE_ENV: 'test',
      ACK_TEST_STORAGE_KEY: storageKeyText
    }
  });
}

test('migrates plaintext state to encrypted named profiles and switches the active key', async () => {
  const home = await mkdtemp(join(tmpdir(), 'ack-keys-'));
  const firstKey = 'key_first_secret_1234';
  const secondKey = 'key_second_secret_9876';
  try {
    await writeFile(join(home, 'ack.json'), JSON.stringify({
      version: 1,
      apiKey: firstKey,
      model: 'lordx64/cyberglm',
      endpoint: 'https://api.adverserial.ai/v1',
      updatedAt: '2026-10-17T00:00:00.000Z'
    }));

    const listed = run(home, 'keys', 'list');
    assert.equal(listed.status, 0);
    assert.match(listed.stdout, /default/);
    assert.match(listed.stdout, /key••••••••234/);
    assert.doesNotMatch(listed.stdout, new RegExp(firstKey));

    const migrated = JSON.parse(await readFile(join(home, 'ack.json'), 'utf8'));
    assert.equal(migrated.version, 2);
    assert.equal('apiKey' in migrated, false);
    assert.doesNotMatch(JSON.stringify(migrated), new RegExp(firstKey));
    assert.ok(migrated.apiKeyProfiles.default.encryptedKey.ciphertext);

    migrated.apiKeyProfiles.work = {
      encryptedKey: encrypt(secondKey),
      mask: 'key••••••••876',
      createdAt: '2026-10-17T00:00:00.000Z',
      updatedAt: '2026-10-17T00:00:00.000Z'
    };
    await writeFile(join(home, 'ack.json'), JSON.stringify(migrated));

    const switched = run(home, 'keys', 'use', 'work');
    assert.equal(switched.status, 0);
    assert.match(switched.stdout, /Active profile.*work/);
    assert.doesNotMatch(switched.stdout, new RegExp(secondKey));
    const switchedState = JSON.parse(await readFile(join(home, 'ack.json'), 'utf8'));
    assert.equal(switchedState.activeKeyProfile, 'work');
    assert.equal('apiKey' in switchedState, false);

    assert.equal(run(home, 'keys', 'delete', 'default').status, 0);
    const activeDelete = run(home, 'keys', 'delete', 'work');
    assert.notEqual(activeDelete.status, 0);
    assert.match(activeDelete.stderr, /Cannot delete the active profile/);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
test('a denied Keychain read never replaces the key that protects existing profiles',{skip:process.platform!=='darwin'},async()=>{
 const home=await mkdtemp(join(tmpdir(),'ack-locked-keychain-'));
 try {
  const log=join(home,'security-calls');const binary=join(home,'security');
  await writeFile(binary,'#!/bin/sh\nprintf "%s\\n" "$1" >> "$ACK_SECURITY_CALLS"\nprintf "Keychain access denied\\n" >&2\nexit 36\n',{mode:0o700});
  const saved={version:2,apiKeyProfiles:{default:{encryptedKey:encrypt('secret-before-denial'),mask:'sec••••••••ial'}},activeKeyProfile:'default',model:'lordx64/cyberglm',endpoint:'https://api.adverserial.ai/v1'};
  const statePath=join(home,'ack.json');await writeFile(statePath,JSON.stringify(saved));
  const env={...process.env,ACK_HOME:home,ACK_QUIET:'1',PATH:home,ACK_SECURITY_CALLS:log};delete env.ACK_TEST_STORAGE_KEY;
  const result=spawnSync(process.execPath,[cli,'keys','list'],{env,encoding:'utf8'});
  assert.notEqual(result.status,0);assert.match(result.stderr,/existing key was not replaced/);
  assert.equal((await readFile(log,'utf8')).trim(),'find-generic-password');
  assert.deepEqual(JSON.parse(await readFile(statePath,'utf8')),saved);
 } finally {await rm(home,{recursive:true,force:true});}
});

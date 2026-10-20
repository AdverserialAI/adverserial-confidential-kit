import { randomBytes } from 'node:crypto';
import { readFile, writeFile, link, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { spawn } from './platform.mjs';

async function protect(operation, data, env) {
  // A fixed script on the command channel works under Windows' default script
  // execution policy. Secrets travel only on stdin, never in process arguments.
  const script = await readFile(new URL('../resources/windows-vault.ps1', import.meta.url), 'utf8');
  return new Promise((resolve, reject) => {
    const powershell = join(env.SystemRoot || env.SYSTEMROOT || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const child = spawn(powershell, ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { stdio: ['pipe', 'pipe', 'pipe'] });
    let output = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('Windows credential protection timed out; existing keys were not replaced.')); }, 15000);
    child.stdout.on('data', part => { output += part; });
    child.stderr.resume();
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.stdin.on('error', () => {});
    child.on('close', code => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error('Could not unlock the Windows DPAPI storage key; existing keys were not replaced.'));
      resolve(Buffer.from(output.trim(), 'base64'));
    });
    child.stdin.end(JSON.stringify({ operation, data: data.toString('base64') }));
  });
}

export async function windowsStorageKey(home, env = process.env) {
  const path = join(home, 'storage-key.dpapi');
  let encrypted;
  try { encrypted = await readFile(path); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    // Never replace a missing key when encrypted profiles already depend on it.
    try {
      const state = JSON.parse(await readFile(join(home, 'ack.json'), 'utf8'));
      if (Object.values(state.apiKeyProfiles || {}).some(profile => profile.encryptedKey)) {
        throw new Error('The Windows DPAPI storage key is missing; existing profiles were not replaced. Restore storage-key.dpapi from backup.');
      }
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    const temporary = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
    encrypted = await protect('protect', randomBytes(32), env);
    await writeFile(temporary, encrypted, { flag: 'wx', mode: 0o600 });
    try { await link(temporary, path); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
    finally { await unlink(temporary); }
    encrypted = await readFile(path);
  }
  const key = await protect('unprotect', encrypted, env);
  if (key.length !== 32) throw new Error('The Windows DPAPI storage key is invalid; existing keys were not replaced.');
  return key;
}

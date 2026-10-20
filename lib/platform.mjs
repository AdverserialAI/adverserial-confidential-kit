import { accessSync, constants, readdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, join } from 'node:path';
import crossSpawn from 'cross-spawn';

export const spawn = (command, args, options = {}) => crossSpawn(command, args, { windowsHide: true, ...options });
export const spawnSync = crossSpawn.sync;
export const userHome = (env = process.env) => env.HOME || env.USERPROFILE || homedir();
export function isExecutable(path) {
  try { return statSync(path).isFile() && (accessSync(path, constants.X_OK), true); } catch { return false; }
}

export function findBinary(binary, env = process.env, extra = []) {
  const path = Object.entries(env).find(([key]) => key.toUpperCase() === 'PATH')?.[1] || '';
  const extensions = process.platform === 'win32' ? ['.exe', '.com', '.cmd', '.bat'] : [''];
  const directories = path.split(delimiter).filter(Boolean).map(value => value.replace(/^"|"$/g, ''));
  if (process.platform === 'win32') {
    directories.push(join(userHome(env), '.local', 'bin'), join(userHome(env), '.bun', 'bin'));
    if (env.APPDATA) directories.push(join(env.APPDATA, 'npm'));
    if (env.LOCALAPPDATA) directories.push(join(env.LOCALAPPDATA, 'Microsoft', 'WinGet', 'Links'));
  }
  for (const directory of directories) {
    for (const extension of extensions) {
      const candidate = join(directory, binary + extension);
      if (isExecutable(candidate)) return candidate;
    }
  }
  // Desktop updates use versioned directories. Prefer the most recently written CLI.
  if (binary === 'codex' && process.platform === 'win32' && env.LOCALAPPDATA) {
    const root = join(env.LOCALAPPDATA, 'OpenAI', 'Codex', 'bin');
    try {
      const candidates = readdirSync(root).map(name => join(root, name, 'codex.exe')).filter(isExecutable);
      candidates.sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
      if (candidates.length) return candidates[0];
    } catch { /* Desktop app is optional. */ }
  }
  return extra.find(isExecutable) || null;
}

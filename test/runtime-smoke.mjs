// Installs the real runtime in a disposable home. No API key or inference call.
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { installGateway, startSessionGateway } from '../lib/ack.mjs';
import { spawn } from '../lib/platform.mjs';

const home = await mkdtemp(join(tmpdir(), 'ack runtime smoke '));
const env = { ...process.env, ACK_HOME: home, ADVERSERIAL_GATEWAY_PORT: '' };
const state = { apiKey: 'dummy-local-startup-only', model: 'lordx64/cyberglm', endpoint: 'https://api.adverserial.ai/v1' };
const sessions = [];
const start = () => startSessionGateway(state, env, {
  spawnImpl(command, args, options) {
    const child = spawn(command, args, options);
    // This smoke test has only dummy credentials; preserve diagnostics in CI.
    child.stderr.on('data', part => process.stderr.write(part));
    return child;
  }
});
const url = session => `http://127.0.0.1:${session.env.ADVERSERIAL_GATEWAY_PORT}/healthz`;
async function stop(session) {
  const closed = once(session.child, 'close');
  session.child.kill();
  await closed;
  await assert.rejects(fetch(url(session), { signal: AbortSignal.timeout(2000) }));
}
try {
  await installGateway(env, console.log);
  await writeFile(join(home, 'receipt-keys.json'), JSON.stringify({ test: { kty: 'EC' } }));
  // Sequential acquisition makes cleanup reliable even if the second fails.
  console.time('Cold gateway startup');
  sessions.push(await start());
  console.timeEnd('Cold gateway startup');
  sessions.push(await start());
  assert.notEqual(url(sessions[0]), url(sessions[1]));
  for (const session of sessions) assert.equal((await fetch(url(session))).status, 200);
  await stop(sessions.shift());
  assert.equal((await fetch(url(sessions[0]))).status, 200);
  await stop(sessions.shift());
  console.log('Real runtime installation, independent gateways and shutdown: PASS');
} finally {
  for (const session of sessions) await stop(session);
  await rm(home, { recursive: true, force: true });
}

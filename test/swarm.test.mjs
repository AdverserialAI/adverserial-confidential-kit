import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const root = new URL('..', import.meta.url).pathname;
const cli = join(root, 'bin', 'ack.mjs');

function run(home, ...args) {
  return spawnSync(process.execPath, [cli, ...args], {
    encoding: 'utf8',
    env: { ...process.env, ACK_HOME: home, ACK_QUIET: '1' }
  });
}

test('a Claude task can be explicitly assigned to and answered by Pi', () => {
  const home = mkdtempSync(join(tmpdir(), 'ack-swarm-'));
  assert.equal(run(home, 'swarm', 'create', 'review').status, 0);
  assert.equal(run(home, 'swarm', 'invite', '--to', 'pi', 'Review the cancellation path.').status, 0);
  const piInbox = run(home, 'swarm', 'inbox', '--agent', 'pi', '--json');
  assert.equal(piInbox.status, 0);
  assert.match(piInbox.stdout, /Review the cancellation path/);
  assert.equal(run(home, 'swarm', 'post', '--from', 'pi', '--to', 'claude', 'Cancellation is released.').status, 0);
  const claudeInbox = run(home, 'swarm', 'inbox', '--agent', 'claude', '--json');
  assert.equal(claudeInbox.status, 0);
  assert.match(claudeInbox.stdout, /Cancellation is released/);
});

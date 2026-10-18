import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import test from 'node:test';

const root = new URL('..', import.meta.url).pathname;
const cli = join(root, 'bin', 'ack.mjs');
const ansi = /\x1B\[[0-?]*[ -/]*[@-~]/g;

test('renders a compact logo with an aligned two-line wordmark', () => {
  const result = spawnSync(process.execPath, [cli, '--help'], { encoding: 'utf8' });
  assert.equal(result.status, 0);
  const output = result.stdout.replace(ansi, '');
  const banner = output.split('\n\nAdverserial Confidential Kit')[0];
  const lines = banner.split('\n');
  const title = lines.find((line) => line.includes('ADVERSERIAL CONFIDENTIAL'));
  const subtitle = lines.find((line) => line.includes('Confidential coding kit'));
  assert.equal(lines.length, 16);
  assert.equal(title.indexOf('ADVERSERIAL CONFIDENTIAL'), subtitle.indexOf('Confidential coding kit'));
  assert.ok(lines.every((line) => line.length < 80), 'banner fits an 80-column terminal');
  assert.ok(lines[0].search(/[^ ]/) > lines.at(-1).search(/[^ ]/), 'left blade slopes toward the lower-left point');
  assert.match(lines.at(-1), /^\. {3}\.\./, 'left blade ends in a taper rather than a rectangular foot');
});

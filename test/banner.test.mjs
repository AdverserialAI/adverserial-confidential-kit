import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import test from 'node:test';

const root = new URL('..', import.meta.url).pathname;
const cli = join(root, 'bin', 'ack.mjs');
const ansi = /\x1B\[[0-?]*[ -/]*[@-~]/g;

test('renders the upper Adverserial A/X mark from the supplied artwork', () => {
  const result = spawnSync(process.execPath, [cli, '--help'], { encoding: 'utf8' });
  assert.equal(result.status, 0);
  const output = result.stdout.replace(ansi, '');
  const logo = output.split('\n\nAdverserial Confidential Kit')[0]
    .replace('  ADVERSERIAL CONFIDENTIAL', '')
    .replace('  Confidential coding kit', '');
  assert.equal(logo, `              .+++++.
             .######..
            +#####+.+#.
           +#####+.+###.
          +#####+ +#####.
         +#####+  .#####+    .++.
        +#####+    .#####+++###+
      .+#####+      .#########+
     .######.     .++######+.
    .######.   .++####+#####.
   .######. .+###++..  +#####.
  .####++++++++.        +#####.
 .##+++++++.             ######.
 .......                 .+####.`);
  assert.match(output, /ADVERSERIAL CONFIDENTIAL/);
});

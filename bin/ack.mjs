#!/usr/bin/env node
import { main } from '../lib/ack.mjs';

main(process.argv.slice(2)).catch((error) => {
  process.stderr.write(`ack: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});

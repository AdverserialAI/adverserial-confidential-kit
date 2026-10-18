/**
 * Smoke test: drive the plugin's tool functions directly (plain Node, no
 * opencode runtime) against a DEV_MODE attest-proxy.
 *
 * Start a dev proxy first, e.g.:
 *   (cd ../../../attest-proxy && DEV_MODE=1 AUTH_REQUIRED=0 LISTEN_ADDR=127.0.0.1:0 go run ./cmd/attest-proxy)
 * then:
 *   ADVERSERIAL_API_URL=https://127.0.0.1:<port>/v1 ADVERSERIAL_TRUST_EVIDENCE_KEY=1 \
 *     ADVERSERIAL_HARDWARE_VERIFIER_COMMAND=<abs path>/test/dev-hardware-verifier.mjs \
 *     node test/smoke.mjs            # TOFU run: expect VERIFIED + dev_mode warnings
 *   ADVERSERIAL_API_URL=https://127.0.0.1:<port>/v1 \
 *     node test/smoke.mjs --expect-unpinned
 *
 * The hardware verifier command is mandatory (fail closed); the fixture
 * accepts only synthetic dev evidence, like the SDK's own dev test double.
 *
 * Exercises the exact code path the opencode tools use (same module, same
 * cache), minus opencode's tool dispatch.
 */

import assert from 'node:assert/strict';
import { pathToFileURL, fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const expectUnpinned = process.argv.includes('--expect-unpinned') || (!process.env.ADVERSERIAL_TRUST_EVIDENCE_KEY && !process.env.ADVERSERIAL_RECEIPT_KEYS_JSON && !process.env.ADVERSERIAL_RECEIPT_KEYS_FILE);

const mod = await import(pathToFileURL(path.join(HERE, '../dist/plugins/opencode/src/index.js')).href);
const pluginFn = mod.AdverserialPlugin ?? mod.default;
assert.equal(typeof pluginFn, 'function', 'plugin export not found');

const logs = [];
const hooks = await pluginFn({
	client: { app: { log: async (entry) => logs.push(entry) } },
	project: { id: 'smoke', name: 'smoke' },
	directory: process.cwd(),
	worktree: process.cwd(),
	$: null
});
assert.ok(hooks.tool.adverserial_verify, 'adverserial_verify tool missing');
assert.ok(hooks.tool.adverserial_status, 'adverserial_status tool missing');

const ctx = { directory: process.cwd(), worktree: process.cwd() };

console.log('— adversarial_verify (first call, fresh) —');
const verifyOut = await hooks.tool.adverserial_verify.execute({}, ctx);
console.log(verifyOut);

if (expectUnpinned) {
	assert.match(verifyOut, /no trusted receipt keys configured/, 'expected the unpinned refusal');
	assert.doesNotMatch(verifyOut, /^ADVERSERIAL ATTESTATION: VERIFIED$/m, 'must not claim verified');
} else {
	assert.match(verifyOut, /VERIFIED — UNPINNED \(TOFU dev mode\)/, 'expected TOFU verified verdict');
	assert.match(verifyOut, /dev_mode evidence \(dev=true\)/, 'expected the dev_mode warning');
	assert.match(verifyOut, /lordx64\/cyberglm/, 'expected the model id');
	assert.match(verifyOut, /adverserial-policy\/dev/, 'expected the policy id');
}

console.log('\n— adverserial_status (second call, cached) —');
const statusOut = await hooks.tool.adverserial_status.execute({}, ctx);
console.log(statusOut);
assert.match(statusOut, /attestation status:/);
assert.match(statusOut, /verified \d+s ago \(fresh/, 'expected a cached verdict with age');

console.log('\n— adverserial_verify (third call, still cached) —');
const verifyOut2 = await hooks.tool.adverserial_verify.execute({}, ctx);
assert.match(verifyOut2, /cached result/, 'expected the TTL cache to serve the third call');

console.log('\nsmoke test passed.');

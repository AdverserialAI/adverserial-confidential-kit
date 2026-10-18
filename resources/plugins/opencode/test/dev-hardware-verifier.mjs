#!/usr/bin/env node
/**
 * Test double for the plugins' ADVERSERIAL_HARDWARE_VERIFIER_COMMAND
 * contract (plugins/shared hardware.ts): reads one JSON request on stdin,
 * writes one JSON result on stdout.
 *
 * Accepts ONLY synthetic DEV_MODE evidence (dev === true), mirroring the
 * SDK's own dev test double (`test-synthetic-evidence` in
 * typescript/test/node-dev-test.mjs), so the plugin smoke test can exercise
 * the full verification path against a local DEV_MODE attest-proxy. Genuine
 * hardware evidence is refused — real TDX/NVIDIA verification belongs to
 * the shipped typescript/bin/adverserial-hardware-verify.mjs.
 */
let raw = '';
for await (const chunk of process.stdin) raw += chunk;

let input;
try {
	input = JSON.parse(raw);
} catch {
	input = null;
}

if (input && typeof input === 'object' && input.evidence?.dev === true) {
	process.stdout.write(
		JSON.stringify({ verified: true, verifier: 'smoke-test-synthetic-evidence', tee: 'dev', gpu: 'dev' }) + '\n'
	);
} else {
	process.stderr.write('dev-hardware-verifier: refusing non-dev evidence\n');
	process.exit(1);
}

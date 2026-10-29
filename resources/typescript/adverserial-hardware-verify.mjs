#!/usr/bin/env node
/**
 * adverserial-hardware-verify — standalone hardware-evidence verifier command.
 *
 * Contract (plugins/shared hardware.ts): read one JSON request from stdin
 * ({evidence, nonce, expectedModelId, expectedEndpoint?}), write one JSON
 * result to stdout ({"verified":true,"verifier":"...","tee":"...","gpu":"..."}).
 * Exit non-zero and print nothing to stdout on any rejection.
 *
 * Uses the SDK's built-in Phala TDX verifier (@phala/dcap-qvl against Intel
 * collateral) and the NVIDIA NRAS detached-EAT bundle verifier (NVIDIA's
 * public JWKS). ADVERSERIAL_MIN_GPU_COUNT overrides the default minimum of 8.
 */
let createPhalaNVIDIAVerifier, validateRuntimePolicy;
try {
  ({ createPhalaNVIDIAVerifier, validateRuntimePolicy } = await import('./dist/index.js'));
} catch {
  process.stderr.write('ACK hardware-verifier runtime is incomplete. Reinstall ACK with npm install -g github:AdverserialAI/adverserial-confidential-kit. For a linked source checkout, run npm ci in that checkout.\n');
  process.exit(1);
}
if (process.argv.includes('--check-runtime')) {
  process.stdout.write('ACK hardware-verifier runtime ready\n');
  process.exit(0);
}

const readStdin = async () => {
	const chunks = [];
	for await (const chunk of process.stdin) chunks.push(chunk);
	return Buffer.concat(chunks).toString('utf8');
};

const fail = (message) => {
	process.stderr.write(`${message}\n`);
	process.exit(1);
};

let input;
try {
	input = JSON.parse(await readStdin());
} catch {
	fail('invalid verifier request JSON');
}
if (!input || typeof input !== 'object' || Array.isArray(input)) fail('verifier request must be an object');

const minimumGPUCount = Number.parseInt(process.env.ADVERSERIAL_MIN_GPU_COUNT || '8', 10);
if (!Number.isInteger(minimumGPUCount) || minimumGPUCount < 1) fail('ADVERSERIAL_MIN_GPU_COUNT must be a positive integer');

try {
	let policy;
  if ((input.expectedEndpoint ?? input.endpoint) === 'https://api.adverserial.ai') {
    const response = await fetch('https://verify.adverserial.ai/policies/production.json', {cache:'no-store',signal:AbortSignal.timeout(15000)});
    if (!response.ok) fail('Published runtime policy unavailable');
    policy = validateRuntimePolicy(await response.json(), input.expectedModelId ?? input.model);
    const w = input.evidence?.workload;
    if (w?.compose_digest !== policy.deployment_configuration_digest || w?.proxy_version !== policy.proxy_version || w?.model_digest !== policy.model_artifact_digest || input.evidence?.tls_spki_sha256 !== policy.tls_spki_sha256) fail('Hardware evidence workload does not match approved policy');
  }
  const verifier = createPhalaNVIDIAVerifier({ minimumGPUCount: policy?.allowed_runtime.minimum_gpu_count ?? minimumGPUCount });
	const result = await verifier({
		evidence: input.evidence,
		nonce: input.nonce,
		expectedModelId: input.expectedModelId ?? input.model,
		expectedEndpoint: input.expectedEndpoint ?? input.endpoint,
    expectedTDXPolicy: policy?.tdx ?? input.expectedTDXPolicy
	});
	if (!result || result.verified !== true) fail('hardware evidence rejected');
	process.stdout.write(JSON.stringify({
		verified: true,
		verifier: result.verifier,
		tee: result.tee,
		gpu: result.gpu
	}) + '\n');
} catch (error) {
	fail(error instanceof Error ? error.message : 'hardware evidence rejected');
}

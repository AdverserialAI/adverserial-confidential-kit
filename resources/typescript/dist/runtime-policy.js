export const validateRuntimePolicy = (value, modelId) => {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        throw new Error('Missing runtime policy.');
    const p = value;
    if (p.status !== 'active' || p.model_id !== modelId)
        throw new Error('No active runtime policy matches the selected model.');
    for (const field of ['model_artifact_digest', 'runtime_image_digest', 'deployment_configuration_digest']) {
        if (!/^sha256:[0-9a-f]{64}$/.test(p[field] ?? ''))
            throw new Error(`Runtime policy is missing ${field}.`);
    }
    if (!/^sha256:[A-Za-z0-9_-]{43}$/.test(p.tls_spki_sha256 ?? '') || !p.proxy_version)
        throw new Error('Runtime policy is missing TLS or release pins.');
    if (!p.tdx || typeof p.tdx !== 'object')
        throw new Error('Runtime policy is missing TDX measurement pins.');
    for (const field of ['mrtd', 'rtmr0', 'rtmr1', 'rtmr2']) {
        if (!/^[0-9a-f]{96}$/.test(p.tdx[field] ?? ''))
            throw new Error(`Runtime policy is missing TDX ${field}.`);
    }
    for (const field of ['app_id', 'compose_hash', 'os_image_hash']) {
        if (!new RegExp(`^[0-9a-f]{${field === 'app_id' ? 40 : 64}}$`).test(p.tdx[field] ?? ''))
            throw new Error(`Runtime policy is missing TDX ${field}.`);
    }
    if (!p.receipt_keys || !Object.keys(p.receipt_keys).length)
        throw new Error('Runtime policy is missing receipt keys.');
    if (!Number.isInteger(p.allowed_runtime?.minimum_gpu_count) || p.allowed_runtime.minimum_gpu_count < 1 ||
        !p.allowed_runtime.tee?.includes('intel-tdx') || !p.allowed_runtime.gpu_attestation?.includes('nvidia-cc'))
        throw new Error('Runtime policy has invalid hardware requirements.');
    return p;
};
export const checkWorkloadPolicy = (policy, evidence, claims, keyId) => {
    const workload = evidence.workload;
    if (!workload || typeof workload !== 'object')
        throw new Error('The evidence is missing workload identity.');
    const checks = [
        [claims.model_digest, policy.model_artifact_digest, 'model artifact digest'],
        [workload.model_digest, policy.model_artifact_digest, 'workload model digest'],
        [workload.model_id, policy.model_id, 'workload model identity'],
        [claims.runtime_digest, policy.runtime_image_digest, 'runtime digest'],
        [workload.compose_digest, policy.deployment_configuration_digest, 'deployment configuration digest'],
        [workload.proxy_version, policy.proxy_version, 'proxy release'],
        [evidence.tls_spki_sha256, policy.tls_spki_sha256, 'TLS key'],
    ];
    for (const [actual, expected, name] of checks)
        if (actual !== expected)
            throw new Error(`The ${name} does not match the published policy.`);
    const pin = policy.receipt_keys[keyId];
    const observed = evidence.receipt_pubkey_jwk;
    if (!pin || !observed || pin.x !== observed.x || pin.y !== observed.y || pin.crv !== observed.crv)
        throw new Error('The attested signer does not match the published policy.');
};

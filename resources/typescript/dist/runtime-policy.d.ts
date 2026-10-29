import type { JsonRecord } from './canonjson.js';
export type TDXPolicy = {
    mrtd: string;
    rtmr0: string;
    rtmr1: string;
    rtmr2: string;
    app_id: string;
    compose_hash: string;
    os_image_hash: string;
};
export type RuntimePolicy = {
    status: string;
    model_id: string;
    model_artifact_digest: string;
    runtime_image_digest: string;
    deployment_configuration_digest: string;
    tls_spki_sha256: string;
    proxy_version: string;
    tdx: TDXPolicy;
    receipt_keys: Record<string, JsonWebKey>;
    allowed_runtime: {
        minimum_gpu_count: number;
        tee: string[];
        gpu_attestation: string[];
    };
};
export declare const validateRuntimePolicy: (value: unknown, modelId: string) => RuntimePolicy;
export declare const checkWorkloadPolicy: (policy: RuntimePolicy, evidence: JsonRecord, claims: JsonRecord, keyId: string) => void;

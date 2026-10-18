/**
 * Browser-verifiable NVIDIA NRAS detached-EAT bundle validation.
 *
 * The GPU collector inside the CVM submits device evidence to NVIDIA NRAS.
 * NRAS returns an overall EAT and one detached EAT per GPU.  This module does
 * not trust the proxy's `verdict` field: it fetches NVIDIA's public JWKS,
 * verifies every ES384 JWS, checks the overall result and each detached-token
 * digest, then enforces freshness and a minimum GPU count.
 */
import type { JsonRecord } from './canonjson.js';
export type NVIDIAEvidenceResult = {
    verified: true;
    verifier: 'nras-eat-jwks-es384';
    gpuCount: number;
    issuedAt: string;
    expiresAt: string;
};
export type NVIDIAEvidenceOptions = {
    minimumGPUCount: number;
    maxAgeMs?: number;
    fetchImpl?: typeof fetch;
    now?: () => number;
};
/** Validate the NRAS bundle embedded in a fresh attestation response. */
export declare const verifyNVIDIAEvidence: (evidence: JsonRecord, options: NVIDIAEvidenceOptions) => Promise<NVIDIAEvidenceResult>;

/**
 * OpenAI-compatible fetch wrapper bound to a verified attestation.
 *
 * createVerifiedOpenAI() verifies the endpoint first and returns a fetchImpl
 * you hand to any OpenAI-compatible client (or use directly). The fetchImpl
 * injects the Authorization header and REFUSES to send anything when
 * verification failed — no proof, no prompts.
 *
 * TLS PINNING LIMITATION: neither browser nor Node fetch exposes the peer
 * certificate for hard SPKI pinning. When the verified evidence contains an
 * RFC 9458 EHBP key configuration, this wrapper encrypts request and response
 * bodies to that quote-bound key, including streaming responses, so a TLS
 * terminator cannot read them. The
 * Python SDK additionally pins the live TLS SPKI before it sends any bytes.
 */
import type { RuntimePolicy } from './runtime-policy.js';
import type { HardwareEvidenceVerifier, TrustedReceiptKeys, VerifiedProof } from './verify.js';
export type VerifiedOpenAIOptions = {
    expectedPolicy?: RuntimePolicy;
    /** Endpoint base URL, e.g. "https://host/v1". */
    baseURL: string;
    /** Short-lived, model-bound billing entitlement sent to the CVM. Never pass a platform API key here. */
    entitlement?: string;
    expectedModelId: string;
    trustedReceiptKeys: TrustedReceiptKeys;
    issuer: string;
    audience: string;
    expectedEndpoint?: string;
    expectedModelDigest?: string;
    expectedRuntimeDigest?: string;
    attestationUrl?: string;
    verifyHardwareEvidence: HardwareEvidenceVerifier;
    fetchImpl?: typeof fetch;
};
export type VerifiedOpenAI = {
    /** True when verification succeeded and fetchImpl will send requests. */
    verified: boolean;
    /** The verified proof, or null when verification failed. */
    proof: VerifiedProof | null;
    /** Failure reason when verification failed, else null. */
    reason: string | null;
    /** The base URL the wrapper targets. */
    baseURL: string;
    /**
     * fetch-compatible function that injects the Authorization header. Throws
     * VerificationRequiredError without touching the network when verification
     * failed.
     */
    fetchImpl: typeof fetch;
    /** Bind a fresh, one-use billing entitlement to this already verified proof.
     * This never re-fetches evidence or weakens the verified endpoint binding. */
    fetchWithEntitlement: (entitlement: string) => typeof fetch;
};
export declare class VerificationRequiredError extends Error {
    constructor(reason: string);
}
export declare const createVerifiedOpenAI: (options: VerifiedOpenAIOptions) => Promise<VerifiedOpenAI>;

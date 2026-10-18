import type { TrustedReceiptKeys } from './verify.js';
export type InferenceReceiptProof = {
    issuedAt: number;
    expiresAt: number;
    usage?: {
        inputTokens: number;
        cachedTokens: number;
        outputTokens: number;
    };
    responseHash: string;
};
export type VerifyInferenceReceiptOptions = {
    receipt: string;
    trustedReceiptKeys: TrustedReceiptKeys;
    issuer: string;
    audience: string;
    modelId: string;
    requestNonce: string;
    requestBody: string;
    responseBody: string;
    tlsSpkiSha256: string;
    attestationStateDigest: string;
    now?: () => number;
};
/**
 * Validates an `X-Adverserial-Receipt` value without sending any network
 * request. It proves that the response bytes and request bytes were handled
 * by the attested proxy state verified immediately before dispatch.
 */
export declare const verifyInferenceReceipt: (options: VerifyInferenceReceiptOptions) => Promise<InferenceReceiptProof>;

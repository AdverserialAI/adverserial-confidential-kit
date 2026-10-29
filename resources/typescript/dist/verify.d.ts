/**
 * Verifier for an Adverserial confidential-inference endpoint.
 *
 * The endpoint (attest-proxy) returns fresh raw attestation evidence plus a
 * compact ES256 JWS verification receipt. The receipt is trusted only after
 * this client verifies its signature against a pinned JWK receipt key set and
 * binds it to the nonce, issuer, audience, model, endpoint, and the canonical
 * evidence digest. The evidence's `tls_spki_sha256` is surfaced on the proof
 * so runtimes that can pin TLS (the Python SDK) can bind the channel; see the
 * README for the browser/Node limitations.
 *
 * DEV MODE: when the evidence carries `dev: true` the TDX quote is synthetic.
 * The proof then proves the plumbing (signatures, nonce binding, digests),
 * NOT the hardware. `VerifiedProof.devMode` surfaces this; never treat a
 * dev-mode proof as a TEE guarantee.
 *
 * This module deliberately does not accept a bare { verified: true }.
 */
import type { RuntimePolicy, TDXPolicy } from './runtime-policy.js';
import type { JsonRecord } from './canonjson.js';
export type TrustedReceiptKeys = Record<string, JsonWebKey>;
/** Result produced by an independent TDX/GPU evidence verifier. */
export type HardwareVerification = {
    verified: true;
    /** Stable verifier identifier, for example `phala-dcap-qvl-wasm@<version>`. */
    verifier: string;
    /** Optional evidence provider identifiers surfaced in the verification UI. */
    tee?: string;
    gpu?: string;
};
/**
 * Verifies the raw hardware evidence locally or through a separately trusted
 * verifier. A proxy-signed receipt is never a replacement for this step.
 */
export type HardwareEvidenceVerifier = (input: {
    evidence: JsonRecord;
    nonce: string;
    expectedModelId: string;
    expectedEndpoint?: string;
    expectedTDXPolicy?: TDXPolicy;
}) => Promise<HardwareVerification>;
export type VerifyEndpointOptions = {
    /** Approved runtime identity, required by production integrations. */
    expectedPolicy?: RuntimePolicy;
    /** Expected receipt claim `model_id`, e.g. "lordx64/cyberglm". */
    expectedModelId: string;
    /** Pinned receipt verification keys: JWS header kid -> public JWK (P-256). */
    trustedReceiptKeys: TrustedReceiptKeys;
    /** Expected receipt claim `iss`. */
    issuer: string;
    /** Expected receipt claim `aud` (string or array membership). */
    audience: string;
    /** Expected receipt claim `endpoint`; defaults to the HTTPS origin of `baseURL`. */
    expectedEndpoint?: string;
    /** Expected receipt claim `model_digest`; checked only when provided. */
    expectedModelDigest?: string;
    /** Expected receipt claim `runtime_digest`; checked only when provided. */
    expectedRuntimeDigest?: string;
    /** Defaults to <origin of baseURL>/attestation. */
    attestationUrl?: string;
    /** Required independent TDX/GPU evidence verifier. Fail closed when unavailable. */
    verifyHardwareEvidence: HardwareEvidenceVerifier;
    /** Test-only opt-in for a proxy explicitly marked with synthetic DEV_MODE evidence. */
    allowDevMode?: boolean;
    /** fetch override (testing, custom TLS dispatchers, …). */
    fetchImpl?: typeof fetch;
    /** Clock override in ms (testing). */
    now?: () => number;
};
export type VerifiedProof = {
    status: 'verified';
    issuedAt: string;
    expiresAt: string;
    issuedEpoch: number;
    expiresEpoch: number;
    nonce: string;
    modelId: string;
    endpoint?: string;
    issuer: string;
    audience: string;
    modelDigest?: string;
    runtimeDigest?: string;
    policyId?: string;
    composeDigest?: string;
    evidenceDigest: string;
    /** `sha256:<base64url>` of the serving certificate's SPKI, from the evidence. */
    tlsSpkiSha256: string;
    receiptKeyId: string;
    receiptDigest: string;
    /** True when the evidence carried `dev: true` — synthetic plumbing proof. */
    devMode: boolean;
    /** The independent verifier that accepted the raw hardware evidence. */
    hardwareVerifier: string;
    /** Public P-256 key bound by the attestation, used for per-request receipts. */
    receiptPublicKey: JsonWebKey;
    /** Stable attestation state referenced by signed inference receipts. */
    attestationStateDigest: string;
    /** Quote-bound RFC 9458 EHBP key configuration for encrypted HTTP bodies. */
    ehbpKeyConfig?: Uint8Array;
    ehbpPublicKeySha256?: string;
};
export type VerificationResult = {
    status: 'verified';
    proof: VerifiedProof;
} | {
    status: 'failed';
    reason: string;
};
/**
 * Verify the attestation of the endpoint behind `baseURL` (e.g.
 * "https://host/v1"). Never rejects: failures return { status: 'failed' }.
 */
export declare const verifyEndpoint: (baseURL: string, options: VerifyEndpointOptions) => Promise<VerificationResult>;

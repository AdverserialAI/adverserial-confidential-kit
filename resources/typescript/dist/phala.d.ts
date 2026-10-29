/**
 * Local Intel-TDX verification for Phala/dstack evidence.
 *
 * This module verifies the quote to Intel's trust chain through Phala's PCCS,
 * then checks the quote's report_data against the exact v2 binding that the
 * proxy publishes: fresh challenge, TLS SPKI, receipt key, and EHBP receiver
 * public key. It is browser-capable through @phala/dcap-qvl.
 *
 * NVIDIA evidence deliberately is not treated as verified here: a browser
 * caller must provide a separate verifier for the signed NRAS EAT bundle
 * before claiming a complete CPU+GPU result.
 */
import type { HardwareEvidenceVerifier } from './verify.js';
/**
 * A real browser/Node CPU-TEE verifier for use as verifyHardwareEvidence.
 * It does not silently accept NVIDIA evidence; use a composition that checks
 * that signed EAT bundle if your policy requires GPU-confidential proof.
 */
export declare const verifyPhalaTDXEvidence: ({ evidence, nonce, expectedTDXPolicy }: Parameters<HardwareEvidenceVerifier>[0], pccsURL?: string) => Promise<{
    verified: boolean;
    verifier: string;
    tee: string;
}>;
/**
 * Creates a complete browser verifier for a Phala TDX + NVIDIA deployment.
 * It verifies both independent vendor evidence chains before returning a
 * verified result; callers cannot accidentally present CPU-TEE-only proof as
 * a complete confidential-GPU proof.
 */
export declare const createPhalaNVIDIAVerifier: (options: {
    minimumGPUCount: number;
    maxGPUEvidenceAgeMs?: number;
    fetchImpl?: typeof fetch;
    pccsURL?: string;
}) => HardwareEvidenceVerifier;

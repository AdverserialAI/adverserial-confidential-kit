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
import { getCollateralAndVerify } from '@phala/dcap-qvl';
import { asArrayBuffer, fromBase64Url } from './canonjson.js';
import { verifyNVIDIAEvidence } from './nvidia.js';
const text = new TextEncoder();
const asRecord = (value) => typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value
    : null;
const nonEmpty = (value) => typeof value === 'string' && value.length > 0 ? value : null;
const equalBytes = (left, right) => {
    if (left.byteLength !== right.byteLength)
        return false;
    let different = 0;
    for (let index = 0; index < left.byteLength; index += 1)
        different |= left[index] ^ right[index];
    return different === 0;
};
const fromHex = (value) => {
    if (!/^[0-9a-f]+$/i.test(value) || value.length % 2 !== 0)
        throw new Error('The TDX quote is not hexadecimal.');
    const output = new Uint8Array(value.length / 2);
    for (let index = 0; index < output.byteLength; index += 1)
        output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
    return output;
};
const receiptSPKI = async (jwk) => {
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    return new Uint8Array(await crypto.subtle.exportKey('spki', key));
};
const quoteReportData = (report) => report.asTd10()?.reportData ?? report.asTd15()?.base.reportData ?? (() => { throw new Error('The verified quote is not a TDX quote.'); })();
/**
 * A real browser/Node CPU-TEE verifier for use as verifyHardwareEvidence.
 * It does not silently accept NVIDIA evidence; use a composition that checks
 * that signed EAT bundle if your policy requires GPU-confidential proof.
 */
export const verifyPhalaTDXEvidence = async ({ evidence, nonce }) => {
    const quoteHex = nonEmpty(evidence.tdx_quote);
    const tlsSPKI = nonEmpty(evidence.tls_spki_der);
    const receiptJWK = asRecord(evidence.receipt_pubkey_jwk);
    const ehbp = asRecord(evidence.ehbp);
    const ehbpPublic = ehbp ? nonEmpty(ehbp.public_key) : null;
    if (!quoteHex || !tlsSPKI || !receiptJWK || !ehbpPublic) {
        throw new Error('The evidence is incomplete for Phala TDX report-data verification.');
    }
    const verified = await getCollateralAndVerify(fromHex(quoteHex));
    if (verified.status !== 'UpToDate') {
        throw new Error(`Intel TDX verification did not reach UpToDate status: ${verified.status}.`);
    }
    const binding = new Uint8Array(await crypto.subtle.digest('SHA-256', asArrayBuffer(new Uint8Array([
        ...text.encode('adverserial-attestation-v2\0'),
        ...fromBase64Url(nonce),
        ...fromBase64Url(tlsSPKI),
        ...await receiptSPKI(receiptJWK),
        ...fromBase64Url(ehbpPublic)
    ]))));
    const expected = new Uint8Array(64);
    expected.set(binding, 0);
    if (!equalBytes(quoteReportData(verified.report), expected)) {
        throw new Error('The Intel TDX quote report_data does not bind this fresh evidence and encrypted receiver key.');
    }
    return { verified: true, verifier: '@phala/dcap-qvl@0.6.5', tee: 'Intel TDX' };
};
/**
 * Creates a complete browser verifier for a Phala TDX + NVIDIA deployment.
 * It verifies both independent vendor evidence chains before returning a
 * verified result; callers cannot accidentally present CPU-TEE-only proof as
 * a complete confidential-GPU proof.
 */
export const createPhalaNVIDIAVerifier = (options) => async (input) => {
    const tdx = await verifyPhalaTDXEvidence(input);
    const gpu = await verifyNVIDIAEvidence(input.evidence, {
        minimumGPUCount: options.minimumGPUCount,
        maxAgeMs: options.maxGPUEvidenceAgeMs
    });
    return {
        verified: true,
        verifier: `${tdx.verifier}+${gpu.verifier}`,
        tee: tdx.tee,
        gpu: `NVIDIA NRAS (${gpu.gpuCount} GPUs)`
    };
};

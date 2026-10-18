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
import { verifyEndpoint } from './verify.js';
import { Identity, KeyConfigMismatchError, PROTOCOL } from 'ehbp';
export class VerificationRequiredError extends Error {
    constructor(reason) {
        super(`Refusing to send a request to an unverified confidential endpoint: ${reason}`);
        this.name = 'VerificationRequiredError';
    }
}
const entitlementPattern = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const MAX_EHBP_PROBLEM_BYTES = 64 * 1024;
const requireEntitlement = (value) => {
    if (!value || value.length > 16_384 || !entitlementPattern.test(value)) {
        throw new VerificationRequiredError('a compact, short-lived confidential entitlement is required; refusing to forward another credential');
    }
    return value;
};
const proofOrigin = (proof) => {
    if (!proof.endpoint)
        throw new VerificationRequiredError('the verified proof has no endpoint origin');
    const endpoint = new URL(proof.endpoint);
    if (endpoint.protocol !== 'https:' || endpoint.origin !== proof.endpoint) {
        throw new VerificationRequiredError('the verified proof has an invalid endpoint origin');
    }
    return endpoint.origin;
};
const sameVerifiedOrigin = (request, proof) => {
    if (new URL(request.url).origin !== proofOrigin(proof)) {
        throw new VerificationRequiredError('refusing to send an entitlement outside the verified endpoint origin');
    }
};
const responseSignalsEHBPKeyMismatch = async (response) => {
    if (response.status !== 422)
        return;
    const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
    if (contentType !== PROTOCOL.PROBLEM_JSON_MEDIA_TYPE || !response.body)
        return;
    try {
        const reader = response.clone().body?.getReader();
        if (!reader)
            return;
        const chunks = [];
        let length = 0;
        while (true) {
            const { done, value } = await reader.read();
            if (done)
                break;
            length += value.byteLength;
            if (length > MAX_EHBP_PROBLEM_BYTES) {
                await reader.cancel();
                return;
            }
            chunks.push(value);
        }
        const body = new Uint8Array(length);
        let offset = 0;
        for (const chunk of chunks) {
            body.set(chunk, offset);
            offset += chunk.byteLength;
        }
        const problem = JSON.parse(new TextDecoder().decode(body));
        if (typeof problem === 'object' && problem !== null && problem.type === PROTOCOL.KEY_CONFIG_PROBLEM_TYPE) {
            const title = problem.title;
            throw new KeyConfigMismatchError(typeof title === 'string' ? title : undefined);
        }
    }
    catch (error) {
        if (error instanceof KeyConfigMismatchError)
            throw error;
        // A malformed problem response is an ordinary failed HTTP request. The
        // original response body remains untouched for the caller to inspect.
    }
};
const mustDecryptEHBPResponse = async (response) => {
    if (response.headers.has(PROTOCOL.RESPONSE_NONCE_HEADER))
        return true;
    await responseSignalsEHBPKeyMismatch(response);
    if (!response.ok)
        return false;
    throw new VerificationRequiredError('the confidential endpoint returned a successful response without EHBP framing');
};
const encryptedFetch = async (proof, innerFetch, input, init) => {
    if (!proof.ehbpKeyConfig)
        throw new VerificationRequiredError('the verified evidence has no EHBP key configuration');
    const request = new Request(input, init);
    sameVerifiedOrigin(request, proof);
    // Use the maintained MIT-licensed EHBP reference implementation. Its
    // streaming frame format and downgrade handling are interoperable with the
    // proxy; the key config is quote-bound above, so discovery is forbidden.
    const identity = await Identity.unmarshalPublicConfig(proof.ehbpKeyConfig);
    const encrypted = await identity.encryptRequestWithContext(request);
    const response = await innerFetch(encrypted.request);
    if (!encrypted.context)
        return response;
    // Keep the reference transport's response rules without letting it choose
    // the network function. In particular, an EHBP key-configuration mismatch
    // must not look like an ordinary 422 response, while a legitimate non-2xx
    // response remains available to the caller.
    if (!(await mustDecryptEHBPResponse(response)))
        return response;
    return identity.decryptResponseWithContext(response, encrypted.context);
};
const fetchForProof = (proof, reason, innerFetch, entitlement) => {
    return (async (input, init) => {
        if (!proof)
            throw new VerificationRequiredError(reason ?? 'verification failed');
        if (proof.expiresEpoch <= Date.now() / 1000)
            throw new VerificationRequiredError('the verified confidential proof has expired');
        const originalRequest = new Request(input, init);
        sameVerifiedOrigin(originalRequest, proof);
        const headers = new Headers(originalRequest.headers);
        // Do not allow an OpenAI client's long-lived API key to cross this
        // boundary. The CVM receives only a short-lived model-bound entitlement.
        headers.delete('Authorization');
        headers.set('Authorization', `Bearer ${requireEntitlement(entitlement)}`);
        // An attested endpoint has no reason to redirect an API request. Refuse
        // redirects so the entitlement cannot escape to a different origin.
        const request = new Request(originalRequest, { headers, redirect: 'error' });
        return proof.ehbpKeyConfig
            ? encryptedFetch(proof, innerFetch, request)
            : innerFetch(request);
    });
};
export const createVerifiedOpenAI = async (options) => {
    const result = await verifyEndpoint(options.baseURL, options);
    const proof = result.status === 'verified' ? result.proof : null;
    const reason = result.status === 'failed' ? result.reason : null;
    const innerFetch = options.fetchImpl ?? fetch;
    const fetchWithEntitlement = (entitlement) => fetchForProof(proof, reason, innerFetch, entitlement);
    return {
        verified: proof !== null,
        proof,
        reason,
        baseURL: options.baseURL,
        fetchImpl: fetchForProof(proof, reason, innerFetch, options.entitlement),
        fetchWithEntitlement
    };
};

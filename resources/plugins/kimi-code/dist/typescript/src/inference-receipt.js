/** Verify the signed, hash-only receipt returned with one inference response. */
import { asArrayBuffer, fromBase64Url, sha256Digest } from './canonjson.js';
const decoder = new TextDecoder();
const asObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value) ? value : null;
const string = (value) => typeof value === 'string' && value.length > 0 ? value : null;
const epoch = (value, label) => {
    if (typeof value !== 'number' || !Number.isFinite(value))
        throw new Error(`Inference receipt is missing ${label}.`);
    return value;
};
const audienceMatches = (value, expected) => value === expected || (Array.isArray(value) && value.includes(expected));
/**
 * Validates an `X-Adverserial-Receipt` value without sending any network
 * request. It proves that the response bytes and request bytes were handled
 * by the attested proxy state verified immediately before dispatch.
 */
export const verifyInferenceReceipt = async (options) => {
    const parts = options.receipt.split('.');
    if (parts.length !== 3 || parts.some((part) => !part))
        throw new Error('Inference receipt is not a compact JWS.');
    let header;
    let claims;
    try {
        header = asObject(JSON.parse(decoder.decode(fromBase64Url(parts[0]))));
        claims = asObject(JSON.parse(decoder.decode(fromBase64Url(parts[1]))));
    }
    catch {
        throw new Error('Inference receipt has an invalid JSON payload.');
    }
    if (!header || !claims || header.alg !== 'ES256' || typeof header.kid !== 'string') {
        throw new Error('Inference receipt has an unexpected JWS header.');
    }
    const key = options.trustedReceiptKeys[header.kid];
    if (!key)
        throw new Error('Inference receipt was signed by an untrusted key.');
    const cryptoKey = await crypto.subtle.importKey('jwk', key, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, cryptoKey, asArrayBuffer(fromBase64Url(parts[2])), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
    if (!valid)
        throw new Error('Inference receipt signature is invalid.');
    const now = Math.floor((options.now?.() ?? Date.now()) / 1000);
    const issuedAt = epoch(claims.iat, 'iat');
    const expiresAt = epoch(claims.exp, 'exp');
    if (expiresAt <= now || issuedAt > now + 60)
        throw new Error('Inference receipt is expired or not yet valid.');
    if (string(claims.iss) !== options.issuer || !audienceMatches(claims.aud, options.audience))
        throw new Error('Inference receipt issuer or audience does not match.');
    if (string(claims.model_id) !== options.modelId)
        throw new Error('Inference receipt model does not match the request.');
    if (string(claims.request_nonce) !== options.requestNonce)
        throw new Error('Inference receipt is not bound to this request nonce.');
    if (string(claims.request_body_hash) !== await sha256Digest(options.requestBody))
        throw new Error('Inference receipt is not bound to the request bytes.');
    if (string(claims.response_hash) !== await sha256Digest(options.responseBody))
        throw new Error('Inference receipt is not bound to the response bytes.');
    const binding = asObject(claims.attestation_binding);
    if (!binding || string(binding.tls_spki_sha256) !== options.tlsSpkiSha256 || string(binding.evidence_digest) !== options.attestationStateDigest) {
        throw new Error('Inference receipt does not bind the verified attestation state.');
    }
    let usage;
    const rawUsage = asObject(claims.usage);
    if (rawUsage) {
        const values = [rawUsage.input_tokens, rawUsage.cached_tokens, rawUsage.output_tokens];
        if (values.some((v) => typeof v !== 'number' || !Number.isInteger(v) || v < 0) || rawUsage.cached_tokens > rawUsage.input_tokens)
            throw new Error('Inference receipt usage is invalid.');
        usage = { inputTokens: rawUsage.input_tokens, cachedTokens: rawUsage.cached_tokens, outputTokens: rawUsage.output_tokens };
    }
    return { issuedAt, expiresAt, usage, responseHash: claims.response_hash };
};

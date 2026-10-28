/**
 * Browser-verifiable NVIDIA NRAS detached-EAT bundle validation.
 *
 * The GPU collector inside the CVM submits device evidence to NVIDIA NRAS.
 * NRAS returns an overall EAT and one detached EAT per GPU.  This module does
 * not trust the proxy's `verdict` field: it fetches NVIDIA's public JWKS,
 * verifies every ES384 JWS, checks the overall result and each detached-token
 * digest, then enforces freshness and a minimum GPU count.
 */
import { asArrayBuffer } from './canonjson.js';
const decoder = new TextDecoder();
const asRecord = (value) => typeof value === 'object' && value !== null && !Array.isArray(value) ? value : null;
const string = (value) => typeof value === 'string' && value.length > 0 ? value : null;
const base64url = (value) => {
    if (!/^[A-Za-z0-9_-]*$/.test(value))
        throw new Error('NVIDIA EAT contains invalid base64url data.');
    const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
    const bytes = Uint8Array.from(atob(padded), char => char.charCodeAt(0));
    return bytes;
};
const hex = (bytes) => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const parseToken = (compact) => {
    const parts = compact.split('.');
    if (parts.length !== 3 || parts.some(part => !part))
        throw new Error('NVIDIA EAT is not a compact JWS.');
    try {
        const header = asRecord(JSON.parse(decoder.decode(base64url(parts[0]))));
        const claims = asRecord(JSON.parse(decoder.decode(base64url(parts[1]))));
        if (!header || !claims)
            throw new Error('NVIDIA EAT header or claims are malformed.');
        return { compact, header, claims, input: new TextEncoder().encode(`${parts[0]}.${parts[1]}`), signature: base64url(parts[2]) };
    }
    catch (error) {
        throw error instanceof Error ? error : new Error('NVIDIA EAT JSON is malformed.');
    }
};
const jwksURL = (nrasURL) => {
    const origin = new URL(nrasURL).origin;
    return new URL('/.well-known/jwks.json', origin);
};
const fetchNrasKeys = async (nrasURL, fetchImpl) => {
    const response = await fetchImpl(jwksURL(nrasURL), { cache: 'no-store', credentials: 'omit' });
    if (!response.ok)
        throw new Error(`NVIDIA NRAS JWKS returned ${response.status}.`);
    const body = await response.json();
    if (!Array.isArray(body.keys))
        throw new Error('NVIDIA NRAS JWKS has no key array.');
    const keys = {};
    for (const value of body.keys) {
        const key = asRecord(value);
        if (key?.kid && key.kty === 'EC' && key.crv === 'P-384')
            keys[key.kid] = key;
    }
    if (!Object.keys(keys).length)
        throw new Error('NVIDIA NRAS JWKS has no P-384 signing key.');
    return keys;
};
const verifyToken = async (token, keys) => {
    const algorithm = string(token.header.alg);
    const keyId = string(token.header.kid);
    if (algorithm !== 'ES384' || !keyId || !keys[keyId])
        throw new Error('NVIDIA EAT does not select a trusted ES384 key.');
    const key = await crypto.subtle.importKey('jwk', keys[keyId], { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify']);
    const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, key, asArrayBuffer(token.signature), asArrayBuffer(token.input));
    if (!valid)
        throw new Error('NVIDIA EAT signature is invalid.');
};
const epoch = (value, label) => {
    if (typeof value !== 'number' || !Number.isFinite(value))
        throw new Error(`NVIDIA EAT is missing ${label}.`);
    return value;
};
const sha256Hex = async (value) => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))));
/** Validate the NRAS bundle embedded in a fresh attestation response. */
export const verifyNVIDIAEvidence = async (evidence, options) => {
    if (!Number.isInteger(options.minimumGPUCount) || options.minimumGPUCount < 1)
        throw new Error('minimumGPUCount must be a positive integer.');
    const bundle = asRecord(evidence.gpu_evidence);
    if (!bundle || bundle.verdict !== 'successful')
        throw new Error('The endpoint did not provide a successful NVIDIA evidence bundle.');
    if (evidence.gpu_evidence_stale === true)
        throw new Error('The NVIDIA evidence bundle is stale.');
    const nrasURL = string(bundle.nras_url);
    const bundleNonce = string(bundle.nonce);
    const generatedAt = string(bundle.generated_at);
    const rawTokens = bundle.eat_jwts;
    if (!nrasURL || !bundleNonce || !generatedAt || !Array.isArray(rawTokens) || !rawTokens.every(item => typeof item === 'string')) {
        throw new Error('The NVIDIA evidence bundle is incomplete.');
    }
    const generatedMs = Date.parse(generatedAt);
    const nowMs = options.now?.() ?? Date.now();
    const maxAgeMs = options.maxAgeMs ?? 30 * 60_000;
    if (!Number.isFinite(generatedMs) || generatedMs > nowMs + 60_000 || nowMs - generatedMs > maxAgeMs) {
        throw new Error('The NVIDIA evidence bundle is outside its freshness window.');
    }
    const tokens = rawTokens.map(parseToken);
    const keys = await fetchNrasKeys(nrasURL, options.fetchImpl ?? fetch);
    // Verify each detached token before consuming its claims. Ordering keeps
    // failures deterministic in the Verification Center.
    for (const token of tokens)
        await verifyToken(token, keys);
    const issuer = new URL(nrasURL).origin;
    for (const token of tokens) {
        if (string(token.claims.iss) !== issuer)
            throw new Error('NVIDIA EAT issuer does not match the declared NRAS endpoint.');
        if (epoch(token.claims.exp, 'exp') * 1000 <= nowMs || epoch(token.claims.iat, 'iat') * 1000 > nowMs + 60_000) {
            throw new Error('NVIDIA EAT is expired or issued in the future.');
        }
    }
    const overall = tokens.find(token => string(token.claims.sub) === 'NVIDIA-PLATFORM-ATTESTATION' && asRecord(token.claims.submods));
    if (!overall || overall.claims['x-nvidia-overall-att-result'] !== true)
        throw new Error('NVIDIA did not attest the overall GPU platform.');
    if (string(overall.claims.eat_nonce) !== bundleNonce)
        throw new Error('NVIDIA EAT nonce does not match its bundle.');
    const submodules = asRecord(overall.claims.submods);
    const expectedDigests = new Set();
    for (const claim of Object.values(submodules)) {
        if (!Array.isArray(claim) || claim[0] !== 'DIGEST' || !Array.isArray(claim[1]) || claim[1][0] !== 'SHA-256' || typeof claim[1][1] !== 'string') {
            throw new Error('NVIDIA EAT submodule digest has an unsupported format.');
        }
        expectedDigests.add(claim[1][1].toLowerCase());
    }
    if (expectedDigests.size < options.minimumGPUCount)
        throw new Error('NVIDIA EAT contains fewer attested GPUs than policy requires.');
    const actualDigests = new Set(await Promise.all(tokens.filter(token => token !== overall).map(token => sha256Hex(token.compact))));
    for (const digest of expectedDigests)
        if (!actualDigests.has(digest))
            throw new Error('NVIDIA EAT detached GPU token does not match the overall token digest.');
    return { verified: true, verifier: 'nras-eat-jwks-es384', gpuCount: expectedDigests.size, issuedAt: new Date(epoch(overall.claims.iat, 'iat') * 1000).toISOString(), expiresAt: new Date(epoch(overall.claims.exp, 'exp') * 1000).toISOString() };
};

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
import { asArrayBuffer, evidenceDigest, fromBase64Url, sha256Digest, toBase64Url } from './canonjson.js';
import { Identity } from 'ehbp';
import { validateRuntimePolicy, checkWorkloadPolicy } from './runtime-policy.js';
const textDecoder = new TextDecoder();
const ONE_MINUTE_MS = 60_000;
const asObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value
    : null;
const asNonEmptyString = (value) => typeof value === 'string' && value.trim().length > 0 ? value : null;
const readCompactJws = (receipt) => {
    const parts = receipt.split('.');
    if (parts.length !== 3 || parts.some((part) => !part)) {
        throw new Error('The verification receipt is not a compact JWS.');
    }
    const header = asObject(JSON.parse(textDecoder.decode(fromBase64Url(parts[0]))));
    const claims = asObject(JSON.parse(textDecoder.decode(fromBase64Url(parts[1]))));
    if (!header || !claims)
        throw new Error('The verification receipt has an invalid JSON payload.');
    return {
        header,
        claims: claims,
        signingInput: `${parts[0]}.${parts[1]}`,
        signature: parts[2]
    };
};
const verifyReceiptSignature = async (receipt, trustedReceiptKeys) => {
    const { header, claims, signingInput, signature } = readCompactJws(receipt);
    const algorithm = asNonEmptyString(header.alg);
    const keyId = asNonEmptyString(header.kid);
    if (algorithm !== 'ES256' || !keyId || !trustedReceiptKeys[keyId]) {
        throw new Error('The receipt is not signed by a configured ES256 verification key.');
    }
    const key = await crypto.subtle.importKey('jwk', trustedReceiptKeys[keyId], { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const signatureValid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, asArrayBuffer(fromBase64Url(signature)), new TextEncoder().encode(signingInput));
    if (!signatureValid)
        throw new Error('The verification receipt signature is invalid.');
    return { claims, keyId };
};
const asEpochSeconds = (value, label) => {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        throw new Error(`The verification receipt is missing ${label}.`);
    }
    return value;
};
const hasAudience = (audienceClaim, expected) => typeof audienceClaim === 'string'
    ? audienceClaim === expected
    : Array.isArray(audienceClaim) && audienceClaim.includes(expected);
const endpointURL = (raw, label) => {
    const parsed = new URL(raw);
    if (parsed.protocol !== 'https:' ||
        !parsed.hostname ||
        parsed.username ||
        parsed.password ||
        parsed.search ||
        parsed.hash) {
        throw new Error(`${label} must be a plain https URL without credentials, query, or fragment.`);
    }
    return parsed;
};
/**
 * Verify the attestation of the endpoint behind `baseURL` (e.g.
 * "https://host/v1"). Never rejects: failures return { status: 'failed' }.
 */
export const verifyEndpoint = async (baseURL, options) => {
    try {
        const endpoint = endpointURL(baseURL, 'baseURL');
        const expectedEndpoint = options.expectedEndpoint ?? endpoint.origin;
        if (expectedEndpoint !== endpoint.origin) {
            throw new Error('expected endpoint must equal the origin of baseURL.');
        }
        const fetchImpl = options.fetchImpl ?? fetch;
        const clock = options.now ?? Date.now;
        const nowMs = clock();
        const nonce = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
        const attestationUrl = new URL(options.attestationUrl ?? '/attestation', endpoint);
        if (attestationUrl.protocol !== 'https:' || attestationUrl.origin !== endpoint.origin) {
            throw new Error('attestationUrl must remain on the configured HTTPS endpoint origin.');
        }
        attestationUrl.searchParams.set('nonce', nonce);
        // This request deliberately carries only a fresh nonce. It never sends a
        // chat prompt, response, API key, cookie, or account identifier.
        const response = await fetchImpl(attestationUrl, {
            method: 'GET',
            credentials: 'omit',
            cache: 'no-store',
            headers: { Accept: 'application/json' }
        });
        if (!response.ok)
            throw new Error(`The attestation endpoint returned ${response.status}.`);
        const payload = (await response.json());
        const evidence = asObject(payload.evidence);
        const receipt = asNonEmptyString(payload.verification_receipt);
        if (!evidence || !receipt)
            throw new Error('The attestation response is missing evidence or a receipt.');
        const { claims, keyId } = await verifyReceiptSignature(receipt, options.trustedReceiptKeys);
        let policy = options.expectedPolicy ? validateRuntimePolicy(options.expectedPolicy, options.expectedModelId) : undefined;
        if (!policy && endpoint.origin === 'https://api.adverserial.ai') {
            const response = await fetchImpl('https://verify.adverserial.ai/policies/production.json', { credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(15000) });
            if (!response.ok)
                throw new Error('The approved production policy is unavailable.');
            policy = validateRuntimePolicy(await response.json(), options.expectedModelId);
        }
        if (policy)
            checkWorkloadPolicy(policy, evidence, claims, keyId);
        const issuedAt = asEpochSeconds(claims.iat, 'iat');
        const expiresAt = asEpochSeconds(claims.exp, 'exp');
        if (expiresAt * 1000 <= nowMs)
            throw new Error('The verification receipt has expired.');
        if (issuedAt * 1000 > nowMs + ONE_MINUTE_MS) {
            throw new Error('The verification receipt was issued in the future.');
        }
        if (asNonEmptyString(claims.iss) !== options.issuer) {
            throw new Error('The receipt issuer does not match the configured verifier.');
        }
        if (!hasAudience(claims.aud, options.audience)) {
            throw new Error('The receipt was not issued for this application.');
        }
        if (asNonEmptyString(claims.nonce) !== nonce) {
            throw new Error('The receipt is not bound to this verification attempt.');
        }
        if (asNonEmptyString(claims.verdict) !== 'verified') {
            throw new Error('The verifier did not accept the supplied hardware evidence.');
        }
        if (asNonEmptyString(claims.model_id) !== options.expectedModelId) {
            throw new Error('The receipt model does not match the selected model.');
        }
        if (asNonEmptyString(claims.endpoint) !== expectedEndpoint) {
            throw new Error('The receipt is not bound to the configured inference endpoint.');
        }
        if (options.expectedModelDigest &&
            asNonEmptyString(claims.model_digest) !== options.expectedModelDigest) {
            throw new Error('The receipt model artifact digest does not match policy.');
        }
        if (options.expectedRuntimeDigest &&
            asNonEmptyString(claims.runtime_digest) !== options.expectedRuntimeDigest) {
            throw new Error('The receipt runtime digest does not match policy.');
        }
        const digest = await evidenceDigest(evidence);
        const receiptDigest = await sha256Digest(receipt);
        if (asNonEmptyString(claims.evidence_sha256) !== digest) {
            throw new Error('The receipt is not bound to the returned evidence.');
        }
        if (!asNonEmptyString(evidence.tdx_quote)) {
            throw new Error('The evidence is missing the TDX quote.');
        }
        // An RTMR replay is necessary to connect a valid quote to the workload
        // being measured. Preserve its native JSON shape for the hardware
        // verifier; only null and an empty string are invalid here.
        if (evidence.tdx_event_log === null || evidence.tdx_event_log === undefined || evidence.tdx_event_log === '') {
            throw new Error('The evidence is missing the TDX event log.');
        }
        if (evidence.dev === true && options.allowDevMode !== true) {
            throw new Error('Synthetic DEV_MODE evidence is not accepted by this client.');
        }
        // The endpoint's receipt may bind evidence, but it cannot independently
        // establish that the evidence is genuine hardware. Require a distinct
        // verifier before exposing a verified state to the caller.
        const hardware = await options.verifyHardwareEvidence({
            evidence,
            nonce,
            expectedModelId: options.expectedModelId,
            expectedEndpoint,
            expectedTDXPolicy: policy?.tdx
        });
        if (!hardware || hardware.verified !== true || !asNonEmptyString(hardware.verifier)) {
            throw new Error('The hardware verifier did not accept the attestation evidence.');
        }
        // Surface the TLS binding for runtimes that can pin (Python SDK). A
        // browser/Node fetch cannot observe the peer certificate; see README.
        const tlsSpkiSha256 = asNonEmptyString(evidence.tls_spki_sha256);
        if (!tlsSpkiSha256 || !tlsSpkiSha256.startsWith('sha256:')) {
            throw new Error('The evidence is missing tls_spki_sha256.');
        }
        const tlsSpkiDER = asNonEmptyString(evidence.tls_spki_der);
        if (!tlsSpkiDER)
            throw new Error('The evidence is missing tls_spki_der.');
        const tlsSpkiDigest = await crypto.subtle.digest('SHA-256', asArrayBuffer(fromBase64Url(tlsSpkiDER)));
        if (`sha256:${toBase64Url(new Uint8Array(tlsSpkiDigest))}` !== tlsSpkiSha256) {
            throw new Error('The evidence TLS SPKI DER does not match its fingerprint.');
        }
        const workload = asObject(evidence.workload) ?? {};
        const receiptPublicKey = asObject(evidence.receipt_pubkey_jwk);
        if (!receiptPublicKey || receiptPublicKey.kty !== 'EC' || receiptPublicKey.crv !== 'P-256' || receiptPublicKey.x !== options.trustedReceiptKeys[keyId]?.x || receiptPublicKey.y !== options.trustedReceiptKeys[keyId]?.y) {
            throw new Error('The evidence receipt key does not match the pinned attestation signer.');
        }
        const attestationStateDigest = asNonEmptyString(evidence.attestation_state_digest);
        if (!attestationStateDigest?.startsWith('sha256:'))
            throw new Error('The evidence is missing attestation_state_digest.');
        let ehbpKeyConfig;
        let ehbpPublicKeySha256;
        if (evidence.ehbp !== undefined && evidence.ehbp !== null) {
            const metadata = asObject(evidence.ehbp);
            const keyConfig = metadata ? asNonEmptyString(metadata.key_config) : null;
            const advertisedPublicKey = metadata ? asNonEmptyString(metadata.public_key) : null;
            ehbpPublicKeySha256 = metadata ? asNonEmptyString(metadata.public_key_sha256) ?? undefined : undefined;
            if (!keyConfig || !advertisedPublicKey || !ehbpPublicKeySha256?.startsWith('sha256:')) {
                throw new Error('The evidence EHBP key configuration is incomplete.');
            }
            ehbpKeyConfig = fromBase64Url(keyConfig);
            const advertised = fromBase64Url(advertisedPublicKey);
            const advertisedDigest = await crypto.subtle.digest('SHA-256', asArrayBuffer(advertised));
            if (`sha256:${toBase64Url(new Uint8Array(advertisedDigest))}` !== ehbpPublicKeySha256) {
                throw new Error('The evidence EHBP public-key digest does not match.');
            }
            const identity = await Identity.unmarshalPublicConfig(ehbpKeyConfig);
            const configuredKey = await identity.getPublicKeyHex();
            const advertisedKey = Array.from(advertised, (byte) => byte.toString(16).padStart(2, '0')).join('');
            if (configuredKey !== advertisedKey) {
                throw new Error('The evidence EHBP key configuration does not contain its quote-bound public key.');
            }
        }
        if (expiresAt * 1000 <= clock())
            throw new Error('The verification receipt expired during hardware verification.');
        return {
            status: 'verified',
            proof: {
                status: 'verified',
                issuedAt: new Date(issuedAt * 1000).toISOString(),
                expiresAt: new Date(expiresAt * 1000).toISOString(),
                issuedEpoch: issuedAt,
                expiresEpoch: expiresAt,
                nonce,
                modelId: options.expectedModelId,
                endpoint: asNonEmptyString(claims.endpoint) ?? undefined,
                issuer: options.issuer,
                audience: options.audience,
                modelDigest: asNonEmptyString(claims.model_digest) ?? undefined,
                runtimeDigest: asNonEmptyString(claims.runtime_digest) ?? undefined,
                policyId: asNonEmptyString(workload.policy_id) ?? undefined,
                composeDigest: asNonEmptyString(workload.compose_digest) ?? undefined,
                evidenceDigest: digest,
                tlsSpkiSha256,
                receiptKeyId: keyId,
                receiptDigest,
                devMode: evidence.dev === true,
                hardwareVerifier: hardware.verifier,
                receiptPublicKey,
                attestationStateDigest,
                ehbpKeyConfig,
                ehbpPublicKeySha256
            }
        };
    }
    catch (error) {
        return {
            status: 'failed',
            reason: error instanceof Error ? error.message : 'Verification failed unexpectedly.'
        };
    }
};

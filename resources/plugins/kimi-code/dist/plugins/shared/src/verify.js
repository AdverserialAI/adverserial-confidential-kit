/**
 * Shared verification runner for the Adversarial harness plugins: wraps the
 * SDK's verifyEndpoint with TOFU key bootstrap, an explicit "unpinned"
 * refusal state, a fetch timeout, and a 5-minute TTL cache.
 */
import { toBase64Url, verifyEndpoint } from '../../../typescript/src/index.js';
import { hardwareVerifier } from './hardware.js';
export const CACHE_TTL_MS = 5 * 60_000;
export const FETCH_TIMEOUT_MS = 15_000;
export const summarizeConfig = (config) => ({
    baseURL: config.baseURL,
    modelId: config.modelId,
    issuer: config.issuer,
    audience: config.audience,
    ...(config.expectedEndpoint ? { expectedEndpoint: config.expectedEndpoint } : {}),
    keysSource: config.keysSource,
    trustEvidenceKey: config.trustEvidenceKey,
    hardwareVerifierConfigured: config.hardwareVerifierCommand !== null,
});
const withTimeout = (fetchImpl, ms) => ((input, init) => fetchImpl(input, { ...init, signal: init?.signal ?? AbortSignal.timeout(ms) }));
/**
 * TOFU bootstrap: fetch the attestation evidence and adopt its embedded
 * ephemeral receipt_pubkey_jwk as the trusted key set. Dev-only — anyone
 * terminating TLS can present such a key. Mirrors the SDK's own node
 * integration test and the Python CLI's --trust-evidence-key.
 */
const tofuBootstrap = async (baseURL, fetchImpl) => {
    // Same resolution as verifyEndpoint: <origin of baseURL>/attestation.
    const attestationUrl = new URL('/attestation', baseURL);
    attestationUrl.searchParams.set('nonce', toBase64Url(crypto.getRandomValues(new Uint8Array(32))));
    const response = await fetchImpl(attestationUrl, {
        method: 'GET',
        credentials: 'omit',
        cache: 'no-store',
        headers: { Accept: 'application/json' }
    });
    if (!response.ok) {
        throw new Error(`TOFU bootstrap: the attestation endpoint returned ${response.status}.`);
    }
    const payload = (await response.json());
    const evidence = typeof payload.evidence === 'object' && payload.evidence !== null
        ? payload.evidence
        : null;
    const jwk = evidence &&
        typeof evidence.receipt_pubkey_jwk === 'object' &&
        evidence.receipt_pubkey_jwk !== null
        ? evidence.receipt_pubkey_jwk
        : null;
    if (!jwk)
        throw new Error('TOFU bootstrap: the evidence carries no receipt_pubkey_jwk.');
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
        throw new Error('TOFU bootstrap: receipt_pubkey_jwk is not an EC P-256 key.');
    }
    if (typeof jwk.kid !== 'string' || !jwk.kid) {
        throw new Error('TOFU bootstrap: receipt_pubkey_jwk has no kid.');
    }
    return { [jwk.kid]: jwk };
};
/**
 * Run one verification pass against the configured endpoint. Never throws
 * for verification failures (they become verdicts); may only throw via
 * AbortSignal/cancellation semantics of fetch itself.
 */
export const runVerification = async (config, deps) => {
    const summary = summarizeConfig(config);
    const verifiedAt = deps?.now?.() ?? Date.now();
    if (!config.trustedReceiptKeys && !config.trustEvidenceKey) {
        return {
            status: 'unpinned',
            reason: 'No trusted receipt keys configured; refusing to claim "verified". ' +
                'Pin keys via ADVERSERIAL_RECEIPT_KEYS_JSON or ADVERSERIAL_RECEIPT_KEYS_FILE ' +
                '(production: key set from https://verify.adverserial.ai), or use the dev-only ' +
                'TOFU escape hatch ADVERSERIAL_TRUST_EVIDENCE_KEY=1 / --trust-evidence-key.',
            verifiedAt,
            config: summary
        };
    }
    const fetchImpl = withTimeout(deps?.fetchImpl ?? fetch, FETCH_TIMEOUT_MS);
    let keys = config.trustedReceiptKeys;
    let trust = 'pinned';
    if (!keys) {
        trust = 'tofu';
        try {
            keys = await tofuBootstrap(config.baseURL, fetchImpl);
        }
        catch (error) {
            return {
                status: 'failed',
                trust,
                reason: error instanceof Error ? error.message : 'TOFU key bootstrap failed.',
                verifiedAt,
                config: summary
            };
        }
    }
    const result = await verifyEndpoint(config.baseURL, {
        expectedModelId: config.modelId,
        trustedReceiptKeys: keys,
        issuer: config.issuer,
        audience: config.audience,
        ...(config.expectedEndpoint ? { expectedEndpoint: config.expectedEndpoint } : {}),
        // The SDK rejects synthetic DEV_MODE evidence unless the caller opts in;
        // the only legitimate opt-in here is the dev-only TOFU escape hatch.
        allowDevMode: config.trustEvidenceKey,
        verifyHardwareEvidence: hardwareVerifier(config.hardwareVerifierCommand),
        fetchImpl
    });
    if (result.status === 'verified') {
        return { status: 'verified', trust, proof: result.proof, verifiedAt, config: summary };
    }
    return { status: 'failed', trust, reason: result.reason, verifiedAt, config: summary };
};
/**
 * Lazily runs verification on first use and caches the verdict for `ttlMs`.
 * Concurrent callers share one in-flight verification.
 */
export class VerificationCache {
    #current = null;
    #inflight = null;
    #ttlMs;
    #now;
    constructor(ttlMs = CACHE_TTL_MS, now = Date.now) {
        this.#ttlMs = ttlMs;
        this.#now = now;
    }
    async get(config, deps) {
        const now = this.#now();
        if (this.#current && now - this.#current.verifiedAt < this.#ttlMs) {
            return { verdict: this.#current, ageMs: now - this.#current.verifiedAt, fromCache: true };
        }
        this.#inflight ??= runVerification(config, deps)
            .then((verdict) => {
            this.#current = verdict;
            return verdict;
        })
            .finally(() => {
            this.#inflight = null;
        });
        const verdict = await this.#inflight;
        return { verdict, ageMs: 0, fromCache: false };
    }
}

/**
 * Compact human-readable rendering of CoreVerdicts for agent tool output
 * and CLI stdout. Kept deliberately plain (ASCII) so it survives every
 * terminal, log sink, and chat renderer.
 */
export const isFreshVerdict = (verdict, now = Date.now(), ttlMs = 300000) =>
    verdict?.status === 'verified' && verdict.trust === 'pinned' && verdict.proof?.devMode === false &&
    Number.isFinite(verdict.verifiedAt) && verdict.verifiedAt <= now + 5000 && now - verdict.verifiedAt < ttlMs &&
    Number.isFinite(verdict.proof.expiresEpoch) && verdict.proof.expiresEpoch * 1000 > now;

export const humanDuration = (ms) => {
    if (ms < 0)
        ms = 0;
    const totalSeconds = Math.round(ms / 1000);
    if (totalSeconds < 60)
        return `${totalSeconds}s`;
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    if (minutes < 60)
        return seconds ? `${minutes}m ${seconds}s` : `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h ${minutes % 60}m`;
};
const field = (label, value) => `  ${label.padEnd(10)}${value}`;
const verdictHeader = (verdict) => {
    switch (verdict.status) {
        case 'verified':
            return verdict.trust === 'pinned'
                ? 'ADVERSERIAL ATTESTATION: VERIFIED'
                : 'ADVERSERIAL ATTESTATION: VERIFIED — UNPINNED (TOFU dev mode)';
        case 'failed':
            return `ADVERSERIAL ATTESTATION: FAILED (${verdict.trust === 'tofu' ? 'UNPINNED (TOFU dev mode)' : 'pinned keys'})`;
        case 'unpinned':
            return 'ADVERSERIAL ATTESTATION: UNVERIFIED — no trusted receipt keys configured';
    }
};
/** Render one verdict as a compact multi-line report. */
export const formatVerdict = (verdict, now = Date.now()) => {
    const lines = [verdictHeader(verdict)];
    const { config } = verdict;
    if (verdict.status === 'unpinned') {
        lines.push('  Refusing to claim "verified" without pinned receipt keys.', '  Production : pin the key set from https://verify.adverserial.ai via', '               ADVERSERIAL_RECEIPT_KEYS_JSON or ADVERSERIAL_RECEIPT_KEYS_FILE', '  Dev only   : ADVERSERIAL_TRUST_EVIDENCE_KEY=1 (opencode) or', '               --trust-evidence-key (kimi-code CLI) — verdict then reads', '               UNPINNED (TOFU dev mode)');
        return lines.join('\n');
    }
    lines.push(field('endpoint', config.baseURL));
    lines.push(field('model', config.modelId + (verdict.status === 'failed' ? ' (expected)' : '')));
    lines.push(field('hardware', config.hardwareVerifierConfigured ? 'independent verifier configured' : 'NOT configured'));
    if (verdict.status === 'failed') {
        lines.push(field('reason', verdict.reason));
    }
    else {
        const { proof } = verdict;
        lines.push(field('policy', proof.policyId ?? '(none in evidence)'));
        lines.push(field('evidence', proof.evidenceDigest));
        lines.push(field('receipt', `kid=${proof.receiptKeyId} digest=${proof.receiptDigest}`));
        lines.push(field('tls_spki', proof.tlsSpkiSha256));
        lines.push(field('issued', proof.issuedAt));
        lines.push(field('expires', `${proof.expiresAt} (in ${humanDuration(proof.expiresEpoch * 1000 - now)})`));
        lines.push(field('trust', verdict.trust === 'pinned'
            ? `pinned receipt keys (${config.keysSource ?? 'configured'})`
            : 'UNPINNED (TOFU dev mode) — receipt key bootstrapped from the evidence itself'));
    }
    if (verdict.trust === 'tofu') {
        lines.push('  WARNING: the receipt key was trust-on-first-use bootstrapped from the evidence;', '           anyone terminating TLS could present it. Production deployments pin', '           receipt keys from https://verify.adverserial.ai.');
    }
    if (verdict.status === 'verified' && verdict.proof.devMode) {
        lines.push('  WARNING: dev_mode evidence (dev=true) — the TDX quote is SYNTHETIC.', '           This proves the plumbing (signatures, nonce, digests), NOT the hardware.');
    }
    return lines.join('\n');
};
/**
 * Render the cached verification state for `adverserial_status` /
 * `adverserial-verify --status`: one summary line with the age, then the
 * full verdict body.
 */
export const formatStatus = (entry, ttlMs, now = Date.now()) => {
    if (!entry) {
        return ('attestation status: never verified in this process — ' +
            'run the verification first (it also runs lazily on the first tool call).');
    }
    const { ageMs, fromCache } = entry;
    const fresh = isFreshVerdict(entry.verdict, now, ttlMs);
    const verdict = entry.verdict.status === 'verified' && !fresh
        ? {...entry.verdict, status:'failed', reason:'Cached attestation is expired, unpinned, synthetic or incomplete; run a fresh verification.'}
        : entry.verdict;
    const freshness = fresh ? `fresh, ttl ${humanDuration(ttlMs)}` : 'STALE OR UNVERIFIED';
    const head = `attestation status: ${verdictHeader(verdict)} — ` +
        (fromCache ? `verified ${humanDuration(ageMs)} ago (${freshness})` : 'just verified (fresh check)');
    return `${head}\n${formatVerdict(verdict, now)}`;
};

/**
 * adverserial-verify CLI — the kimi-code harness integration.
 *
 * Runs the shared verification against the configured Adverserial endpoint,
 * prints the verdict table, and caches the verdict to a small JSON file so
 * `--status` (used by hooks) is instant and network-free.
 *
 * Exit codes: 0 = verified (pinned or UNPINNED/TOFU), 1 = anything else
 * (failed, unpinned, stale/missing cache with --status, usage/config error).
 *
 * Flags:
 *   --trust-evidence-key   TOFU-bootstrap the receipt key from the evidence
 *                          (dev only; same as ADVERSERIAL_TRUST_EVIDENCE_KEY=1)
 *   --status               print the cached verdict + age, no network I/O
 *   --json                 print the raw verdict JSON instead of the table
 *   --help                 usage
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
	CACHE_TTL_MS,
	ConfigError,
	formatStatus,
	formatVerdict,
	maybeRelaxLoopbackTofuTls,
	resolveConfig,
	runVerification
} from '../../shared/src/index.js';
import type { CacheEntry, CoreVerdict } from '../../shared/src/index.js';

const USAGE = `adverserial-verify — verify the attestation of the Adverserial confidential inference endpoint

usage: adverserial-verify [--trust-evidence-key] [--status] [--json] [--help]

  (no flags)            run a fresh attestation check, print the verdict, cache it
  --trust-evidence-key  dev-only TOFU escape: adopt the ephemeral receipt key from
                        the evidence; the verdict reads UNPINNED (TOFU dev mode)
  --status              print the cached verdict and its age (no network I/O)
  --json                print the raw verdict JSON
  --help                this text

exit codes: 0 = endpoint verified, 1 = failed / unpinned / stale cache / error

environment:
  ADVERSERIAL_API_URL             endpoint base URL (default https://api.adverserial.ai/v1)
  ADVERSERIAL_MODEL               expected model id (default lordx64/cyberglm)
  ADVERSERIAL_ISSUER              receipt issuer (default https://verify.adverserial.ai)
  ADVERSERIAL_AUDIENCE            receipt audience (default https://chat.adverserial.ai)
  ADVERSERIAL_EXPECTED_ENDPOINT   also pin the receipt's endpoint claim
  ADVERSERIAL_RECEIPT_KEYS_JSON   pinned receipt keys: JSON map kid -> public JWK
  ADVERSERIAL_RECEIPT_KEYS_FILE   path to a JSON file with that same map
  ADVERSERIAL_TRUST_EVIDENCE_KEY  =1 enables the TOFU dev escape hatch
  ADVERSERIAL_CACHE_FILE          status cache path (default ~/.cache/adverserial/verify.json)

production deployments pin receipt keys from https://verify.adverserial.ai.`;

const cacheFilePath = (): string =>
	process.env.ADVERSERIAL_CACHE_FILE ??
	path.join(os.homedir(), '.cache', 'adverserial', 'verify.json');

const saveCache = (verdict: CoreVerdict): void => {
	try {
		const file = cacheFilePath();
		mkdirSync(path.dirname(file), { recursive: true });
		writeFileSync(file, JSON.stringify(verdict, null, 2));
	} catch (error) {
		console.error(
			`warning: could not write status cache: ${error instanceof Error ? error.message : String(error)}`
		);
	}
};

const isValidCachedVerdict = (verdict: CoreVerdict): boolean => {
	if (!verdict.config || typeof verdict.config !== 'object') return false;
	switch (verdict.status) {
		case 'verified':
			return typeof verdict.proof === 'object' && verdict.proof !== null;
		case 'failed':
		case 'unpinned':
			return typeof verdict.reason === 'string';
		default:
			return false;
	}
};

const loadCache = (): CacheEntry | null => {
	try {
		const verdict = JSON.parse(readFileSync(cacheFilePath(), 'utf8')) as CoreVerdict;
		if (!verdict || typeof verdict.verifiedAt !== 'number' || !isValidCachedVerdict(verdict)) return null;
		return { verdict, ageMs: Date.now() - verdict.verifiedAt, fromCache: true };
	} catch {
		return null;
	}
};

const main = async (): Promise<number> => {
	const flags = new Set(process.argv.slice(2));
	if (flags.has('--help') || flags.has('-h')) {
		console.log(USAGE);
		return 0;
	}
	const known = new Set(['--trust-evidence-key', '--status', '--json']);
	for (const flag of flags) {
		if (!known.has(flag)) {
			console.error(`unknown flag: ${flag}\n\n${USAGE}`);
			return 1;
		}
	}

	if (flags.has('--status')) {
		const entry = loadCache();
		if (!entry) {
			console.log('attestation status: no cached verdict — run adverserial-verify first.');
			return 1;
		}
		if (flags.has('--json')) {
			console.log(JSON.stringify({ ...entry.verdict, ageMs: entry.ageMs }, null, 2));
		} else {
			console.log(formatStatus(entry, CACHE_TTL_MS));
		}
		const fresh = entry.ageMs < CACHE_TTL_MS;
		return entry.verdict.status === 'verified' && fresh ? 0 : 1;
	}

	let config;
	try {
		config = resolveConfig(process.env, { trustEvidenceKey: flags.has('--trust-evidence-key') });
	} catch (error) {
		// A missing/invalid configuration must never leave a stale "verified"
		// badge behind: record the failure so --status and the statusline flip.
		saveCache({
			status: 'failed',
			trust: 'pinned',
			reason: error instanceof ConfigError ? `config error: ${error.message}` : String(error),
			verifiedAt: Date.now(),
			config: { baseURL: '', modelId: '', issuer: '', audience: '', keysSource: null, trustEvidenceKey: false, hardwareVerifierConfigured: false }
		});
		console.error(error instanceof ConfigError ? `config error: ${error.message}` : String(error));
		return 1;
	}

	const tlsWarning = maybeRelaxLoopbackTofuTls(config);
	if (tlsWarning) console.error(`WARNING: ${tlsWarning}`);

	const verdict = await runVerification(config);
	saveCache(verdict);

	if (flags.has('--json')) {
		console.log(JSON.stringify(verdict, null, 2));
	} else {
		console.log(formatVerdict(verdict));
	}
	return verdict.status === 'verified' ? 0 : 1;
};

process.exitCode = await main();

/**
 * opencode plugin: verify the attestation of the Adverserial confidential
 * inference endpoint from inside the coding session.
 *
 * Registers two tools:
 *   - adverserial_verify  — run (or return the cached) attestation check
 *   - adverserial_status  — show the cached verification state + age
 *
 * Verification runs lazily on the first tool call and is cached for 5
 * minutes (VerificationCache). Configuration comes from the environment;
 * see README.md. Without pinned receipt keys the plugin refuses to claim
 * "verified" unless the explicit TOFU dev escape hatch is set.
 */

import { type Plugin, tool } from '@opencode-ai/plugin';
import {
	CACHE_TTL_MS,
	ConfigError,
	VerificationCache,
	envFlag,
	formatStatus,
	formatVerdict,
	humanDuration,
	maybeRelaxLoopbackTofuTls,
	resolveConfig
} from '../../shared/src/index.js';
import type { CoreConfig } from '../../shared/src/index.js';

const cache = new VerificationCache();

let cachedConfig: CoreConfig | null = null;
let configError: string | null = null;
let tlsWarning: string | null = null;

/** Resolve the config once per process; rethrows the stored ConfigError afterwards. */
const getConfig = (): CoreConfig => {
	if (configError) throw new ConfigError(configError);
	if (!cachedConfig) {
		try {
			cachedConfig = resolveConfig(process.env);
			tlsWarning = maybeRelaxLoopbackTofuTls(cachedConfig);
		} catch (error) {
			configError = error instanceof Error ? error.message : String(error);
			throw error;
		}
	}
	return cachedConfig;
};

const warningPrefix = (): string => (tlsWarning ? `WARNING: ${tlsWarning}\n\n` : '');

const configErrorMessage = (error: unknown): string =>
	`CONFIG ERROR: ${error instanceof Error ? error.message : String(error)}\n` +
	'Set ADVERSERIAL_API_URL / ADVERSERIAL_MODEL / ADVERSERIAL_RECEIPT_KEYS_JSON / ' +
	'ADVERSERIAL_RECEIPT_KEYS_FILE (see the plugin README).';

export const AdverserialPlugin: Plugin = async ({ client }) => {
	await client.app.log({
		body: {
			service: 'adverserial-verify',
			level: 'info',
			message: 'Adverserial attestation plugin loaded; verification runs lazily on the first tool call'
		}
	});
	if (envFlag(process.env.ADVERSERIAL_TRUST_EVIDENCE_KEY)) {
		await client.app.log({
			body: {
				service: 'adverserial-verify',
				level: 'warn',
				message:
					'ADVERSERIAL_TRUST_EVIDENCE_KEY is set: the receipt key will be TOFU-bootstrapped ' +
					'from the evidence (dev mode, insecure). Production deployments pin keys from ' +
					'https://verify.adverserial.ai.'
			}
		});
	}

	return {
		tool: {
			adverserial_verify: tool({
				description:
					'Verify the attestation of the configured Adverserial confidential-inference ' +
					'endpoint (TDX evidence + ES256 verification receipt, checked against pinned ' +
					'receipt keys). Returns a compact verdict: VERIFIED / FAILED / UNPINNED, with ' +
					'model, policy, evidence digest, expiry, and a dev-mode warning when the ' +
					'evidence is synthetic. Runs lazily on first call and is cached for 5 minutes.',
				args: {},
				async execute() {
					try {
						const config = getConfig();
						const entry = await cache.get(config);
						const cacheNote = entry.fromCache
							? `cached result, ${humanDuration(entry.ageMs)} old (ttl ${humanDuration(CACHE_TTL_MS)})`
							: 'fresh attestation check';
						return `${warningPrefix()}${formatVerdict(entry.verdict)}\n\n(${cacheNote})`;
					} catch (error) {
						return configErrorMessage(error);
					}
				}
			}),
			adverserial_status: tool({
				description:
					'Show the current Adverserial attestation verification state: the cached last ' +
					'verdict and its age relative to the 5-minute TTL. Triggers the same lazy ' +
					'first-run verification as adverserial_verify when nothing is cached yet.',
				args: {},
				async execute() {
					try {
						const config = getConfig();
						const entry = await cache.get(config);
						return `${warningPrefix()}${formatStatus(entry, CACHE_TTL_MS)}`;
					} catch (error) {
						return configErrorMessage(error);
					}
				}
			})
		}
	};
};

export default AdverserialPlugin;

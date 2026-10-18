/**
 * Pi extension for Adverserial confidential inference.
 *
 * It registers the loopback-only provider after a fresh independent
 * attestation verdict succeeds. Pi then uses its normal OpenAI-compatible
 * streaming and tool-call implementation against the local gateway; the
 * gateway separately verifies every fresh runtime proof and every final
 * inference receipt before completing a request.
 */
import { spawn } from 'node:child_process';
import { parseVerifierResult, installAttestationStatus } from '../shared/attestation-status.mjs';
import { accessSync, constants, realpathSync, statSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Type } from '@earendil-works/pi-ai';
import type { ExtensionAPI } from '@earendil-works/pi-coding-agent';

const gatewayURL = () => process.env.ADVERSERIAL_GATEWAY_URL?.trim() || 'http://127.0.0.1:8787/v1';
const modelID = () => process.env.ADVERSERIAL_MODEL?.trim() || 'lordx64/cyberglm';
const bundledVerifier = fileURLToPath(new URL('../adverserial-verify/bin/adverserial-verify.mjs', import.meta.url));

type VerifierInvocation = { command: string; args: string[] } | { error: string };

const verifier = (): VerifierInvocation => {
	const configured = process.env.ADVERSERIAL_VERIFY_COMMAND?.trim();
	if (configured) {
		if (!isAbsolute(configured)) {
			return { error: 'ADVERSERIAL_VERIFY_COMMAND must be an absolute executable path; PATH lookup is disabled for attestation verification.' };
		}
		try {
			const command = realpathSync(configured);
			if (!statSync(command).isFile()) throw new Error('not a file');
			accessSync(command, constants.X_OK);
			return { command, args: [] };
		} catch {
			return { error: 'ADVERSERIAL_VERIFY_COMMAND must name an executable file.' };
		}
	}
	try {
		const script = realpathSync(bundledVerifier);
		if (!statSync(script).isFile()) throw new Error('not a file');
		accessSync(script, constants.R_OK);
		return { command: process.execPath, args: [script] };
	} catch {
		return { error: 'The bundled adverserial-verify script is missing or unreadable. Reinstall the confidential SDK extension.' };
	}
};

const runVerifier = (args: string[] = []): Promise<{ ok: boolean; output: string; verdict?: unknown }> =>
	new Promise((resolve) => {
		const invocation = verifier();
		if ('error' in invocation) {
			resolve({ ok: false, output: invocation.error });
			return;
		}
		const child = spawn(invocation.command, [...invocation.args, ...args, '--json'], { shell: false, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
		let stdout = '', stderr = '', oversized = false;
		child.stdout.on('data', (chunk: Buffer) => {
			if (stdout.length + chunk.length > 262144) { oversized = true; child.kill('SIGTERM'); return; }
			stdout += chunk.toString('utf8');
		});
		child.stderr.on('data', (chunk: Buffer) => { stderr = (stderr + chunk.toString('utf8')).slice(-8192); });
		child.once('error', (error) => resolve({ ok: false, output: `Could not start the attestation verifier: ${error.message}` }));
		child.once('close', (code) => resolve(oversized ? { ok: false, output: 'Attestation verifier output exceeded the size limit.' } : parseVerifierResult(code, stdout, stderr)));
	});

type AckInvocation = { command: string; args: string[] } | { error: string };

const ack = (): AckInvocation => {
	const configured = process.env.ADVERSERIAL_ACK_CLI?.trim();
	if (!configured) return { error: 'The Adverserial swarm CLI is unavailable. Start Pi with `ack code pi`.' };
	if (!isAbsolute(configured)) return { error: 'ADVERSERIAL_ACK_CLI must be an absolute path.' };
	try {
		const script = realpathSync(configured);
		if (!statSync(script).isFile()) throw new Error('not a file');
		accessSync(script, constants.R_OK);
		return { command: process.execPath, args: [script] };
	} catch {
		return { error: 'The configured Adverserial swarm CLI is missing or unreadable. Run `ack upgrade`.' };
	}
};

const runAck = (args: string[]): Promise<{ ok: boolean; output: string }> =>
	new Promise((resolve) => {
		const invocation = ack();
		if ('error' in invocation) { resolve({ ok: false, output: invocation.error }); return; }
		const child = spawn(invocation.command, [...invocation.args, ...args], {
			shell: false,
			env: { ...process.env, ACK_QUIET: '1' },
			stdio: ['ignore', 'pipe', 'pipe'],
			windowsHide: true
		});
		let output = '';
		child.stdout.on('data', (chunk: Buffer) => { output += chunk.toString('utf8'); });
		child.stderr.on('data', (chunk: Buffer) => { output += chunk.toString('utf8'); });
		child.once('error', (error) => resolve({ ok: false, output: `Could not start the swarm CLI: ${error.message}` }));
		child.once('close', (code) => resolve({ ok: code === 0, output: output.trim() || `ack exited ${code ?? 'by signal'}.` }));
	});

export default async function (pi: ExtensionAPI) {
	const verdict = await runVerifier();
	const status = installAttestationStatus(pi, verdict);
	if (!verdict.ok) {
		pi.registerCommand('adverserial-verify', {
			description: 'Run a fresh Adverserial confidential-runtime attestation check',
			handler: async (_args, ctx) => { const result = await runVerifier(); status.update(result, ctx); ctx.ui.notify(result.output + (result.ok ? '\nRestart the harness to load the confidential provider.' : ''), result.ok ? 'info' : 'warning'); }
		});
		pi.on('session_start', async (_event, ctx) => {
			ctx.ui.notify('Adverserial confidential provider is unavailable: attestation did not verify. Run /adverserial-verify for details.', 'error');
		});
		return;
	}

	pi.registerProvider('adverserial-confidential', {
		name: 'Adverserial Confidential',
		baseUrl: gatewayURL(),
		// Resolve from the short-lived process environment. This Pi release does
		// not resolve ProviderConfig's $ENV interpolation during extension setup.
		apiKey: process.env.ADVERSERIAL_API_KEY || '',
		api: 'openai-completions',
		models: [{
			id: modelID(),
			name: 'CyberGLM — confidential gateway',
			reasoning: true,
			input: ['text'],
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
			contextWindow: 1_000_000,
			maxTokens: 65_536
		}]
	});

	pi.registerTool({
		name: 'adverserial_verify',
		label: 'Verify confidential runtime',
		description: 'Run a fresh independent Adverserial TEE, GPU evidence, policy, key-binding, and receipt-key verification. Use before handling sensitive material.',
		parameters: Type.Object({}),
		async execute(_toolCallId, _params, _signal, _onUpdate, _ctx) {
			const result = await runVerifier();
			status.update(result, _ctx);
			return { content: [{ type: 'text', text: result.output }], details: { verified: result.ok } };
		}
	});

	pi.registerTool({
		name: 'adverserial_swarm_inbox',
		label: 'Read confidential swarm inbox',
		description: 'Read work explicitly assigned to Pi in the local Adverserial swarm room. This reads only user-created local task messages; it does not access another agent’s private context.',
		parameters: Type.Object({}),
		async execute(_toolCallId, _params, _signal, _onUpdate, _ctx) {
			const result = await runAck(['swarm', 'inbox', '--agent', 'pi']);
			return { content: [{ type: 'text', text: result.output }], details: { ok: result.ok } };
		}
	});

	pi.registerTool({
		name: 'adverserial_swarm_post',
		label: 'Post confidential swarm result',
		description: 'Post Pi’s concise result or question to the selected participant in the local Adverserial swarm room. Never include credentials or unneeded sensitive prompt content.',
		parameters: Type.Object({
			message: Type.String({ description: 'The result, decision, or question to share.' }),
			to: Type.Optional(Type.String({ description: 'Recipient harness: claude, codex, opencode, pi, hermes, kimi, or all. Defaults to all.' }))
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
			const recipient = params.to?.trim() || 'all';
			const result = await runAck(['swarm', 'post', '--from', 'pi', '--to', recipient, params.message]);
			return { content: [{ type: 'text', text: result.output }], details: { ok: result.ok } };
		}
	});

	pi.registerCommand('adverserial-swarm-inbox', {
		description: 'Read work explicitly assigned to Pi in the local confidential swarm room',
		handler: async (_args, ctx) => {
			const result = await runAck(['swarm', 'inbox', '--agent', 'pi']);
			ctx.ui.notify(result.output, result.ok ? 'info' : 'warning');
		}
	});

	pi.registerCommand('adverserial-verify', {
		description: 'Run a fresh Adverserial confidential-runtime attestation check',
			handler: async (_args, ctx) => {
			const result = await runVerifier();
			status.update(result, ctx);
			ctx.ui.notify(result.output, result.ok ? 'info' : 'error');
		}
	});

	pi.on('session_start', async (_event, ctx) => {
		ctx.ui.notify('Requests use the local receipt-verifying gateway. The footer tracks the last check and its expiry.', 'info');
	});
}

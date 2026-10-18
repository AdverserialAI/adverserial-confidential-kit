#!/usr/bin/env node
/**
 * adverserial-statusline — Kimi Code status-line command.
 *
 * Reads the kimi status JSON snapshot on stdin and the plugin's cached
 * verdict at ~/.cache/adverserial/verify.json (ADVERSERIAL_CACHE_FILE
 * overrides), and prints ONE footer line: the Adverserial attestation badge
 * plus the session's model and directory. No network I/O; runs in ms.
 *
 * Wire it in ~/.kimi-code/tui.toml:
 *   [status_line]
 *   command = "node /path/to/adverserial-statusline.mjs"
 */
import { readFileSync, existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const readStdin = async () => {
	const chunks = [];
	for await (const chunk of process.stdin) chunks.push(chunk);
	return Buffer.concat(chunks).toString('utf8');
};

let snapshot = {};
try {
	snapshot = JSON.parse(await readStdin());
} catch {
	snapshot = {};
}

const cacheFile = process.env.ADVERSERIAL_CACHE_FILE ?? path.join(os.homedir(), '.cache', 'adverserial', 'verify.json');
let badge = '◌ adverserial: not verified';
if (existsSync(cacheFile)) {
	try {
		const verdict = JSON.parse(readFileSync(cacheFile, 'utf8'));
		const ageMin = Math.max(0, Math.round((Date.now() - Number(verdict.verifiedAt || 0)) / 60000));
		const age = ageMin < 1 ? 'just now' : `${ageMin}m ago`;
		if (verdict.status === 'verified' && ageMin < 60) {
			badge = `✓ Adverserial AI attestation verified (${age})`;
		} else if (verdict.status === 'verified') {
			badge = `… Adverserial attestation stale (${age})`;
		} else if (verdict.status === 'unpinned') {
			badge = '⚠ Adverserial attestation UNPINNED (TOFU)';
		} else {
			badge = '✗ Adverserial attestation FAILED';
		}
	} catch {
		badge = '⚠ adverserial: unreadable verdict cache';
	}
}

const model = snapshot.model?.display_name || snapshot.model?.id || '';
const cwd = snapshot.cwd ? snapshot.cwd.replace(os.homedir(), '~') : '';
const git = snapshot.git?.branch ? `(${snapshot.git.branch})` : '';
const parts = [badge, model, cwd, git].filter(Boolean);
process.stdout.write(parts.join(' · ') + '\n');

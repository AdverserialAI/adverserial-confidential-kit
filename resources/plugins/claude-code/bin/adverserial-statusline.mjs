#!/usr/bin/env node
/**
 * adverserial-statusline — Claude Code statusLine command.
 *
 * Reads the Claude Code status JSON snapshot on stdin and the plugin's
 * cached verdict at ~/.cache/adverserial/verify.json (ADVERSERIAL_CACHE_FILE
 * overrides), and prints ONE line: the Adverserial attestation badge plus
 * the session's model and directory. No network I/O; runs in ms.
 *
 * Wire it in ~/.claude/settings.json (absolute path; settings do not expand
 * ${CLAUDE_PLUGIN_ROOT}):
 *   {
 *     "statusLine": {
 *       "type": "command",
 *       "command": "node /absolute/path/to/plugins/claude-code/bin/adverserial-statusline.mjs"
 *     }
 *   }
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
const currentDir = snapshot.workspace?.current_dir || snapshot.cwd || '';
const cwd = currentDir ? currentDir.replace(os.homedir(), '~') : '';
const parts = [badge, model, cwd].filter(Boolean);
process.stdout.write(parts.join(' · ') + '\n');

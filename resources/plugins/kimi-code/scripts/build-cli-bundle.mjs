// Bundle the plugin CLI into one self-contained ESM file. The Kimi Code
// plugin manager copies the plugin directory without node_modules, so bare
// imports (ehbp, @phala/dcap-qvl) must be inlined for the managed copy to run.
import { build } from 'esbuild';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const outfile = join(root, 'dist', 'adverserial-verify.bundle.mjs');

await build({
	entryPoints: [join(root, 'src', 'cli.ts')],
	bundle: true,
	format: 'esm',
	platform: 'node',
	target: ['node18'],
	sourcemap: false,
	minify: false,
	outfile,
	legalComments: 'linked',
	banner: {
		js: '// adverserial-verify — self-contained bundle (built by scripts/build-cli-bundle.mjs)\nimport { createRequire as __createRequire } from \'node:module\';\nconst require = __createRequire(import.meta.url);'
	}
});
console.log(`built ${outfile}`);

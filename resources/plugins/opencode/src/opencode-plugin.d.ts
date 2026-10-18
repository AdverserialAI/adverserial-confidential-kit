// The OpenCode host supplies this module at runtime. Keeping the narrow
// declaration here lets the source compile in a standalone SDK checkout even
// when a package manager omits OpenCode's optional runtime dependency.
declare module '@opencode-ai/plugin' {
	export type Plugin = (input: {
		client: { app: { log(input: { body: { service: string; level: string; message: string } }): Promise<unknown> } };
	}) => Promise<unknown>;
	export const tool: (definition: unknown) => unknown;
}

import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import {runInNewContext} from 'node:vm';
import { harnessCommand, headlessCommand, configureKimi } from '../lib/ack.mjs';

const state = () => ({apiKey:'sk-test-billing-secret-not-for-config', model:'lordx64/cyberglm', endpoint:'https://api.adverserial.ai/v1'});
async function fixture(t) {
  const home=await mkdtemp(join(tmpdir(),'ack-harness-config-'));
  t.after(()=>rm(home,{recursive:true,force:true}));
  return {home, env:{HOME:home,ACK_HOME:home,PATH:'',ACK_CLAUDE_BIN:'/bin/echo',ACK_HERMES_BIN:'/bin/echo',ACK_KIMI_BIN:'/bin/echo',ACK_ZCODE_BIN:'/bin/echo',ACK_DSH_BIN:'/bin/echo',ADVERSERIAL_GATEWAY_PORT:'8765'}};
}
test('Claude headless keeps its plugin and private status-line settings',async t=>{
 const {env}=await fixture(t); const launch=await headlessCommand('claude',state(),env,'hello');
 assert.ok(launch.args.includes('--plugin-dir')); assert.ok(launch.args.includes('-p'));
 const settings=JSON.parse(launch.args[launch.args.indexOf('--settings')+1]);
 assert.match(settings.statusLine.command,/adverserial-statusline.mjs/);
 assert.ok(!launch.args.join(' ').includes(state().apiKey));
});
test('fresh Kimi config has a root default and an environment credential; refresh preserves user settings',async t=>{
 const {home,env}=await fixture(t);env.KIMI_CODE_HOME=join(home,'kimi');
 await configureKimi(state(),env);const path=join(env.KIMI_CODE_HOME,'config.toml');
 let text=await readFile(path,'utf8');assert.match(text,/^default_model = "adverserial_confidential"/);
 assert.match(text,/api_key_env = "ADVERSERIAL_API_KEY"/);assert.ok(!text.includes(state().apiKey));
 text=text.replace('default_model = "adverserial_confidential"','default_model = "my-existing-model"');await writeFile(path,text);
 await configureKimi(state(),env);text=await readFile(path,'utf8');assert.match(text,/^default_model = "my-existing-model"/);
 assert.equal(text.match(/BEGIN ADVERSERIAL/g).length,1);
});
test('Hermes uses chat query arguments and an isolated named provider without plaintext keys',async t=>{
 const {home,env}=await fixture(t);const launch=await headlessCommand('hermes',state(),env,'hello');
 assert.deepEqual(launch.args.slice(0,3),['chat','--provider','adverserial-confidential']);
 assert.ok(launch.args.includes('--oneshot'));assert.ok(!launch.args.includes('--base-url'));assert.ok(!launch.args.includes('--config'));assert.ok(!launch.args.includes('--print'));
 assert.equal(launch.env.HERMES_HOME,join(home,'hermes'));
 const text=await readFile(join(home,'hermes/config.yaml'),'utf8');assert.match(text,/key_env: ADVERSERIAL_API_KEY/);assert.ok(!text.includes(state().apiKey));
 assert.match(await readFile(join(home,'hermes/skills/adverserial-verify/SKILL.md'),'utf8'),/ADVERSERIAL_ACK_CLI/);
});
test('DeepSeek selects the configured confidential route instead of its official default',async t=>{
 const {home,env}=await fixture(t);const launch=await headlessCommand('deepseek-harness',state(),env,'hello');
 assert.deepEqual(launch.args,['--profile','headless','--patch',launch.env.ACK_DSH_PATCH,'hello']);
 const patch=await readFile(join(home,'deepseek-harness/cordis.patch.yml'),'utf8');
 assert.match(patch,/- id: agent-default-model\n  config:\n    provider: adverserial-confidential/);
 assert.match(patch,/apiKeyEnv: ADVERSERIAL_API_KEY/);assert.ok(!patch.includes(state().apiKey));
});
test('ZCode writes its current versioned provider schema with only a session-scoped loopback token',async t=>{
 const {env}=await fixture(t);const current=state();const first=await harnessCommand('zcode',current,env);
 const config=JSON.parse(await readFile(first.env.ZCODE_PERSONAL_PROVIDER_CONFIG_FILE,'utf8'));
 assert.equal(config.schemaVersion,1);assert.equal(config.config.defaultModelSelection.modelId,current.model);
 assert.ok(!JSON.stringify(config).includes(current.apiKey));
 assert.equal(config.config.providerConfigRules.providerRules[0].config.access.apiKey,first.env.ADVERSERIAL_LOCAL_GATEWAY_TOKEN);
 const second=await harnessCommand('zcode',current,env);assert.equal(second.env.ADVERSERIAL_LOCAL_GATEWAY_TOKEN,first.env.ADVERSERIAL_LOCAL_GATEWAY_TOKEN);
 const other=await harnessCommand('zcode',state(),env);assert.notEqual(other.env.ADVERSERIAL_LOCAL_GATEWAY_TOKEN,first.env.ADVERSERIAL_LOCAL_GATEWAY_TOKEN);
});
test('Codex plugin installation honors the isolated CODEX_HOME',async t=>{
 const {home,env}=await fixture(t);const binary=join(home,'codex');const log=join(home,'calls');
 await writeFile(binary,'#!/bin/sh\nprintf "%s\\n" "$CODEX_HOME" >> "$ACK_TEST_CALLS"\n',{mode:0o700});
 env.ACK_CODEX_BIN=binary;env.CODEX_HOME=join(home,'isolated-codex');env.ACK_TEST_CALLS=log;
 await harnessCommand('codex',state(),env);
 assert.deepEqual((await readFile(log,'utf8')).trim().split('\n'),[env.CODEX_HOME,env.CODEX_HOME]);
});
test('Claude badge refuses expired, unpinned, synthetic and future-dated cached verdicts',async t=>{
 const {home}=await fixture(t);const cache=join(home,'verdict.json');const script=new URL('../resources/plugins/claude-code/bin/adverserial-statusline.mjs',import.meta.url).pathname;
 const now=Date.now();const valid={status:'verified',trust:'pinned',verifiedAt:now,proof:{expiresEpoch:now/1000+60,devMode:false}};
 for(const [name,verdict,good] of [['fresh',valid,true],['expired',{...valid,proof:{expiresEpoch:now/1000-1}},false],['old',{...valid,verifiedAt:now-360000},false],['unpinned',{...valid,trust:'tofu'},false],['synthetic',{...valid,proof:{...valid.proof,devMode:true}},false],['future',{...valid,verifiedAt:now+60000},false]]){
 await writeFile(cache,JSON.stringify(verdict));const result=spawnSync(process.execPath,[script],{input:'{}',encoding:'utf8',env:{...process.env,ADVERSERIAL_CACHE_FILE:cache}});
 assert.equal(result.status,0,name);assert.equal(result.stdout.includes('✓ Adverserial AI attestation verified'),good,name);
 }
});
test('a policy-bound verifier keeps public pins available when a harness scrubs its environment',async t=>{
 const {home,env}=await fixture(t);const current=state();
 const pins={kid:{kty:'EC',crv:'P-256',x:'public-x',y:'public-y'}};
 await writeFile(join(home,'receipt-keys.json'),JSON.stringify(pins));
 for(const name of ['pi','zcode','deepseek-harness']) {
  env.ACK_PI_BIN='/bin/echo';
  const launch=await harnessCommand(name,current,env);
  assert.match(launch.env.ADVERSERIAL_VERIFY_COMMAND,/\/bin\/verify-[a-f0-9]+\.mjs$/);
  const script=await readFile(launch.env.ADVERSERIAL_VERIFY_COMMAND,'utf8');
  assert.ok(script.includes('ADVERSERIAL_RECEIPT_KEYS_JSON'));assert.ok(script.includes('public-x'));
  assert.ok(!script.includes(current.apiKey));assert.ok(script.includes('ADVERSERIAL_HARDWARE_VERIFIER_COMMAND'));
  const context={process:{env:{ADVERSERIAL_RECEIPT_KEYS_FILE:'/existing/keyfile'}}};
  runInNewContext(script.split('\n').slice(1).join('\n').split('await import(')[0],context);
  assert.equal(context.process.env.ADVERSERIAL_RECEIPT_KEYS_FILE,'');
  assert.deepEqual(JSON.parse(context.process.env.ADVERSERIAL_RECEIPT_KEYS_JSON),pins);
 }
});
test('ZCode removes only its previous ACK-owned plaintext provider configuration',async t=>{
 const {home,env}=await fixture(t);const path=join(home,'zcode/cli/config.json');await mkdir(join(home,'zcode/cli'),{recursive:true});
 await writeFile(path,JSON.stringify({$schema:'zcode.config.v1',provider:{zai:{name:'Adverserial Confidential',options:{apiKey:state().apiKey}}}}));
 await harnessCommand('zcode',state(),env);await assert.rejects(readFile(path),/ENOENT/);
 await writeFile(path,JSON.stringify({ownedBy:'someone-else'}));await harnessCommand('zcode',state(),env);
 assert.deepEqual(JSON.parse(await readFile(path,'utf8')),{ownedBy:'someone-else'});
});
test('Oh My Pi does not reuse a Pi agent-directory override from another harness',async t=>{
 const {home,env}=await fixture(t);env.ACK_OMP_BIN='/bin/echo';env.PI_CODING_AGENT_DIR=join(home,'pi');env.OMP_CODING_AGENT_DIR=join(home,'omp');
 const omp=await harnessCommand('oh-my-pi',state(),env);
 assert.equal(omp.env.PI_CODING_AGENT_DIR,env.OMP_CODING_AGENT_DIR);assert.notEqual(omp.env.PI_CODING_AGENT_DIR,env.PI_CODING_AGENT_DIR);
});

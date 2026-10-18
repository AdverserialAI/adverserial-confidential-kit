import assert from 'node:assert/strict';
import test from 'node:test';
import {mkdtemp, mkdir, cp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createAttestationStatus, installAttestationStatus, parseVerifierResult, verificationDeadline} from '../resources/plugins/shared/attestation-status.mjs';
import {hardwareRuntimeStatus} from '../lib/ack.mjs';
const now = 1_800_000_000_000;
const verdict = () => ({status:'verified', trust:'pinned', verifiedAt:now, proof:{devMode:false,expiresEpoch:(now+5000)/1000}, config:{baseURL:'https://api.example',modelId:'model'}});

test('only a fresh pinned non-development verifier verdict can create a verified badge', () => {
 assert.equal(verificationDeadline(verdict(),now),now+5000);
 for (const v of [{...verdict(),trust:'tofu'},{...verdict(),verifiedAt:now-300001},{...verdict(),verifiedAt:now+6000},{...verdict(),proof:{...verdict().proof,devMode:true}},{...verdict(),proof:{devMode:false,expiresEpoch:now/1000-1}}]) assert.equal(verificationDeadline(v,now),0);
 assert.equal(parseVerifierResult(0,'not a verdict','',now).ok,false);
 assert.equal(parseVerifierResult(1,JSON.stringify(verdict()),'',now).ok,false);
 assert.equal(parseVerifierResult(0,JSON.stringify({...verdict(),trust:'tofu'}),'',now).ok,false);
 assert.equal(parseVerifierResult(0,JSON.stringify(verdict()),'',now).ok,true);
});
test('verified badge expires without user interaction and request failure stays failed until re-verification', () => {
 let clock=now, scheduled,delay, last;
 const status=createAttestationStatus((tone,label)=>last={tone,label},{now:()=>clock,schedule:(fn,ms)=>{scheduled=fn;delay=ms;return 1},cancel:()=>{scheduled=null}});
 status.update({ok:true,verdict:verdict()});assert.equal(last.tone,'success');assert.equal(delay,5000);
 const expire=scheduled;clock=now+5001;expire();assert.equal(last.tone,'warning');assert.match(last.label,/expired/);
 clock=now;status.update({ok:true,verdict:verdict()});status.invalidate();assert.equal(last.tone,'error');assert.equal(scheduled,null);
 status.refresh();assert.equal(last.tone,'error');status.update({ok:true,verdict:verdict()});assert.equal(last.tone,'success');
 status.dispose();assert.equal(scheduled,null);
});
test('Pi event hooks invalidate the footer on gateway verification errors, including agent_end-only failures', async () => {
 const handlers={};let label;const ctx={model:{provider:'adverserial-confidential'},ui:{setStatus:(_id,value)=>{label=value},theme:{fg:(_tone,text)=>text}}};
 const initial={ok:true,verdict:{...verdict(),verifiedAt:Date.now(),proof:{devMode:false,expiresEpoch:Date.now()/1000+20}}};
 const status=installAttestationStatus({on:(event,fn)=>{handlers[event]=fn}},initial);
 await handlers.session_start({},ctx);assert.match(label,/✓/);
 await handlers.message_end({message:{role:'assistant',errorMessage:'503 Confidential endpoint verification failed: the independent hardware verifier failed'}},ctx);assert.match(label,/needs attention/);
 status.update(initial,ctx);await handlers.agent_end({messages:[{role:'assistant',errorMessage:'Confidential endpoint verification failed'}]},ctx);assert.match(label,/needs attention/);
 status.update(initial,ctx);await handlers.message_end({message:{role:'assistant',errorMessage:'401 insufficient credits'}},ctx);assert.match(label,/✓/);
 await handlers.session_shutdown();
});
test('hardware-runtime preflight catches a linked checkout with no npm dependency tree', async t => {
 assert.equal((await hardwareRuntimeStatus()).ok,true);
 const root=await mkdtemp(join(tmpdir(),'ack-no-node-deps-'));t.after(()=>rm(root,{recursive:true,force:true}));
 await mkdir(join(root,'resources/typescript'),{recursive:true});
 await cp(new URL('../resources/typescript/adverserial-hardware-verify.mjs',import.meta.url),join(root,'resources/typescript/adverserial-hardware-verify.mjs'));
 await cp(new URL('../resources/typescript/dist',import.meta.url),join(root,'resources/typescript/dist'),{recursive:true});
 const result=await hardwareRuntimeStatus(root);assert.equal(result.ok,false);assert.match(result.detail,/npm ci/);assert.match(result.detail,/linked source checkout/);
});

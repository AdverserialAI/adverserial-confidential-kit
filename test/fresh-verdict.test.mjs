import assert from 'node:assert/strict';
import test from 'node:test';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {evidenceDigest} from '../resources/typescript/dist/canonjson.js';
import {VerificationCache} from '../resources/plugins/opencode/dist/plugins/shared/src/verify.js';
import {verificationLabel} from '../lib/console.mjs';
import {verificationDeadline} from '../resources/plugins/shared/attestation-status.mjs';

test('all status surfaces reject expired, incomplete, synthetic and unpinned cached proofs', async t=>{
 const home=await mkdtemp(join(tmpdir(),'ack-verdict-'));t.after(()=>rm(home,{recursive:true,force:true}));
 const cache=join(home,'verdict.json');
 const now=Date.now();
 const good={status:'verified',trust:'pinned',verifiedAt:now,proof:{status:'verified',devMode:false,expiresEpoch:now/1000+180},config:{baseURL:'https://example.invalid',modelId:'fixture'}};
 const cases=[
  ['fresh',good,true],
  ['expired',{...good,proof:{...good.proof,expiresEpoch:now/1000-1}},false],
  ['future',{...good,verifiedAt:now+60000},false],
  ['old',{...good,verifiedAt:now-300001},false],
  ['unpinned',{...good,trust:'tofu'},false],
  ['synthetic',{...good,proof:{...good.proof,devMode:true}},false],
  ['incomplete',{...good,proof:{expiresEpoch:now/1000+60}},false],
  ['invalid expiry',{...good,proof:{...good.proof,expiresEpoch:String(now/1000+60)}},false],
 ];
 for(const [name,verdict,valid] of cases){
  await writeFile(cache,JSON.stringify(verdict));
  assert.equal(verificationLabel(verdict,now).tone==='good',valid,`console ${name}`);
  assert.equal(Boolean(verificationDeadline(verdict,now)),valid,`shared ${name}`);
  for(const plugin of ['claude-code','kimi-code']){
   const script=fileURLToPath(new URL(`../resources/plugins/${plugin}/bin/adverserial-statusline.mjs`,import.meta.url));
   const result=spawnSync(process.execPath,[script],{input:'{}',encoding:'utf8',env:{...process.env,ADVERSERIAL_CACHE_FILE:cache}});
   assert.equal(result.stdout.includes('✓ Adverserial AI attestation verified'),valid,`${plugin} ${name}`);
  }
  for(const relative of ['claude-code/bin/adverserial-verify-cli.mjs','adverserial-verify/bin/adverserial-verify.mjs']){
   const script=fileURLToPath(new URL('../resources/plugins/'+relative,import.meta.url));
   const result=spawnSync(process.execPath,[script,'--status','--json'],{encoding:'utf8',env:{...process.env,ADVERSERIAL_CACHE_FILE:cache}});
   assert.equal(result.status===0,valid,`${relative} exit ${name}`);
   assert.equal(JSON.parse(result.stdout).status==='verified',valid,`${relative} JSON ${name}`);
  }
 }
});

function signedFixture(clock){
 const {publicKey,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const jwk={...publicKey.export({format:'jwk'}),kid:'fixture'};
 const der=publicKey.export({format:'der',type:'spki'});
 const evidence={dev:false,tdx_quote:'fixture-quote',tdx_event_log:[],tls_spki_der:der.toString('base64url'),tls_spki_sha256:'sha256:'+createHash('sha256').update(der).digest('base64url'),receipt_pubkey_jwk:jwk,attestation_state_digest:'sha256:fixture-state'};
 const options={expectedModelId:'fixture',issuer:'fixture-issuer',audience:'fixture-audience',trustedReceiptKeys:{fixture:jwk},now:clock,verifyHardwareEvidence:async()=>({verified:true,verifier:'fixture-only'})};
 let fetches=0;
 options.fetchImpl=async url=>{
  fetches++;
  const claims={iat:Math.floor(clock()/1000),exp:Math.floor(clock()/1000)+30,iss:options.issuer,aud:options.audience,model_id:'fixture',endpoint:'https://fixture.invalid',nonce:new URL(url).searchParams.get('nonce'),verdict:'verified',evidence_sha256:await evidenceDigest(evidence)};
  const encode=value=>Buffer.from(JSON.stringify(value)).toString('base64url');
  const input=encode({alg:'ES256',kid:'fixture'})+'.'+encode(claims);
  const signature=sign('sha256',Buffer.from(input),{key:privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
  return new Response(JSON.stringify({evidence,verification_receipt:input+'.'+signature}),{status:200});
 };
 return {options,fetches:()=>fetches};
}

test('all bundled JS verifiers reject proof expiry during hardware verification',async t=>{
 const home=await mkdtemp(join(tmpdir(),'ack-verifier-'));t.after(()=>rm(home,{recursive:true,force:true}));
 const modules=[await import('../resources/typescript/dist/verify.js'),await import('../resources/plugins/opencode/dist/typescript/src/verify.js')];
 for(const [index,relative] of ['claude-code/bin/adverserial-verify-cli.mjs','adverserial-verify/bin/adverserial-verify.mjs'].entries()){
  const source=await readFile(new URL('../resources/plugins/'+relative,import.meta.url),'utf8');
  assert.ok(source.includes('process.exitCode = await main();'));
  const path=join(home,`bundle-${index}.mjs`);
  await writeFile(path,source.replace('process.exitCode = await main();','export { verifyEndpoint };'));
  modules.push(await import(pathToFileURL(path)));
 }
 for(const module of modules){
  let now=Date.now();const fixture=signedFixture(()=>now);
  assert.equal((await module.verifyEndpoint('https://fixture.invalid/v1',fixture.options)).status,'verified');
  fixture.options.verifyHardwareEvidence=async()=>{now+=31000;return{verified:true,verifier:'fixture-only'}};
  const result=await module.verifyEndpoint('https://fixture.invalid/v1',fixture.options);
  assert.equal(result.status,'failed');assert.match(result.reason,/expired/);
 }
});

test('OpenCode refreshes a proof when its expiry precedes the cache TTL',async t=>{
 const home=await mkdtemp(join(tmpdir(),'ack-cache-'));t.after(()=>rm(home,{recursive:true,force:true}));
 const verifier=join(home,'fixture.mjs');
 await writeFile(verifier,"for await (const part of process.stdin) {} console.log(JSON.stringify({verified:true,verifier:'fixture-only'}));");
 let now=Date.now();const fixture=signedFixture(()=>now);const cache=new VerificationCache(300000,()=>now);
 const config={baseURL:'https://fixture.invalid/v1',modelId:'fixture',issuer:fixture.options.issuer,audience:fixture.options.audience,trustedReceiptKeys:fixture.options.trustedReceiptKeys,trustEvidenceKey:false,hardwareVerifierCommand:verifier};
 const deps={fetchImpl:fixture.options.fetchImpl,now:()=>now};
 assert.equal((await cache.get(config,deps)).verdict.status,'verified');
 assert.equal((await cache.get(config,deps)).fromCache,true);
 now+=31000;
 const renewed=await cache.get(config,deps);
 assert.equal(renewed.fromCache,false);assert.equal(renewed.verdict.status,'verified');assert.equal(fixture.fetches(),2);
});

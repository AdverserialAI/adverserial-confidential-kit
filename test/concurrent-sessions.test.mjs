import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
import test from 'node:test';
import {mkdtemp,mkdir,writeFile,readFile,rm,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:http';
import {once} from 'node:events';
import {startSessionGateway as realStartSessionGateway,harnessCommand} from '../lib/ack.mjs';
const startSessionGateway=(state,env)=>realStartSessionGateway(state,env,{spawnImpl:(_command,args,options)=>spawn(process.execPath,[join(env.ACK_HOME,'gateway.cjs'),...args.slice(2)],options)});
const state=()=>({apiKey:'sk-test-configuration-only',model:'lordx64/cyberglm',endpoint:'https://api.adverserial.ai/v1'});
async function fixture(t){
 const home=await mkdtemp(join(tmpdir(),'ack-concurrent-'));t.after(()=>rm(home,{recursive:true,force:true}));
 await mkdir(join(home,'venv/bin'),{recursive:true});
 const stub=`#!${process.execPath}\nconst http=require('node:http'),fs=require('node:fs');const port=Number(process.argv[process.argv.indexOf('--port')+1]);const server=http.createServer((req,res)=>res.end('owned'));server.on('error',e=>e.code==='EADDRINUSE'?server.listen(0,'127.0.0.1'):process.exit(1));server.on('listening',()=>{fs.writeSync(1,JSON.stringify({port:server.address().port,pid:process.env.ACK_BAD_PID?'wrong':process.pid})+'\\n');});server.listen(port,'127.0.0.1');`;
 await writeFile(join(home,'gateway.cjs'),stub,{mode:0o700});
 return {home,env:{...process.env,ACK_HOME:home,ADVERSERIAL_GATEWAY_PORT:''}};
}
async function stop(child){const closed=once(child,'close');child.kill('SIGTERM');await closed;}
test('two simultaneous sessions own separate bound gateways and stopping one leaves the other running',async t=>{
 const {env}=await fixture(t);const [a,b]=await Promise.all([startSessionGateway(state(),env),startSessionGateway(state(),env)]);
 t.after(async()=>{for(const session of [a,b])if(session.child.exitCode===null&&session.child.signalCode===null)await stop(session.child)});
 assert.notEqual(a.env.ADVERSERIAL_GATEWAY_PORT,b.env.ADVERSERIAL_GATEWAY_PORT);assert.notEqual(a.env.ACK_SESSION_HOME,b.env.ACK_SESSION_HOME);
 const url=s=>`http://127.0.0.1:${s.env.ADVERSERIAL_GATEWAY_PORT}/healthz`;
 assert.equal(await(await fetch(url(a))).text(),'owned');assert.equal(await(await fetch(url(b))).text(),'owned');
 await stop(a.child);assert.equal(await(await fetch(url(b))).text(),'owned');
});
test('an occupied preferred port is left untouched and a second gateway uses an OS-assigned port',async t=>{
 const {env}=await fixture(t);const unrelated=createServer((req,res)=>res.end('unrelated'));unrelated.listen(0,'127.0.0.1');await once(unrelated,'listening');t.after(()=>new Promise(r=>unrelated.close(r)));
 const port=String(unrelated.address().port);const session=await startSessionGateway(state(),{...env,ADVERSERIAL_GATEWAY_PORT:port});t.after(()=>stop(session.child));
 assert.notEqual(session.env.ADVERSERIAL_GATEWAY_PORT,port);assert.equal(await(await fetch(`http://127.0.0.1:${port}/healthz`)).text(),'unrelated');
});
test('an unrelated health response cannot forge child readiness',async t=>{
 const {env}=await fixture(t);await assert.rejects(startSessionGateway(state(),{...env,ACK_BAD_PID:'1'}),/could not start/);
});
test('session-specific connection files cannot replace another window configuration or its stored history',async t=>{
 const {home,env}=await fixture(t);Object.assign(env,{PATH:'',ACK_KIMI_BIN:process.execPath,ACK_HERMES_BIN:process.execPath,ACK_ZCODE_BIN:process.execPath,ACK_DSH_BIN:process.execPath,ACK_OPENCODE_BIN:process.execPath,KIMI_CODE_HOME:join(home,'original-kimi')});
 await mkdir(join(env.KIMI_CODE_HOME,'sessions'),{recursive:true});await writeFile(join(env.KIMI_CODE_HOME,'sessions/keep.txt'),'keep-history');
 for(const name of ['kimi','hermes','zcode','deepseek-harness','opencode']){
  const a=await harnessCommand(name,state(),{...env,ACK_SESSION_HOME:join(home,'a'),ADVERSERIAL_GATEWAY_PORT:'18881'});
  const b=await harnessCommand(name,state(),{...env,ACK_SESSION_HOME:join(home,'b'),ADVERSERIAL_GATEWAY_PORT:'18882'});
  const path=s=>name==='kimi'?join(s.env.KIMI_CODE_HOME,'config.toml'):name==='hermes'?join(s.env.HERMES_HOME,'config.yaml'):name==='zcode'?s.env.ZCODE_PERSONAL_PROVIDER_CONFIG_FILE:name==='deepseek-harness'?s.env.ACK_DSH_PATCH:join(s.env.XDG_CONFIG_HOME,'opencode/opencode.json');
  assert.notEqual(path(a),path(b),name);assert.ok((await readFile(path(a),'utf8')).includes(':18881'),name);assert.ok(!(await readFile(path(a),'utf8')).includes(':18882'),name);
  if(name==='kimi'){assert.equal(await readFile(join(b.env.KIMI_CODE_HOME,'sessions/keep.txt'),'utf8'),'keep-history');}
  if(name==='hermes'){assert.notEqual(a.env.HERMES_HOME,b.env.HERMES_HOME);await assert.rejects(readFile(join(a.env.HERMES_HOME,'state.db')),/ENOENT/);}
 }
});

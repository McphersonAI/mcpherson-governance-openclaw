import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { NativeLedger, readNativeEvidenceStatus } from '../plugins/openclaw-connector/native-ledger.mjs';
import { NativeAdapter } from '../plugins/openclaw-connector/native-adapter.mjs';
import { installCredential, credentialPath, parseCredential } from '../plugins/openclaw-connector/credentials.mjs';
import { atomicWriteSecureFile } from '../plugins/openclaw-connector/secure-files.mjs';

const results = [];
const event = {toolName:'write',params:{},runId:'run-test',toolCallId:'call-test'};
const ctx = {toolName:'write',agentId:'main',sessionId:'session-a'};
const terminal = {...event,result:{content:[]}};
function fresh() {return mkdtempSync(join(tmpdir(),'observa-independent-ledger-'));}
function open(root,deployment='deployment-a',client={}) {
  const ledger=new NativeLedger(root);
  const adapter=new NativeAdapter({config:{enabled:true,stateDir:root,deploymentId:deployment,apiUrl:'https://synthetic.invalid'},client,ledger});
  return {ledger,adapter};
}

test('same invocation produces exactly one delivery before and after restart', async()=>{
  const root=fresh();let {ledger,adapter}=open(root);
  adapter.before(event,ctx);adapter.after(terminal,ctx);
  adapter.before(event,ctx);adapter.after(terminal,ctx);
  assert.equal(ledger.pendingCount(),1);await adapter.stop();
  ({ledger,adapter}=open(root));adapter.before(event,ctx);adapter.after(terminal,ctx);
  assert.equal(ledger.pendingCount(),1);assert.equal(ledger.records().filter(x=>x.payload.kind==='DUPLICATE_NATIVE_EVENT').length,4);
  await adapter.stop();results.push({case:'duplicate_restart',status:'PASS'});
});

test('UNKNOWN persists through restart and can settle once with omitted optional session',async()=>{
  const root=fresh();let {ledger,adapter}=open(root);
  adapter.before(event,ctx);adapter.after(event,ctx);assert.equal(ledger.pendingCount(),0);await adapter.stop();
  ({ledger,adapter}=open(root));adapter.after(terminal,{toolName:'write',agentId:'main'});
  assert.equal(ledger.pendingCount(),1);
  const outcomes=ledger.records().filter(x=>x.payload.kind==='TOOL_OUTCOME').map(x=>x.payload);
  assert.deepEqual(outcomes.map(x=>x.outcome),['UNKNOWN','COMPLETED']);assert.equal(outcomes[0].correlation_ref,outcomes[1].correlation_ref);
  assert.equal(outcomes[1].correlation,'EXACT_NATIVE_IDS');await adapter.stop();results.push({case:'unknown_restart_settlement',status:'PASS'});
});

test('contradictory optional session stays unresolved and does not consume genuine attempt',async()=>{
  const root=fresh();const {ledger,adapter}=open(root);
  adapter.before(event,ctx);adapter.after(terminal,{...ctx,sessionId:'session-b'});assert.equal(ledger.pendingCount(),0);
  adapter.after(terminal,ctx);assert.equal(ledger.pendingCount(),1);
  const p=ledger.records().filter(x=>x.payload.kind==='TOOL_OUTCOME').map(x=>x.payload);
  assert.deepEqual(p.map(x=>x.correlation),['UNRESOLVED','EXACT_NATIVE_IDS']);await adapter.stop();results.push({case:'session_conflict',status:'PASS'});
});

test('changed deployment does not correlate terminal event with prior deployment attempt',async()=>{
  const root=fresh();let {ledger,adapter}=open(root);adapter.before(event,ctx);await adapter.stop();
  ({ledger,adapter}=open(root,'deployment-b'));adapter.after(terminal,ctx);assert.equal(ledger.pendingCount(),0);
  assert.equal(ledger.records().at(-1).payload.correlation,'UNRESOLVED_NO_ATTEMPT');await adapter.stop();results.push({case:'deployment_correlation',status:'PASS'});
});

test('pending evidence must not be sent using a replacement credential in another deployment',async()=>{
  const root=fresh();const tokenA='mgd1_'+ 'a'.repeat(32)+'.'+'A'.repeat(43);const tokenB='mgd1_'+'b'.repeat(32)+'.'+'B'.repeat(43);
  installCredential(root,tokenA);
  let {ledger,adapter}=open(root,'deployment-a',{observeShadow:async()=>{throw Error('synthetic outage');}});
  adapter.before(event,ctx);adapter.after(terminal,ctx);await adapter.stop();
  atomicWriteSecureFile(credentialPath(root),tokenB+'\n');
  const sent=[];
  ({ledger,adapter}=open(root,'deployment-b',{observeShadow:async(bytes,token)=>{sent.push({request:JSON.parse(bytes.toString()),credentialId:parseCredential(token).credentialId});throw Error('synthetic no-network sink');}}));
  await adapter.flush();await adapter.stop();
  results.push({case:'replacement_credential_cross_deployment',attempted:sent.length,replacementCredentialUsed:sent.some(x=>x.credentialId==='b'.repeat(32)),status:sent.length===0?'PASS':'FAIL'});
  assert.equal(sent.length,0,'old deployment evidence was dispatched using replacement deployment credential');
});

test('corrupted invocation terminal index must fail integrity verification',async()=>{
  const root=fresh();let {ledger,adapter}=open(root);adapter.before(event,ctx);adapter.after(terminal,ctx);await adapter.stop();
  const db=new DatabaseSync(join(root,'native-v1/evidence.sqlite'));db.exec('UPDATE native_invocations SET terminal_hash=NULL');db.close();
  let rejected=false;let pending;
  try {({ledger,adapter}=open(root));adapter.after(terminal,ctx);pending=ledger.pendingCount();await adapter.stop();}catch{rejected=true;}
  const health=readNativeEvidenceStatus(root).health;
  results.push({case:'corrupt_terminal_index',rejected,pending,health,status:rejected?'PASS':'FAIL'});
  assert.equal(rejected,true,'unsigned terminal index rollback was accepted and allowed duplicate delivery');
});



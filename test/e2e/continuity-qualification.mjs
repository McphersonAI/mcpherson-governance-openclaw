import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createServer } from 'node:https';
import { spawn } from 'node:child_process';
import { createDiskHostedFixture } from './hosted-fixture.mjs';

const lab = resolve(process.env.OBSERVA_LAB_ROOT);
assert.ok(lab.endsWith('/observa-qualification/openclaw-v080'));
const pack = resolve(process.env.OBSERVA_LAB_PACKAGE);
const load = file => import(pathToFileURL(join(pack, 'plugins/openclaw-connector', file)));
const [{ NativeAdapter }, { NativeLedger, readNativeEvidenceStatus }, { GovernanceApiClient }, { installCredential }, { setControl }] = await Promise.all([
  load('native-adapter.mjs'), load('native-ledger.mjs'), load('client.mjs'), load('credentials.mjs'), load('controls.mjs'),
]);
const root = mkdtempSync(join(lab, 'continuity-'));
const fixture = await createDiskHostedFixture(process.env.OBSERVA_LAB_HOSTED_SOURCE, root);
const credential = fixture.mint();
const caFile = join(lab, 'evidence/tls/loopback.crt');
let network = 'UP';
const server = createServer({ key: readFileSync(join(lab, 'evidence/tls/loopback.key')), cert: readFileSync(caFile) }, (req, res) => {
  if (network === 'DOWN') { req.socket.destroy(); return; }
  if (network === 'LOST_ACK') {
    const shadowResponse = { headersSent: false,
      writeHead() { this.headersSent = true; },
      end() { req.socket.destroy(); },
    };
    void fixture.app.handler(req, shadowResponse); return;
  }
  void fixture.app.handler(req, res);
});
await new Promise((ok, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', ok); });
const origin = `https://127.0.0.1:${server.address().port}`;
const results = [];
const newState = () => { const dir = mkdtempSync(join(root, 'installation-')); installCredential(dir, credential.token); return dir; };
const open = stateDir => {
  const config = { enabled: true, stateDir, deploymentId: 'synthetic-deployment', apiUrl: origin };
  const ledger = new NativeLedger(stateDir);
  const client = new GovernanceApiClient({ baseUrl: origin, caFile, connectTimeoutMs: 100, absoluteTimeoutMs: 400 });
  const adapter = new NativeAdapter({ config, client, ledger });
  return { ledger, adapter, client, async stop() { await adapter.stop(); await client.shutdown(); } };
};
const ctx = { toolName: 'write', agentId: 'main', sessionId: 'session-synthetic' };
const event = id => ({ toolName: 'write', params: { content: 'never-stored-sentinel' }, runId: `run-${id}`, toolCallId: `call-${id}` });
const acquire = (a, id) => { const e = event(id); a.before(e, ctx); a.after({ ...e, result: { content: [] } }, ctx); };
const rows = () => fixture.db.prepare('SELECT observation_id,request_hash,org_id,workspace_id,installation_id FROM v1_shadow_observations ORDER BY observation_id').all().map(r => ({ ...r }));
const worker = (file, action) => new Promise((ok, reject) => {
  const child = spawn(process.execPath, [new URL('./continuity-worker.mjs', import.meta.url).pathname, file, action], { env: { PATH: '/usr/bin:/bin', HOME: root }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = ''; let error = ''; child.stdout.on('data', d => { out += d; }); child.stderr.on('data', d => { error += d; });
  child.once('error', reject); child.once('close', code => code === 0 ? ok(JSON.parse(out)) : reject(Error(`synthetic continuity worker failed: ${error}`)));
});
try {
  const state = newState(); let h;
  const workerConfig = join(root, 'worker.json');
  writeFileSync(workerConfig, JSON.stringify({ packageRoot: pack, caFile, config: { enabled: true, stateDir: state, deploymentId: 'synthetic-deployment', apiUrl: origin } }), { mode: 0o600 });
  network = 'DOWN'; const captureProcess = await worker(workerConfig, 'capture');
  assert.equal(rows().length, 0); assert.equal(readNativeEvidenceStatus(state).pending, 1);
  network = 'UP'; const replayProcess = await worker(workerConfig, 'flush');
  assert.notEqual(captureProcess.pid, replayProcess.pid);
  h = open(state);
  assert.equal(h.ledger.pendingCount(), 0);
  const proof = h.ledger.records().find(r => r.payload.kind === 'HOSTED_ACCEPTANCE').payload;
  assert.equal(rows()[0].request_hash, proof.request_hash); assert.equal(rows()[0].observation_id, proof.observation_id);
  assert.equal(JSON.stringify(h.ledger.records()).includes('never-stored-sentinel'), false);
  await h.stop(); results.push({ case: 'network_outage_process_restart_authenticated_replay', status: 'PASS', capture_pid: captureProcess.pid, replay_pid: replayProcess.pid });

  const beforeRestart = rows(); fixture.restart(); assert.deepEqual(rows(), beforeRestart);
  assert.ok(rows().every(r => r.org_id === fixture.scope.org_id && r.workspace_id === fixture.scope.workspace_id && r.installation_id === fixture.scope.installation_id));
  results.push({ case: 'durable_hosted_restart_exact_hash_id_tenant_readback', status: 'PASS' });

  const lost = newState(); h = open(lost); network = 'LOST_ACK'; acquire(h.adapter, 'lost'); await h.stop();
  assert.equal(rows().length, 2); assert.equal(readNativeEvidenceStatus(lost).pending, 1);
  network = 'UP'; h = open(lost); await h.adapter.flush();
  assert.equal(rows().length, 2); assert.equal(h.ledger.pendingCount(), 1);
  assert.equal(h.ledger.records().filter(r => r.payload.kind === 'HOSTED_ACCEPTANCE').length, 0);
  await h.stop(); results.push({ case: 'lost_ack_consumed_nonce_never_fabricates_acceptance', status: 'PASS', delivery: 'UNRESOLVED_CURRENT_HOSTED_LIMIT' });

  const stopped = newState(); h = open(stopped); network = 'DOWN'; acquire(h.adapter, 'stop'); await h.stop();
  const retained = readNativeEvidenceStatus(stopped).records; setControl(stopped, 'disabled', true);
  network = 'UP'; h = open(stopped); await h.adapter.flush(); acquire(h.adapter, 'disabled');
  assert.equal(h.ledger.pendingCount(), 1); assert.equal(h.ledger.records().length, retained); await h.stop();
  setControl(stopped, 'disabled', false); h = open(stopped); await h.adapter.flush(); assert.equal(h.ledger.pendingCount(), 0); await h.stop();
  results.push({ case: 'disable_preserves_pending_proof_and_resume_delivers', status: 'PASS' });
  writeFileSync(join(root, 'results.json'), JSON.stringify({ results, hosted: 'current composed app; disk store; provenance verified; synthetic control-plane entitlement' }, null, 2));
  console.log(JSON.stringify({ status: 'PASS', root, cases: results.length }));
} finally { server.closeAllConnections(); await new Promise(ok => server.close(ok)); fixture.close(); }

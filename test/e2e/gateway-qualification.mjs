// Explicit opt-in qualification against the installed, packaged candidate.
// All effects and state are confined to the caller's disposable lab profile.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { spawn } from 'node:child_process';
import { randomUUID, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, appendFileSync, existsSync, copyFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { connectApprovalClient } from './approval-client.mjs';
import { createDiskHostedFixture } from './hosted-fixture.mjs';

const profile = resolve(process.env.OBSERVA_LAB_PROFILE ?? '');
assert.ok(profile.includes('/observa-qualification/openclaw-v080/'), 'explicit isolated lab profile required');
const host = resolve(process.env.OBSERVA_LAB_OPENCLAW ?? '');
assert.ok(host.includes('/observa-qualification/openclaw-v080/runtime/'));
const packageRoot = join(profile, 'npm/projects/mcphersonai-mcpherson-governance-openclaw-02bd18512c/node_modules/@mcphersonai/mcpherson-governance-openclaw');
const { buildBundle } = await import(pathToFileURL(join(packageRoot, 'plugins/openclaw-connector/v7/packages/enforcement-core/index.mjs')));
const state = join(profile, 'observa-state');
const runTag = String(Date.now());
const log = join(profile, `qualification-${runTag}.jsonl`);
const suffix = randomBytes(6).toString('hex').replace(/[0-9]/g, n => String.fromCharCode(103 + Number(n)));
const allowTarget = `allow-${suffix}.txt`;
const denyTarget = `denied-${suffix}.txt`;
const approvalTarget = `approve-${suffix}.txt`;
let operator;
const record = value => appendFileSync(log, JSON.stringify({ at: new Date().toISOString(), ...value }) + '\n');
for (const dir of [state, join(state, 'bound-synthetic'), join(profile, 'workspace'), join(profile, 'home')]) mkdirSync(dir, { recursive: true, mode: 0o700 });
const env = { PATH: `${dirname(process.execPath)}:/Users/bmcpherson/observa-qualification/openclaw-v080/runtime/node_modules/.bin:/usr/bin:/bin:/usr/sbin:/sbin`, HOME: join(profile, 'home'), OPENCLAW_STATE_DIR: profile, LANG: 'en_US.UTF-8', CI: '1' };
const children = new Set();
function command(args, label, timeout = 180000, entry = host) {
  const child = spawn(process.execPath, [entry, ...args], { cwd: profile, env, stdio: ['ignore', 'pipe', 'pipe'] }); children.add(child);
  let output = ''; child.stdout.on('data', d => { output += d; }); child.stderr.on('data', d => { output += d; });
  const timer = setTimeout(() => child.kill('SIGTERM'), timeout);
  return new Promise((accept, reject) => {
    child.on('error', reject);
    child.on('close', (code, signal) => { clearTimeout(timer); children.delete(child); writeFileSync(join(profile, `${runTag}-${label}.log`), output, { mode: 0o600 }); accept({ code, signal, output }); });
  });
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
let counter = 0;
const model = createServer(async (req, res) => {
  if (req.method !== 'POST' || !req.url.endsWith('/chat/completions')) { res.writeHead(404).end(); return; }
  const chunks = []; for await (const c of req) chunks.push(c);
  const body = JSON.parse(Buffer.concat(chunks));
  const last = body.messages.at(-1);
  const asText = c => typeof c === 'string' ? c : Array.isArray(c) ? c.map(x => x.text ?? '').join('') : '';
  const message = asText([...body.messages].reverse().find(x => x.role === 'user')?.content);
  const match = message.match(/SYNTHETIC:([a-z0-9_-]+\.txt)/);
  const toolName = body.tools?.some(t => t.function?.name === 'observa_bound_write') ? 'observa_bound_write' : 'tool_call';
  const invoke = last.role !== 'tool' && match;
  if (invoke && !body.tools?.some(t => t.function?.name === toolName)) { record({ kind: 'MODEL_SCHEMA_FAILURE', tools: body.tools?.map(t => t.function?.name) }); res.writeHead(400).end(); return; }
  const callId = `call_lab_${++counter}`;
  record({ kind: invoke ? 'MODEL_TOOL_REQUEST' : 'MODEL_FINAL', call_id: callId, target: invoke ? match[1] : null, exposed_tools: body.tools?.map(t => t.function?.name) });
  const base = { id: `chatcmpl-${counter}`, object: 'chat.completion.chunk', created: 1, model: body.model };
  const delta = invoke ? { role: 'assistant', tool_calls: [{ index: 0, id: callId, type: 'function', function: { name: toolName, arguments: JSON.stringify(toolName === 'tool_call' ? { id: 'observa_bound_write', args: { name: match[1], content: 'isolated-synthetic-content' } } : { name: match[1], content: 'isolated-synthetic-content' }) } }] } : { role: 'assistant', content: 'Synthetic turn complete.' };
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
  res.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta, finish_reason: null }] })}\n\n`);
  res.end(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: {}, finish_reason: invoke ? 'tool_calls' : 'stop' }], usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 } })}\n\ndata: [DONE]\n\n`);
});
await new Promise((ok, reject) => { model.once('error', reject); model.listen(0, '127.0.0.1', ok); });
let hosted; let hostedServer; let hostedOrigin = 'https://127.0.0.1:1'; let caFile;
if (process.env.OBSERVA_LAB_HOSTED_SOURCE) {
  hosted = await createDiskHostedFixture(process.env.OBSERVA_LAB_HOSTED_SOURCE, profile);
  const { installCredential, credentialPath } = await import(pathToFileURL(join(packageRoot, 'plugins/openclaw-connector/credentials.mjs')));
  const credential = hosted.mint();
  assert.equal(existsSync(credentialPath(state)), false, 'use fresh isolated state for Hosted credential');
  installCredential(state, credential.token);
  caFile = '/Users/bmcpherson/observa-qualification/openclaw-v080/evidence/tls/loopback.crt';
  hostedServer = createHttpsServer({ key: readFileSync('/Users/bmcpherson/observa-qualification/openclaw-v080/evidence/tls/loopback.key'), cert: readFileSync(caFile) }, (req, res) => hosted.app.handler(req, res));
  await new Promise((ok, reject) => { hostedServer.once('error', reject); hostedServer.listen(0, '127.0.0.1', ok); });
  hostedOrigin = `https://127.0.0.1:${hostedServer.address().port}`;
}
const port = 29482;
const modelPort = model.address().port;
const configPath = join(profile, 'openclaw.json');
copyFileSync(configPath, join(profile, `openclaw-before-qualification-${Date.now()}.json`));
const config = JSON.parse(readFileSync(configPath));
config.gateway = { mode: 'local', bind: 'loopback', port, auth: { mode: 'token', token: randomBytes(32).toString('hex') } };
config.logging = { file: join(profile, 'gateway-runtime.log'), level: 'debug', consoleLevel: 'info' };
config.agents = { defaults: { workspace: join(profile, 'workspace'), skipBootstrap: true, model: { primary: 'lab/lab-model' } } };
config.models = { mode: 'merge', providers: { lab: { baseUrl: `http://127.0.0.1:${modelPort}/v1`, apiKey: 'synthetic-loopback-only', api: 'openai-completions', models: [{ id: 'lab-model', name: 'Scripted local qualification', contextWindow: 64000, maxTokens: 4096, reasoning: false, input: ['text'], cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } }] } } };
config.tools = { toolSearch: process.env.OBSERVA_LAB_TOOL_SEARCH === '1', allow: ['observa_bound_write', 'mcpherson_connection_test'] };
config.plugins.allow = ['mcpherson-governance-connector', 'openai'];
config.plugins.entries['mcpherson-governance-connector'] = { enabled: true, hooks: { allowConversationAccess: false, allowPromptInjection: false }, config: { enabled: true, stateDir: state, apiUrl: hostedOrigin, ...(caFile ? { caFile } : {}), deploymentId: 'synthetic-deployment', agentId: 'main', boundNode: { enabled: true, mode: 'SYNTHETIC', customerAuthorization: false } } };
writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
const bundle = buildBundle({ schema: 'mcpherson-governance-enforcement-policy-bundle/v1', bundle_id: 'synthetic-policy', bundle_version: '1', engine_range: { min_inclusive: '0.7.0', max_inclusive: '0.7.0' }, default_decision: 'DENY', conflict_strategy: 'lattice', approval_ttl_seconds: 60,
  rules: [
    { rule_id: 'allow', description_label: 'synthetic-allow', priority: 10, enabled: true, match: { all: [{ field: 'resource_ref', op: 'eq', value: allowTarget }] }, effect: { decision: 'ALLOW' } },
    { rule_id: 'approve', description_label: 'synthetic-approve', priority: 10, enabled: true, match: { all: [{ field: 'resource_ref', op: 'eq', value: approvalTarget }] }, effect: { decision: 'REQUIRE_APPROVAL', required_approval_subject: 'openclaw-operator', required_approval_scope: 'exclusive-create-once' } },
  ] });
writeFileSync(join(state, 'bound-policy.json'), JSON.stringify({ schema: 'observa-openclaw-bound-policy/v1', mode: 'SYNTHETIC', tool_id: 'observa_bound_write', deployment_id: 'synthetic-deployment', agent_id: 'main', tenant_id: 'synthetic-tenant', workspace_id: 'synthetic-workspace', expires_at: new Date(Date.now() + 3600000).toISOString(), bundle }), { mode: 0o600 });
const gateway = spawn(process.execPath, [host, 'gateway', 'run', '--port', String(port)], { cwd: profile, env, stdio: ['ignore', 'pipe', 'pipe'] }); children.add(gateway);
gateway.stdout.on('data', d => appendFileSync(join(profile, 'gateway-process.log'), d)); gateway.stderr.on('data', d => appendFileSync(join(profile, 'gateway-process.log'), d));
gateway.once('close', () => children.delete(gateway));
try {
  let ready = false;
  for (let i = 0; i < 40 && !ready; i++) {
    if (gateway.exitCode !== null) throw Error('isolated gateway failed; inspect preserved log');
    await sleep(1000);
    try { const r = await fetch(`http://127.0.0.1:${port}/healthz`); ready = r.ok; } catch {}
  }
  assert.ok(ready, 'gateway readiness'); record({ kind: 'GATEWAY_READY', pid: gateway.pid });
  for (const name of [allowTarget, denyTarget]) {
    let result;
    for (let retry = 0; retry < 15; retry++) {
      result = await command(['agent', '--agent', 'main', '--session-id', randomUUID(), '--message', `SYNTHETIC:${name}`, '--json', '--timeout', '90'], `${name.replace('.txt', '')}-${retry}`);
      if (!result.output.includes('not completed startup inspection')) break;
      await sleep(2000);
    }
    record({ kind: 'AGENT_RESULT', target: name, code: result.code });
    assert.equal(result.code, 0, `agent ${name}, inspect preserved log`);
    assert.equal(existsSync(join(state, 'bound-synthetic', name)), name === allowTarget, `actual downstream effect ${name}`);
  }
  record({ kind: 'ALLOW_DENY_PASS' });
  operator = await connectApprovalClient({ port, token: config.gateway.auth.token, profile, command, record });
  await operator.rpc('chat.send', { sessionKey: `agent:main:lab-${runTag}`, message: `SYNTHETIC:${approvalTarget}`, idempotencyKey: randomUUID() });
  let pending;
  for (let i = 0; i < 20 && !pending; i++) {
    await sleep(500);
    const list = await operator.rpc('plugin.approval.list');
    pending = list.find(x => x.request?.toolName === 'observa_bound_write' || x.toolName === 'observa_bound_write');
  }
  assert.ok(pending, 'actual host approval must be visible');
  assert.equal(existsSync(join(state, 'bound-synthetic', approvalTarget)), false);
  record({ kind: 'HOST_APPROVAL_PENDING', id: pending.id });
  await assert.rejects(operator.rpc('plugin.approval.resolve', { id: pending.id, decision: 'allow-always' }));
  assert.equal(existsSync(join(state, 'bound-synthetic', approvalTarget)), false);
  await operator.rpc('plugin.approval.resolve', { id: pending.id, decision: 'allow-once' });
  for (let i = 0; i < 20 && !existsSync(join(state, 'bound-synthetic', approvalTarget)); i++) await sleep(500);
  assert.ok(existsSync(join(state, 'bound-synthetic', approvalTarget)));
  record({ kind: 'HOST_APPROVAL_PASS' });
  if (hosted) {
    // Read-only packaged diagnostics against the live host and real Hosted app.
    let doctor;
    for (let retry = 0; retry < 12; retry++) {
      doctor = await command(['doctor', '--json'], `doctor-live-${retry}`, 30000, join(packageRoot, 'observa.mjs'));
      if (doctor.code === 0) break;
      await sleep(1000);
    }
    assert.equal(doctor.code, 0, 'packaged doctor must verify live native evidence and Hosted binding');
    const report = JSON.parse(doctor.output); assert.equal(report.doctor.production_authorization, false);
    assert.equal(report.doctor.enforcement, 'SYNTHETIC_CONFIGURED_NOT_PROBED');
    record({ kind: 'PACKAGED_DOCTOR_LIVE_PASS', checks: report.doctor });
  }
  if (process.env.OBSERVA_LAB_EXTENDED === '1') {
    const policyPath = join(state, 'bound-policy.json');
    const originalPolicy = JSON.parse(readFileSync(policyPath));
    for (const kind of ['denied', 'expired', 'stale']) {
      const target = `${kind}-${suffix}.txt`;
      const updated = { ...originalPolicy, bundle: buildBundle({ ...bundle, rules: bundle.rules.map(r => r.rule_id === 'approve' ? { ...r, match: { all: [{ field: 'resource_ref', op: 'eq', value: target }] } } : r) }) };
      writeFileSync(policyPath, JSON.stringify(updated));
      await operator.rpc('chat.send', { sessionKey: `agent:main:${kind}-${suffix}`, message: `SYNTHETIC:${target}`, idempotencyKey: randomUUID() });
      let approval;
      for (let i = 0; i < 20 && !approval; i++) { await sleep(500); approval = (await operator.rpc('plugin.approval.list')).find(x => x.request?.toolName === 'observa_bound_write' || x.toolName === 'observa_bound_write'); }
      assert.ok(approval, `${kind} pending approval`);
      if (kind === 'denied') await operator.rpc('plugin.approval.resolve', { id: approval.id, decision: 'deny' });
      if (kind === 'expired') {
        record({ kind: 'WAITING_REAL_HOST_APPROVAL_EXPIRY' });
        for (let i = 0; i < 62; i++) await sleep(1000);
        await assert.rejects(operator.rpc('plugin.approval.resolve', { id: approval.id, decision: 'allow-once' }));
      }
      if (kind === 'stale') {
        writeFileSync(policyPath, JSON.stringify({ ...updated, workspace_id: 'changed-workspace' }));
        await operator.rpc('plugin.approval.resolve', { id: approval.id, decision: 'allow-once' });
      }
      await sleep(500); assert.equal(existsSync(join(state, 'bound-synthetic', target)), false);
      record({ kind: `HOST_APPROVAL_${kind.toUpperCase()}_ZERO_EFFECT_PASS` });
    }
    writeFileSync(policyPath, JSON.stringify(originalPolicy));
    const forbidden = `direct-${suffix}.txt`;
    const response = await fetch(`http://127.0.0.1:${port}/tools/invoke`, { method: 'POST', headers: { authorization: `Bearer ${config.gateway.auth.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ tool: 'observa_bound_write', args: { name: forbidden, content: 'synthetic' }, agentId: 'main', idempotencyKey: 'synthetic-denied-route' }) });
    await response.text(); assert.equal(existsSync(join(state, 'bound-synthetic', forbidden)), false);
    record({ kind: 'DIRECT_HTTP_ROUTE_ZERO_FORBIDDEN_EFFECT_PASS', http_status: response.status });
    for (const kind of ['missing', 'contradictory']) {
      const target = `${kind}-${suffix}.txt`;
      writeFileSync(policyPath, JSON.stringify({ ...originalPolicy, ...(kind === 'missing' ? { tenant_id: undefined } : { agent_id: 'wrong-agent' }) }));
      const result = await command(['agent', '--agent', 'main', '--session-id', randomUUID(), '--message', `SYNTHETIC:${target}`, '--json', '--timeout', '90'], `policy-${kind}`);
      assert.equal(result.code, 0); assert.equal(existsSync(join(state, 'bound-synthetic', target)), false);
      record({ kind: `POLICY_IDENTITY_${kind.toUpperCase()}_ZERO_EFFECT_PASS` });
    }
    writeFileSync(policyPath, JSON.stringify(originalPolicy));
    const stop = await command(['stop'], 'observa-stop', 30000, join(packageRoot, 'observa.mjs'));
    assert.equal(stop.code, 0); assert.ok(existsSync(join(state, 'native-v1/evidence.sqlite'))); assert.ok(existsSync(join(state, 'bound-synthetic', allowTarget)));
    const status = await command(['status', '--json'], 'observa-status-stopped', 30000, join(packageRoot, 'observa.mjs'));
    assert.equal(status.code, 0); assert.equal(JSON.parse(status.output).status.enabled, false);
    record({ kind: 'PACKAGED_CLI_STOP_STATUS_PRESERVE_PROOF_PASS' });
  }
  if (hosted) {
    await sleep(1000);
    const rows = hosted.db.prepare('SELECT observation_id,credential_id,org_id,workspace_id,tool_id,tool_outcome,request_hash FROM v1_shadow_observations').all();
    record({ kind: 'HOSTED_READBACK', rows });
    assert.equal(rows.filter(r => r.tool_id === 'observa_bound_write' && r.tool_outcome === 'COMPLETED').length, 2, 'exact successful bound Hosted observations');
    const { NativeLedger } = await import(pathToFileURL(join(packageRoot, 'plugins/openclaw-connector/native-ledger.mjs')));
    const ledger = new NativeLedger(state);
    const acknowledgements = ledger.records().filter(r => r.payload.kind === 'HOSTED_ACCEPTANCE').map(r => r.payload);
    for (const row of rows) assert.ok(acknowledgements.some(a => a.request_hash === row.request_hash && a.observation_id === row.observation_id), 'exact durable ACK/hash/id pair');
    ledger.verify(); ledger.close();
    assert.ok(rows.every(r => r.org_id === hosted.scope.org_id && r.workspace_id === hosted.scope.workspace_id));
    hosted.restart();
    const persisted = hosted.db.prepare('SELECT observation_id,request_hash FROM v1_shadow_observations ORDER BY observation_id').all();
    assert.deepEqual(persisted.map(r => ({ ...r })), rows.map(r => ({ observation_id: r.observation_id, request_hash: r.request_hash })).sort((a,b) => a.observation_id.localeCompare(b.observation_id)));
    record({ kind: 'HOSTED_DISK_RESTART_PASS', count: persisted.length });
  }
  console.log(JSON.stringify({ status: 'PASS', log, profile }));
} catch (error) { record({ kind: 'QUALIFICATION_FAIL', error: error.message }); throw error; }
finally {
  operator?.close();
  for (const child of children) child.kill('SIGTERM');
  model.closeAllConnections(); await new Promise(ok => model.close(ok));
  await Promise.race([new Promise(ok => gateway.once('close', ok)), sleep(10000)]);
  if (hostedServer) { hostedServer.closeAllConnections(); await new Promise(ok => hostedServer.close(ok)); hosted.close(); }
}

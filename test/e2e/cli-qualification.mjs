import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDiskHostedFixture } from './hosted-fixture.mjs';

const lab = process.env.OBSERVA_LAB_ROOT;
assert.ok(lab?.endsWith('/observa-qualification/openclaw-v080'));
const home = process.env.OBSERVA_LAB_CLI_HOME ?? join(lab, 'cli-candidate5-home'); const profile = join(home, '.openclaw');
assert.ok(home.startsWith(lab + '/'));
const packageRoot = join(profile, 'npm/projects/mcphersonai-mcpherson-governance-openclaw-02bd18512c/node_modules/@mcphersonai/mcpherson-governance-openclaw');
const entry = join(packageRoot, 'observa.mjs'); const state = join(profile, 'mcpherson-governance-connector');
const credentialFile = join(state, 'deployment-credential');
assert.equal(existsSync(credentialFile), false, 'fresh isolated profile required');
const tls = join(lab, 'evidence/tls'); const caFile = join(tls, 'loopback.crt');
const env = { HOME: home, OPENCLAW_STATE_DIR: profile, PATH: `${dirname(process.execPath)}:${join(lab, 'runtime/node_modules/.bin')}:/usr/bin:/bin:/usr/sbin:/sbin`, NODE_EXTRA_CA_CERTS: caFile, CI: '1' };
const fixture = await createDiskHostedFixture(process.env.OBSERVA_LAB_HOSTED_SOURCE, profile);
const results = []; const forbidden = new Set([fixture.verificationCode]);
const privateOutput = output => { for (const value of forbidden) assert.equal(output.includes(value), false, 'CLI must not disclose a secret'); };
const execute = (executable, args, options = {}) => new Promise((ok, reject) => {
  const child = spawn(executable, args, { env, cwd: profile, stdio: ['pipe', 'pipe', 'pipe'] });
  let output = ''; child.stdout.on('data', d => { output += d; }); child.stderr.on('data', d => { output += d; });
  const timer = setTimeout(() => child.kill('SIGTERM'), 100000);
  child.once('error', reject); child.once('close', code => { clearTimeout(timer); ok({ code, output }); });
  child.stdin.end(options.input ?? '');
});
const cli = args => execute(process.execPath, [entry, ...args]);
let mode = 'normal'; let receivedAt; let redirects = 0;
const attackToken = fixture.mint(); forbidden.add(attackToken.token);
let origin;
const server = createServer({ key: readFileSync(join(tls, 'loopback.key')), cert: readFileSync(caFile) }, async (req, res) => {
  if (req.url === '/redirect-sink') { redirects++; res.writeHead(500).end(); return; }
  if (req.url !== '/v1/pairing/redeem' || mode === 'normal') { await fixture.app.handler(req, res); return; }
  receivedAt = Date.now();
  const chunks = []; for await (const chunk of req) chunks.push(chunk);
  const body = JSON.parse(Buffer.concat(chunks)); forbidden.add(body.pairing_code);
  const payload = { paired: true, credential: attackToken.token, credential_id: attackToken.credentialId, fingerprint: attackToken.fingerprint, installation_id: fixture.scope.installation_id, deployment_id: body.deployment_id };
  if (mode === 'oversized') { res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ ...payload, pad: 'x'.repeat(20000) })); return; }
  if (mode === 'echo') { res.writeHead(400).end(JSON.stringify({ reason: body.pairing_code, detail: attackToken.token })); return; }
  if (mode === 'redirect') { res.writeHead(307, { location: `${origin}/redirect-sink` }).end(); return; }
  if (mode === 'stall') return;
  if (mode === 'deployment') payload.deployment_id = 'wrong-deployment';
  if (mode === 'credential-id') payload.credential_id = 'e'.repeat(32);
  if (mode === 'fingerprint') payload.fingerprint = 'sha256:' + 'f'.repeat(16);
  if (mode === 'truthy') payload.paired = 'true';
  res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(payload));
});
await new Promise((ok, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', ok); });
origin = `https://127.0.0.1:${server.address().port}`;
const accessRoot = join(profile, 'observa-access'); mkdirSync(accessRoot, { recursive: true, mode: 0o700 });
writeFileSync(join(accessRoot, 'binding.json'), JSON.stringify({ schema: 'observa-access-binding/v1', origin }), { mode: 0o600 });
try {
  const driver = join(dirname(fileURLToPath(import.meta.url)), 'terminal-driver.py');
  const guided = await execute('/usr/bin/python3', [driver], { input: JSON.stringify({ executable: process.execPath, argv: [process.execPath, entry, 'access'], env, inputs: [
    ['Name: ', 'Synthetic Operator'], ['Email: ', 'synthetic@example.invalid'], ['Workspace or organization (optional): ', 'Synthetic Workspace'], ['Use case (optional): ', 'Isolated qualification'], ['Type yes: ', 'yes'], ['Verification code (input hidden): ', fixture.verificationCode],
  ] }) });
  assert.equal(guided.code, 0); const terminal = JSON.parse(guided.output); privateOutput(terminal.output);
  assert.equal(terminal.code, 0, terminal.output); assert.equal(terminal.steps, 6); assert.match(terminal.output, /PENDING_REVIEW/);
  const receipt = JSON.parse(readFileSync(join(accessRoot, 'request.json'))); forbidden.add(receipt.owner_key); privateOutput(terminal.output);
  assert.equal(statSync(join(accessRoot, 'request.json')).mode & 0o777, 0o600);
  results.push({ case: 'packaged guided access without api-url, hidden verification, private receipt', status: 'PASS', prompts: terminal.steps, external_admission_and_mail: 'SYNTHETIC_FIXTURE' });
  for (const args of [['access', 'status'], ['request-access'], ['request-status'], ['status'], ['access', '--help'], ['pair', '--help'], ['doctor', '--help'], ['stop', '--help']]) {
    const result = await cli(args); assert.equal(result.code, 0, result.output); privateOutput(result.output);
    results.push({ case: args.join(' '), status: 'PASS' });
  }
  let result = await cli(['doctor', '--json']); assert.equal(result.code, 2); privateOutput(result.output);
  results.push({ case: 'doctor truthfully reports unpaired/unverified setup', status: 'PASS' });
  const code = fixture.pairingCode(); forbidden.add(code); const codeFile = join(profile, 'synthetic-pair-code'); writeFileSync(codeFile, code, { mode: 0o600 });
  const pairArgs = ['pair', '--code-file', codeFile, '--ca-file', caFile, '--deployment-id', 'synthetic-deployment'];
  const configBefore = readFileSync(join(profile, 'openclaw.json'));
  for (const attack of ['oversized', 'echo', 'deployment', 'credential-id', 'fingerprint', 'redirect', 'truthy', 'stall']) {
    mode = attack; receivedAt = undefined; result = await cli(pairArgs); privateOutput(result.output);
    assert.equal(result.code, 1, `${attack}: ${result.output}`); assert.ok(receivedAt, 'must reach actual pairing transport');
    assert.equal(existsSync(credentialFile), false); assert.deepEqual(readFileSync(join(profile, 'openclaw.json')), configBefore);
    if (attack === 'stall') assert.ok(Date.now() - receivedAt < 19000, '15 second absolute transport deadline');
    assert.equal(redirects, 0); results.push({ case: `hostile pairing response: ${attack}`, status: 'PASS', active_credential: false, config_unchanged: true });
  }
  mode = 'normal';
  const hiddenPair = await execute('/usr/bin/python3', [driver], { input: JSON.stringify({ executable: process.execPath, argv: [process.execPath, entry, 'pair', '--ca-file', caFile, '--deployment-id', 'synthetic-deployment'], env, inputs: [['Pairing code (input hidden): ', code]] }) });
  assert.equal(hiddenPair.code, 0); result = JSON.parse(hiddenPair.output); privateOutput(result.output); assert.equal(result.code, 0, result.output); assert.equal(result.steps, 1);
  const credential = readFileSync(credentialFile, 'utf8').trim(); forbidden.add(credential); privateOutput(result.output);
  assert.equal(statSync(credentialFile).mode & 0o777, 0o600);
  const paired = fixture.db.prepare('SELECT credential_id,org_id,workspace_id,installation_id,deployment_id,source_class,status FROM v1_connector_credentials WHERE credential_id=?').get(credential.slice(5,37));
  assert.equal(paired.org_id, fixture.scope.org_id); assert.equal(paired.workspace_id, fixture.scope.workspace_id); assert.equal(paired.deployment_id, 'synthetic-deployment'); assert.equal(paired.source_class, 'LIVE_CAPTURE');
  results.push({ case: 'packaged pair without api-url through actual Hosted credential issuance, health and identity', status: 'PASS', row: { ...paired } });
  for (const command of ['identify', 'hosted-health', 'status']) { result = await cli([command, '--json']); privateOutput(result.output); assert.equal(result.code, command === 'status' ? 0 : 2, result.output); if (command === 'identify') assert.match(result.output, /NO_PUBLICATION_JOURNAL/); if (command === 'hosted-health') { assert.match(result.output, /CONNECTED_HEARTBEAT_UNKNOWN/); assert.match(result.output, /"binding":"VALID"/); } results.push({ case: `paired ${command} before gateway startup`, status: 'PASS' }); }
  result = await cli(['doctor', '--json']); privateOutput(result.output); assert.equal(result.code, 2); assert.match(result.output, /NOT_VERIFIED/);
  results.push({ case: 'doctor refuses qualified-runtime claim before native gateway evidence', status: 'PASS' });
  const proofBefore = createHash('sha256').update(readFileSync(credentialFile)).digest('hex');
  result = await cli(['stop']); privateOutput(result.output); assert.equal(result.code, 0); assert.equal(createHash('sha256').update(readFileSync(credentialFile)).digest('hex'), proofBefore);
  results.push({ case: 'stop preserves paired credential and admission receipt', status: 'PASS' });
  const report = { status: 'PASS', profile, package_version: '0.8.1', results };
  const evidence = process.env.OBSERVA_LAB_EVIDENCE ?? join(lab, 'evidence/candidate5'); assert.ok(evidence.startsWith(lab + '/'));
  writeFileSync(join(evidence, 'cli-results.json'), JSON.stringify(report, null, 2)); console.log(JSON.stringify({ status: 'PASS', cases: results.length }));
} finally { server.closeAllConnections(); await new Promise(ok => server.close(ok)); fixture.close(); }

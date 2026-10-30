import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const lab = process.env.OBSERVA_LAB_ROOT;
assert.ok(lab?.endsWith('/observa-qualification/openclaw-v080'));
const profile = join(lab, 'upgrade-rollback-profile');
const host = join(lab, 'runtime/node_modules/openclaw/openclaw.mjs');
let packageRoot = join(profile, 'npm/projects/mcphersonai-mcpherson-governance-openclaw-02bd18512c/node_modules/@mcphersonai/mcpherson-governance-openclaw');
const state = join(profile, 'mcpherson-governance-connector');
for (const p of [state, join(state, 'receipts'), join(profile, 'workspace'), join(profile, 'home')]) mkdirSync(p, { recursive: true, mode: 0o700 });
const env = { HOME: join(profile, 'home'), OPENCLAW_STATE_DIR: profile, PATH: `${dirname(process.execPath)}:${join(lab, 'runtime/node_modules/.bin')}:/usr/bin:/bin:/usr/sbin:/sbin`, CI: '1' };
const token = 'mgd1_' + 'a'.repeat(32) + '.' + 'A'.repeat(43);
const protectedFiles = [join(profile, 'workspace/MEMORY.md'), join(state, 'deployment-credential'), join(state, 'receipts/historical-proof.json')];
for (const [i, p] of protectedFiles.entries()) if (!existsSync(p)) writeFileSync(p, i === 1 ? token + '\n' : `synthetic preserved qualification state ${i}\n`, { mode: 0o600, flag: 'wx' });
const sha = p => createHash('sha256').update(readFileSync(p)).digest('hex');
const original = protectedFiles.map(sha);
const configPath = join(profile, 'openclaw.json'); const config = JSON.parse(readFileSync(configPath));
config.gateway = { mode: 'local', port: 29484, bind: 'loopback', auth: { mode: 'token', token: randomBytes(32).toString('hex') } };
config.agents = { defaults: { workspace: join(profile, 'workspace'), skipBootstrap: true } };
config.plugins.allow = ['mcpherson-governance-connector'];
config.plugins.entries['mcpherson-governance-connector'] = { enabled: true, hooks: { allowConversationAccess: false, allowPromptInjection: false }, config: { enabled: false, apiUrl: 'https://127.0.0.1:1', stateDir: state, deploymentId: 'synthetic-preserved' } };
writeFileSync(configPath, JSON.stringify(config), { mode: 0o600 });
const configProtected = JSON.stringify({ agents: config.agents, entry: config.plugins.entries['mcpherson-governance-connector'] });
const results = [];
const sleep = ms => new Promise(ok => setTimeout(ok, ms));
function start(args, label) {
  const child = spawn(process.execPath, [host, ...args], { cwd: profile, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = ''; child.stdout.on('data', d => { output += d; }); child.stderr.on('data', d => { output += d; });
  const done = new Promise((ok, reject) => { child.once('error', reject); child.once('close', code => { writeFileSync(join(profile, `${label}-${Date.now()}.log`), output); ok(code); }); });
  return { child, done, get output() { return output; } };
}
async function gateway(label, version) {
  const info = start(['plugins', 'info', 'mcpherson-governance-connector', '--json'], `${label}-info`);
  assert.equal(await info.done, 0);
  packageRoot = JSON.parse(info.output).plugin.rootDir;
  assert.ok(packageRoot.startsWith(profile + '/'));
  assert.equal(JSON.parse(readFileSync(join(packageRoot, 'package.json'))).version, version);
  const p = start(['gateway', 'run', '--port', '29484'], label);
  try {
    let ready = false;
    for (let i = 0; i < 40 && !ready; i++) { await sleep(500); if (p.child.exitCode !== null) break; try { ready = (await fetch('http://127.0.0.1:29484/healthz')).ok; } catch {} }
    assert.ok(ready, `${version} real gateway loaded`); await sleep(3000);
  } finally { p.child.kill('SIGTERM'); assert.equal(await p.done, 0, 'clean gateway shutdown'); }
  assert.deepEqual(protectedFiles.map(sha), original);
  const current = JSON.parse(readFileSync(configPath));
  assert.equal(JSON.stringify({ agents: current.agents, entry: current.plugins.entries['mcpherson-governance-connector'] }), configProtected);
  results.push({ phase: label, version, preserved_files: protectedFiles.map((path, i) => ({ path, sha256: original[i] })), status: 'PASS' });
}
assert.equal(await start(['plugins', 'install', `npm-pack:${join(lab, 'preserved/original-v0.7.4.tgz')}`, '--accept-capabilities', '--force'], 'preserved-original-install').done, 0);
await gateway('original', '0.7.4');
const candidate = join(lab, 'evidence/candidate4/mcphersonai-mcpherson-governance-openclaw-0.8.0.tgz');
assert.equal(await start(['plugins', 'install', `npm-pack:${candidate}`, '--accept-capabilities', '--force'], 'upgrade-install').done, 0);
await gateway('upgraded', '0.8.0');
const { NativeLedger } = await import(pathToFileURL(join(packageRoot, 'plugins/openclaw-connector/native-ledger.mjs')));
const journal = new NativeLedger(state); journal.append({ kind: 'QUALIFICATION_CHECKPOINT', at: new Date().toISOString(), outcome: 'NOT_ACTIVITY' }); journal.close();
const proofPath = join(state, 'native-v1/evidence.sqlite'); const proofHash = sha(proofPath);
assert.equal(await start(['plugins', 'install', `npm-pack:${join(lab, 'preserved/original-v0.7.4.tgz')}`, '--accept-capabilities', '--force'], 'rollback-install').done, 0);
await gateway('rolled-back', '0.7.4'); assert.equal(sha(proofPath), proofHash);
writeFileSync(join(lab, 'evidence/candidate4/upgrade-rollback.json'), JSON.stringify({ results, native_proof_preserved_after_rollback: true, original_artifact_sha256: sha(join(lab, 'preserved/original-v0.7.4.tgz')) }, null, 2));
console.log(JSON.stringify({ status: 'PASS', phases: results.length }));

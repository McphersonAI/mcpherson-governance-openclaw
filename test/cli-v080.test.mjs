import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, delimiter, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { runObserva } from '../cli/cli.mjs';
import { makeOpenClawLayout, makeFakePlugin, makeLocalNode } from './cli-fixtures.mjs';
import { ensureObservaEntrypoint } from '../plugins/openclaw-connector/cli-entrypoint.mjs';

test('fresh one-command access guides identity, workspace and verification without an address', async () => {
  const home = mkdtempSync(join(tmpdir(), 'observa-access-v080-'));
  const prompts = []; const output = []; const requests = []; let requestId; let status = 'EMAIL_PENDING';
  const inputs = ['Synthetic Operator', 'synthetic@example.com', 'Synthetic Workspace', 'Qualification', 'yes', 'a'.repeat(32)];
  const dependencies = {
    accessPrompt: (prompt, secret) => { prompts.push({ prompt, secret }); return inputs.shift(); },
    accessOutput: line => output.push(line),
    accessFetch: async (url, options) => {
      requests.push({ url, options }); assert.equal(options.redirect, 'error');
      const data = JSON.parse(options.body); requestId ??= data.data?.request_id;
      if (url.endsWith('/verify')) status = 'PENDING_REVIEW';
      return new Response(JSON.stringify({ request_id: requestId, status }), { status: 200 });
    },
  };
  const result = await runObserva(['access'], { home, env: {}, dependencies });
  assert.equal(result.code, 0, result.stderr); assert.match(result.stdout, /PENDING_REVIEW/);
  assert.equal(prompts.length, 6); assert.equal(prompts.at(-1).secret, true);
  assert.ok(prompts.some(p => p.prompt.includes('Workspace')));
  assert.ok(requests.every(r => new URL(r.url).origin === 'https://governance-plane-observa.tailb473db.ts.net'));
  assert.equal(output.join('').includes('synthetic@example.com'), false);
  assert.equal(output.join('').includes('a'.repeat(32)), false);
  const saved = JSON.parse(readFileSync(join(home, '.openclaw/observa-access/request.json')));
  assert.equal(result.stdout.includes(saved.owner_key), false);
  const checked = await runObserva(['access', 'status'], { home, env: {}, dependencies });
  assert.equal(checked.code, 0); assert.match(checked.stdout, /PENDING_REVIEW/);
  const alias = await runObserva(['request-status'], { home, env: {}, dependencies });
  assert.equal(alias.stdout, checked.stdout);
});

test('origin change cannot send saved request credentials to another server', async () => {
  const home = mkdtempSync(join(tmpdir(), 'observa-origin-v080-'));
  const root = join(home, '.openclaw/observa-access'); mkdirSync(root, { recursive: true, mode: 0o700 });
  writeFileSync(join(root, 'request.json'), JSON.stringify({ endpoint: 'https://trusted.example', request_id: 'req_' + 'a'.repeat(32), owner_key: 'b'.repeat(64) }), { mode: 0o600 });
  let calls = 0;
  const result = await runObserva(['access', 'status', '--api-url', 'https://other.example'], { home, env: {}, dependencies: { accessFetch() { calls++; } } });
  assert.equal(result.code, 1); assert.match(result.stderr, /ACCESS_RECEIPT_INVALID/); assert.equal(calls, 0);
});

test('namespaced OpenClaw launcher works alongside untouched Local Node command', () => {
  const layout = makeOpenClawLayout(); const plugin = makeFakePlugin('0.8.0');
  makeLocalNode(layout.prefix, layout.bin);
  const before = readFileSync(join(layout.bin, 'observa'));
  const options = { packageRoot: plugin, argv1: layout.launcher, env: { PATH: layout.bin } };
  assert.equal(ensureObservaEntrypoint(options).state, 'COLLISION_LOCAL_NODE');
  assert.equal(ensureObservaEntrypoint({ ...options, entrypointName: 'observa-openclaw' }).state, 'INSTALLED');
  assert.deepEqual(readFileSync(join(layout.bin, 'observa')), before);
  const result = spawnSync(join(layout.bin, 'observa-openclaw'), ['access', '--help'], { encoding: 'utf8', env: { PATH: `${dirname(process.execPath)}${delimiter}/usr/bin:/bin` } });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { version: '0.8.0', argv: ['access', '--help'] });
});

test('new command help is available and invalid access subcommands are refused', async () => {
  for (const name of ['access', 'doctor', 'stop']) assert.equal((await runObserva([name, '--help'])).code, 0);
  assert.equal((await runObserva(['access', 'delete'])).code, 1);
});

import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
const [file, action] = process.argv.slice(2);
assert.ok(file.includes('/observa-qualification/openclaw-v080/'));
const { packageRoot, config, caFile } = JSON.parse(readFileSync(file));
const load = name => import(pathToFileURL(join(packageRoot, 'plugins/openclaw-connector', name)));
const [{ NativeAdapter }, { GovernanceApiClient }] = await Promise.all([load('native-adapter.mjs'), load('client.mjs')]);
const client = new GovernanceApiClient({ baseUrl: config.apiUrl, caFile, connectTimeoutMs: 100, absoluteTimeoutMs: 400 });
const adapter = new NativeAdapter({ config, client });
if (action === 'capture') {
  const event = { toolName: 'write', params: {}, runId: 'run-worker', toolCallId: 'call-worker' };
  const ctx = { toolName: 'write', agentId: 'main' };
  adapter.before(event, ctx); adapter.after({ ...event, result: { content: [] } }, ctx);
} else { assert.equal(action, 'flush'); await adapter.flush(); }
await adapter.stop(); await client.shutdown();
console.log(JSON.stringify({ pid: process.pid, action, status: adapter.status() }));

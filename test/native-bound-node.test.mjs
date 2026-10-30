import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NativeLedger } from '../plugins/openclaw-connector/native-ledger.mjs';
import { nativeToolOutcome } from '../plugins/openclaw-connector/native-outcome.mjs';
import { registerBoundWrite, BOUND_WRITE_TOOL } from '../plugins/openclaw-connector/bound-write.mjs';
import { buildBundle } from '../plugins/openclaw-connector/v7/packages/enforcement-core/index.mjs';

function lab() {
  const root = mkdtempSync(join(tmpdir(), 'observa-v080-bound-'));
  mkdirSync(join(root, 'bound-synthetic'), { mode: 0o700 });
  const bundle = buildBundle({ schema: 'mcpherson-governance-enforcement-policy-bundle/v1', bundle_id: 'synthetic-policy', bundle_version: '1',
    engine_range: { min_inclusive: '0.7.0', max_inclusive: '0.7.0' }, default_decision: 'DENY', conflict_strategy: 'lattice', approval_ttl_seconds: 60,
    rules: [
      { rule_id: 'allow', description_label: 'synthetic-allow', priority: 10, enabled: true, match: { all: [{ field: 'resource_ref', op: 'eq', value: 'allow.txt' }] }, effect: { decision: 'ALLOW' } },
      { rule_id: 'approve', description_label: 'synthetic-approval', priority: 10, enabled: true, match: { all: [{ field: 'resource_ref', op: 'eq', value: 'approve.txt' }] },
        effect: { decision: 'REQUIRE_APPROVAL', required_approval_subject: 'openclaw-operator', required_approval_scope: 'exclusive-create-once' } },
    ] });
  const binding = { schema: 'observa-openclaw-bound-policy/v1', mode: 'SYNTHETIC', tool_id: BOUND_WRITE_TOOL, deployment_id: 'deployment-test',
    agent_id: 'main', tenant_id: 'tenant-test', workspace_id: 'workspace-test', expires_at: new Date(Date.now() + 3600000).toISOString(), bundle };
  const policyPath = join(root, 'bound-policy.json');
  writeFileSync(policyPath, JSON.stringify(binding), { mode: 0o600 });
  const ledger = new NativeLedger(root);
  let before; let tool; let clock = Date.now();
  const api = { pluginConfig: { boundNode: { enabled: true, mode: 'SYNTHETIC', customerAuthorization: false } },
    on(name, fn) { assert.equal(name, 'before_tool_call'); before = fn; }, registerTool(value) { tool = value; } };
  const config = { stateDir: root, deploymentId: 'deployment-test' };
  const handle = registerBoundWrite(api, { config, ledger, now: () => clock });
  const event = (name, call = name) => ({ toolName: BOUND_WRITE_TOOL, params: { name, content: 'synthetic-content-private-sentinel' }, runId: 'run-test', toolCallId: call });
  const ctx = { toolName: BOUND_WRITE_TOOL, agentId: 'main', sessionId: 'session-test' };
  return { root, ledger, before, tool, event, ctx, binding, policyPath, api, config, handle, advance(ms) { clock += ms; } };
}

test('missing and asynchronous native results remain UNKNOWN', () => {
  for (const event of [{}, { error: undefined }, { error: null, result: null }, { result: { details: { status: 'running' } } }, { result: {} }, { result: { status: 'unrecognized' } }, { result: { status: 'cancelled' } }]) assert.equal(nativeToolOutcome(event), 'UNKNOWN');
  assert.equal(nativeToolOutcome({ result: { isError: true } }), 'FAILED');
  assert.equal(nativeToolOutcome({ error: 'TIMEOUT' }), 'TIMED_OUT');
  assert.equal(nativeToolOutcome({ toolName: 'exec', result: { content: [], details: { status: 'completed', exitCode: 1 } } }), 'FAILED');
  assert.equal(nativeToolOutcome({ toolName: 'exec', result: { content: [], details: { status: 'completed', exitCode: 0 } } }), 'COMPLETED');
  assert.equal(nativeToolOutcome({ result: { content: [] } }), 'COMPLETED');
});

test('V7 ALLOW permits exact synthetic write and DENY has zero downstream effect', () => {
  const l = lab();
  try {
    const allowed = l.event('allow.txt');
    assert.equal(l.before(allowed, l.ctx), undefined);
    l.tool.execute(allowed.toolCallId, allowed.params);
    assert.equal(readFileSync(join(l.root, 'bound-synthetic/allow.txt'), 'utf8'), allowed.params.content);
    const denied = l.event('denied.txt');
    assert.equal(l.before(denied, l.ctx).block, true);
    assert.throws(() => l.tool.execute(denied.toolCallId, denied.params));
    assert.equal(existsSync(join(l.root, 'bound-synthetic/denied.txt')), false);
    assert.equal(JSON.stringify(l.ledger.records()).includes('synthetic-content-private-sentinel'), false);
    assert.ok(l.ledger.verify().records >= 4);
  } finally { l.ledger.close(); }
});

test('host allow-once callback is re-evaluated by V7 and bound to exact operation', () => {
  const l = lab();
  try {
    const request = l.event('approve.txt');
    const result = l.before(request, l.ctx);
    assert.deepEqual(result.requireApproval.allowedDecisions, ['allow-once', 'deny']);
    result.requireApproval.onResolution('allow-once');
    l.tool.execute(request.toolCallId, request.params);
    assert.ok(existsSync(join(l.root, 'bound-synthetic/approve.txt')));
    assert.throws(() => l.tool.execute(request.toolCallId, request.params));
    const decisions = l.ledger.records().filter(r => r.payload.kind === 'BOUND_POLICY_DECISION').map(r => r.payload.evaluator_record);
    assert.ok(decisions.some(r => r.abstract_decision === 'REQUIRE_APPROVAL' && !r.decision_permit));
    assert.ok(decisions.some(r => r.decision_permit && r.reason_code === 'approval_satisfied'));
  } finally { l.ledger.close(); }
});

test('later-hook rewrite, expiry, identity mismatch, direct executor bypass and stale policy are refused', () => {
  for (const mode of ['rewrite', 'expiry', 'identity', 'direct', 'policy']) {
    const l = lab();
    try {
      const req = l.event('allow.txt');
      if (mode !== 'direct') {
        const response = l.before(req, mode === 'identity' ? { ...l.ctx, agentId: 'other' } : l.ctx);
        if (mode === 'identity') assert.equal(response.block, true);
      }
      if (mode === 'rewrite') req.params.content = 'forbidden-changed-content';
      if (mode === 'expiry') l.advance(60001);
      if (mode === 'policy') writeFileSync(l.policyPath, JSON.stringify({ ...l.binding, workspace_id: 'other' }));
      assert.throws(() => l.tool.execute(req.toolCallId, req.params), mode);
      assert.equal(existsSync(join(l.root, 'bound-synthetic/allow.txt')), false, mode);
    } finally { l.ledger.close(); }
  }
});

test('restart preserves signed proof and rejects replay of consumed operation', () => {
  const l = lab(); const req = l.event('allow.txt');
  l.before(req, l.ctx); l.tool.execute(req.toolCallId, req.params); l.handle.stop();
  const head = l.ledger.verify(); l.ledger.close();
  const reopened = new NativeLedger(l.root);
  try {
    assert.deepEqual(reopened.verify(), head);
    let handler;
    registerBoundWrite({ ...l.api, on(_, fn) { handler = fn; } }, { config: l.config, ledger: reopened });
    assert.equal(handler(req, l.ctx).block, true);
  } finally { reopened.close(); }
});

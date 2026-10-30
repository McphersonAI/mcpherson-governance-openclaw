import { randomUUID } from 'node:crypto';
import { join, resolve } from 'node:path';
import { readJson, assertPath } from '../../cli/safe-local.mjs';
import { writeExclusiveSecureFile } from './secure-files.mjs';
import { normalizeOpenClawToolHook } from './hook-adapter.mjs';
import { digest } from './native-ledger.mjs';
import { inspectNetworkControls } from './controls.mjs';
import { buildEnvelope, buildEvaluationContext, buildApprovalVerification, evaluate, ENFORCEMENT_ENGINE_VERSION } from './v7/packages/enforcement-core/index.mjs';

export const BOUND_WRITE_TOOL = 'observa_bound_write';
const refuse = () => { throw new Error('OBSERVA_BOUND_OPERATION_REFUSED'); };
const block = () => ({ block: true, blockReason: 'Observa could not authorize this exact operation.' });
const PARAMETERS = Object.freeze({ type: 'object', additionalProperties: false, required: ['name', 'content'],
  properties: { name: { type: 'string', pattern: '^[a-z0-9][a-z0-9_-]{0,47}\\.txt$' }, content: { type: 'string', maxLength: 1024 } } });

// One explicitly scoped, exclusive-create tool. The policy evaluator remains
// immutable SIMULATION code; this adapter separately records its host binding.
// No generic exec/write/MCP enforcement claim follows from this registration.
export function registerBoundWrite(api, { config, ledger, now = Date.now }) {
  const setting = api.pluginConfig?.boundNode;
  if (!setting || setting.enabled !== true) return null;
  // This release permits isolated synthetic qualification only. Production
  // activation requires Control Gate C and a separately authorized release.
  if (setting.mode !== 'SYNTHETIC' || setting.customerAuthorization !== false) refuse();
  const root = resolve(config.stateDir, 'bound-synthetic');
  const policyPath = join(config.stateDir, 'bound-policy.json');
  let stopped = false;
  const pending = new Map();
  const policy = () => {
    const b = readJson(config.stateDir, policyPath, { maxBytes: 128 * 1024 });
    if (!b || b.schema !== 'observa-openclaw-bound-policy/v1' || b.deployment_id !== config.deploymentId
        || b.mode !== 'SYNTHETIC' || b.tool_id !== BOUND_WRITE_TOOL || typeof b.agent_id !== 'string'
        || !b.agent_id || !b.tenant_id || !b.workspace_id || !b.bundle
        || !Number.isFinite(Date.parse(b.expires_at)) || now() >= Date.parse(b.expires_at)) refuse();
    return b;
  };
  const validParams = p => p && Object.keys(p).sort().join(',') === 'content,name'
    && /^[a-z0-9][a-z0-9_-]{0,47}\.txt$/.test(p.name) && typeof p.content === 'string' && Buffer.byteLength(p.content) <= 1024;
  const decision = (entry, approvals = [], verifications = []) => {
    const current = policy();
    if (digest(current) !== entry.policyHash || stopped || entry.abortSignal?.aborted || inspectNetworkControls(config.stateDir).blocked) refuse();
    const context = buildEvaluationContext({ evaluated_at: new Date(now()).toISOString(), engine_version: ENFORCEMENT_ENGINE_VERSION,
      approval_verifications: verifications, consumed_approval_ids: [] });
    const record = evaluate(entry.envelope, current.bundle, approvals, context);
    ledger.append({ kind: 'BOUND_POLICY_DECISION', at: context.evaluated_at, operation_ref: entry.operation,
      correlation_ref: entry.correlation, evaluator_record: record, binding_mode: 'SYNTHETIC', business_outcome: 'UNRESOLVED' });
    entry.record = record;
    return record;
  };
  const refusal = (event, ctx, reason) => {
    try {
      const n = normalizeOpenClawToolHook(event, ctx, 'before_tool_call');
      ledger.append({ kind: 'BOUND_REFUSAL', at: new Date(now()).toISOString(), reason,
        correlation_ref: n.accepted && n.agentId && n.runId && n.toolCallId ? digest([config.deploymentId, n.agentId, n.runId, n.toolCallId, BOUND_WRITE_TOOL]) : null,
        execution_disposition: 'BLOCKED', policy_decision: 'UNRESOLVED', business_outcome: 'UNRESOLVED' });
    } catch { /* evidence unavailability is itself a non-permit */ }
    return block();
  };
  const before = (event, ctx) => {
    if (event?.toolName !== BOUND_WRITE_TOOL) return;
    try {
      const n = normalizeOpenClawToolHook(event, ctx, 'before_tool_call');
      if (stopped || ctx?.abortSignal?.aborted || inspectNetworkControls(config.stateDir).blocked || !n.accepted || !n.agentId || !n.runId || !n.toolCallId || !validParams(n.params)) return refusal(event, ctx, 'INVALID_NATIVE_IDENTITY_OR_REQUEST');
      for (const [key, value] of pending) if (now() >= value.deadline) {
        ledger.append({ kind: 'BOUND_APPROVAL_EXPIRED', at: new Date(now()).toISOString(), correlation_ref: value.correlation, operation_ref: value.operation });
        pending.delete(key);
      }
      if (pending.size >= 128) return refusal(event, ctx, 'CAPACITY_UNAVAILABLE');
      const b = policy();
      if (n.agentId !== b.agent_id || pending.has(n.toolCallId)) return refusal(event, ctx, 'IDENTITY_OR_RETRY_REFUSED');
      const correlation = digest([b.deployment_id, n.agentId, n.runId, n.toolCallId, BOUND_WRITE_TOOL]);
      // Retained evidence makes a previously authorized invocation single-use
      // across process restart, including uncertain crash-after-effect cases.
      if (ledger.hasClaim(correlation)) return refusal(event, ctx, 'CONSUMED_INVOCATION');
      const operation = digest({ tool: BOUND_WRITE_TOOL, params: n.params, correlation });
      const envelope = buildEnvelope({ schema: 'mcpherson-governance-enforcement-envelope/v1', envelope_version: '1',
        evaluation_mode: 'SIMULATION', envelope_id: randomUUID(), actor_type: 'AGENT', actor_id: n.agentId,
        agent_id: n.agentId, tool_id: BOUND_WRITE_TOOL, operation: 'exclusive_create', action_class: 'file_modification',
        resource_class: 'synthetic_file', resource_ref: n.params.name, resource_scope: 'INTERNAL',
        argument_digest: digest(n.params), tenant_id: b.tenant_id, workspace_id: b.workspace_id,
        policy_bundle_id: b.bundle.bundle_id, policy_bundle_version: b.bundle.bundle_version, policy_bundle_hash: b.bundle.bundle_hash,
        correlation_ref: correlation, observed_at: new Date(now()).toISOString(), approval_state: 'NOT_REQUIRED' });
      const entry = { envelope, policyHash: digest(b), operation, correlation, paramsHash: digest(n.params), deadline: now() + 60000, permit: false, abortSignal: ctx?.abortSignal };
      const record = decision(entry);
      if (record.abstract_decision === 'ALLOW' && record.decision_permit === true) {
        entry.permit = true; pending.set(n.toolCallId, entry); return;
      }
      if (record.abstract_decision !== 'REQUIRE_APPROVAL') return refusal(event, ctx, 'EVALUATOR_NON_PERMIT');
      pending.set(n.toolCallId, entry);
      return { requireApproval: { title: 'Observa synthetic file creation',
        description: `Authorize one exact synthetic operation (${operation}). No business outcome is implied.`,
        allowedDecisions: ['allow-once', 'deny'], timeoutMs: 60000,
        onResolution(resolution) {
          try {
            ledger.append({ kind: 'HOST_APPROVAL_RESOLUTION', at: new Date(now()).toISOString(), operation_ref: operation,
              correlation_ref: correlation, resolution: ['allow-once', 'allow-always', 'deny', 'timeout', 'cancelled'].includes(resolution) ? resolution : 'UNKNOWN' });
            if (resolution !== 'allow-once' || stopped || now() >= entry.deadline || pending.get(n.toolCallId) !== entry) { pending.delete(n.toolCallId); return; }
            const approved = { approval_id: randomUUID(), issuer_id: 'openclaw-host-approval', tenant_id: b.tenant_id,
              workspace_id: b.workspace_id, bound_envelope_hash: digest(envelope), bound_bundle_id: b.bundle.bundle_id,
              bound_bundle_version: b.bundle.bundle_version, bound_bundle_hash: b.bundle.bundle_hash,
              approval_subject: 'openclaw-operator', approval_scope: 'exclusive-create-once', approval_state: 'APPROVED',
              issued_at: new Date(now()).toISOString(), expires_at: new Date(entry.deadline).toISOString() };
            const artifact = { schema: 'mcpherson-governance-enforcement-approval/v1', approval_version: '1', ...approved, authentication: 'NONE', signed: false };
            // Only this host-owned callback supplies the trust result. No tool
            // parameter, file, environment value or remote response can mint it.
            entry.approval = artifact; entry.verification = buildApprovalVerification(approved);
            entry.permit = decision(entry, [artifact], [entry.verification]).decision_permit === true;
          } catch { entry.permit = false; pending.delete(n.toolCallId); }
        } } };
    } catch { return refusal(event, ctx, 'POLICY_OR_EVIDENCE_UNAVAILABLE'); }
  };
  api.on('before_tool_call', before, { matcher: [BOUND_WRITE_TOOL], priority: 1000 });
  api.registerTool({ name: BOUND_WRITE_TOOL, label: 'Observa bound synthetic write', description: 'Create one synthetic qualification file under the isolated Observa test directory.', parameters: PARAMETERS,
    execute(toolCallId, params, signal) {
      const entry = pending.get(toolCallId); pending.delete(toolCallId);
      if (stopped || signal?.aborted || !entry?.permit || now() >= entry.deadline || !validParams(params) || digest(params) !== entry.paramsHash) refuse();
      const record = decision(entry, entry.approval ? [entry.approval] : [], entry.verification ? [entry.verification] : []);
      if (record.decision_permit !== true) refuse();
      ledger.append({ kind: 'BOUND_EXECUTION_CLAIM', at: new Date(now()).toISOString(), correlation_ref: entry.correlation,
        operation_ref: entry.operation, decision_id: record.decision_id, outcome: 'UNKNOWN', business_outcome: 'UNRESOLVED' }, null, entry.correlation);
      assertPath(config.stateDir, root);
      const target = join(root, params.name); assertPath(config.stateDir, target);
      writeExclusiveSecureFile(target, params.content);
      ledger.append({ kind: 'BOUND_EXECUTION_RETURN', at: new Date(now()).toISOString(), correlation_ref: entry.correlation,
        operation_ref: entry.operation, decision_id: record.decision_id, outcome: 'COMPLETED', business_outcome: 'UNRESOLVED' });
      return { content: [{ type: 'text', text: 'Synthetic file created.' }] };
    } }, { name: BOUND_WRITE_TOOL });
  return { stop() { stopped = true; pending.clear(); }, status: () => ({ enabled: !stopped && !inspectNetworkControls(config.stateDir).blocked, mode: 'SYNTHETIC', production_authorization: false, tools: [BOUND_WRITE_TOOL] }) };
}

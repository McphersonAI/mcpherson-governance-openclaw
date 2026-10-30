import { normalizeOpenClawToolHook, canonicalObservationToolId } from './hook-adapter.mjs';
import { NativeLedger, digest } from './native-ledger.mjs';
import { buildLinkedShadowObservationRequest, serializeShadowObservationRequest } from './runtime-observation-contract.mjs';
import { inspectObservationControls } from './controls.mjs';
import { withCredential, credentialPath, parseCredential } from './credentials.mjs';
import { readSecureFile } from './secure-files.mjs';

export const NATIVE_ADAPTER_VERSION = 'openclaw-2026.10.9/v1';
// Common supported Hosted observation contract stays authoritative. Additional
// native identity, unknown outcomes and acquisition proofs remain in a separate
// signed journal because Hosted's existing OpenClaw route cannot carry them.
export class NativeAdapter {
  #config; #client; #ledger; #busy = false; #timer; #stopped = false; #failure = null; #lastPending = 0; #runtimeId; #hostVersion;
  constructor({ config, client, ledger = null, runtimeInstanceId = null, hostVersion = null }) {
    this.#config = config; this.#client = client;
    this.#ledger = ledger ?? new NativeLedger(config.stateDir);
    this.#runtimeId = runtimeInstanceId ?? this.#ledger.runtimeId;
    this.#hostVersion = hostVersion === '2026.10.9' ? hostVersion : null;

  }
  #enabled() { return !this.#stopped && !inspectObservationControls(this.#config).blocked; }
  #binding(token) {
    return { origin: this.#config.apiUrl, deployment_id: this.#config.deploymentId,
      credential_id: parseCredential(token).credentialId, credential_ref: digest(String(token).trim()) };
  }
  #captureBinding() {
    let bytes;
    try { bytes = readSecureFile(credentialPath(this.#config.stateDir), 512); return this.#binding(bytes.toString('utf8')); }
    catch { return null; }
    finally { bytes?.fill(0); }
  }
  #capture(event, ctx, phase, linkage = null) {
    if (!this.#enabled()) return null;
    const n = normalizeOpenClawToolHook(event, ctx, phase);
    if (!n.accepted) {
      this.#ledger.append({ kind: 'ACQUISITION_REFUSED', reason: n.reason, at: new Date().toISOString(), adapter: NATIVE_ADAPTER_VERSION });
      return null;
    }
    const identity = {
      deployment_id: this.#config.deploymentId, agent_id: n.agentId,
      session_ref: n.sessionId ? digest(n.sessionId) : null,
      session_key_ref: n.sessionKey ? digest(n.sessionKey) : null,
      run_ref: n.runId ? digest(n.runId) : null, tool_call_ref: n.toolCallId ? digest(n.toolCallId) : null, tool_id: n.toolName,
      runtime_tool_kind: n.runtimeToolKind,
      host_tool_kind: n.hostToolKind, harness_origin: 'UNRESOLVED',
    };
    const exact = Boolean(n.agentId && n.runId && n.toolCallId);
    const correlation = exact ? digest([identity.deployment_id, n.agentId, n.runId, n.toolCallId, n.toolName]) : null;
    const invocation = correlation ? this.#ledger.invocation(correlation) : null;
    const prior = invocation?.identity ?? null;
    let correlated = exact;
    if (phase === 'after_tool_call' && prior) {
      for (const field of ['session_ref', 'session_key_ref']) {
        if (identity[field] && prior[field] && identity[field] !== prior[field]) correlated = false;
        identity[field] ??= prior[field];
      }
      if (identity.runtime_tool_kind !== prior.runtime_tool_kind) correlated = false;
      if ((identity.host_tool_kind ?? null) !== (prior.host_tool_kind ?? null)) correlated = false;
    }
    if (invocation?.terminal || (phase === 'before_tool_call' && prior)) {
      this.#ledger.append({ kind: 'DUPLICATE_NATIVE_EVENT', at: new Date().toISOString(), correlation_ref: correlation,
        phase, outcome: n.outcome, delivery: 'NO_SECOND_DELIVERY' });
      return null;
    }
    const payload = { kind: phase === 'before_tool_call' ? 'TOOL_ATTEMPT' : 'TOOL_OUTCOME',
      adapter: NATIVE_ADAPTER_VERSION, runtime_version: this.#hostVersion, at: new Date().toISOString(), identity,
      correlation_ref: correlation,
      outcome: n.outcome, correlation: !correlated ? 'UNRESOLVED' : phase === 'after_tool_call' && !prior ? 'UNRESOLVED_NO_ATTEMPT' : 'EXACT_NATIVE_IDS',
      business_outcome: 'UNRESOLVED', delivery: 'LOCAL_ONLY',
      delivery_binding: phase === 'before_tool_call' ? this.#captureBinding() : invocation?.binding ?? null };
    let delivery = null;
    if (phase === 'after_tool_call' && correlated && prior && n.outcome !== 'UNKNOWN') {
      try {
      delivery = buildLinkedShadowObservationRequest({ agentId: n.agentId, toolId: canonicalObservationToolId(n.toolName),
        runtimeToolKind: n.runtimeToolKind, runtimeInstanceId: this.#runtimeId,
        runId: n.runId, toolCallId: n.toolCallId, decisionId: linkage?.runtimeInstanceId === this.#runtimeId && linkage.runId === n.runId && linkage.toolCallId === n.toolCallId && linkage.agentId === n.agentId && linkage.toolId === canonicalObservationToolId(n.toolName) ? linkage.decisionId : null, decisionRequestHash: linkage?.runtimeInstanceId === this.#runtimeId && linkage.runId === n.runId && linkage.toolCallId === n.toolCallId && linkage.agentId === n.agentId && linkage.toolId === canonicalObservationToolId(n.toolName) ? linkage.decisionRequestHash : null, toolOutcome: n.outcome });
      payload.delivery = 'PENDING_AUTHENTICATED_ACCEPTANCE';
      } catch { delivery = null; payload.delivery = 'UNRESOLVED_CONTRACT'; }
    }
    const transition = correlation && phase === 'before_tool_call' ? { phase: 'attempt', correlation }
      : delivery ? { phase: 'terminal', correlation } : null;
    const evidence = this.#ledger.append(payload, delivery, null, null, transition);
    if (delivery) void this.flush();
    return { evidence, normalized: n, identity };
  }
  before(event, ctx) { return this.#capture(event, ctx, 'before_tool_call'); }
  after(event, ctx, linkage = null) { return this.#capture(event, ctx, 'after_tool_call', linkage); }
  lifecycle(kind, event, ctx) {
    if (!this.#enabled() || !['session_start', 'session_end', 'model_call_started', 'model_call_ended'].includes(kind)) return;
    const safe = v => typeof v === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(v) ? v : null;
    const ref = v => typeof v === 'string' && v.length <= 512 ? digest(v) : null;
    this.#ledger.append({ kind: kind.toUpperCase(), adapter: NATIVE_ADAPTER_VERSION, runtime_version: this.#hostVersion, at: new Date().toISOString(),
      deployment_id: this.#config.deploymentId, agent_id: safe(ctx?.agentId),
      run_ref: ref(event?.runId ?? ctx?.runId), model_call_ref: ref(event?.callId), session_ref: ref(event?.sessionId ?? ctx?.sessionId),
      session_key_ref: ref(event?.sessionKey ?? ctx?.sessionKey),
      outcome: kind === 'model_call_ended' && ['completed', 'error'].includes(event?.outcome) ? event.outcome.toUpperCase() : 'UNKNOWN',
      business_outcome: 'UNRESOLVED' });
  }
  start() {
    if (this.#timer || this.#stopped) return;
    this.#timer = setInterval(() => void this.flush(), 5000); this.#timer.unref();
    void this.flush();
  }
  async flush() {
    if (this.#busy || !this.#enabled()) return;
    this.#busy = true;
    try {
      for (const job of this.#ledger.pending()) {
        if (!this.#enabled()) break;
        const request = JSON.parse(job.body);
        const bytes = serializeShadowObservationRequest(request);
        try {
          this.#ledger.attempted(job.hash);
          const ack = await withCredential(this.#config.stateDir, credential => {
            const captured = JSON.parse(job.evidence).payload.delivery_binding;
            if (!captured || digest(captured) !== digest(this.#binding(credential))) throw new Error('DELIVERY_BINDING_MISMATCH');
            return this.#client.observeShadow(bytes, credential, {
            expectedRequestHash: request.request_hash,
            beforeAttempt: () => { if (!this.#enabled()) throw new Error('NOT_ATTEMPTED'); },
          }); });
          this.#ledger.acknowledge(job.hash, ack);
          this.#failure = null;
        } catch { this.#failure = 'DELIVERY_UNRESOLVED'; }
        finally { bytes.fill(0); }
      }
    } catch { this.#failure = 'EVIDENCE_UNAVAILABLE'; }
    finally { this.#busy = false; }
  }
  status() { return { adapter: NATIVE_ADAPTER_VERSION, delivery: this.#failure ?? 'PENDING_OR_ACCEPTED', pending: this.#stopped ? this.#lastPending : this.#ledger.pendingCount(), native_v3: 'UNSUPPORTED_HOSTED_CONTRACT' }; }
  async stop() {
    this.#stopped = true; clearInterval(this.#timer);
    // Client shutdown is owned by the connector; retain the DB until any
    // in-flight authenticated delivery settles, with no evidence deletion.
    while (this.#busy) await new Promise(resolve => setTimeout(resolve, 10));
    this.#lastPending = this.#ledger.pendingCount();
    this.#ledger.close();
  }
}

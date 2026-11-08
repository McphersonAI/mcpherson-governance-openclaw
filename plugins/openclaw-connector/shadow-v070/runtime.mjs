import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { withCredential } from "../credentials.mjs";
import { inspectHostedOutboundControls, inspectObservationControls } from "../controls.mjs";
import {
  MIN_SHADOW_OPENCLAW_VERSION,
  SHADOW_CORRELATION_WINDOW,
  SHADOW_DECISION_TIMEOUT_MS,
  SHADOW_DECISION_WINDOW,
  SHADOW_EVIDENCE_FILE,
  SHADOW_RELEASE,
} from "./constants.mjs";
import { createShadowEvidenceWriter } from "./evidence.mjs";
import { createArgumentDigester } from "./argument-digest.mjs";
import { correlationIdentity, normalizeShadowRequest } from "./normalize.mjs";
import { ShadowDecisionWindow, validateShadowResponse } from "./response.mjs";
import { createShadowTransport } from "./transport.mjs";

const EXECUTION_EVENTS = new Set([
  "tool.execution.started",
  "tool.execution.completed",
  "tool.execution.error",
  "tool.execution.blocked",
]);

function versionParts(value) {
  const match = /^(\d+)\.(\d+)\.(\d+)/u.exec(String(value ?? ""));
  return match ? match.slice(1).map(Number) : null;
}

export function supportsNativeShadowSeam(version, minimum = MIN_SHADOW_OPENCLAW_VERSION) {
  const left = versionParts(version);
  const right = versionParts(minimum);
  if (!left || !right) return null;
  for (let i = 0; i < 3; i += 1) {
    if (left[i] !== right[i]) return left[i] > right[i];
  }
  return true;
}

export function agentRuntimeCompatibility(value) {
  if (value === undefined || value === null || value === "") {
    return Object.freeze({ status: "UNDECLARED", compatible: null });
  }
  const id = typeof value === "string" ? value : value?.id;
  if (id === "openclaw") return Object.freeze({ status: "OPENCLAW_NATIVE", compatible: true });
  return Object.freeze({ status: "BYPASS_RUNTIME", compatible: false });
}

function lifecycleAction(event) {
  if (event?.type === "tool.execution.started") return "EXECUTION_STARTED";
  if (event?.type === "tool.execution.completed") return "EXECUTION_COMPLETED";
  if (event?.type === "tool.execution.blocked") return "BLOCKED_BEFORE_EXECUTION";
  if (event?.type === "tool.execution.error") {
    return event.errorCategory === "before_tool_call"
      ? "BLOCKED_BEFORE_EXECUTION"
      : "EXECUTION_FAILED";
  }
  return null;
}

function safeAppend(writer, record) {
  try {
    const pending = writer.append(record);
    pending?.catch?.(() => {});
  } catch {
    // Evidence loss never becomes OpenClaw execution authority.
  }
}

function safeErrorCode(error) {
  const code = typeof error?.code === "string" ? error.code.toUpperCase() : "INTERNAL";
  return /^[A-Z][A-Z0-9_]{0,79}$/u.test(code) ? code : "INTERNAL";
}

export function createShadowRuntime({
  config,
  runtimeVersion,
  runtimeInstanceId = randomUUID(),
  agentRuntime = null,
  transport = null,
  evidenceWriter = null,
  credentialProvider = withCredential,
  controlInspector = inspectObservationControls,
  nowIso = () => new Date().toISOString(),
  makeRequestId = randomUUID,
  decisionTimeoutMs = SHADOW_DECISION_TIMEOUT_MS,
  argumentDigester = null,
} = {}) {
  // Q-44: keyed argument digest under a dedicated per-installation key. The
  // key is loaded lazily on the first governed request that passes the gate.
  const digester = argumentDigester ?? createArgumentDigester(config.stateDir);
  const writer = evidenceWriter ?? createShadowEvidenceWriter(
    join(config.receiptDir, SHADOW_EVIDENCE_FILE),
  );
  const client = transport ?? createShadowTransport({
    apiUrl: config.apiUrl,
    caFile: config.caFile,
    timeoutMs: SHADOW_DECISION_TIMEOUT_MS,
  });
  const decisionIds = new ShadowDecisionWindow(SHADOW_DECISION_WINDOW);
  const correlations = new Map();
  const correlationOrder = [];
  const diagnosticKeys = new Set();
  const resultKeys = new Set();
  const seam = supportsNativeShadowSeam(runtimeVersion);
  const agentRuntimeState = agentRuntimeCompatibility(agentRuntime);
  let startupRecorded = false;
  let closed = false;
  const totals = {
    governed: 0,
    decisions: 0,
    errors: 0,
    passUngoverned: 0,
    passPrincipal: 0,
    duplicateHooks: 0,
    correlationConflicts: 0,
    notEvaluated: 0,
  };

  const base = () => ({
    schema: "observa-openclaw-shadow-evidence/v1",
    plugin_version: SHADOW_RELEASE.version,
    mode: SHADOW_RELEASE.mode,
    authority: SHADOW_RELEASE.authority,
    enforcement: SHADOW_RELEASE.enforcement,
    active: SHADOW_RELEASE.active,
    runtime_name: "openclaw",
    runtime_version: runtimeVersion,
    runtime_instance_id: runtimeInstanceId,
  });
  const emit = (record) => safeAppend(writer, { ts: nowIso(), ...base(), ...record });

  // Q-44: the single local observation gate for every shadow activity
  // entrypoint (before/after tool call, diagnostics, and again at the Hosted
  // boundary and before any decision record). It follows the connector-wide
  // contract in hook.mjs: operational DISABLED (`observa stop`/`disable`,
  // source configuration disabled) is INERT — no activity evidence record and
  // no Hosted contact. (A call already admitted when stop lands may leave
  // transient in-memory counters/correlation; nothing is persisted or sent.)
  // Kill switch and system lock keep their documented behaviour of
  // refusing Hosted contact while still recording locally. Any abnormal
  // control answer (throwing inspector, malformed result, unknown blocked
  // priority) fails closed to INERT.
  const LOCAL_ONLY_PRIORITIES = new Set(["KILL_SWITCH", "SYSTEM_LOCK"]);
  // Operational controls only (stop/disable, config, abnormal control state).
  function controlsGate() {
    if (config?.enabled !== true) return Object.freeze({ inert: true, controls: null });
    const controls = inspectHostedOutboundControls(() => controlInspector(config));
    const inert = controls.blocked === true && !LOCAL_ONLY_PRIORITIES.has(controls.priority);
    return Object.freeze({ inert, controls });
  }
  // Admission gate: a closed (shutting down) runtime admits no new activity.
  function observationGate() {
    if (closed) return Object.freeze({ inert: true, controls: null });
    return controlsGate();
  }

  function runtimeRefusal(entry) {
    if (seam === false || seam === null) {
      terminal(entry, "ERROR", { reason_code: "native_openclaw_seam_incompatible" });
      return true;
    }
    if (agentRuntimeState.compatible === false) {
      terminal(entry, "ERROR", { reason_code: "bypass_agent_runtime" });
      return true;
    }
    return false;
  }

  function remember(key, entry) {
    correlations.set(key, entry);
    correlationOrder.push(key);
    while (correlationOrder.length > SHADOW_CORRELATION_WINDOW) {
      correlations.delete(correlationOrder.shift());
    }
  }

  function terminal(entry, action, extra = {}) {
    if (entry.terminal) return;
    entry.terminal = true;
    // A stop that lands while a Hosted evaluation is in flight suppresses the
    // decision record too: nothing is written once observation is stopped.
    // Ordinary shutdown (close) is NOT a stop: an admitted in-flight call still
    // settles with its decision record, as in v0.8.0, before the writer closes.
    if (controlsGate().inert) return;
    entry.action = action;
    if (action === "ERROR") totals.errors += 1;
    else totals.decisions += 1;
    emit({
      kind: "SHADOW_DECISION",
      action,
      request_id: entry.request?.request_id ?? null,
      request_hash: entry.request?.request_hash ?? null,
      correlation_ref: entry.request?.correlation_ref ?? null,
      tool_name: entry.request?.tool_name ?? entry.tool_name ?? null,
      executable_class: entry.executableClass ?? null,
      tool_call_id: entry.tool_call_id ?? null,
      run_id: entry.run_id ?? null,
      agent_id: entry.request?.agent_id ?? config.agentId,
      execution_effect: "NONE",
      ...extra,
    });
  }

  async function evaluate(entry, normalized) {
    try {
      // Re-check at the Hosted boundary: a stop that lands after the hook
      // entered leaves no record at all; kill switch/lock record locally only.
      const gate = observationGate();
      if (gate.inert) {
        entry.terminal = true;
        return;
      }
      if (runtimeRefusal(entry)) return;
      const controls = gate.controls;
      if (controls?.blocked) {
        terminal(entry, "INDETERMINATE", {
          reason_code: "kill_state",
          kill_state: controls.priority ?? controls.remoteStatus ?? "ACTIVE",
        });
        return;
      }
      let timer;
      const deadline = new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error("TIMEOUT"), { code: "TIMEOUT" })),
          Math.max(1, Math.min(decisionTimeoutMs, SHADOW_DECISION_TIMEOUT_MS)));
        timer.unref?.();
      });
      let response;
      try {
        response = await Promise.race([
          credentialProvider(config.stateDir, (credential) => (
            client.evaluate(normalized.body, credential)
          )),
          deadline,
        ]);
      } finally {
        clearTimeout(timer);
      }
      if (entry.poisoned) {
        terminal(entry, "ERROR", { reason_code: "correlation_identity_conflict" });
        return;
      }
      const accepted = validateShadowResponse(response, normalized.request, decisionIds);
      entry.linkage = Object.freeze({
        decisionId: accepted.value.decision_id,
        decisionRequestHash: normalized.request.request_hash,
        correlationRef: normalized.request.correlation_ref,
        runtimeInstanceId,
        runId: normalized.correlation.run_id,
        toolCallId: normalized.correlation.tool_call_id,
        agentId: normalized.request.agent_id,
        toolId: normalized.request.tool_id,
      });
      terminal(entry, accepted.action, {
        abstract_decision: accepted.value.abstract_decision,
        reason_code: accepted.value.reason_code,
        decision_id: accepted.value.decision_id,
        policy_bundle_hash: accepted.value.policy_bundle_hash,
        engine_version: accepted.value.engine_version,
        evaluated_at: accepted.value.evaluated_at,
        approval_state: accepted.value.abstract_decision === "REQUIRE_APPROVAL"
          ? "shadow_mode_no_approval"
          : null,
      });
    } catch (error) {
      const code = safeErrorCode(error);
      const action = code === "TIMEOUT" || code === "UNAVAILABLE" || code.startsWith("HTTP_")
        ? "INDETERMINATE"
        : "ERROR";
      terminal(entry, action, { reason_code: code.toLowerCase() });
    }
  }

  async function beforeToolCallInner(event, ctx) {
    const requestId = makeRequestId();
    const normalized = normalizeShadowRequest({
      event,
      ctx,
      deploymentId: config.deploymentId,
      agentId: config.agentId,
      runtimeVersion,
      runtimeInstanceId,
      requestId,
      observedAt: nowIso(),
      argumentDigest: (params) => digester.digest(params),
    });
    if (!normalized.ok) {
      const scope = normalized.scope?.scope;
      if (scope === "PASS_UNGOVERNED") {
        totals.passUngoverned += 1;
        emit({ kind: "SHADOW_DECISION", action: "PASS_UNGOVERNED", tool_name: normalized.scope.tool_name, execution_effect: "NONE" });
      } else if (scope === "PASS_OUT_OF_SCOPE_PRINCIPAL") {
        totals.passPrincipal += 1;
        emit({ kind: "SHADOW_DECISION", action: "PASS_OUT_OF_SCOPE_PRINCIPAL", tool_name: normalized.scope.tool_name, execution_effect: "NONE" });
      } else if (normalized.notEvaluated === true) {
        // Q-44: sanitized coverage limitation. Observa did not evaluate this
        // action; it is never presented as a decision, approval or coverage.
        totals.notEvaluated += 1;
        const ids = correlationIdentity(event, ctx);
        emit({
          kind: "SHADOW_DECISION",
          action: "NOT_EVALUATED",
          coverage: "NOT_EVALUATED",
          reason_code: normalized.reason,
          tool_name: normalized.scope?.tool_name ?? null,
          tool_call_id: ids.tool_call_id,
          run_id: ids.run_id,
          agent_id: config.agentId,
          execution_effect: "NONE",
        });
      } else {
        totals.errors += 1;
        const ids = correlationIdentity(event, ctx);
        emit({
          kind: "SHADOW_DECISION",
          action: "ERROR",
          reason_code: normalized.reason ?? normalized.scope?.reason ?? "normalization_error",
          tool_name: normalized.scope?.tool_name ?? null,
          tool_call_id: ids.tool_call_id,
          run_id: ids.run_id,
          execution_effect: "NONE",
        });
      }
      return undefined;
    }
    totals.governed += 1;
    const existing = correlations.get(normalized.correlation.key);
    if (existing) {
      if (existing.fingerprint === normalized.fingerprint) totals.duplicateHooks += 1;
      else {
        totals.correlationConflicts += 1;
        existing.poisoned = true;
      }
      await existing.promise;
      return undefined;
    }
    const entry = {
      fingerprint: normalized.fingerprint,
      executableClass: normalized.executableClass ?? null,
      request: normalized.request,
      tool_call_id: normalized.correlation.tool_call_id,
      run_id: normalized.correlation.run_id,
      terminal: false,
      poisoned: false,
      promise: null,
    };
    remember(normalized.correlation.key, entry);
    entry.promise = evaluate(entry, normalized);
    await entry.promise;
    return undefined;
  }

  async function beforeToolCall(event, ctx) {
    if (observationGate().inert) return undefined;
    try {
      return await beforeToolCallInner(event, ctx);
    } catch (error) {
      totals.errors += 1;
      const ids = correlationIdentity(event, ctx);
      emit({
        kind: "SHADOW_DECISION",
        action: "ERROR",
        reason_code: safeErrorCode(error).toLowerCase(),
        tool_name: typeof event?.toolName === "string" ? event.toolName : null,
        tool_call_id: ids.tool_call_id,
        run_id: ids.run_id,
        execution_effect: "NONE",
      });
      return undefined;
    }
  }

  function onDiagnosticEvent(event, metadata = {}) {
    if (!metadata.trusted || !EXECUTION_EVENTS.has(event?.type)) return;
    if (observationGate().inert) return;
    const ids = correlationIdentity(event, event);
    const action = lifecycleAction(event);
    const eventKey = `${ids.key ?? "none"}\n${event.type}\n${event.seq ?? "none"}`;
    if (!action || diagnosticKeys.has(eventKey)) return;
    diagnosticKeys.add(eventKey);
    const entry = ids.key ? correlations.get(ids.key) : null;
    emit({
      kind: "EXECUTION_EVIDENCE",
      action,
      request_id: entry?.request?.request_id ?? null,
      correlation_ref: entry?.request?.correlation_ref ?? null,
      correlation_state: entry ? "MATCHED" : "UNMATCHED_HOST_LIFECYCLE",
      gate_action_at_intercept: entry?.action ?? null,
      tool_name: event.toolName ?? null,
      tool_call_id: ids.tool_call_id,
      run_id: ids.run_id,
      host_event_type: event.type,
      host_event_seq: event.seq ?? null,
      host_event_trusted: true,
      execution_occurred: ["EXECUTION_STARTED", "EXECUTION_COMPLETED", "EXECUTION_FAILED"].includes(action),
      execution_completed: action === "EXECUTION_COMPLETED",
      verification_state: "NOT_AVAILABLE",
    });
  }

  function afterToolCall(event, ctx) {
    if (observationGate().inert) return;
    const ids = correlationIdentity(event, ctx);
    const key = ids.key ?? `${ids.tool_call_id ?? "none"}\n${ids.run_id ?? "none"}`;
    if (resultKeys.has(key)) return;
    resultKeys.add(key);
    const entry = ids.key ? correlations.get(ids.key) : null;
    emit({
      kind: "RESULT_EVIDENCE",
      action: event?.error ? "RUNTIME_RESULT_ERROR" : "RUNTIME_RESULT_RETURNED",
      request_id: entry?.request?.request_id ?? null,
      correlation_ref: entry?.request?.correlation_ref ?? null,
      correlation_state: entry ? "MATCHED" : "UNMATCHED_RUNTIME_RESULT",
      tool_name: event?.toolName ?? null,
      tool_call_id: ids.tool_call_id,
      run_id: ids.run_id,
      result_present: event?.result !== undefined,
      error_present: Boolean(event?.error),
      execution_claim: "NONE",
      verification_state: "NOT_AVAILABLE",
    });
  }

  function linkageFor(event, ctx) {
    const ids = correlationIdentity(event, ctx);
    if (ids.conflict || ids.key === null) return null;
    const entry = correlations.get(ids.key);
    const link = entry?.linkage ?? null;
    const toolName = typeof event?.toolName === "string" ? event.toolName : null;
    const agentId = typeof ctx?.agentId === "string" ? ctx.agentId : null;
    if (link === null || !["exec", "openclawexec"].includes(toolName)
        || link.agentId !== agentId || link.runId !== ids.run_id
        || link.toolCallId !== ids.tool_call_id) return null;
    return link;
  }

  function onGatewayStart() {
    // Lifecycle-only attestation (no tool activity), like the connector's
    // gateway_start lifecycle receipt; deliberately not behind the activity gate.
    if (startupRecorded) return;
    startupRecorded = true;
    emit({
      kind: "SHADOW_ATTESTATION",
      action: "REGISTERED",
      before_tool_call_contract: "SYNCHRONOUS_PRE_EXECUTION_EVALUATION",
      native_seam_compatible: seam,
      minimum_openclaw_version: MIN_SHADOW_OPENCLAW_VERSION,
      agent_runtime_status: agentRuntimeState.status,
      agent_runtime_compatible: agentRuntimeState.compatible,
      agent_runtime_required_for_oauth_openai: "openclaw",
      config_mutated: false,
    });
  }

  async function close() {
    closed = true;
    try {
      await Promise.allSettled([
        ...[...correlations.values()].map((entry) => entry.promise).filter(Boolean),
        Promise.resolve().then(() => writer.flush()),
      ]);
    } catch { /* shutdown cannot affect OpenClaw */ }
    try { client.close?.(); } catch { /* transport cleanup is observational */ }
    try { digester.close?.(); } catch { /* key material is zeroed best-effort */ }
    try { await writer.close?.(); } catch { /* evidence cleanup is observational */ }
  }

  return Object.freeze({
    beforeToolCall,
    onDiagnosticEvent,
    afterToolCall,
    linkageFor,
    onGatewayStart,
    close,
    status: () => Object.freeze({
      ...base(),
      nativeSeamCompatible: seam,
      agentRuntime: agentRuntimeState,
      evidencePath: writer.path ?? null,
      decisionWindow: decisionIds.size,
      correlations: correlations.size,
      totals: Object.freeze({ ...totals }),
    }),
  });
}

export function createInertShadowRuntime(reason = "SHADOW_RUNTIME_INIT_FAILED") {
  const code = String(reason?.code ?? reason?.message ?? reason);
  const status = Object.freeze({
    ...SHADOW_RELEASE,
    initialized: false,
    reason: /^[A-Z][A-Z0-9_]{0,79}$/u.test(code) ? code : "SHADOW_RUNTIME_INIT_FAILED",
    executionEffect: "NONE",
  });
  return Object.freeze({
    beforeToolCall: async () => undefined,
    onDiagnosticEvent: () => undefined,
    afterToolCall: () => undefined,
    linkageFor: () => null,
    onGatewayStart: () => undefined,
    close: async () => undefined,
    status: () => status,
  });
}

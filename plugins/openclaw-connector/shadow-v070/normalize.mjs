import { createHash, randomUUID } from "node:crypto";
import {
  SHADOW_GOVERNED_TOOLS,
  SHADOW_MAX_REQUEST_BYTES,
  SHADOW_RELEASE,
  SHADOW_REQUEST_SCHEMA,
} from "./constants.mjs";

const SAFE_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const SAFE_REF_PART = /^[A-Za-z0-9._:-]{1,80}$/;

export function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
}

export function sha256(value) {
  return `sha256:${createHash("sha256").update(String(value)).digest("hex")}`;
}

export function extractArgv0(command) {
  if (typeof command !== "string") return null;
  const first = command.trim().split(/\s+/u)[0];
  return first || null;
}

function resourceRef(argv0) {
  return SAFE_REF_PART.test(argv0)
    ? `exec:argv0:${argv0}`
    : `exec:argv0-sha256:${sha256(argv0).slice(7, 31)}`;
}

function firstString(...values) {
  return values.find((value) => typeof value === "string" && value.length > 0) ?? null;
}

export function correlationIdentity(event, ctx) {
  const toolCallId = firstString(event?.toolCallId, ctx?.toolCallId);
  const runId = firstString(event?.runId, ctx?.runId);
  return {
    tool_call_id: toolCallId,
    run_id: runId,
    key: toolCallId && runId ? `${toolCallId}\n${runId}` : null,
  };
}

export function classifyShadowScope({ event, ctx, agentId }) {
  const rawTool = typeof event?.toolName === "string" ? event.toolName : null;
  if (!rawTool) return Object.freeze({ scope: "ERROR", reason: "tool_identity_incomplete" });
  const governed = SHADOW_GOVERNED_TOOLS[rawTool] ?? null;
  if (!governed) {
    return Object.freeze({ scope: "PASS_UNGOVERNED", tool_name: rawTool });
  }
  const observedAgent = typeof ctx?.agentId === "string" ? ctx.agentId : null;
  if (observedAgent !== agentId) {
    return Object.freeze({
      scope: observedAgent ? "PASS_OUT_OF_SCOPE_PRINCIPAL" : "ERROR",
      reason: observedAgent ? "agent_out_of_scope" : "agent_identity_incomplete",
      tool_name: governed.canonical_name,
      tool_name_raw: rawTool,
      agent_id_raw: observedAgent,
    });
  }
  return Object.freeze({
    scope: "GOVERNED",
    governed,
    tool_name: governed.canonical_name,
    tool_name_raw: rawTool,
    alias: rawTool !== governed.canonical_name,
    agent_id_raw: observedAgent,
  });
}

export function normalizeShadowRequest({
  event,
  ctx,
  deploymentId,
  agentId,
  runtimeVersion,
  runtimeInstanceId,
  requestId = randomUUID(),
  observedAt = new Date().toISOString(),
}) {
  const scope = classifyShadowScope({ event, ctx, agentId });
  if (scope.scope !== "GOVERNED") return Object.freeze({ ok: false, scope });
  const correlation = correlationIdentity(event, ctx);
  const command = event?.params?.command;
  const argv0 = extractArgv0(command);
  const missing = [];
  if (!argv0) missing.push("event.params.command");
  if (!correlation.tool_call_id) missing.push("toolCallId");
  if (!correlation.run_id) missing.push("runId");
  for (const [name, value] of Object.entries({ deploymentId, agentId, runtimeVersion, runtimeInstanceId, requestId })) {
    if (typeof value !== "string" || !SAFE_ID.test(value)) missing.push(name);
  }
  if (!Number.isFinite(Date.parse(observedAt))) missing.push("observedAt");
  if (missing.length > 0) {
    return Object.freeze({ ok: false, scope, reason: "identity_incomplete", missing });
  }

  const request = {
    schema: SHADOW_REQUEST_SCHEMA,
    request_id: requestId,
    observed_at: observedAt,
    deployment_id: deploymentId,
    agent_id: agentId,
    tool_id: scope.governed.tool_id,
    tool_name: scope.tool_name,
    runtime_tool_kind: scope.governed.runtime_tool_kind,
    operation: "execute",
    action_class: scope.governed.action_class,
    resource_class: scope.governed.resource_class,
    resource_ref: resourceRef(argv0),
    argv0,
    argument_digest: sha256(stableStringify(event.params)),
    correlation_ref: sha256(correlation.key).slice(0, 31),
    tool_call_id: correlation.tool_call_id,
    run_id: correlation.run_id,
    runtime_name: "openclaw",
    runtime_version: runtimeVersion,
    runtime_instance_id: runtimeInstanceId,
    mode: SHADOW_RELEASE.mode,
    authority: SHADOW_RELEASE.authority,
    enforcement: SHADOW_RELEASE.enforcement,
    active: SHADOW_RELEASE.active,
  };
  request.request_hash = sha256(stableStringify(request));
  const bytes = Buffer.from(stableStringify(request), "utf8");
  if (bytes.length > SHADOW_MAX_REQUEST_BYTES) {
    return Object.freeze({ ok: false, scope, reason: "request_oversize", missing: [] });
  }
  return Object.freeze({
    ok: true,
    scope,
    correlation,
    request: Object.freeze(request),
    body: bytes,
    fingerprint: `${scope.tool_name}\n${agentId}\n${request.argument_digest}`,
  });
}

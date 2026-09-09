import { createHash } from "node:crypto";

import { isSafeConnectorId } from "./config.mjs";
import {
  ACTION_CLASSES,
  canonicalizeJson,
} from "./runtime/governance-core/index.mjs";

export const OPENCLAW_HOOK_PROVENANCE = "openclaw-plugin-hook/v1";

const PLAIN_PROTOTYPES = new Set([Object.prototype, null]);
// OpenAI's normal tool-call identity can combine a call and response item with
// a literal `|`. The raw value is never sent; correlationRef hashes it before
// the request leaves the connector.
const CORRELATION_ID = /^[^\u0000-\u001F\u007F]{1,512}$/;
const SCHEMA_VERSION = /^[A-Za-z0-9._:-]{1,96}$/;
const FORBIDDEN_EVENT_FIELDS = Object.freeze(new Set([
  "actionClass",
  "deploymentId",
  "installationId",
  "metadata",
  "runtimeId",
  "schemaHash",
  "schemaVersion",
  "toolMetadata",
]));
const FORBIDDEN_CONTEXT_FIELDS = Object.freeze(new Set([
  "actionClass",
  "deploymentId",
  "installationId",
  "metadata",
  "schemaHash",
  "schemaVersion",
  "toolMetadata",
]));

function refused(reason) {
  return Object.freeze({ accepted: false, reason });
}

function plainDescriptors(value) {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)
        || !PLAIN_PROTOTYPES.has(Object.getPrototypeOf(value))
        || Object.getOwnPropertySymbols(value).length !== 0) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.values(descriptors).some((descriptor) => !("value" in descriptor))) return null;
    return descriptors;
  } catch {
    return null;
  }
}

function forbiddenPresent(descriptors, names) {
  return [...names].some((name) => Object.hasOwn(descriptors, name));
}

function requiredString(descriptors, key, validator) {
  const descriptor = descriptors[key];
  if (!descriptor || typeof descriptor.value !== "string" || !validator(descriptor.value)) return null;
  return descriptor.value;
}

function optionalString(descriptors, key, validator) {
  const descriptor = descriptors[key];
  if (!descriptor || descriptor.value === undefined || descriptor.value === null) {
    return Object.freeze({ ok: true, value: null });
  }
  if (typeof descriptor.value !== "string" || !validator(descriptor.value)) {
    return Object.freeze({ ok: false, value: null });
  }
  return Object.freeze({ ok: true, value: descriptor.value });
}

function copyPlainParams(value) {
  const descriptors = plainDescriptors(value);
  if (descriptors === null) return null;
  const result = Object.create(null);
  for (const [key, descriptor] of Object.entries(descriptors)) result[key] = descriptor.value;
  return Object.freeze(result);
}

function consistentIdentity(eventDescriptors, contextDescriptors, key) {
  const fromEvent = optionalString(eventDescriptors, key, (value) => CORRELATION_ID.test(value));
  const fromContext = optionalString(contextDescriptors, key, (value) => CORRELATION_ID.test(value));
  if (!fromEvent.ok || !fromContext.ok) return Object.freeze({ ok: false, value: null });
  if (fromEvent.value !== null && fromContext.value !== null
      && fromEvent.value !== fromContext.value) {
    return Object.freeze({ ok: false, value: null });
  }
  return Object.freeze({ ok: true, value: fromContext.value ?? fromEvent.value });
}

function runtimeToolKind(eventDescriptors, contextDescriptors) {
  const accepted = (value) => value === "code_mode_exec";
  const fromEvent = optionalString(eventDescriptors, "toolKind", accepted);
  const fromContext = optionalString(contextDescriptors, "toolKind", accepted);
  if (!fromEvent.ok || !fromContext.ok) return Object.freeze({ ok: false, value: null });
  if (fromEvent.value !== null && fromContext.value !== null
      && fromEvent.value !== fromContext.value) {
    return Object.freeze({ ok: false, value: null });
  }
  return Object.freeze({
    ok: true,
    value: (fromContext.value ?? fromEvent.value) === "code_mode_exec"
      ? "CODEX_NATIVE"
      : "OPENCLAW_DYNAMIC",
  });
}

/**
 * Normalize the real OpenClaw plugin-hook contract without consulting tool
 * arguments for identity or governance metadata. The host supplies toolName on
 * both the event and context; agreement is required before attribution.
 */
export function normalizeOpenClawToolHook(event, ctx, phase) {
  if (!new Set(["before_tool_call", "after_tool_call"]).has(phase)) {
    return refused("HOOK_PHASE_INVALID");
  }
  const eventDescriptors = plainDescriptors(event);
  const contextDescriptors = plainDescriptors(ctx);
  if (eventDescriptors === null || contextDescriptors === null) {
    return refused("HOOK_SHAPE_INVALID");
  }
  if (forbiddenPresent(eventDescriptors, FORBIDDEN_EVENT_FIELDS)
      || forbiddenPresent(contextDescriptors, FORBIDDEN_CONTEXT_FIELDS)) {
    return refused("HOOK_METADATA_SPOOF_REFUSED");
  }

  const eventToolName = requiredString(eventDescriptors, "toolName", isSafeConnectorId);
  const contextToolName = requiredString(contextDescriptors, "toolName", isSafeConnectorId);
  if (eventToolName === null || contextToolName === null) {
    return refused("HOOK_TOOL_IDENTITY_MISSING");
  }
  if (eventToolName !== contextToolName) return refused("HOOK_TOOL_IDENTITY_CONFLICT");

  const paramsDescriptor = eventDescriptors.params;
  const params = paramsDescriptor && "value" in paramsDescriptor
    ? copyPlainParams(paramsDescriptor.value)
    : null;
  if (params === null) return refused("HOOK_PARAMS_INVALID");

  const eventAgent = optionalString(eventDescriptors, "agentId", isSafeConnectorId);
  const agent = optionalString(contextDescriptors, "agentId", isSafeConnectorId);
  if (!eventAgent.ok || !agent.ok
      || (eventAgent.value !== null
        && (agent.value === null || eventAgent.value !== agent.value))) {
    return refused("HOOK_AGENT_IDENTITY_INVALID");
  }
  const toolCall = consistentIdentity(eventDescriptors, contextDescriptors, "toolCallId");
  const run = consistentIdentity(eventDescriptors, contextDescriptors, "runId");
  const kind = runtimeToolKind(eventDescriptors, contextDescriptors);
  if (!toolCall.ok || !run.ok) return refused("HOOK_CORRELATION_IDENTITY_CONFLICT");
  if (!kind.ok) return refused("HOOK_RUNTIME_TOOL_KIND_INVALID");

  const errorDescriptor = eventDescriptors.error;
  const normalizedEvent = Object.freeze({
    toolName: eventToolName,
    params,
    ...(run.value === null ? {} : { runId: run.value }),
    ...(toolCall.value === null ? {} : { toolCallId: toolCall.value }),
    ...(errorDescriptor && "value" in errorDescriptor
      ? { error: errorDescriptor.value }
      : {}),
  });
  const normalizedContext = Object.freeze({
    toolName: contextToolName,
    ...(agent.value === null ? {} : { agentId: agent.value }),
    ...(run.value === null ? {} : { runId: run.value }),
    ...(toolCall.value === null ? {} : { toolCallId: toolCall.value }),
  });
  return Object.freeze({
    accepted: true,
    phase,
    provenance: OPENCLAW_HOOK_PROVENANCE,
    toolName: eventToolName,
    agentId: agent.value,
    runId: run.value,
    toolCallId: toolCall.value,
    runtimeToolKind: kind.value,
    params,
    event: normalizedEvent,
    context: normalizedContext,
  });
}

function metadataEqual(left, right) {
  try {
    return canonicalizeJson(left) === canonicalizeJson(right);
  } catch {
    return false;
  }
}

function buildBinding(registration) {
  const registrationDescriptors = plainDescriptors(registration);
  if (registrationDescriptors === null) throw new TypeError("CODE_OWNED_TOOL_REGISTRATION_INVALID");
  const tool = registrationDescriptors.tool?.value;
  const governance = registrationDescriptors.governance?.value;
  const toolDescriptors = plainDescriptors(tool);
  const governanceDescriptors = plainDescriptors(governance);
  if (toolDescriptors === null || governanceDescriptors === null) {
    throw new TypeError("CODE_OWNED_TOOL_REGISTRATION_INVALID");
  }
  const toolName = requiredString(toolDescriptors, "name", isSafeConnectorId);
  const schemaVersion = requiredString(governanceDescriptors, "schemaVersion", (value) => (
    SCHEMA_VERSION.test(value)
  ));
  const actionClass = requiredString(governanceDescriptors, "actionClass", (value) => (
    ACTION_CLASSES.has(value)
  ));
  const parameterSchema = toolDescriptors.parameters?.value;
  const validateParams = governanceDescriptors.validateParams?.value;
  if (toolName === null || schemaVersion === null || actionClass === null
      || typeof validateParams !== "function") {
    throw new TypeError("CODE_OWNED_TOOL_REGISTRATION_INVALID");
  }
  let schemaBytes;
  try {
    schemaBytes = canonicalizeJson(parameterSchema);
  } catch {
    throw new TypeError("CODE_OWNED_TOOL_SCHEMA_INVALID");
  }
  const metadata = Object.freeze({
    schemaVersion,
    schemaHash: `sha256:${createHash("sha256").update(schemaBytes).digest("hex")}`,
    actionClass,
  });
  return Object.freeze({
    toolName,
    metadata,
    parameterSchema,
    validateParams,
    provenance: "connector-code-owned-tool-registration/v1",
  });
}

export function buildCodeOwnedToolCatalog(registrations) {
  if (!Array.isArray(registrations)) throw new TypeError("CODE_OWNED_TOOL_CATALOG_INVALID");
  const catalog = Object.create(null);
  for (const registration of registrations) {
    const binding = buildBinding(registration);
    if (Object.hasOwn(catalog, binding.toolName)) throw new TypeError("CODE_OWNED_TOOL_DUPLICATE");
    catalog[binding.toolName] = binding;
  }
  return Object.freeze(catalog);
}

/**
 * Resolve metadata only from code-owned registration or operator-validated
 * configuration. Hook arguments are used solely for code-owned schema
 * validation and can never supply or override identity metadata.
 */
export function resolveRuntimeObservationEligibility(normalized, config, codeOwnedTools) {
  if (!normalized?.accepted) return refused("HOOK_NORMALIZATION_REQUIRED");
  if (config.runtimeObservation === null) return refused("RUNTIME_OBSERVATION_NOT_BOOTSTRAPPED");
  if (normalized.agentId === null || normalized.runId === null && normalized.toolCallId === null) {
    return refused("RUNTIME_OBSERVATION_IDENTITY_INCOMPLETE");
  }
  if (Object.prototype.hasOwnProperty.call(codeOwnedTools || {}, normalized.toolName)) {
    return refused("RUNTIME_OBSERVATION_CODE_OWNED_TOOL");
  }
  if (Object.prototype.hasOwnProperty.call(config.toolMetadata || {}, normalized.toolName)) {
    return refused("RUNTIME_OBSERVATION_SEMANTIC_METADATA_PRESENT");
  }
  return Object.freeze({
    accepted: true,
    runtimeToolKind: normalized.runtimeToolKind,
    provenance: OPENCLAW_HOOK_PROVENANCE,
    mappingStatus: "UNMAPPED",
    authority: "NONE",
    enforcement: "OFF",
  });
}

export function resolveHookAttribution(normalized, config, codeOwnedTools) {
  if (!normalized?.accepted) return refused("HOOK_NORMALIZATION_REQUIRED");
  const registered = codeOwnedTools?.[normalized.toolName] ?? null;
  const configured = config.toolMetadata[normalized.toolName] ?? null;
  if (registered !== null) {
    let paramsAccepted = false;
    try { paramsAccepted = registered.validateParams(normalized.params) === true; } catch {}
    if (!paramsAccepted) return refused("HOOK_PARAMS_SCHEMA_REFUSED");
    if (configured !== null && !metadataEqual(configured, registered.metadata)) {
      return refused("HOOK_TOOL_METADATA_CONFLICT");
    }
    return Object.freeze({
      accepted: true,
      metadata: registered.metadata,
      provenance: registered.provenance,
    });
  }
  if (configured === null) return refused("HOOK_TOOL_METADATA_UNAVAILABLE");
  return Object.freeze({
    accepted: true,
    metadata: configured,
    provenance: "operator-validated-tool-configuration/v1",
  });
}

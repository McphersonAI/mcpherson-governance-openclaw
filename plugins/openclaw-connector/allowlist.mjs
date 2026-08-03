import { randomBytes, randomUUID } from "node:crypto";
import {
  API_VERSION,
  CONNECTION_TOOL_NAME,
  CANARY_TOOL_NAME,
  MAX_OUTBOUND_BYTES,
  OUTBOUND_FIELDS,
} from "./constants.mjs";
import { canonicalizeJson, correlationRef, requestHash, validateDecisionRequest } from "./runtime/governance-core/index.mjs";
import { isSafeConnectorId } from "./config.mjs";

const OUTBOUND = new Set(OUTBOUND_FIELDS);
const SAFE_LABEL = /^[A-Za-z0-9._:-]{1,128}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const NONCE = /^[a-f0-9]{32}$/;
const PROHIBITED_VALUE_PATTERNS = Object.freeze([
  /\r|\n/,
  /https?:\/\//i,
  /\bBearer\s+[A-Za-z0-9._~-]+/i,
  /\bmgd1_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/,
  /\b(?:api[_-]?key|access[_-]?token|private[_-]?key|password)\s*[:=]/i,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\b\d{3}-\d{2}-\d{4}\b/,
]);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function includeOptional(request, key, value) {
  if (value !== undefined && value !== null) request[key] = value;
}

export function deriveSafeToolSummary({ toolName, agentId, toolCallId, runId }, config) {
  // This function deliberately has no parameter for tool arguments. Callers
  // cannot accidentally pass event.params into the outbound request builder.
  const safeTool = isSafeConnectorId(toolName) ? toolName : "unknown";
  const safeAgent = isSafeConnectorId(agentId) ? agentId : config.agentId;
  const metadata = config.toolMetadata[safeTool] || Object.freeze({
    schemaVersion: "1",
    schemaHash: `sha256:${"0".repeat(64)}`,
    actionClass: safeTool === CONNECTION_TOOL_NAME
      ? "read_only_internal"
      : "unknown",
  });
  const rawCorrelation = typeof toolCallId === "string" && toolCallId.length > 0
    ? toolCallId
    : typeof runId === "string" && runId.length > 0 ? runId : null;
  return Object.freeze({
    agentId: safeAgent,
    toolId: safeTool,
    toolSchemaVersion: metadata.schemaVersion,
    toolSchemaHash: metadata.schemaHash,
    actionClass: metadata.actionClass,
    resourceClass: metadata.resourceClass,
    recipientType: metadata.recipientType,
    recipientCount: metadata.recipientCount,
    attachmentIndicator: metadata.attachmentIndicator,
    dataSensitivityLabel: metadata.dataSensitivityLabel,
    reversibilityLabel: metadata.reversibilityLabel,
    rawCorrelation,
  });
}

export function buildObservationRequest(summary, config, providers = {}) {
  const requestId = (providers.randomUUID || randomUUID)();
  const nonce = (providers.randomBytes || randomBytes)(16).toString("hex");
  const timestamp = (providers.now || (() => new Date()))().toISOString();
  if (!UUID_V4.test(requestId) || !NONCE.test(nonce)) fail("REQUEST_IDENTITY_INVALID");
  const request = {
    api_version: API_VERSION,
    request_id: requestId,
    nonce,
    timestamp,
    agent_id: summary.agentId,
    tool_id: summary.toolId,
    tool_schema_version: summary.toolSchemaVersion,
    tool_schema_hash: summary.toolSchemaHash,
    action_class: summary.actionClass,
    policy_version: config.policyVersion,
    correlation_ref: correlationRef(summary.rawCorrelation || requestId),
  };
  includeOptional(request, "resource_class", summary.resourceClass);
  includeOptional(request, "recipient_type", summary.recipientType);
  includeOptional(request, "recipient_count", summary.recipientCount);
  includeOptional(request, "attachment_indicator", summary.attachmentIndicator);
  includeOptional(request, "data_sensitivity_label", summary.dataSensitivityLabel);
  includeOptional(request, "reversibility_label", summary.reversibilityLabel);
  request.request_hash = requestHash(request);
  serializeAllowlistedRequest(request);
  return Object.freeze(request);
}

export function serializeAllowlistedRequest(request) {
  if (!request || typeof request !== "object" || Array.isArray(request)) fail("PRIVACY_GUARD_TRIPPED");
  const keys = Object.keys(request);
  if (keys.some((key) => !OUTBOUND.has(key))) fail("PRIVACY_GUARD_TRIPPED");
  const required = [
    "api_version", "request_id", "nonce", "timestamp", "agent_id", "tool_id",
    "tool_schema_version", "tool_schema_hash", "action_class", "request_hash",
    "policy_version", "correlation_ref",
  ];
  if (required.some((key) => !(key in request))) fail("PRIVACY_GUARD_TRIPPED");
  for (const [key, value] of Object.entries(request)) {
    if (typeof value === "string") {
      if (value.length > 256 || PROHIBITED_VALUE_PATTERNS.some((pattern) => pattern.test(value))) fail("PRIVACY_GUARD_TRIPPED");
      if (!["api_version", "timestamp", "request_hash", "tool_schema_hash"].includes(key) && !SAFE_LABEL.test(value)) fail("PRIVACY_GUARD_TRIPPED");
    } else if (typeof value === "number") {
      if (!Number.isSafeInteger(value) || value < 0) fail("PRIVACY_GUARD_TRIPPED");
    } else if (typeof value !== "boolean") fail("PRIVACY_GUARD_TRIPPED");
  }
  if (request.api_version !== API_VERSION || !UUID_V4.test(request.request_id) || !NONCE.test(request.nonce)) fail("PRIVACY_GUARD_TRIPPED");
  if (!SHA256.test(request.request_hash) || !SHA256.test(request.tool_schema_hash)) fail("PRIVACY_GUARD_TRIPPED");
  if (!Number.isFinite(Date.parse(request.timestamp))) fail("PRIVACY_GUARD_TRIPPED");
  if (!validateDecisionRequest(request).ok) fail("PRIVACY_GUARD_TRIPPED");
  const bytes = Buffer.from(canonicalizeJson(request), "utf8");
  if (bytes.length > MAX_OUTBOUND_BYTES) fail("PRIVACY_GUARD_TRIPPED");
  return bytes;
}

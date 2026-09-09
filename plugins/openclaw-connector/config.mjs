import { join, resolve } from "node:path";
import { validateRuntimeObservationBootstrap } from "./runtime-observation-contract.mjs";
import { ACTION_CLASSES } from "./runtime/governance-core/index.mjs";
import { connectorStateRoot, resolveOpenClawStateDir } from "./host.mjs";
import {
  ABSOLUTE_OBSERVATION_CAP_MS,
  DEFAULT_CONNECT_TIMEOUT_MS,
  DEFAULT_OBSERVATION_BUDGET_MS,
  FORBIDDEN_AUTHORITY_CONFIG_KEYS,
  MAX_OBSERVATION_BUDGET_MS,
  MAX_OBSERVATION_QUEUE,
  MAX_OBSERVATIONS_IN_FLIGHT,
} from "./constants.mjs";

const SAFE_ID = /^[A-Za-z0-9._:-]{1,96}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const ACTION_CLASS = /^[a-z][a-z0-9_]{0,63}$/;
const ALLOWED_KEYS = new Set([
  "enabled",
  "apiUrl",
  "deploymentId",
  "agentId",
  "policyVersion",
  "observationBudgetMs",
  "connectTimeoutMs",
  "maxInFlight",
  "maxQueue",
  "stateDir",
  "receiptDir",
  "caFile",
  "toolMetadata",
  "runtimeObservation",
]);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function integerIn(value, min, max, code) {
  if (!Number.isInteger(value) || value < min || value > max) fail(code);
  return value;
}

function safeId(value, code) {
  if (typeof value !== "string" || !SAFE_ID.test(value)) fail(code);
  return value;
}

function validateToolMetadata(input = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail("CONFIG_TOOL_METADATA_INVALID");
  const result = Object.create(null);
  for (const [toolId, value] of Object.entries(input)) {
    safeId(toolId, "CONFIG_TOOL_ID_INVALID");
    if (!value || typeof value !== "object" || Array.isArray(value)) fail("CONFIG_TOOL_METADATA_INVALID");
    const allowed = new Set([
      "schemaVersion", "schemaHash", "actionClass", "resourceClass", "recipientType",
      "recipientCount", "attachmentIndicator", "dataSensitivityLabel", "reversibilityLabel",
    ]);
    if (Object.keys(value).some((key) => !allowed.has(key))) fail("CONFIG_TOOL_METADATA_UNKNOWN_KEY");
    if (typeof value.schemaVersion !== "string" || !SAFE_ID.test(value.schemaVersion)) fail("CONFIG_SCHEMA_VERSION_INVALID");
    if (typeof value.schemaHash !== "string" || !SHA256.test(value.schemaHash)) fail("CONFIG_SCHEMA_HASH_INVALID");
    if (typeof value.actionClass !== "string" || !ACTION_CLASS.test(value.actionClass) || !ACTION_CLASSES.has(value.actionClass)) fail("CONFIG_ACTION_CLASS_INVALID");
    const normalized = {
      schemaVersion: value.schemaVersion,
      schemaHash: value.schemaHash,
      actionClass: value.actionClass,
    };
    for (const key of ["resourceClass", "recipientType", "dataSensitivityLabel", "reversibilityLabel"]) {
      if (value[key] !== undefined) normalized[key] = safeId(value[key], "CONFIG_DERIVED_LABEL_INVALID");
    }
    if (value.recipientCount !== undefined) normalized.recipientCount = integerIn(value.recipientCount, 0, 100000, "CONFIG_RECIPIENT_COUNT_INVALID");
    if (value.attachmentIndicator !== undefined) {
      if (typeof value.attachmentIndicator !== "boolean") fail("CONFIG_ATTACHMENT_INDICATOR_INVALID");
      normalized.attachmentIndicator = value.attachmentIndicator;
    }
    result[toolId] = Object.freeze(normalized);
  }
  return Object.freeze(result);
}

export function loadConnectorConfig(input = {}, pathOverrides = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail("CONFIG_INVALID");
  for (const key of Object.keys(input)) {
    if (FORBIDDEN_AUTHORITY_CONFIG_KEYS.includes(key)) fail("FORBIDDEN_AUTHORITY_CONFIG");
    if (!ALLOWED_KEYS.has(key)) fail("CONFIG_UNKNOWN_KEY");
  }

  // Precedence: explicit override > explicit configuration > the connector
  // state root inside the ACTIVE OpenClaw profile. The default never resolves
  // to another profile's root, and no state is read or migrated from one.
  const openclawStateDir = resolve(
    pathOverrides.openclawStateDir || resolveOpenClawStateDir(),
  );
  const stateDir = resolve(
    pathOverrides.stateDir
    || input.stateDir
    || connectorStateRoot(openclawStateDir),
  );
  const receiptDir = resolve(pathOverrides.receiptDir || input.receiptDir || join(stateDir, "receipts"));
  const apiUrl = input.apiUrl || "https://127.0.0.1:8443";
  let parsed;
  try { parsed = new URL(apiUrl); } catch { fail("CONFIG_API_URL_INVALID"); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash) fail("CONFIG_API_URL_NOT_VERIFIED_HTTPS");

  const config = {
    enabled: input.enabled === true,
    apiUrl: parsed.origin,
    deploymentId: safeId(input.deploymentId || "deployment-unpaired", "CONFIG_DEPLOYMENT_ID_INVALID"),
    agentId: safeId(input.agentId || "agent-unpaired", "CONFIG_AGENT_ID_INVALID"),
    policyVersion: integerIn(input.policyVersion ?? 3, 1, Number.MAX_SAFE_INTEGER, "CONFIG_POLICY_VERSION_INVALID"),
    observationBudgetMs: integerIn(input.observationBudgetMs ?? DEFAULT_OBSERVATION_BUDGET_MS, 0, MAX_OBSERVATION_BUDGET_MS, "CONFIG_OBSERVATION_BUDGET_INVALID"),
    connectTimeoutMs: integerIn(input.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS, 1, ABSOLUTE_OBSERVATION_CAP_MS, "CONFIG_CONNECT_TIMEOUT_INVALID"),
    maxInFlight: integerIn(input.maxInFlight ?? MAX_OBSERVATIONS_IN_FLIGHT, 1, MAX_OBSERVATIONS_IN_FLIGHT, "CONFIG_MAX_IN_FLIGHT_INVALID"),
    maxQueue: integerIn(input.maxQueue ?? MAX_OBSERVATION_QUEUE, 0, MAX_OBSERVATION_QUEUE, "CONFIG_MAX_QUEUE_INVALID"),
    stateDir,
    receiptDir,
    caFile: input.caFile ? resolve(input.caFile) : null,
    toolMetadata: validateToolMetadata(input.toolMetadata),
    runtimeObservation: input.runtimeObservation === undefined
      ? null
      : validateRuntimeObservationBootstrap(input.runtimeObservation, openclawStateDir),
  };
  return Object.freeze(config);
}

export function isSafeConnectorId(value) {
  return typeof value === "string" && SAFE_ID.test(value);
}

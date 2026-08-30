// Closed contract for neutral OpenClaw runtime observation.
//
// This is intentionally separate from semantic `toolMetadata` and from the
// mgp/1 decision request. A supported runtime hook can establish that a bounded
// tool identity executed for a bounded agent identity. It cannot establish the
// tool's business action class, resource meaning, sensitivity, reversibility,
// policy meaning, approval, or authority, so none of those claims exists in
// this envelope.
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { resolve } from "node:path";

export const RUNTIME_OBSERVATION_BOOTSTRAP_SCHEMA =
  "observa-runtime-observation-bootstrap/v1";
export const SHADOW_OBSERVATION_SCHEMA = "observa-shadow-observation/v1";
export const SHADOW_OBSERVATION_ACK_SCHEMA = "observa-shadow-observation-ack/v1";
export const SHADOW_OBSERVATION_MODE = "SHADOW_METADATA_ONLY";
export const SHADOW_OBSERVATION_DISCOVERY = "ACTUAL_SUPPORTED_OPENCLAW_TOOL_HOOK";
export const SHADOW_OBSERVATION_MAPPING_STATUS = "UNMAPPED";
export const SHADOW_OBSERVATION_STATUS = "OBSERVED_UNMAPPED";
export const SHADOW_OBSERVATION_AUTHORITY = "NONE";
export const SHADOW_OBSERVATION_ENFORCEMENT = "OFF";
export const SHADOW_OBSERVATION_BASIS = "DIRECT_SUPPORTED_POST_HOOK";
export const SHADOW_OBSERVATION_PROVENANCE = "openclaw-plugin-hook/v1";
export const SHADOW_OBSERVATION_MAX_BYTES = 2 * 1024;

export const RUNTIME_TOOL_KINDS = Object.freeze([
  "OPENCLAW_DYNAMIC",
  "CODEX_NATIVE",
]);
export const TOOL_OUTCOMES = Object.freeze(["COMPLETED", "FAILED", "TIMED_OUT"]);

const REQUEST_FIELDS = Object.freeze([
  "schema",
  "request_id",
  "nonce",
  "timestamp",
  "agent_id",
  "tool_id",
  "runtime_tool_kind",
  "runtime_provenance",
  "observation_basis",
  "observation_mode",
  "tool_outcome",
  "mapping_status",
  "authority",
  "enforcement",
  "correlation_ref",
  "request_hash",
]);
const ACK_FIELDS = Object.freeze([
  "schema",
  "accepted",
  "observation_id",
  "request_hash",
  "observation_status",
  "mapping_status",
  "authority",
  "enforcement",
  "automatic_mapping_activation",
]);
const BOOTSTRAP_FIELDS = Object.freeze([
  "schema",
  "mode",
  "discoverySource",
  "profileBinding",
  "mappingStatus",
  "authority",
  "enforcement",
  "automaticMappingActivation",
]);

const SAFE_ID = /^[A-Za-z0-9._:-]{1,96}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NONCE = /^[a-f0-9]{32}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const PLAIN_PROTOTYPES = new Set([Object.prototype, null]);
const PROHIBITED_VALUE_PATTERNS = Object.freeze([
  /\r|\n/,
  /https?:\/\//i,
  /\bBearer\s+[A-Za-z0-9._~-]+/i,
  /\bmgd1_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/,
  /\b(?:api[_-]?key|access[_-]?token|private[_-]?key|password)\s*[:=]/i,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
]);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function plainDescriptors(value) {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)
        || !PLAIN_PROTOTYPES.has(Object.getPrototypeOf(value))
        || Object.getOwnPropertySymbols(value).length !== 0) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.values(descriptors).some((descriptor) => !descriptor.enumerable
        || !("value" in descriptor))) return null;
    return descriptors;
  } catch {
    return null;
  }
}

function exactFields(value, expected) {
  const descriptors = plainDescriptors(value);
  if (descriptors === null) return null;
  const keys = Object.keys(descriptors).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(keys) !== JSON.stringify(wanted)) return null;
  return descriptors;
}

function safeString(value, pattern) {
  return typeof value === "string"
    && value.length <= 256
    && pattern.test(value)
    && !PROHIBITED_VALUE_PATTERNS.some((candidate) => candidate.test(value));
}

function validTimestamp(value) {
  return typeof value === "string" && value.length <= 32
    && RFC3339_UTC.test(value) && Number.isFinite(Date.parse(value));
}

function canonicalFlatObject(value) {
  const descriptors = plainDescriptors(value);
  if (descriptors === null) fail("SHADOW_OBSERVATION_NOT_PLAIN");
  const keys = Object.keys(descriptors).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${JSON.stringify(
    descriptors[key].value,
  )}`).join(",")}}`;
}

export function canonicalShadowObservationJson(value) {
  return canonicalFlatObject(value);
}

export function shadowObservationRequestHash(value) {
  const descriptors = plainDescriptors(value);
  if (descriptors === null) fail("SHADOW_OBSERVATION_NOT_PLAIN");
  const unhashed = Object.create(null);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (key !== "request_hash") unhashed[key] = descriptor.value;
  }
  return `sha256:${createHash("sha256").update(canonicalFlatObject(unhashed)).digest("hex")}`;
}

export function runtimeObservationProfileBinding(profileState) {
  if (typeof profileState !== "string" || profileState.length === 0) {
    fail("RUNTIME_OBSERVATION_PROFILE_INVALID");
  }
  return `sha256:${createHash("sha256").update(resolve(profileState)).digest("hex")}`;
}

export function createRuntimeObservationBootstrap(profileState) {
  return Object.freeze({
    schema: RUNTIME_OBSERVATION_BOOTSTRAP_SCHEMA,
    mode: SHADOW_OBSERVATION_MODE,
    discoverySource: SHADOW_OBSERVATION_DISCOVERY,
    profileBinding: runtimeObservationProfileBinding(profileState),
    mappingStatus: SHADOW_OBSERVATION_MAPPING_STATUS,
    authority: SHADOW_OBSERVATION_AUTHORITY,
    enforcement: SHADOW_OBSERVATION_ENFORCEMENT,
    automaticMappingActivation: false,
  });
}

export function validateRuntimeObservationBootstrap(value, profileState) {
  const descriptors = exactFields(value, BOOTSTRAP_FIELDS);
  if (descriptors === null) fail("CONFIG_RUNTIME_OBSERVATION_INVALID");
  const expected = createRuntimeObservationBootstrap(profileState);
  for (const key of BOOTSTRAP_FIELDS) {
    if (descriptors[key].value !== expected[key]) {
      fail(key === "profileBinding"
        ? "CONFIG_RUNTIME_OBSERVATION_PROFILE_MISMATCH"
        : "CONFIG_RUNTIME_OBSERVATION_INVALID");
    }
  }
  return expected;
}

export function correlationReference(raw, fallback) {
  const candidate = typeof raw === "string" && raw.length > 0 ? raw : fallback;
  if (typeof candidate !== "string" || candidate.length > 512
      || /[\u0000-\u001F\u007F]/.test(candidate)) {
    fail("SHADOW_OBSERVATION_CORRELATION_INVALID");
  }
  return `sha256:${createHash("sha256").update(candidate).digest("hex")}`;
}

export function validateShadowObservationRequest(value) {
  const descriptors = exactFields(value, REQUEST_FIELDS);
  if (descriptors === null) return Object.freeze({ ok: false, code: "MALFORMED" });
  const field = (name) => descriptors[name].value;
  const checks = [
    [field("schema") === SHADOW_OBSERVATION_SCHEMA, "schema"],
    [safeString(field("request_id"), UUID_V4), "request_id"],
    [safeString(field("nonce"), NONCE), "nonce"],
    [validTimestamp(field("timestamp")), "timestamp"],
    [safeString(field("agent_id"), SAFE_ID), "agent_id"],
    [safeString(field("tool_id"), SAFE_ID), "tool_id"],
    [RUNTIME_TOOL_KINDS.includes(field("runtime_tool_kind")), "runtime_tool_kind"],
    [field("runtime_provenance") === SHADOW_OBSERVATION_PROVENANCE,
      "runtime_provenance"],
    [field("observation_basis") === SHADOW_OBSERVATION_BASIS, "observation_basis"],
    [field("observation_mode") === SHADOW_OBSERVATION_MODE, "observation_mode"],
    [TOOL_OUTCOMES.includes(field("tool_outcome")), "tool_outcome"],
    [field("mapping_status") === SHADOW_OBSERVATION_MAPPING_STATUS, "mapping_status"],
    [field("authority") === SHADOW_OBSERVATION_AUTHORITY, "authority"],
    [field("enforcement") === SHADOW_OBSERVATION_ENFORCEMENT, "enforcement"],
    [safeString(field("correlation_ref"), SHA256), "correlation_ref"],
    [safeString(field("request_hash"), SHA256), "request_hash"],
  ];
  const failed = checks.find(([ok]) => !ok);
  if (failed) return Object.freeze({ ok: false, code: "MALFORMED", field: failed[1] });
  let expected;
  try { expected = shadowObservationRequestHash(value); }
  catch { return Object.freeze({ ok: false, code: "MALFORMED" }); }
  if (field("request_hash") !== expected) {
    return Object.freeze({ ok: false, code: "HASH_MISMATCH", field: "request_hash" });
  }
  return Object.freeze({ ok: true });
}

export function serializeShadowObservationRequest(request) {
  const validation = validateShadowObservationRequest(request);
  if (!validation.ok) fail("SHADOW_OBSERVATION_PRIVACY_GUARD_TRIPPED");
  const bytes = Buffer.from(canonicalShadowObservationJson(request), "utf8");
  if (bytes.length > SHADOW_OBSERVATION_MAX_BYTES) {
    bytes.fill(0);
    fail("SHADOW_OBSERVATION_PRIVACY_GUARD_TRIPPED");
  }
  return bytes;
}

export function buildShadowObservationRequest(identity, providers = {}) {
  // Deliberately accept identity and closed outcome only. There is no API for
  // prompt text, arguments, results, exception text, schema, or semantics.
  const requestId = (providers.randomUUID || randomUUID)();
  const request = {
    schema: SHADOW_OBSERVATION_SCHEMA,
    request_id: requestId,
    nonce: (providers.randomBytes || randomBytes)(16).toString("hex"),
    timestamp: (providers.now || (() => new Date()))().toISOString(),
    agent_id: identity.agentId,
    tool_id: identity.toolId,
    runtime_tool_kind: identity.runtimeToolKind,
    runtime_provenance: SHADOW_OBSERVATION_PROVENANCE,
    observation_basis: SHADOW_OBSERVATION_BASIS,
    observation_mode: SHADOW_OBSERVATION_MODE,
    tool_outcome: identity.toolOutcome,
    mapping_status: SHADOW_OBSERVATION_MAPPING_STATUS,
    authority: SHADOW_OBSERVATION_AUTHORITY,
    enforcement: SHADOW_OBSERVATION_ENFORCEMENT,
    correlation_ref: correlationReference(identity.rawCorrelation, requestId),
  };
  request.request_hash = shadowObservationRequestHash(request);
  serializeShadowObservationRequest(request);
  return Object.freeze(request);
}

export function buildShadowObservationAck(request, observationId) {
  const value = {
    schema: SHADOW_OBSERVATION_ACK_SCHEMA,
    accepted: true,
    observation_id: observationId,
    request_hash: request.request_hash,
    observation_status: SHADOW_OBSERVATION_STATUS,
    mapping_status: SHADOW_OBSERVATION_MAPPING_STATUS,
    authority: SHADOW_OBSERVATION_AUTHORITY,
    enforcement: SHADOW_OBSERVATION_ENFORCEMENT,
    automatic_mapping_activation: false,
  };
  if (!validateShadowObservationAck(value, request.request_hash)) {
    fail("SHADOW_OBSERVATION_ACK_INVALID");
  }
  return Object.freeze(value);
}

export function validateShadowObservationAck(value, expectedRequestHash) {
  const descriptors = exactFields(value, ACK_FIELDS);
  if (descriptors === null) return false;
  const field = (name) => descriptors[name].value;
  return field("schema") === SHADOW_OBSERVATION_ACK_SCHEMA
    && field("accepted") === true
    && safeString(field("observation_id"), SAFE_ID)
    && field("request_hash") === expectedRequestHash
    && safeString(field("request_hash"), SHA256)
    && field("observation_status") === SHADOW_OBSERVATION_STATUS
    && field("mapping_status") === SHADOW_OBSERVATION_MAPPING_STATUS
    && field("authority") === SHADOW_OBSERVATION_AUTHORITY
    && field("enforcement") === SHADOW_OBSERVATION_ENFORCEMENT
    && field("automatic_mapping_activation") === false;
}

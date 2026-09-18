// Closed metadata-only contracts for authenticated OpenClaw runtime roster
// publication and liveness heartbeats.  These messages carry no tool,
// capability, activity, decision, execution, prompt, argument, or result data.
import { createHash, randomBytes, randomUUID } from "node:crypto";

export const RUNTIME_INVENTORY_ROUTE = "/v1/runtime/inventory";
export const RUNTIME_HEARTBEAT_ROUTE = "/v1/runtime/heartbeat";
// v2 adds the required `runtime_generation`: the monotonic per-process
// generation the plugin takes once at start (see runtime-generation.mjs).
// v1 was never published or deployed and is refused as malformed.
export const RUNTIME_INVENTORY_SCHEMA = "observa-openclaw-agent-inventory/v2";
export const RUNTIME_HEARTBEAT_SCHEMA = "observa-openclaw-runtime-heartbeat/v2";
export const RUNTIME_PUBLICATION_ACK_SCHEMA = "observa-openclaw-runtime-publication-ack/v1";
export const RUNTIME_PUBLICATION_MAX_BYTES = 16 * 1024;
export const MIN_HEARTBEAT_CADENCE_SECONDS = 10;
export const MAX_HEARTBEAT_CADENCE_SECONDS = 300;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NONCE = /^[a-f0-9]{32}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const SAFE_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const AGENT_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const PLAIN = new Set([Object.prototype, null]);

const INVENTORY_FIELDS = Object.freeze([
  "schema", "request_id", "nonce", "timestamp", "runtime_instance_id",
  "runtime_generation", "roster_revision", "agents", "authority", "enforcement", "active", "request_hash",
]);
const HEARTBEAT_FIELDS = Object.freeze([
  "schema", "request_id", "nonce", "timestamp", "runtime_instance_id",
  "runtime_generation", "roster_revision", "sequence", "cadence_seconds", "runtime_state",
  "authority", "enforcement", "active", "request_hash",
]);
const ACK_FIELDS = Object.freeze([
  "schema", "accepted", "kind", "record_id", "request_hash", "authority",
  "enforcement", "active",
]);

function descriptors(value) {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)
        || !PLAIN.has(Object.getPrototypeOf(value))
        || Object.getOwnPropertySymbols(value).length !== 0) return null;
    const result = Object.getOwnPropertyDescriptors(value);
    if (Object.values(result).some((item) => !item.enumerable || !("value" in item))) return null;
    return result;
  } catch { return null; }
}

function exact(value, fields) {
  const found = descriptors(value);
  return found !== null
    && JSON.stringify(Object.keys(found).sort()) === JSON.stringify([...fields].sort())
    ? found : null;
}

function timestamp(value) {
  return typeof value === "string" && value.length <= 32
    && RFC3339.test(value) && Number.isFinite(Date.parse(value));
}

export function canonicalRuntimePublicationJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalRuntimePublicationJson).join(",")}]`;
  if (descriptors(value) === null) throw Object.assign(new Error("RUNTIME_PUBLICATION_NOT_PLAIN"), { code: "RUNTIME_PUBLICATION_NOT_PLAIN" });
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalRuntimePublicationJson(value[key])}`).join(",")}}`;
}

export const runtimePublicationDigest = (value) =>
  `sha256:${createHash("sha256").update(String(value)).digest("hex")}`;

export function runtimePublicationRequestHash(value) {
  const found = descriptors(value);
  if (found === null) throw new TypeError("RUNTIME_PUBLICATION_NOT_PLAIN");
  const unhashed = Object.create(null);
  for (const [key, descriptor] of Object.entries(found)) {
    if (key !== "request_hash") unhashed[key] = descriptor.value;
  }
  return runtimePublicationDigest(canonicalRuntimePublicationJson(unhashed));
}

export function rosterRevision(agents) {
  if (!Array.isArray(agents) || agents.length < 1 || agents.length > 256) {
    throw new TypeError("RUNTIME_ROSTER_INVALID");
  }
  const ids = agents.map((agent) => {
    const found = exact(agent, ["agent_id"]);
    const id = found?.agent_id?.value;
    if (typeof id !== "string" || !AGENT_ID.test(id)) throw new TypeError("RUNTIME_ROSTER_INVALID");
    return id;
  });
  if (new Set(ids).size !== ids.length || JSON.stringify(ids) !== JSON.stringify([...ids].sort())) {
    throw new TypeError("RUNTIME_ROSTER_INVALID");
  }
  return runtimePublicationDigest(canonicalRuntimePublicationJson(agents));
}

function commonValid(field, expectedSchema) {
  return field("schema") === expectedSchema
    && typeof field("request_id") === "string" && UUID.test(field("request_id"))
    && typeof field("nonce") === "string" && NONCE.test(field("nonce"))
    && timestamp(field("timestamp"))
    && typeof field("runtime_instance_id") === "string" && SAFE_ID.test(field("runtime_instance_id"))
    && Number.isSafeInteger(field("runtime_generation")) && field("runtime_generation") >= 1
    && typeof field("roster_revision") === "string" && SHA256.test(field("roster_revision"))
    && field("authority") === "NONE" && field("enforcement") === "OFF"
    && field("active") === false
    && typeof field("request_hash") === "string" && SHA256.test(field("request_hash"));
}

export function validateRuntimeInventoryRequest(value) {
  const found = exact(value, INVENTORY_FIELDS);
  if (found === null) return Object.freeze({ ok: false, code: "MALFORMED" });
  const field = (name) => found[name].value;
  let revision = null;
  try { revision = rosterRevision(field("agents")); } catch {}
  if (!commonValid(field, RUNTIME_INVENTORY_SCHEMA) || revision !== field("roster_revision")) {
    return Object.freeze({ ok: false, code: "MALFORMED" });
  }
  return requestHashResult(value);
}

export function validateRuntimeHeartbeatRequest(value) {
  const found = exact(value, HEARTBEAT_FIELDS);
  if (found === null) return Object.freeze({ ok: false, code: "MALFORMED" });
  const field = (name) => found[name].value;
  if (!commonValid(field, RUNTIME_HEARTBEAT_SCHEMA)
      || !Number.isSafeInteger(field("sequence")) || field("sequence") < 1
      || !Number.isSafeInteger(field("cadence_seconds"))
      || field("cadence_seconds") < MIN_HEARTBEAT_CADENCE_SECONDS
      || field("cadence_seconds") > MAX_HEARTBEAT_CADENCE_SECONDS
      || field("runtime_state") !== "RUNNING") {
    return Object.freeze({ ok: false, code: "MALFORMED" });
  }
  return requestHashResult(value);
}

function requestHashResult(value) {
  let expected;
  try { expected = runtimePublicationRequestHash(value); } catch {
    return Object.freeze({ ok: false, code: "MALFORMED" });
  }
  return value.request_hash === expected
    ? Object.freeze({ ok: true })
    : Object.freeze({ ok: false, code: "HASH_MISMATCH" });
}

function baseRequest(schema, identity, providers) {
  return {
    schema,
    request_id: (providers.randomUUID || randomUUID)(),
    nonce: (providers.randomBytes || randomBytes)(16).toString("hex"),
    timestamp: (providers.now || (() => new Date()))().toISOString(),
    runtime_instance_id: identity.runtimeInstanceId,
    runtime_generation: identity.runtimeGeneration,
    roster_revision: identity.rosterRevision,
  };
}

export function buildRuntimeInventoryRequest(identity, providers = {}) {
  const request = {
    ...baseRequest(RUNTIME_INVENTORY_SCHEMA, identity, providers),
    agents: identity.agents,
    authority: "NONE", enforcement: "OFF", active: false,
  };
  request.request_hash = runtimePublicationRequestHash(request);
  if (!validateRuntimeInventoryRequest(request).ok) throw new TypeError("RUNTIME_INVENTORY_INVALID");
  return Object.freeze(request);
}

export function buildRuntimeHeartbeatRequest(identity, providers = {}) {
  const request = {
    ...baseRequest(RUNTIME_HEARTBEAT_SCHEMA, identity, providers),
    sequence: identity.sequence,
    cadence_seconds: identity.cadenceSeconds,
    runtime_state: "RUNNING",
    authority: "NONE", enforcement: "OFF", active: false,
  };
  request.request_hash = runtimePublicationRequestHash(request);
  if (!validateRuntimeHeartbeatRequest(request).ok) throw new TypeError("RUNTIME_HEARTBEAT_INVALID");
  return Object.freeze(request);
}

export function serializeRuntimePublication(request) {
  const valid = request?.schema === RUNTIME_INVENTORY_SCHEMA
    ? validateRuntimeInventoryRequest(request) : validateRuntimeHeartbeatRequest(request);
  if (!valid.ok) throw new TypeError("RUNTIME_PUBLICATION_INVALID");
  const bytes = Buffer.from(canonicalRuntimePublicationJson(request), "utf8");
  if (bytes.length > RUNTIME_PUBLICATION_MAX_BYTES) {
    bytes.fill(0);
    throw new TypeError("RUNTIME_PUBLICATION_OVERSIZE");
  }
  return bytes;
}

export function buildRuntimePublicationAck(kind, request, recordId) {
  return Object.freeze({
    schema: RUNTIME_PUBLICATION_ACK_SCHEMA, accepted: true, kind,
    record_id: recordId, request_hash: request.request_hash,
    authority: "NONE", enforcement: "OFF", active: false,
  });
}

export function validateRuntimePublicationAck(value, kind, requestHash) {
  const found = exact(value, ACK_FIELDS);
  if (found === null) return false;
  const field = (name) => found[name].value;
  return field("schema") === RUNTIME_PUBLICATION_ACK_SCHEMA
    && field("accepted") === true && field("kind") === kind
    && typeof field("record_id") === "string" && SAFE_ID.test(field("record_id"))
    && field("request_hash") === requestHash && SHA256.test(field("request_hash"))
    && field("authority") === "NONE" && field("enforcement") === "OFF"
    && field("active") === false;
}

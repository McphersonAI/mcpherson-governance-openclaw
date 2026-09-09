import {
  SHADOW_ABSTRACT_DECISIONS,
  SHADOW_ACTIONS,
  SHADOW_RELEASE,
  SHADOW_RESPONSE_SCHEMA,
} from "./constants.mjs";

const SHA256 = /^sha256:[a-f0-9]{64}$/;
const SAFE_ID = /^[A-Za-z0-9._:-]{1,160}$/;
const DECISIONS = new Set(SHADOW_ABSTRACT_DECISIONS);

export class ShadowResponseError extends Error {
  constructor(code) {
    super(code);
    this.name = "ShadowResponseError";
    this.code = code;
  }
}

function fail(code) {
  throw new ShadowResponseError(code);
}

function exactApproval(value, decision) {
  if (decision !== "REQUIRE_APPROVAL") return value === null;
  return value
    && typeof value === "object"
    && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([
      "created", "held", "reason",
    ])
    && value.created === false
    && value.held === false
    && value.reason === "shadow_mode_no_approval";
}

export function validateShadowResponse(value, expected, decisionIds) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("NOT_OBJECT");
  const required = [
    "schema", "request_id", "request_hash", "decision_id", "abstract_decision",
    "reason_code", "deployment_id", "agent_id", "tool_id", "policy_bundle_hash",
    "engine_version", "evaluated_at", "authority", "enforcement", "active", "approval",
  ].sort();
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(required)) fail("FIELD_SET");
  if (value.schema !== SHADOW_RESPONSE_SCHEMA) fail("SCHEMA");
  if (value.request_id !== expected.request_id) fail("REQUEST_MISMATCH");
  if (value.request_hash !== expected.request_hash || !SHA256.test(value.request_hash)) {
    fail("REQUEST_HASH_MISMATCH");
  }
  if (value.deployment_id !== expected.deployment_id) fail("DEPLOYMENT_MISMATCH");
  if (value.agent_id !== expected.agent_id) fail("AGENT_MISMATCH");
  if (value.tool_id !== expected.tool_id) fail("TOOL_MISMATCH");
  if (typeof value.decision_id !== "string" || !SAFE_ID.test(value.decision_id)) fail("DECISION_ID");
  if (decisionIds.has(value.decision_id)) fail("DECISION_REPLAY");
  if (!DECISIONS.has(value.abstract_decision)) fail("DECISION_CLASS");
  if (typeof value.reason_code !== "string" || !SAFE_ID.test(value.reason_code)) fail("REASON_CODE");
  if (!SHA256.test(value.policy_bundle_hash)) fail("POLICY_BUNDLE_HASH");
  if (typeof value.engine_version !== "string" || !SAFE_ID.test(value.engine_version)) fail("ENGINE_VERSION");
  if (!Number.isFinite(Date.parse(value.evaluated_at))) fail("EVALUATED_AT");
  if (value.authority !== SHADOW_RELEASE.authority) fail("AUTHORITY_CLAIM");
  if (value.enforcement !== SHADOW_RELEASE.enforcement) fail("ENFORCEMENT_CLAIM");
  if (value.active !== SHADOW_RELEASE.active) fail("ACTIVE_CLAIM");
  if (!exactApproval(value.approval, value.abstract_decision)) fail("APPROVAL_AUTHORITY_CLAIM");
  decisionIds.add(value.decision_id);
  return Object.freeze({
    value: Object.freeze({ ...value }),
    action: SHADOW_ACTIONS[value.abstract_decision],
  });
}

export class ShadowDecisionWindow {
  #limit;
  #ids = new Set();
  constructor(limit) {
    this.#limit = limit;
  }
  has(id) { return this.#ids.has(id); }
  add(id) {
    this.#ids.add(id);
    while (this.#ids.size > this.#limit) this.#ids.delete(this.#ids.values().next().value);
  }
  get size() { return this.#ids.size; }
}

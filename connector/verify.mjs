import { API_VERSION, DECISIONS } from "./constants.mjs";
import { validateDecision } from "./runtime/governance-core/index.mjs";

const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const RECEIPT_REF = /^[A-Za-z0-9._:-]{1,160}$/;
const REQUIRED = Object.freeze([
  "api_version", "decision_id", "decision", "policy_id", "policy_version",
  "request_hash", "deployment_id", "agent_id", "tool_id", "issued_at", "expires_at",
  "reason_code", "approval_ref", "receipt_ref",
]);

export class ResponseValidationError extends Error {
  constructor(remoteStatus) {
    super(remoteStatus);
    this.code = remoteStatus;
    this.remoteStatus = remoteStatus;
  }
}

export class DecisionIdWindow {
  #limit;
  #ids = new Map();
  constructor(limit = 1024) { this.#limit = limit; }
  has(value) { return this.#ids.has(value); }
  add(value) {
    this.#ids.set(value, true);
    while (this.#ids.size > this.#limit) this.#ids.delete(this.#ids.keys().next().value);
  }
  clear() { this.#ids.clear(); }
  get size() { return this.#ids.size; }
}

function invalid(status) { throw new ResponseValidationError(status); }

export function verifyDecision(value, expected, { now = new Date(), decisionIds = new DecisionIdWindow() } = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid("INVALID_RESPONSE");
  if (value.api_version !== API_VERSION) invalid("UNSUPPORTED_VERSION");
  if (!validateDecision(value).ok) invalid("INVALID_RESPONSE");
  if (decisionIds.has(value.decision_id)) invalid("REPLAYED_DECISION");
  if (value.request_hash !== expected.requestHash) invalid("BINDING_MISMATCH:request_hash");
  if (value.deployment_id !== expected.deploymentId) invalid("BINDING_MISMATCH:deployment_id");
  if (value.agent_id !== expected.agentId) invalid("BINDING_MISMATCH:agent_id");
  if (value.tool_id !== expected.toolId) invalid("BINDING_MISMATCH:tool_id");
  const issuedAt = Date.parse(value.issued_at);
  const expiresAt = Date.parse(value.expires_at);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt || expiresAt - issuedAt > 60_000) invalid("INVALID_RESPONSE");
  if (expiresAt <= now.getTime()) invalid("STALE_DECISION");
  if (issuedAt > now.getTime() + 60_000) invalid("INVALID_RESPONSE");
  decisionIds.add(value.decision_id);
  return Object.freeze({ ...value });
}

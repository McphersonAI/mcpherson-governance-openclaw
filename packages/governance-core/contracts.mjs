import { ACTION_CLASSES } from "./classify.mjs";
import {
  DECISIONS,
  VALIDATION_REASON_VALUES,
} from "./policy-validate.mjs";
import { ERROR_CODES } from "./errors.mjs";
import { requestHash } from "./canonical.mjs";

export const API_VERSION = "mgp/1";
export const HASH_RE = /^sha256:[a-f0-9]{64}$/;
export const CORRELATION_REF_RE = /^sha256:(?:[a-f0-9]{24}|[a-f0-9]{64})$/;
export const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const ULID_RE = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
export const NONCE_RE = /^[a-f0-9]{32}$/;
export const RFC3339_UTC_RE = /^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(?:\.(\d{1,9}))?Z$/;
export const WIRE_SAFE_ID_RE = /^[A-Za-z0-9._:-]{1,96}$/;
export const WIRE_SAFE_LABEL_RE = /^[A-Za-z0-9._:-]{1,64}$/;
export const WIRE_SAFE_REF_RE = /^[A-Za-z0-9._:-]{1,128}$/;
export const VERSION_RE = /^[A-Za-z0-9._+-]{1,32}$/;
export const ERROR_CATEGORY_RE = /^[A-Z][A-Z0-9_]{0,63}$/;

export const APPROVAL_STATES = Object.freeze([
  "NOT_REQUIRED", "PENDING", "APPROVED", "DENIED", "EXPIRED",
]);
export const ATTEMPT_OUTCOMES = Object.freeze(["UNKNOWN", "NOT_OBSERVED"]);
export const COMPLETION_OUTCOMES = Object.freeze(["COMPLETED", "FAILED", "TIMED_OUT"]);
export const LOCAL_DISPOSITIONS = Object.freeze(["NONE", "BLOCKED_LOCAL", "SKIPPED"]);
export const REMOTE_STATUSES = Object.freeze([
  "OK", "TIMEOUT", "UNREACHABLE", "TLS_FAILURE", "AUTH_REJECTED",
  "INVALID_RESPONSE", "UNSUPPORTED_VERSION", "STALE_DECISION",
  "REPLAYED_DECISION", "DROPPED_SATURATED", "KILL_SWITCH_ACTIVE",
  "SYSTEM_LOCK_ACTIVE", "CIRCUIT_OPEN", "PRIVACY_GUARD_TRIPPED",
  "NOT_ATTEMPTED", "ABORTED_SHUTDOWN",
]);

export const DECISION_REASON_VALUES = Object.freeze([
  "rule_match", "default_decision", "stale_policy", "unexpected_policy_version",
  "policy_state_mismatch", "global_hold",
  "failsafe:missing", "failsafe:malformed_json", "failsafe:insecure_parent",
  "failsafe:wrong_parent_owner", "failsafe:not_regular_file",
  "failsafe:wrong_owner", "failsafe:insecure_permissions", "failsafe:oversize",
  "failsafe:unexpected_owner", "failsafe:unexpected_environment",
  "failsafe:symlink_refused", "failsafe:unreadable", "failsafe:internal_error",
  ...VALIDATION_REASON_VALUES.map((reason) => `failsafe:invalid:${reason}`),
]);

export const REQUEST_FIELDS = Object.freeze([
  "api_version", "request_id", "nonce", "timestamp", "agent_id", "tool_id",
  "tool_schema_version", "tool_schema_hash", "action_class", "resource_class",
  "recipient_type", "recipient_count", "attachment_indicator",
  "data_sensitivity_label", "reversibility_label", "request_hash",
  "policy_version", "correlation_ref",
]);
export const REQUEST_REQUIRED_FIELDS = Object.freeze([
  "api_version", "request_id", "nonce", "timestamp", "agent_id", "tool_id",
  "tool_schema_version", "tool_schema_hash", "action_class", "request_hash",
  "policy_version", "correlation_ref",
]);
export const DECISION_FIELDS = Object.freeze([
  "api_version", "decision_id", "decision", "policy_id", "policy_version",
  "request_hash", "deployment_id", "agent_id", "tool_id", "issued_at",
  "expires_at", "reason_code", "approval_ref", "receipt_ref",
]);
export const DECISION_RECEIPT_FIELDS = Object.freeze([
  "decision_id", "request_hash", "tenant_id", "deployment_id", "agent_id",
  "tool_id", "action_class", "policy_id", "policy_version", "decision",
  "approval_state", "issued_at", "expires_at", "reason_code", "correlation_ref",
]);
export const ATTEMPT_RECEIPT_FIELDS = Object.freeze([
  "receipt_id", "receipt_type", "decision_id", "request_hash", "deployment_id",
  "agent_id", "tool_id", "attempt_at", "outcome", "remote_status",
  "local_disposition", "timestamp", "correlation_ref",
]);
export const COMPLETION_RECEIPT_FIELDS = Object.freeze([
  "receipt_id", "receipt_type", "decision_id", "request_hash", "deployment_id",
  "agent_id", "tool_id", "completed_at", "outcome", "observation_basis",
  "timestamp", "correlation_ref", "error_category",
]);
export const EVIDENCE_FIELDS = Object.freeze([
  "schema", "evidence_id", "ts_utc", "producer_id", "producer_version", "kind",
  "receipt_mode", "hook_capability", "receipt",
]);
export const HOOK_CAPABILITY_FIELDS = Object.freeze([
  "inspection_status", "openclaw_version", "inspected_at",
  "before_tool_call_supported", "post_execution_hook_supported",
  "post_execution_hook_name", "direct_terminal_outcomes",
]);

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactFields(value, allowed, required = allowed) {
  if (!isPlainObject(value)) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) return false;
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !("value" in descriptor)) return false;
  }
  return keys.every((key) => allowed.includes(key))
    && required.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function isSafeId(value) {
  return typeof value === "string" && WIRE_SAFE_ID_RE.test(value);
}

function isSafeLabel(value) {
  return typeof value === "string" && WIRE_SAFE_LABEL_RE.test(value);
}

function isSafeRef(value) {
  return typeof value === "string" && WIRE_SAFE_REF_RE.test(value);
}

function isTimestamp(value) {
  if (typeof value !== "string" || value.length > 32) return false;
  const match = RFC3339_UTC_RE.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= days[month - 1];
}

function isReasonCode(value) {
  return DECISION_REASON_VALUES.includes(value);
}

function result(ok, code = null, field = null) {
  return ok
    ? Object.freeze({ ok: true })
    : Object.freeze({ ok: false, code, field });
}

export function validateDecisionRequest(value, options = {}) {
  const required = options.requireHash === false
    ? REQUEST_REQUIRED_FIELDS.filter((field) => field !== "request_hash")
    : REQUEST_REQUIRED_FIELDS;
  if (!hasExactFields(value, REQUEST_FIELDS, required)) {
    return result(false, "MGP_MALFORMED", null);
  }
  const checks = [
    [value.api_version === API_VERSION, "MGP_VERSION_UNSUPPORTED", "api_version"],
    [UUID_V4_RE.test(value.request_id), "MGP_MALFORMED", "request_id"],
    [NONCE_RE.test(value.nonce), "MGP_MALFORMED", "nonce"],
    [isTimestamp(value.timestamp), "MGP_MALFORMED", "timestamp"],
    [isSafeId(value.agent_id), "MGP_MALFORMED", "agent_id"],
    [isSafeId(value.tool_id), "MGP_MALFORMED", "tool_id"],
    [isSafeLabel(value.tool_schema_version), "MGP_MALFORMED", "tool_schema_version"],
    [HASH_RE.test(value.tool_schema_hash), "MGP_MALFORMED", "tool_schema_hash"],
    [ACTION_CLASSES.has(value.action_class), "MGP_MALFORMED", "action_class"],
    [Number.isInteger(value.policy_version) && value.policy_version >= 1,
      "MGP_MALFORMED", "policy_version"],
    [CORRELATION_REF_RE.test(value.correlation_ref), "MGP_MALFORMED", "correlation_ref"],
  ];
  if (options.requireHash !== false) {
    checks.push([HASH_RE.test(value.request_hash), "MGP_MALFORMED", "request_hash"]);
    checks.push([value.request_hash === requestHash(value), "MGP_HASH_MISMATCH", "request_hash"]);
  }
  for (const optionalId of [
    "resource_class", "recipient_type", "data_sensitivity_label", "reversibility_label",
  ]) {
    if (optionalId in value) {
      checks.push([isSafeLabel(value[optionalId]), "MGP_MALFORMED", optionalId]);
    }
  }
  if ("recipient_count" in value) {
    checks.push([Number.isInteger(value.recipient_count) && value.recipient_count >= 0
      && value.recipient_count <= 1_000_000,
      "MGP_MALFORMED", "recipient_count"]);
  }
  if ("attachment_indicator" in value) {
    checks.push([typeof value.attachment_indicator === "boolean",
      "MGP_MALFORMED", "attachment_indicator"]);
  }
  const failed = checks.find(([ok]) => !ok);
  return failed ? result(false, failed[1], failed[2]) : result(true);
}

export function createDecisionRequest(fields) {
  if (!isPlainObject(fields)) throw new TypeError("MGP_MALFORMED");
  const request = { ...fields };
  if (!("request_hash" in request)) request.request_hash = requestHash(request);
  const validation = validateDecisionRequest(request);
  if (!validation.ok) throw new TypeError(validation.code);
  return Object.freeze(request);
}

export function validateDecision(value) {
  if (!hasExactFields(value, DECISION_FIELDS)) return result(false, "MGP_MALFORMED", null);
  const policyPairNull = value.policy_id === null && value.policy_version === null;
  const policyPairSet = isSafeId(value.policy_id)
    && Number.isInteger(value.policy_version) && value.policy_version >= 1;
  const failsafe = typeof value.reason_code === "string"
    && value.reason_code.startsWith("failsafe:");
  const ok = value.api_version === API_VERSION
    && ULID_RE.test(value.decision_id)
    && DECISIONS.has(value.decision)
    && (policyPairNull || policyPairSet)
    && (failsafe
      ? policyPairNull && value.decision === "HOLD"
      : policyPairSet)
    && HASH_RE.test(value.request_hash)
    && isSafeId(value.deployment_id)
    && isSafeId(value.agent_id)
    && isSafeId(value.tool_id)
    && isTimestamp(value.issued_at)
    && isTimestamp(value.expires_at)
    && isReasonCode(value.reason_code)
    && (value.approval_ref === null || isSafeRef(value.approval_ref))
    && isSafeRef(value.receipt_ref);
  return result(ok, ok ? null : "MGP_MALFORMED", null);
}

export function validateDecisionReceipt(value) {
  if (!hasExactFields(value, DECISION_RECEIPT_FIELDS)) {
    return result(false, "MGP_MALFORMED", null);
  }
  const forbidden = ["outcome", "execution_outcome", "completed_at"];
  const policyPairNull = value.policy_id === null && value.policy_version === null;
  const policyPairSet = isSafeId(value.policy_id)
    && Number.isInteger(value.policy_version) && value.policy_version >= 1;
  const failsafe = typeof value.reason_code === "string"
    && value.reason_code.startsWith("failsafe:");
  const ok = !forbidden.some((field) => field in value)
    && ULID_RE.test(value.decision_id)
    && HASH_RE.test(value.request_hash)
    && [value.tenant_id, value.deployment_id, value.agent_id, value.tool_id,
    ].every(isSafeId)
    && (policyPairNull || policyPairSet)
    && (failsafe
      ? policyPairNull && value.decision === "HOLD"
      : policyPairSet)
    && ACTION_CLASSES.has(value.action_class)
    && DECISIONS.has(value.decision)
    && APPROVAL_STATES.includes(value.approval_state)
    && isTimestamp(value.issued_at) && isTimestamp(value.expires_at)
    && isReasonCode(value.reason_code)
    && CORRELATION_REF_RE.test(value.correlation_ref);
  return result(ok, ok ? null : "MGP_MALFORMED", null);
}

export function validateAttemptReceipt(value) {
  if (!hasExactFields(value, ATTEMPT_RECEIPT_FIELDS)) {
    return result(false, "MGP_MALFORMED", null);
  }
  const ok = ULID_RE.test(value.receipt_id)
    && value.receipt_type === "attempt_receipt"
    && (value.decision_id === null || ULID_RE.test(value.decision_id))
    && HASH_RE.test(value.request_hash)
    && [value.deployment_id, value.agent_id, value.tool_id].every(isSafeId)
    && isTimestamp(value.attempt_at)
    && ATTEMPT_OUTCOMES.includes(value.outcome)
    && (REMOTE_STATUSES.includes(value.remote_status)
      || /^HTTP_ERROR:[45]\d{2}$/.test(value.remote_status)
      || [
        "BINDING_MISMATCH:request_hash", "BINDING_MISMATCH:deployment_id",
        "BINDING_MISMATCH:agent_id", "BINDING_MISMATCH:tool_id",
      ].includes(value.remote_status))
    && LOCAL_DISPOSITIONS.includes(value.local_disposition)
    && isTimestamp(value.timestamp)
    && CORRELATION_REF_RE.test(value.correlation_ref);
  return result(ok, ok ? null : "MGP_MALFORMED", null);
}

export function validateCompletionReceipt(value) {
  if (!hasExactFields(
    value,
    COMPLETION_RECEIPT_FIELDS,
    COMPLETION_RECEIPT_FIELDS.filter((field) => field !== "error_category"),
  )) {
    return result(false, "MGP_MALFORMED", null);
  }
  const ok = ULID_RE.test(value.receipt_id)
    && value.receipt_type === "completion_receipt"
    && (value.decision_id === null || ULID_RE.test(value.decision_id))
    && HASH_RE.test(value.request_hash)
    && [value.deployment_id, value.agent_id, value.tool_id].every(isSafeId)
    && isTimestamp(value.completed_at)
    && COMPLETION_OUTCOMES.includes(value.outcome)
    && value.observation_basis === "DIRECT_SUPPORTED_POST_HOOK"
    && isTimestamp(value.timestamp)
    && CORRELATION_REF_RE.test(value.correlation_ref)
    && (!("error_category" in value) || ERROR_CATEGORY_RE.test(value.error_category));
  return result(ok, ok ? null : "MGP_MALFORMED", null);
}

function validateHookCapability(value, receiptMode) {
  if (!hasExactFields(value, HOOK_CAPABILITY_FIELDS)) return false;
  const common = value.inspection_status === "CONFIRMED"
    && VERSION_RE.test(value.openclaw_version)
    && isTimestamp(value.inspected_at)
    && value.before_tool_call_supported === true;
  if (!common) return false;
  if (receiptMode === "ATTEMPT_ONLY") {
    return value.post_execution_hook_supported === false
      && value.post_execution_hook_name === null
      && Array.isArray(value.direct_terminal_outcomes)
      && value.direct_terminal_outcomes.length === 0;
  }
  return receiptMode === "POST_HOOK"
    && value.post_execution_hook_supported === true
    && isSafeId(value.post_execution_hook_name)
    && Array.isArray(value.direct_terminal_outcomes)
    && value.direct_terminal_outcomes.length === COMPLETION_OUTCOMES.length
    && value.direct_terminal_outcomes.every(
      (outcome, index) => outcome === COMPLETION_OUTCOMES[index],
    );
}

export function validateEvidenceRecord(value) {
  if (!hasExactFields(value, EVIDENCE_FIELDS)) {
    return result(false, "MGP_MALFORMED", null);
  }
  if (value.schema !== "mcpherson-governance-evidence/v2"
      || !ULID_RE.test(value.evidence_id)
      || !isTimestamp(value.ts_utc)
      || !isSafeId(value.producer_id)
      || !VERSION_RE.test(value.producer_version)
      || !["decision_receipt", "attempt_receipt", "completion_receipt"].includes(value.kind)
      || !["POST_HOOK", "ATTEMPT_ONLY"].includes(value.receipt_mode)
      || !validateHookCapability(value.hook_capability, value.receipt_mode)) {
    return result(false, "MGP_MALFORMED", null);
  }
  if (value.receipt_mode === "ATTEMPT_ONLY" && value.kind === "completion_receipt") {
    return result(false, "MGP_MALFORMED", null);
  }
  const receiptValidation = value.kind === "decision_receipt"
    ? validateDecisionReceipt(value.receipt)
    : value.kind === "attempt_receipt"
      ? validateAttemptReceipt(value.receipt)
      : validateCompletionReceipt(value.receipt);
  return receiptValidation.ok ? result(true) : result(false, "MGP_MALFORMED", "receipt");
}

export function validateErrorCode(value) {
  return ERROR_CODES.includes(value);
}

function constructRecord(fields, validateRecord) {
  if (!isPlainObject(fields)) throw new TypeError("MGP_MALFORMED");
  const record = { ...fields };
  const validation = validateRecord(record);
  if (!validation.ok) throw new TypeError(validation.code);
  return Object.freeze(record);
}

export function createDecision(fields) {
  return constructRecord(fields, validateDecision);
}

export function createDecisionReceipt(fields) {
  return constructRecord(fields, validateDecisionReceipt);
}

export function createAttemptReceipt(fields) {
  return constructRecord(fields, validateAttemptReceipt);
}

export function createCompletionReceipt(fields) {
  return constructRecord(fields, validateCompletionReceipt);
}

export function createEvidenceRecord(fields) {
  return constructRecord(fields, validateEvidenceRecord);
}

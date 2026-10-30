import { PolicyValidationError } from "./errors.mjs";
import { ACTION_CLASSES } from "./classify.mjs";

export const POLICY_SCHEMA = "mcpherson-enforcement-policy/v1";
export const POLICY_ID = "mcpherson-enforcement-policy-v3";
export const POLICY_VERSION = 3;
export const MAX_POLICY_BYTES = 65536;

export const DECISION_VALUES = Object.freeze([
  "ALLOW", "ALLOW_AND_LOG", "REQUIRE_APPROVAL", "DENY", "SHADOW_ONLY", "HOLD",
]);
export const DECISIONS = new Set(DECISION_VALUES);
export const EFFECTIVE_STATES = new Set(["dry_run", "active", "hold"]);
export const RUNTIME_MODES = new Set(["dry_run", "active"]);
export const SAFE_DEFAULT_DECISIONS = new Set(["SHADOW_ONLY", "HOLD"]);
export const SAFE_ID_PATTERN = "^[A-Za-z0-9._:*-]{1,96}$";
export const SAFE_ID_RE = new RegExp(SAFE_ID_PATTERN);

export const FORBIDDEN_ACTIVATION_FIELDS = new Set([
  "ACTIVE_CLASSES", "ACTIVE_CLASS_DECISIONS", "activeClasses",
  "activeClassDecisions", "active_classes", "active_class_decisions",
  "allowActiveEnforcement", "allow_active_enforcement",
]);

export const VALIDATION_REASON_VALUES = Object.freeze([
  "not_object", "bad_schema", "bad_policy_id", "bad_version", "bad_state",
  "bad_default", "bad_failsafe", "bad_owner", "bad_environment",
  "rules_not_list", "bad_rule", "bad_rule_decision", "bad_rule_field",
  "duplicate_rule_id", "bad_rule_class", "bad_rule_effective",
  "bad_rule_approval_required", "bad_rule_evidence_required",
  "forbidden_activation_field",
]);
export const VALIDATION_REASONS = new Set(VALIDATION_REASON_VALUES);

export const LOAD_FAILURE_REASON_VALUES = Object.freeze([
  "missing", "symlink_refused", "unreadable", "oversize", "insecure_parent",
  "wrong_parent_owner", "not_regular_file", "wrong_owner",
  "insecure_permissions", "unexpected_owner", "unexpected_environment",
  "malformed_json",
  ...VALIDATION_REASON_VALUES.map((reason) => `invalid:${reason}`),
]);

function validationError(code) {
  return new PolicyValidationError(code);
}

/**
 * Validate the policy shape with the exact v0.4.1 ordering and reason codes.
 * The expected policy id is parameterized for a server-selected deployment
 * mapping; omitting it preserves the frozen v0.4.1 expectation.
 */
export function validatePolicy(doc, options = {}) {
  const expectedPolicyId = options.expectedPolicyId ?? POLICY_ID;
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    throw validationError("not_object");
  }
  if (Object.keys(doc).some((key) => FORBIDDEN_ACTIVATION_FIELDS.has(key))) {
    throw validationError("forbidden_activation_field");
  }
  if (doc.schema !== POLICY_SCHEMA) throw validationError("bad_schema");
  if (doc.policy_id !== expectedPolicyId) throw validationError("bad_policy_id");
  if (!Number.isInteger(doc.policy_version) || doc.policy_version < 1) {
    throw validationError("bad_version");
  }
  if (!EFFECTIVE_STATES.has(doc.effective_state)) {
    throw validationError("bad_state");
  }
  if (!SAFE_DEFAULT_DECISIONS.has(doc.default_decision)) {
    throw validationError("bad_default");
  }
  if (doc.failsafe_decision !== "HOLD") {
    throw validationError("bad_failsafe");
  }
  if (typeof doc.owner !== "string" || !SAFE_ID_RE.test(doc.owner)) {
    throw validationError("bad_owner");
  }
  if (typeof doc.environment !== "string" || !SAFE_ID_RE.test(doc.environment)) {
    throw validationError("bad_environment");
  }
  if (!Array.isArray(doc.rules)) throw validationError("rules_not_list");

  const ids = new Set();
  for (const rule of doc.rules) {
    if (!rule || typeof rule !== "object" || Array.isArray(rule)) {
      throw validationError("bad_rule");
    }
    if (Object.keys(rule).some((key) => FORBIDDEN_ACTIVATION_FIELDS.has(key))) {
      throw validationError("forbidden_activation_field");
    }
    if (!DECISIONS.has(rule.decision)) {
      throw validationError("bad_rule_decision");
    }
    for (const key of ["id", "agent_id", "tool", "action_class"]) {
      if (typeof rule[key] !== "string" || !SAFE_ID_RE.test(rule[key])) {
        throw validationError("bad_rule_field");
      }
    }
    if (ids.has(rule.id)) throw validationError("duplicate_rule_id");
    ids.add(rule.id);
    if (rule.action_class !== "*" && !ACTION_CLASSES.has(rule.action_class)) {
      throw validationError("bad_rule_class");
    }
    if ("effective" in rule && typeof rule.effective !== "boolean") {
      throw validationError("bad_rule_effective");
    }
    if ("approval_required" in rule
        && typeof rule.approval_required !== "boolean") {
      throw validationError("bad_rule_approval_required");
    }
    if ("evidence_required" in rule
        && typeof rule.evidence_required !== "boolean") {
      throw validationError("bad_rule_evidence_required");
    }
  }
  return doc;
}

// Compatibility alias for the source-map vocabulary.
export const validate = validatePolicy;

export function staticFailureReason(error) {
  if (error instanceof SyntaxError) return "malformed_json";
  const validationCode = error && error.policyValidationCode;
  if (VALIDATION_REASONS.has(validationCode)) {
    return `invalid:${validationCode}`;
  }
  const code = error && typeof error.code === "string" ? error.code : "";
  if (code === "ENOENT") return "missing";
  if (code === "ELOOP") return "symlink_refused";
  if (code === "EACCES" || code === "EPERM") return "unreadable";
  return "unreadable";
}

function inspectExpectations(doc, options) {
  const expectedVersion = options.expectedVersion === undefined
    ? POLICY_VERSION
    : options.expectedVersion;
  const expectedOwner = options.expectedOwner === undefined
    ? "blake"
    : options.expectedOwner;
  const expectedEnvironment = options.expectedEnvironment === undefined
    ? "production"
    : options.expectedEnvironment;

  if (doc.owner !== expectedOwner) {
    return { ok: false, reason: "unexpected_owner" };
  }
  if (doc.environment !== expectedEnvironment) {
    return { ok: false, reason: "unexpected_environment" };
  }
  const stale = expectedVersion != null && doc.policy_version < expectedVersion;
  const unexpectedVersion =
    expectedVersion != null && doc.policy_version > expectedVersion;
  return {
    ok: true,
    doc,
    reason: "ok",
    stale,
    unexpected_version: unexpectedVersion,
  };
}

/** Pure object counterpart to the frozen file loader's validation half. */
export function loadPolicyObject(doc, options = {}) {
  try {
    return inspectExpectations(validatePolicy(doc, options), options);
  } catch (error) {
    return { ok: false, reason: staticFailureReason(error) };
  }
}

function decodePolicyBytes(bytes) {
  if (typeof bytes === "string") {
    const encoded = new TextEncoder().encode(bytes);
    return encoded.byteLength > MAX_POLICY_BYTES
      ? { ok: false, reason: "oversize" }
      : { ok: true, text: bytes };
  }
  if (bytes instanceof Uint8Array) {
    return bytes.byteLength > MAX_POLICY_BYTES
      ? { ok: false, reason: "oversize" }
      // ignoreBOM:true keeps a leading U+FEFF in the decoded text, matching
      // Buffer#toString in the frozen loader (and therefore JSON.parse rejects
      // it as malformed rather than silently stripping it).
      : { ok: true, text: new TextDecoder("utf-8", { ignoreBOM: true }).decode(bytes) };
  }
  return { ok: false, reason: "unreadable" };
}

/**
 * Pure bytes-to-policy loader. Filesystem ownership/mode checks stay outside
 * the core; their deterministic failure reasons remain valid evaluate inputs.
 */
export function loadPolicyDocument(bytes, options = {}) {
  const decoded = decodePolicyBytes(bytes);
  if (!decoded.ok) return decoded;
  try {
    return loadPolicyObject(JSON.parse(decoded.text), options);
  } catch (error) {
    return { ok: false, reason: staticFailureReason(error) };
  }
}

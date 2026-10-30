// v0.7 enforcement vocabulary.
//
// The sealed mgp/1 wire decision enum is IMPORTED from the frozen v0.5
// governance-core, never redefined here (D1, decision contract §1.2). The
// abstract decision layer, the decision_permit signal, and the enforcement
// reason-code enum are NEW v0.7 vocabulary carried ALONGSIDE the wire value —
// not a parallel wire enum and not a modification of any frozen byte.
//
// The enforcement reason-code enum is a superset, by value, of the frozen v0.5
// DECISION_REASON_VALUES: the frozen array is imported and spread, then
// enforcement-specific reasons are added. The frozen bytes are not modified.

import { DECISION_VALUES as WIRE_DECISION_VALUES }
  from "../governance-core/policy-validate.mjs";
import { DECISION_REASON_VALUES }
  from "../governance-core/contracts.mjs";

export const ENFORCEMENT_ENGINE_VERSION = "0.7.0";

// The single fixed evaluation mode for every live v0.7 schema and evaluation.
// SHADOW / ACTIVE / LIVE_SHADOW are NOT accepted values anywhere in v0.7.
export const EVALUATION_MODE = "SIMULATION";

// Non-authority constants (schema-fixed on every record).
export const AUTHORITY_NONE = "NONE";
export const RUNTIME_ACTIVE = false;
export const ENFORCEMENT_ELIGIBLE = false;

// Unsigned integrity-evidence honesty constants (D4).
export const AUTHENTICATION_NONE = "NONE";
export const SIGNED = false;

// Re-export the sealed wire enum for consumers (imported, never redefined).
export { WIRE_DECISION_VALUES };
export const WIRE_DECISIONS = new Set(WIRE_DECISION_VALUES);

// The six abstract decision values (decision contract §1.1).
export const ABSTRACT_DECISION_VALUES = Object.freeze([
  "ALLOW", "DENY", "REQUIRE_APPROVAL", "ABSTAIN", "INDETERMINATE", "ERROR",
]);
export const ABSTRACT_DECISIONS = new Set(ABSTRACT_DECISION_VALUES);

// The subset of abstract decisions a policy rule or default may CONTRIBUTE.
// INDETERMINATE and ERROR are never rule outcomes; they arise from evaluation
// failure, not from a rule or the lattice (architecture §3.5).
export const CONTRIBUTABLE_DECISION_VALUES = Object.freeze([
  "ALLOW", "DENY", "REQUIRE_APPROVAL", "ABSTAIN",
]);
export const CONTRIBUTABLE_DECISIONS = new Set(CONTRIBUTABLE_DECISION_VALUES);

// Allowed bundle defaults (D2): ALLOW-by-default is prohibited.
export const ALLOWED_DEFAULT_DECISION_VALUES = Object.freeze([
  "DENY", "REQUIRE_APPROVAL", "ABSTAIN",
]);
export const ALLOWED_DEFAULT_DECISIONS = new Set(ALLOWED_DEFAULT_DECISION_VALUES);

// Most-restrictive decision lattice (D3): DENY > REQUIRE_APPROVAL > ABSTAIN >
// ALLOW. Lower rank = more restrictive = wins.
export const DECISION_LATTICE_ORDER = Object.freeze([
  "DENY", "REQUIRE_APPROVAL", "ABSTAIN", "ALLOW",
]);
const LATTICE_RANK = new Map(
  DECISION_LATTICE_ORDER.map((value, index) => [value, index]),
);
export function latticeRank(decision) {
  return LATTICE_RANK.has(decision) ? LATTICE_RANK.get(decision) : -1;
}

export const CONFLICT_STRATEGY_VALUES = Object.freeze(["lattice", "strict"]);
export const CONFLICT_STRATEGIES = new Set(CONFLICT_STRATEGY_VALUES);

// Approval staleness classification (decision contract §3.3).
export const APPROVAL_STALENESS_VALUES = Object.freeze([
  "FRESH", "STALE", "MISSING", "EXPIRED", "MISMATCH", "UNVERIFIABLE",
  "REPLAYED",
]);
export const APPROVAL_STALENESSES = new Set(APPROVAL_STALENESS_VALUES);

// Comparison classifications (simulation compare.mjs).
export const COMPARISON_RESULT_VALUES = Object.freeze([
  "MATCH", "DECISION_MISMATCH", "PERMIT_MISMATCH", "REASON_MISMATCH",
  "EVALUATION_ERROR",
]);

// Provenance for fixtures/replays. v0.7 has NO live provenance.
export const PROVENANCE_VALUES = Object.freeze(["FIXTURE", "REPLAY"]);
export const PROVENANCES = new Set(PROVENANCE_VALUES);

// Enforcement reason-code enum: a superset, BY VALUE, of the frozen v0.5
// DECISION_REASON_VALUES (imported + spread), plus enforcement-specific
// reasons. Reason codes never contain free text (ERROR_CATEGORY-style shapes
// and colon-scoped families only).
export const ENFORCEMENT_REASON_VALUES = Object.freeze([
  ...DECISION_REASON_VALUES,
  // no-match / abstain
  "no_matching_policy_abstain",
  // conflict
  "conflict_unresolved",
  // approvals
  "approval_required",
  "approval_satisfied",
  "approval_missing",
  "approval_stale",
  "approval_expired",
  "approval_mismatch",
  "approval_unverifiable",
  "approval_untrusted",
  "approval_replayed",
  // context / consistency
  "effects_action_class_mismatch",
  // budgets / engine
  "budget_exceeded",
  "engine_range_unsupported",
  // safety states (modeled)
  "kill_switch_active",
  "system_lock_active",
  "circuit_open",
  // evidence rederivation
  "decision_permit_unsupported_by_policy",
  // enforcement oversize / invalid families (additive to failsafe:invalid:*)
  "failsafe:invalid:oversize:bundle",
  "failsafe:invalid:oversize:rules",
  "failsafe:invalid:oversize:predicates",
  "failsafe:invalid:oversize:envelope",
  "failsafe:invalid:oversize:metadata",
  "failsafe:invalid:oversize:metadata_key",
  "failsafe:invalid:oversize:metadata_value",
  "failsafe:invalid:oversize:set",
  "failsafe:invalid:oversize:segment",
  "failsafe:invalid:oversize:replay_records",
  "failsafe:invalid:oversize:replay_bytes",
  "failsafe:invalid:approval_ttl",
  "failsafe:invalid:bundle_schema",
  "failsafe:invalid:envelope_schema",
  "failsafe:invalid:approval_input",
  "failsafe:invalid:missing_default",
  "failsafe:invalid:bad_matcher",
  "failsafe:invalid:bad_engine_range",
  "failsafe:invalid:privacy_screen",
  "failsafe:invalid:request_hash",
  "failsafe:invalid:model_field",
  "failsafe:invalid:evaluation_mode",
  "failsafe:invalid:evaluation_context",
  "failsafe:invalid:timestamp_order",
  "failsafe:invalid:bundle_hash",
  "failsafe:invalid:duplicate_rule_id",
  "failsafe:invalid:internal_error",
]);
export const ENFORCEMENT_REASONS = new Set(ENFORCEMENT_REASON_VALUES);

// Context-scoped reason family: context_missing:<field>. The base is enumerated
// so callers can build the field-scoped value deterministically.
export const CONTEXT_MISSING_PREFIX = "context_missing:";
export function contextMissingReason(field) {
  return `${CONTEXT_MISSING_PREFIX}${field}`;
}
export function isEnforcementReason(value) {
  if (typeof value !== "string") return false;
  if (ENFORCEMENT_REASONS.has(value)) return true;
  return value.startsWith(CONTEXT_MISSING_PREFIX)
    && /^[a-z0-9_]{1,64}$/.test(value.slice(CONTEXT_MISSING_PREFIX.length));
}

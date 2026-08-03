// Typed positive-value vocabulary for Governor evidence.
//
// Sol re-audit finding: a finite negative-phrase blacklist is not a truth
// test. Free text such as "evidence lacks confirmation" passed an
// identifier value class that allowed spaces. The fix is to drive semantics
// from TYPED values: strict identifiers, positive state enums, flags,
// calendar timestamps, and per-field POSITIVE-ASSERTION enums. A value that
// is not a recognized positive assertion for its field is unusable — it
// cannot be relabeled into support. This module defines those typed value
// classes; the sensitive-value / negative-marker guard remains only as a
// secondary defense, not the main truth test.

import { isCalendarUtcTimestamp } from "./schema-validate.mjs";

// A strict identifier token: no spaces, must start and end alphanumeric.
// "evidence lacks confirmation" fails (spaces); "agent-alpha" passes.
export const STRICT_IDENTIFIER_RE =
  /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,94}[A-Za-z0-9])?$/;

// Per-field positive-assertion enums. A proof field's value must be one of a
// small set of positive tokens; a negative or free-text value is not in the
// set and is therefore unusable. Tokens are deliberately terse and typed.
export const POSITIVE_ASSERTIONS = Object.freeze({
  // VISIBLE
  "VISIBLE.enabled_state": new Set(["enabled"]),
  // ATTRIBUTABLE proof-bearing identity references
  "ATTRIBUTABLE.run_id": "identifier",
  "ATTRIBUTABLE.request_id": "identifier",
  // Relevance is itself a required typed fact. `false` is not negative
  // evidence: it is an explicit, cited assertion that the conditional proof
  // does not apply. Omission remains missing evidence.
  "ATTRIBUTABLE.executor_relevant": new Set(["false", "true"]),
  // SCOPED proof fields
  "SCOPED.parameter_constraints": new Set([
    "schema_enforced", "constrained", "parameters_constrained",
  ]),
  "SCOPED.limits": new Set([
    "bounded", "rate_bounded", "count_bounded", "spend_bounded",
    "rate_and_count_bounded",
  ]),
  "SCOPED.expiry": new Set(["expiry_set", "expires"]),
  "SCOPED.source_state_relevant": new Set(["false", "true"]),
  "SCOPED.source_state_preconditions": new Set([
    "preconditions_enforced", "source_state_checked",
  ]),
  // INDEPENDENTLY_REVOCABLE layers
  "INDEPENDENTLY_REVOCABLE.administrative_claim": new Set([
    "documented", "procedure_documented", "config_flag_documented",
    "revocation_documented",
  ]),
  "INDEPENDENTLY_REVOCABLE.authoritative_revocation_state": new Set([
    "state_resolvable", "resolvable", "authoritative_state_available",
  ]),
  "INDEPENDENTLY_REVOCABLE.execution_time_revocation_check": new Set([
    "checked_per_call", "checked_before_execution", "revalidated_per_call",
  ]),
  "INDEPENDENTLY_REVOCABLE.observed_refusal_evidence": new Set([
    "refusal_observed", "post_revocation_refusal_recorded", "drill_refusal_recorded",
  ]),
});

// Value class per field key ("criterion.field"). identifier fields accept a
// strict identifier token; timestamp fields a calendar UTC time; the rest are
// governed by POSITIVE_ASSERTIONS.
export const FIELD_VALUE_CLASS = Object.freeze({
  "VISIBLE.stable_identity": "identifier",
  "VISIBLE.owner": "identifier",
  "VISIBLE.tenant": "identifier",
  "VISIBLE.source": "identifier",
  "VISIBLE.enabled_state": "positive_assertion",
  "VISIBLE.runtime_association": "identifier",
  "VISIBLE.last_seen_at": "timestamp",
  "ATTRIBUTABLE.human_owner": "identifier",
  "ATTRIBUTABLE.agent_identity": "identifier",
  "ATTRIBUTABLE.runtime_identity": "identifier",
  "ATTRIBUTABLE.tenant": "identifier",
  "ATTRIBUTABLE.connector_or_grant_identity": "identifier",
  "ATTRIBUTABLE.run_id": "identifier",
  "ATTRIBUTABLE.request_id": "identifier",
  "ATTRIBUTABLE.executor_relevant": "positive_assertion",
  "ATTRIBUTABLE.executor_identity": "identifier",
  "SCOPED.permitted_action": "identifier",
  "SCOPED.target_or_resource": "identifier",
  "SCOPED.parameter_constraints": "positive_assertion",
  "SCOPED.tenant": "identifier",
  "SCOPED.limits": "positive_assertion",
  "SCOPED.expiry": "positive_assertion",
  "SCOPED.policy_version": "identifier",
  "SCOPED.source_state_relevant": "positive_assertion",
  "SCOPED.source_state_preconditions": "positive_assertion",
  "INDEPENDENTLY_REVOCABLE.administrative_claim": "positive_assertion",
  "INDEPENDENTLY_REVOCABLE.authoritative_revocation_state": "positive_assertion",
  "INDEPENDENTLY_REVOCABLE.execution_time_revocation_check": "positive_assertion",
  "INDEPENDENTLY_REVOCABLE.observed_refusal_evidence": "positive_assertion",
});

/**
 * Decide whether a typed value positively supports `criterion.field`.
 * Returns null when acceptable, or a deterministic reason string. This is the
 * typed truth test; it does not consult any phrase blacklist.
 */
export function positiveValueReason(criterion, fieldName, value) {
  const key = `${criterion}.${fieldName}`;
  const valueClass = FIELD_VALUE_CLASS[key];
  if (valueClass === undefined) return "field_not_typed";
  if (typeof value !== "string" || value.length === 0 || value.length > 256
      || /[\r\n]/.test(value)) {
    return "value_malformed";
  }
  if (valueClass === "identifier") {
    return STRICT_IDENTIFIER_RE.test(value) ? null : "value_not_strict_identifier";
  }
  if (valueClass === "timestamp") {
    return isCalendarUtcTimestamp(value) ? null : "value_not_calendar_timestamp";
  }
  if (valueClass === "positive_assertion") {
    const accepted = POSITIVE_ASSERTIONS[key];
    if (accepted === "identifier") {
      return STRICT_IDENTIFIER_RE.test(value) ? null : "value_not_strict_identifier";
    }
    if (accepted instanceof Set) {
      return accepted.has(value) ? null : "value_not_positive_assertion";
    }
    return "field_not_typed";
  }
  return "field_not_typed";
}

export function isTypedField(criterion, fieldName) {
  return FIELD_VALUE_CLASS[`${criterion}.${fieldName}`] !== undefined;
}

/**
 * A canonical valid positive value for a field, used to construct valid
 * evidence (fixtures and tests). Returns null for an untyped field.
 */
export function samplePositiveValue(criterion, fieldName, sampleTimestamp = "2026-07-20T00:00:00Z") {
  const key = `${criterion}.${fieldName}`;
  const valueClass = FIELD_VALUE_CLASS[key];
  if (valueClass === undefined) return null;
  if (valueClass === "identifier") return "sample-identifier-1";
  if (valueClass === "timestamp") return sampleTimestamp;
  if (valueClass === "positive_assertion") {
    const accepted = POSITIVE_ASSERTIONS[key];
    if (accepted === "identifier") return "sample-identifier-1";
    if (accepted instanceof Set) return [...accepted][0];
  }
  return null;
}

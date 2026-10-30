// v0.7 declarative, bounded policy matching (D5).
//
// The permitted predicate set is exactly: equality (eq), enum/set membership
// (in), and bounded numeric comparison (lt, lte, gt, gte, range) over
// EXPLICITLY TYPED numeric envelope fields only. Regex, free-text expressions,
// executable/code predicates, model-generated predicates, and any interpretation
// of argument BODIES are structurally impossible: there is no interpreter, and
// matchers read only whitelisted, typed envelope fields. Matching is decidable,
// side-effect-free, and O(1) per predicate.

import { MAX_SET_CARDINALITY } from "./bounds.mjs";

// Whitelisted matchable envelope fields and their value class. A field not in
// this table cannot be matched at all. `number` fields are the ONLY operands
// eligible for numeric comparison.
export const MATCHABLE_FIELD_TYPES = Object.freeze({
  action_class: "string",
  resource_class: "string",
  resource_scope: "string",
  actor_type: "string",
  agent_id: "string",
  actor_id: "string",
  on_behalf_of: "string",
  tool_id: "string",
  operation: "string",
  tenant_id: "string",
  workspace_id: "string",
  resource_ref: "string",
  data_sensitivity_label: "string",
  reversibility_label: "string",
  recipient_type: "string",
  risk_tier: "string",
  approval_state: "string",
  attachment_indicator: "boolean",
  recipient_count: "number",
});

export const NUMERIC_OPS = new Set(["lt", "lte", "gt", "gte", "range"]);
export const ALL_OPS = new Set(["eq", "in", "lt", "lte", "gt", "gte", "range"]);

function isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

/**
 * Semantic validation of ONE predicate against the whitelist and per-op operand
 * rules. Returns null when valid, or a deterministic reason detail otherwise.
 */
export function validatePredicate(predicate) {
  if (!predicate || typeof predicate !== "object" || Array.isArray(predicate)) {
    return { rule: "predicate_not_object" };
  }
  const { field, op, value } = predicate;
  const fieldType = MATCHABLE_FIELD_TYPES[field];
  if (fieldType === undefined) return { rule: "field_not_matchable", field };
  if (!ALL_OPS.has(op)) return { rule: "op_unknown", op };
  if (NUMERIC_OPS.has(op) && fieldType !== "number") {
    return { rule: "numeric_op_on_non_numeric_field", field, op };
  }
  if (op === "eq") {
    if (fieldType === "number" && !isFiniteNumber(value)) return { rule: "eq_value_type", field };
    if (fieldType === "string" && typeof value !== "string") return { rule: "eq_value_type", field };
    if (fieldType === "boolean" && typeof value !== "boolean") return { rule: "eq_value_type", field };
    return null;
  }
  if (op === "in") {
    if (!Array.isArray(value)) return { rule: "in_value_not_array", field };
    if (value.length < 1 || value.length > MAX_SET_CARDINALITY) {
      return { rule: "failsafe:invalid:oversize:set", field, size: value.length };
    }
    for (const element of value) {
      if (fieldType === "number" && !isFiniteNumber(element)) return { rule: "in_element_type", field };
      if (fieldType === "string" && typeof element !== "string") return { rule: "in_element_type", field };
      if (fieldType === "boolean" && typeof element !== "boolean") return { rule: "in_element_type", field };
    }
    return null;
  }
  if (op === "range") {
    if (!value || typeof value !== "object" || Array.isArray(value)) return { rule: "range_value_shape", field };
    const keys = Object.keys(value).sort();
    if (keys.length !== 2 || keys[0] !== "max" || keys[1] !== "min") return { rule: "range_value_shape", field };
    if (!isFiniteNumber(value.min) || !isFiniteNumber(value.max)) return { rule: "range_bound_type", field };
    if (value.min > value.max) return { rule: "range_min_gt_max", field };
    return null;
  }
  // lt/lte/gt/gte
  if (!isFiniteNumber(value)) return { rule: "numeric_operand_type", field, op };
  return null;
}

// Evaluation of one predicate. Returns "MATCH", "NO_MATCH", or "ABSENT" (the
// referenced field is not present on the envelope). ABSENT never contributes a
// match (fail-closed); the evaluator decides whether an absent REQUIRED context
// field escalates to INDETERMINATE via the bundle's required_context list.
export function evaluatePredicate(predicate, envelope) {
  const { field, op, value } = predicate;
  if (!Object.prototype.hasOwnProperty.call(envelope, field) || envelope[field] === undefined) {
    return "ABSENT";
  }
  const actual = envelope[field];
  let matched = false;
  switch (op) {
    case "eq": matched = actual === value; break;
    case "in": matched = Array.isArray(value) && value.includes(actual); break;
    case "lt": matched = isFiniteNumber(actual) && actual < value; break;
    case "lte": matched = isFiniteNumber(actual) && actual <= value; break;
    case "gt": matched = isFiniteNumber(actual) && actual > value; break;
    case "gte": matched = isFiniteNumber(actual) && actual >= value; break;
    case "range":
      matched = isFiniteNumber(actual) && actual >= value.min && actual <= value.max;
      break;
    default: matched = false;
  }
  return matched ? "MATCH" : "NO_MATCH";
}

/**
 * Evaluate a rule's `match` (conjunction of predicates) against an envelope.
 * Returns `{ matched, steps, absentFields }`. A rule matches only when EVERY
 * predicate is MATCH. Any ABSENT or NO_MATCH predicate makes the rule not match;
 * absent fields are reported so the evaluator can honor required_context.
 * `steps` counts one per predicate evaluated (bounded work accounting).
 */
export function evaluateMatch(match, envelope) {
  const predicates = match?.all ?? [];
  let matched = true;
  let steps = 0;
  const absentFields = [];
  for (const predicate of predicates) {
    steps += 1;
    const outcome = evaluatePredicate(predicate, envelope);
    if (outcome === "ABSENT") {
      matched = false;
      absentFields.push(predicate.field);
    } else if (outcome === "NO_MATCH") {
      matched = false;
    }
  }
  return { matched, steps, absentFields };
}

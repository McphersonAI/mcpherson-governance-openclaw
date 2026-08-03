// Governability Governor: deterministic diagnosis of whether connectors and
// capabilities are (1) visible, (2) attributable, (3) scoped, and
// (4) independently revocable.
//
// The Governor evaluates supplied sanitized evidence only. It never revokes,
// blocks, activates, modifies execution, or changes connector state, and it
// produces findings — not a grade and never an aggregate score.
//
// Evidence semantics (Sol repair — typed positive evidence):
// a field supports PASS only when it is
//   - typed: its `evidence_kind` is in the allowlist for that exact field;
//   - positive: its value passes the field's value class and carries no
//     negative-assertion marker ("not proven" is not proof);
//   - referenced: at least one evidence reference is present, and the
//     reference is not reused across criteria of the same unit (one generic
//     record cannot prove unrelated claims);
//   - current: `observed_at` is a valid UTC timestamp, not in the future,
//     and within the evaluation's max evidence age;
//   - linked: `unit_ref` names the evaluated unit and `supports` names the
//     exact criterion and field the evidence claims to support.
// Anything failing these checks is unusable: it is recorded with its reason
// and counts as missing (PARTIAL/UNKNOWN-ward). It never manufactures PASS
// and never manufactures FAIL.
//
// Result semantics:
//   PASS    — every required field is usable positive evidence, internally
//             consistent.
//   PARTIAL — some usable evidence exists but required elements, proof
//             points, or independence are incomplete.
//   FAIL    — only on affirmative demonstration: `absent_confirmed` (cited
//             proof the control is absent), `contradictory` evidence, or an
//             internally inconsistent evidence set. Missing or unusable
//             evidence alone is never FAIL.
//   UNKNOWN — no usable evidence at all. A demonstrated failure is never
//             UNKNOWN.

import { createHash } from "node:crypto";
import { canonicalizeJson } from "../../governance-core/canonical.mjs";
import { WIRE_SAFE_ID_RE } from "../../governance-core/contracts.mjs";
import { sensitiveValueReason } from "../sensitive-values.mjs";
import { positiveValueReason } from "../typed-values.mjs";
import { isCalendarUtcTimestamp } from "../schema-validate.mjs";
import {
  validateArtifact, validateEnvelope, assertValidArtifact,
} from "../contracts.mjs";
import {
  LIVE_OUTPUT_FILES,
  readVerifiedOpenClawLiveArtifact,
} from "../../openclaw-live-observer/index.mjs";

// Evaluator version bumped for the typed-positive-evidence rewrite: a present
// field must carry asserts:true and a typed positive value (strict
// identifier, positive state enum, flag, calendar timestamp, or per-field
// positive-assertion enum) — not merely a value outside a finite phrase
// blacklist. absent_confirmed and contradictory evidence pass the same
// kind/support/unit/currentness discipline before they can drive FAIL.
export const GOVERNOR_EVALUATOR_VERSION = "0.6.3";
export const GOVERNABILITY_EVIDENCE_SCHEMA =
  "mcpherson-governance-governability-evidence/v1";
export const GOVERNABILITY_RESULT_SCHEMA =
  "mcpherson-governance-governability-result/v1";
export const GOVERNABILITY_FINDING_SET_SCHEMA =
  "mcpherson-governance-governability-finding-set/v1";
export const GOVERNABILITY_FINDING_SET_VERSION = "1";
export const GOVERNABILITY_EVIDENCE_SCHEMA_VERSION = "1";
export const DEFAULT_MAX_EVIDENCE_AGE_DAYS = 30;

export const CRITERION_VALUES = Object.freeze([
  "VISIBLE", "ATTRIBUTABLE", "SCOPED", "INDEPENDENTLY_REVOCABLE",
]);
export const RESULT_VALUES = Object.freeze(["PASS", "PARTIAL", "FAIL", "UNKNOWN"]);
export const UNIT_TYPE_VALUES = Object.freeze(["connector", "capability"]);
export const EVIDENCE_FIELD_STATUS_VALUES = Object.freeze([
  "present", "absent", "absent_confirmed", "contradictory",
]);
export const EVIDENCE_KIND_VALUES = Object.freeze([
  "inventory_record", "ownership_record", "runtime_receipt", "grant_record",
  "policy_record", "revocation_state_record", "revocation_drill_record",
  "integration_config", "platform_documentation",
]);
export const GAP_OWNER_VALUES = Object.freeze([
  "source_platform", "connector", "runtime_integration",
  "policy_configuration", "missing_evidence",
]);
const SUPPLIER_VALUES = new Set([
  "source_platform", "connector", "runtime_integration", "policy_configuration",
]);

// Per-field typing: allowed evidence kinds and value class.
// Value classes: identifier (wire-safe id/label), state_enum (exact member),
// timestamp (RFC3339 UTC), proof (bounded single-line positive statement),
// flag ("true"/"false").
export const FIELD_RULES = Object.freeze({
  VISIBLE: Object.freeze({
    stable_identity: { kinds: ["inventory_record"], valueClass: "identifier" },
    owner: { kinds: ["ownership_record", "inventory_record"], valueClass: "identifier" },
    tenant: { kinds: ["inventory_record", "grant_record"], valueClass: "identifier" },
    source: { kinds: ["inventory_record"], valueClass: "identifier" },
    enabled_state: {
      kinds: ["inventory_record", "integration_config"],
      valueClass: "state_enum",
      stateValues: ["enabled", "disabled"],
    },
    runtime_association: {
      kinds: ["integration_config", "runtime_receipt"],
      valueClass: "identifier",
    },
    last_seen_at: { kinds: ["runtime_receipt"], valueClass: "timestamp" },
  }),
  ATTRIBUTABLE: Object.freeze({
    human_owner: { kinds: ["ownership_record"], valueClass: "identifier" },
    agent_identity: {
      kinds: ["runtime_receipt", "integration_config"],
      valueClass: "identifier",
    },
    runtime_identity: {
      kinds: ["runtime_receipt", "integration_config"],
      valueClass: "identifier",
    },
    tenant: { kinds: ["inventory_record", "grant_record"], valueClass: "identifier" },
    connector_or_grant_identity: { kinds: ["grant_record"], valueClass: "identifier" },
    run_id: { kinds: ["runtime_receipt"], valueClass: "proof" },
    request_id: { kinds: ["runtime_receipt"], valueClass: "proof" },
    executor_relevant: {
      kinds: ["integration_config", "platform_documentation"],
      valueClass: "flag",
    },
    executor_identity: { kinds: ["runtime_receipt"], valueClass: "identifier" },
  }),
  SCOPED: Object.freeze({
    permitted_action: {
      kinds: ["grant_record", "policy_record"],
      valueClass: "identifier",
    },
    target_or_resource: {
      kinds: ["grant_record", "policy_record"],
      valueClass: "identifier",
    },
    parameter_constraints: {
      kinds: ["integration_config", "grant_record"],
      valueClass: "proof",
    },
    tenant: { kinds: ["grant_record", "inventory_record"], valueClass: "identifier" },
    limits: { kinds: ["grant_record", "platform_documentation"], valueClass: "proof" },
    expiry: { kinds: ["grant_record"], valueClass: "proof" },
    policy_version: { kinds: ["policy_record"], valueClass: "identifier" },
    source_state_relevant: {
      kinds: ["integration_config", "platform_documentation"],
      valueClass: "flag",
    },
    source_state_preconditions: {
      kinds: ["platform_documentation", "policy_record"],
      valueClass: "proof",
    },
  }),
  INDEPENDENTLY_REVOCABLE: Object.freeze({
    administrative_claim: {
      kinds: ["platform_documentation", "integration_config"],
      valueClass: "proof",
    },
    authoritative_revocation_state: {
      kinds: ["revocation_state_record"],
      valueClass: "proof",
    },
    execution_time_revocation_check: {
      kinds: ["integration_config", "runtime_receipt"],
      valueClass: "proof",
    },
    observed_refusal_evidence: {
      kinds: ["revocation_drill_record", "runtime_receipt"],
      valueClass: "proof",
    },
  }),
});

export const CRITERION_FIELDS = Object.freeze({
  VISIBLE: Object.freeze([
    "stable_identity", "owner", "tenant", "source", "enabled_state",
    "runtime_association", "last_seen_at",
  ]),
  ATTRIBUTABLE: Object.freeze([
    "human_owner", "agent_identity", "runtime_identity", "tenant",
    "connector_or_grant_identity", "run_id", "request_id",
    "executor_relevant",
  ]),
  SCOPED: Object.freeze([
    "permitted_action", "target_or_resource", "parameter_constraints",
    "tenant", "limits", "expiry", "policy_version",
    "source_state_relevant",
  ]),
  INDEPENDENTLY_REVOCABLE: Object.freeze([
    "administrative_claim", "authoritative_revocation_state",
    "execution_time_revocation_check", "observed_refusal_evidence",
  ]),
});

export const CONDITIONAL_FIELDS = Object.freeze({
  ATTRIBUTABLE: Object.freeze({ executor_identity: "executor_relevant" }),
  SCOPED: Object.freeze({ source_state_preconditions: "source_state_relevant" }),
});

export const CRITERION_GAP_IMPACT = Object.freeze({
  VISIBLE: "a capability that cannot be reliably inventoried can act without appearing in any review",
  ATTRIBUTABLE: "actions that cannot be attributed to a human, agent, and runtime cannot be investigated or owned",
  SCOPED: "an unscoped grant authorizes more than anyone decided it should",
  INDEPENDENTLY_REVOCABLE: "authority that cannot be revoked independently of the agent remains in force even after a decision to withdraw it",
});

const REVOCABILITY_PROOF_FIELDS = Object.freeze([
  "authoritative_revocation_state", "execution_time_revocation_check",
  "observed_refusal_evidence",
]);

// Calendar-real UTC timestamp: rejects impossible dates like 2026-02-31.
function isTimestamp(value) {
  return isCalendarUtcTimestamp(value);
}

// Shared typed-field discipline applied to present, absent_confirmed, and
// contradictory evidence: correct kind for the field, a `supports`
// declaration naming this exact criterion.field, a `unit_ref` naming the
// evaluated unit, and a current, calendar-valid observed_at. Returns null
// when all pass, or a deterministic reason.
function typedFieldProblem(raw, criterion, fieldName, unitId, evaluatedAt, maxAgeMs, rule) {
  if (!rule) return "field_not_recognized";
  if (!EVIDENCE_KIND_VALUES.includes(raw.evidence_kind)) return "evidence_kind_invalid";
  if (!rule.kinds.includes(raw.evidence_kind)) return "evidence_kind_not_allowed_for_field";
  if (raw.supports !== `${criterion}.${fieldName}`) return "supports_declaration_mismatch";
  if (raw.unit_ref !== unitId) return "evidence_not_linked_to_unit";
  if (!isTimestamp(raw.observed_at)) return "observed_at_invalid";
  const observed = Date.parse(raw.observed_at);
  const evaluated = Date.parse(evaluatedAt);
  if (observed > evaluated) return "observed_at_in_future";
  if (evaluated - observed > maxAgeMs) return "evidence_stale";
  return null;
}

const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

function isMeaningfulNote(value) {
  return typeof value === "string"
    && value.length <= 512
    && value.trim().length > 0
    && /[A-Za-z0-9]/.test(value);
}

const ABSENT_FORBIDDEN_PAYLOAD_KEYS = Object.freeze([
  "asserts", "value", "note", "evidence_kind", "supports", "unit_ref",
  "observed_at",
]);

/**
 * Normalize one evidence field into a usability decision. Never throws;
 * anything unexpected is `unusable` with a deterministic reason.
 */
function normalizeField({
  raw, criterion, fieldName, unitId, evaluatedAt, maxAgeMs,
}) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { outcome: "unusable", reason: "field_malformed" };
  }
  if (!EVIDENCE_FIELD_STATUS_VALUES.includes(raw.status)) {
    return { outcome: "unusable", reason: "status_invalid" };
  }
  const refs = Array.isArray(raw.refs)
    ? [...new Set(raw.refs.filter((ref) => typeof ref === "string" && ref.length > 0
      && ref.length <= 256 && sensitiveValueReason(ref) === null)
    )]
    : [];
  const supplier = SUPPLIER_VALUES.has(raw.expected_supplier)
    ? raw.expected_supplier
    : null;
  const note = typeof raw.note === "string" && raw.note.length <= 512
    ? raw.note
    : null;
  if (raw.status === "absent") {
    // `absent` means no evidence was supplied. Do not silently ignore a truth
    // assertion, note, citation, kind, linkage, or timestamp attached to it.
    // expected_supplier is the one permitted non-status payload because it
    // identifies the owner of the evidence gap.
    if ((Array.isArray(raw.refs) && raw.refs.length !== 0)
        || ABSENT_FORBIDDEN_PAYLOAD_KEYS.some((key) => hasOwn(raw, key))) {
      return {
        outcome: "unusable",
        reason: "absent_forbids_truth_or_evidence_payload",
        supplier,
        refs,
      };
    }
    return { outcome: "absent", supplier, refs: [] };
  }
  const rule = FIELD_RULES[criterion]?.[fieldName];
  // Every non-absent status must cite refs, name a supplier, and pass the
  // shared typed-field discipline (kind/supports/unit/currentness) before it
  // can drive any result — so an absent_confirmed or contradictory field with
  // the wrong kind, unrelated supports, wrong unit, or a stale time is
  // unusable (missing-ward), never a manufactured FAIL.
  if (refs.length === 0) {
    return { outcome: "unusable", reason: "refs_missing", supplier };
  }
  if (supplier === null) {
    return { outcome: "unusable", reason: "supplier_missing", supplier };
  }
  const typedProblem = typedFieldProblem(
    raw, criterion, fieldName, unitId, evaluatedAt, maxAgeMs, rule,
  );
  if (typedProblem !== null) {
    return { outcome: "unusable", reason: typedProblem, supplier };
  }
  if (raw.status === "absent_confirmed") {
    // A cited, correctly typed claim that the control is confirmed absent.
    // It carries no positive value, must explicitly assert false, and must
    // explain the claimed absence in a meaningful non-blank note.
    if (hasOwn(raw, "value")) {
      return { outcome: "unusable", reason: "absent_confirmed_forbids_value", supplier };
    }
    if (raw.asserts !== false) {
      return { outcome: "unusable", reason: "absent_confirmed_requires_asserts_false", supplier };
    }
    if (!isMeaningfulNote(note)) {
      return { outcome: "unusable", reason: "absent_confirmed_note_missing", supplier };
    }
    return { outcome: "absent_confirmed", supplier, refs, note };
  }
  if (raw.status === "contradictory") {
    // A contradiction is supported by competing cited records, not by a
    // single truth value or a caller-selected boolean assertion.
    if (hasOwn(raw, "value")) {
      return { outcome: "unusable", reason: "contradictory_forbids_value", supplier };
    }
    if (hasOwn(raw, "asserts")) {
      return { outcome: "unusable", reason: "contradictory_forbids_asserts", supplier };
    }
    if (!isMeaningfulNote(note)) {
      return { outcome: "unusable", reason: "contradictory_note_missing", supplier };
    }
    if (refs.length < 2) {
      return {
        outcome: "unusable",
        reason: "contradictory_requires_two_unique_refs",
        supplier,
      };
    }
    return { outcome: "contradictory", supplier, refs, note };
  }
  // status === "present": typed positive support.
  // The typed truth signal must positively support the claim.
  if (raw.asserts !== true) {
    return { outcome: "unusable", reason: "present_requires_asserts_true", supplier };
  }
  // Typed positive VALUE: strict identifier, positive state enum, flag,
  // calendar timestamp, or per-field positive-assertion enum. A negative or
  // free-text value is not a recognized positive assertion (this is the
  // typed truth test, not a phrase blacklist).
  const positiveProblem = positiveValueReason(criterion, fieldName, raw.value);
  if (positiveProblem !== null) {
    return { outcome: "unusable", reason: positiveProblem, supplier };
  }
  if (criterion === "VISIBLE" && fieldName === "last_seen_at") {
    const asserted = Date.parse(raw.value);
    const observed = Date.parse(raw.observed_at);
    const evaluated = Date.parse(evaluatedAt);
    if (asserted > observed || asserted > evaluated) {
      return {
        outcome: "unusable",
        reason: "last_seen_at_after_observation",
        supplier,
      };
    }
    if (evaluated - asserted > maxAgeMs) {
      return {
        outcome: "unusable",
        reason: "last_seen_at_stale",
        supplier,
      };
    }
  }
  // Secondary defenses, never the primary test.
  if (sensitiveValueReason(raw.value) !== null) {
    return { outcome: "unusable", reason: "value_sensitive_shape", supplier };
  }
  return {
    outcome: "usable",
    supplier,
    refs,
    note,
    value: raw.value,
    kind: raw.evidence_kind,
  };
}

function ownersOf(fieldOwners, fieldNames) {
  const owners = new Set();
  for (const name of fieldNames) {
    owners.add(fieldOwners[name] ?? "missing_evidence");
  }
  return [...owners].sort();
}

function remediation(criterion, unitId, problemFields, kind) {
  const fields = problemFields.join(", ");
  if (kind === "contradiction") {
    return `reconcile the contradictory ${fields} evidence for ${unitId} at its supplier before relying on ${criterion.toLowerCase()} status`;
  }
  if (kind === "confirmed_absent") {
    return `add the missing control behind ${fields} for ${unitId}; evidence states it does not exist today`;
  }
  return `record and export typed positive evidence for ${fields} for ${unitId} so ${criterion.toLowerCase()} status can be evaluated`;
}

const STANDARD_PASS_REASON =
  "all required evidence is typed, positive, current, unit-linked, and internally consistent";
const REVOCABILITY_PASS_REASON =
  "authoritative revocation state is independently resolvable, execution is bound to current state, and refusal was observed, each with distinct typed evidence";
const FAIL_REASON =
  "typed evidence demonstrates a required control is absent, contradictory, or internally inconsistent";

function findingProblemFields({
  criterion, result, observed, missing, contradictions,
  confirmedAbsent, independenceConflicts,
}) {
  if (contradictions.length > 0) {
    return [...new Set(contradictions.map((entry) => entry.field))].sort();
  }
  if (result === "FAIL") return [...confirmedAbsent].sort();
  if (independenceConflicts.length > 0) {
    return [...independenceConflicts].sort();
  }
  if (criterion === "INDEPENDENTLY_REVOCABLE" && result === "PARTIAL") {
    const observedSet = new Set(observed);
    const observedProofs = REVOCABILITY_PROOF_FIELDS.filter(
      (name) => observedSet.has(name),
    );
    return observedProofs.length === REVOCABILITY_PROOF_FIELDS.length
      ? [...REVOCABILITY_PROOF_FIELDS]
      : REVOCABILITY_PROOF_FIELDS.filter(
        (name) => !observedSet.has(name),
      ).sort();
  }
  return [...missing].sort();
}

function canonicalFindingReason({
  criterion, result, observed, missing, unusable, independenceConflicts,
}) {
  if (result === "FAIL") return FAIL_REASON;
  if (result === "PASS") {
    return criterion === "INDEPENDENTLY_REVOCABLE"
      ? REVOCABILITY_PASS_REASON
      : STANDARD_PASS_REASON;
  }
  if (result === "UNKNOWN") {
    const suppliedButUnusable = unusable.length > 0;
    if (criterion === "INDEPENDENTLY_REVOCABLE") {
      return suppliedButUnusable
        ? "no usable revocation evidence: supplied evidence failed typed-positive validation"
        : "no usable revocation evidence was supplied";
    }
    return suppliedButUnusable
      ? "no usable evidence: supplied evidence failed typed-positive validation"
      : "no usable evidence was supplied for this criterion";
  }
  if (criterion !== "INDEPENDENTLY_REVOCABLE") {
    return `required evidence for ${[...missing].sort().join(", ")} was not supplied or was not usable`;
  }
  if (independenceConflicts.length > 0) {
    return "revocation layers are named but not independently sourced: proof fields share an evidence reference";
  }
  const observedSet = new Set(observed);
  const proofsUsable = REVOCABILITY_PROOF_FIELDS.filter(
    (name) => observedSet.has(name),
  );
  const missingProofs = REVOCABILITY_PROOF_FIELDS.filter(
    (name) => !observedSet.has(name),
  ).sort();
  const claimOnly = observedSet.has("administrative_claim")
    && proofsUsable.length === 0;
  return claimOnly
    ? `an administrative revocation claim exists but ${missingProofs.join(", ")} were not demonstrated; a claim, flag, or UI state alone is not proof`
    : `revocation control exists but ${missingProofs.join(", ")} were not demonstrated`;
}

function canonicalRemediation({
  criterion, unitId, result, problemFields, contradictions,
}) {
  if (result === "PASS") return null;
  const kind = contradictions.length > 0
    ? "contradiction"
    : result === "FAIL"
      ? "confirmed_absent"
      : "missing";
  return remediation(criterion, unitId, problemFields, kind);
}

function finding({
  criterion, unit, result, evaluatedAt, contradictions, fieldStates,
  requiredNames, unusable, independenceConflicts = [],
}) {
  const observed = [];
  const missing = [];
  const confirmedAbsent = [];
  const references = [];
  const fieldOwners = {};
  for (const name of requiredNames) {
    const state = fieldStates.get(name);
    if (state?.supplier) fieldOwners[name] = state.supplier;
    if (state?.outcome === "usable") {
      observed.push(name);
      references.push(...state.refs);
    } else {
      missing.push(name);
      if (state?.refs) references.push(...state.refs);
    }
    if (state?.outcome === "absent_confirmed") confirmedAbsent.push(name);
  }
  observed.sort();
  missing.sort();
  confirmedAbsent.sort();
  const problems = findingProblemFields({
    criterion,
    result,
    observed,
    missing,
    contradictions,
    confirmedAbsent,
    independenceConflicts,
  });
  const reason = canonicalFindingReason({
    criterion,
    result,
    observed,
    missing,
    unusable,
    independenceConflicts,
  });
  return Object.freeze({
    schema: GOVERNABILITY_RESULT_SCHEMA,
    criterion,
    evaluated_unit_type: unit.unit_type,
    evaluated_unit_id: unit.unit_id,
    result,
    reason,
    evidence_references: [...new Set(references)].sort(),
    observed_fields: observed,
    missing_fields: missing,
    confirmed_absent_fields: confirmedAbsent,
    independence_conflict_fields: [...independenceConflicts].sort(),
    unusable_evidence: unusable,
    contradictory_evidence: contradictions,
    field_owners: fieldOwners,
    gap_owners: result === "PASS" ? [] : ownersOf(fieldOwners, problems),
    gap_impact: result === "PASS" ? null : CRITERION_GAP_IMPACT[criterion],
    remediation_suggestion: canonicalRemediation({
      criterion,
      unitId: unit.unit_id,
      result,
      problemFields: problems,
      contradictions,
    }),
    evaluator_version: GOVERNOR_EVALUATOR_VERSION,
    evaluated_timestamp: evaluatedAt,
  });
}

function requiredNamesFor(criterion, fieldStates) {
  const names = [...CRITERION_FIELDS[criterion]];
  const conditional = CONDITIONAL_FIELDS[criterion] ?? {};
  for (const [name, flag] of Object.entries(conditional)) {
    const flagState = fieldStates.get(flag);
    if (flagState?.outcome === "usable" && flagState.value === "true") {
      names.push(name);
    }
  }
  return names;
}

/**
 * Pre-scan a unit for evidence references that appear under more than one
 * criterion. Positive, contradictory, and confirmed-absence evidence all
 * make truth claims; one generic citation cannot prove unrelated positive or
 * negative claims merely by changing the status label.
 */
function crossCriterionReusedRefs(unit) {
  const refCriteria = new Map();
  for (const criterion of CRITERION_VALUES) {
    const section = unit.evidence?.[criterion.toLowerCase()];
    if (!section || typeof section !== "object" || Array.isArray(section)) continue;
    for (const raw of Object.values(section)) {
      if (!raw || raw.status === "absent" || !Array.isArray(raw.refs)) continue;
      for (const ref of raw.refs) {
        if (typeof ref !== "string") continue;
        if (!refCriteria.has(ref)) refCriteria.set(ref, new Set());
        refCriteria.get(ref).add(criterion);
      }
    }
  }
  return new Set([...refCriteria.entries()]
    .filter(([, criteria]) => criteria.size > 1)
    .map(([ref]) => ref));
}

function collectStates(unit, criterion, evaluatedAt, maxAgeMs, reusedRefs) {
  const section = unit.evidence?.[criterion.toLowerCase()];
  const states = new Map();
  if (section && typeof section === "object" && !Array.isArray(section)) {
    for (const [name, raw] of Object.entries(section)) {
      states.set(name, normalizeField({
        raw, criterion, fieldName: name, unitId: unit.unit_id, evaluatedAt, maxAgeMs,
      }));
    }
  }
  // One evidence reference may support fields of one criterion only.
  for (const [name, state] of states) {
    if (!["usable", "absent_confirmed", "contradictory"].includes(
      state.outcome,
    )) continue;
    if (state.refs.some((ref) => reusedRefs.has(ref))) {
      states.set(name, {
        outcome: "unusable",
        reason: "evidence_reference_reused_across_criteria",
        supplier: state.supplier,
        refs: state.refs,
      });
    }
  }
  return states;
}

function markUnusable(state, reason) {
  if (state?.outcome !== "usable") return state;
  return {
    outcome: "unusable",
    reason,
    supplier: state.supplier,
    refs: state.refs,
  };
}

/**
 * Reconcile facts that are repeated across criteria. Typed shape and unit_ref
 * linkage are not enough: an internally consistent PASS cannot assert a
 * stable identity different from the evaluated unit, or disagree about the
 * same tenant, owner, or runtime under different criterion field names.
 *
 * A mismatch makes each otherwise-usable claim unusable. This remains
 * missing-ward rather than manufacturing FAIL because the caller supplied
 * `present` records, not typed `contradictory` evidence.
 */
function reconcileUnitFacts(unit, perCriterionStates) {
  const visible = perCriterionStates.get("VISIBLE");
  const attributable = perCriterionStates.get("ATTRIBUTABLE");
  const scoped = perCriterionStates.get("SCOPED");

  const stable = visible.get("stable_identity");
  if (stable?.outcome === "usable" && stable.value !== unit.unit_id) {
    visible.set("stable_identity",
      markUnusable(stable, "stable_identity_mismatch"));
  }

  const groups = [
    [
      [visible, "tenant"],
      [attributable, "tenant"],
      [scoped, "tenant"],
    ],
    [
      [visible, "owner"],
      [attributable, "human_owner"],
    ],
    [
      [visible, "runtime_association"],
      [attributable, "runtime_identity"],
    ],
  ];
  for (const group of groups) {
    const usable = group.filter(
      ([states, name]) => states.get(name)?.outcome === "usable",
    );
    if (new Set(usable.map(
      ([states, name]) => states.get(name).value,
    )).size <= 1) continue;
    for (const [states, name] of usable) {
      states.set(name,
        markUnusable(states.get(name), "cross_criterion_value_mismatch"));
    }
  }
}

function evaluateCriterion(criterion, unit, fieldStates, evaluatedAt) {
  const requiredNames = requiredNamesFor(criterion, fieldStates);
  const contradictions = [];
  const confirmedAbsent = [];
  const unusable = [];
  const usable = [];
  const absent = [];
  for (const name of requiredNames) {
    const state = fieldStates.get(name);
    if (!state || state.outcome === "absent") absent.push(name);
    else if (state.outcome === "usable") usable.push(name);
    else if (state.outcome === "contradictory") {
      contradictions.push(Object.freeze({
        field: name,
        note: state.note ?? "conflicting evidence values",
        refs: state.refs,
      }));
    } else if (state.outcome === "absent_confirmed") confirmedAbsent.push(name);
    else {
      unusable.push(Object.freeze({ field: name, reason: state.reason }));
      absent.push(name);
    }
  }
  const isRevocability = criterion === "INDEPENDENTLY_REVOCABLE";
  const proofsUsable = isRevocability
    ? REVOCABILITY_PROOF_FIELDS.filter(
      (name) => fieldStates.get(name)?.outcome === "usable",
    )
    : [];
  // Internal consistency: demonstrated revocation cannot coexist with a
  // confirmed statement that no revocation mechanism exists.
  if (isRevocability && confirmedAbsent.includes("administrative_claim")
      && proofsUsable.length === REVOCABILITY_PROOF_FIELDS.length) {
    const inconsistencyRefs = [...new Set([
      ...(fieldStates.get("administrative_claim")?.refs ?? []),
      ...REVOCABILITY_PROOF_FIELDS.flatMap(
        (name) => fieldStates.get(name)?.refs ?? [],
      ),
    ])].sort();
    // A contradiction entry must identify at least two independently
    // identifiable records. When one record makes every claim, confirmed
    // absence still drives FAIL, but the output does not pretend that one
    // citation is a multi-record contradiction.
    if (inconsistencyRefs.length >= 2) {
      contradictions.push(Object.freeze({
        field: "administrative_claim",
        note: "internally inconsistent evidence: revocation layers are demonstrated while the source affirms no revocation mechanism exists",
        refs: inconsistencyRefs,
      }));
    }
  }
  if (contradictions.length > 0 || confirmedAbsent.length > 0) {
    const problemFields = [...new Set([
      ...contradictions.map((entry) => entry.field),
      ...confirmedAbsent,
    ])].sort();
    return finding({
      criterion,
      unit,
      result: "FAIL",
      reason: contradictions.length > 0
        ? `evidence for ${problemFields.join(", ")} is contradictory or internally inconsistent`
        : `evidence affirmatively confirms ${problemFields.join(", ")} is absent`,
      evaluatedAt,
      contradictions,
      fieldStates,
      requiredNames,
      problemFields,
      problemKind: contradictions.length > 0 ? "contradiction" : "confirmed_absent",
      unusable,
    });
  }
  if (isRevocability) {
    if (proofsUsable.length === REVOCABILITY_PROOF_FIELDS.length) {
      // Independence: the three proof layers may not lean on one shared
      // reference.
      const refSets = REVOCABILITY_PROOF_FIELDS.map(
        (name) => fieldStates.get(name).refs,
      );
      const shared = refSets.some((refs, index) => refs.some(
        (ref) => refSets.some((other, otherIndex) => otherIndex !== index
          && other.includes(ref)),
      ));
      if (shared) {
        return finding({
          criterion,
          unit,
          result: "PARTIAL",
          reason: "revocation layers are named but not independently sourced: proof fields share an evidence reference",
          evaluatedAt,
          contradictions: [],
          fieldStates,
          requiredNames,
          problemFields: [...REVOCABILITY_PROOF_FIELDS],
          problemKind: "missing",
          unusable,
          independenceConflicts: [...REVOCABILITY_PROOF_FIELDS],
        });
      }
      return finding({
        criterion,
        unit,
        result: "PASS",
        reason: "authoritative revocation state is independently resolvable, execution is bound to current state, and refusal was observed, each with distinct typed evidence",
        evaluatedAt,
        contradictions: [],
        fieldStates,
        requiredNames,
        problemFields: [],
        problemKind: "missing",
        unusable,
      });
    }
    const anyUsable = requiredNames.some(
      (name) => fieldStates.get(name)?.outcome === "usable",
    );
    if (!anyUsable) {
      return finding({
        criterion,
        unit,
        result: "UNKNOWN",
        reason: unusable.length > 0
          ? "no usable revocation evidence: supplied evidence failed typed-positive validation"
          : "no usable revocation evidence was supplied",
        evaluatedAt,
        contradictions: [],
        fieldStates,
        requiredNames,
        problemFields: requiredNames,
        problemKind: "missing",
        unusable,
      });
    }
    const missingProofs = REVOCABILITY_PROOF_FIELDS.filter(
      (name) => fieldStates.get(name)?.outcome !== "usable",
    ).sort();
    const claimOnly = fieldStates.get("administrative_claim")?.outcome === "usable"
      && proofsUsable.length === 0;
    return finding({
      criterion,
      unit,
      result: "PARTIAL",
      reason: claimOnly
        ? `an administrative revocation claim exists but ${missingProofs.join(", ")} were not demonstrated; a claim, flag, or UI state alone is not proof`
        : `revocation control exists but ${missingProofs.join(", ")} were not demonstrated`,
      evaluatedAt,
      contradictions: [],
      fieldStates,
      requiredNames,
      problemFields: missingProofs,
      problemKind: "missing",
      unusable,
    });
  }
  if (absent.length === 0) {
    return finding({
      criterion,
      unit,
      result: "PASS",
      reason: "all required evidence is typed, positive, current, unit-linked, and internally consistent",
      evaluatedAt,
      contradictions: [],
      fieldStates,
      requiredNames,
      problemFields: [],
      problemKind: "missing",
      unusable,
    });
  }
  if (usable.length > 0) {
    return finding({
      criterion,
      unit,
      result: "PARTIAL",
      reason: `required evidence for ${[...new Set(absent)].sort().join(", ")} was not supplied or was not usable`,
      evaluatedAt,
      contradictions: [],
      fieldStates,
      requiredNames,
      problemFields: [...new Set(absent)],
      problemKind: "missing",
      unusable,
    });
  }
  return finding({
    criterion,
    unit,
    result: "UNKNOWN",
    reason: unusable.length > 0
      ? "no usable evidence: supplied evidence failed typed-positive validation"
      : "no usable evidence was supplied for this criterion",
    evaluatedAt,
    contradictions: [],
    fieldStates,
    requiredNames,
    problemFields: [...new Set(absent)],
    problemKind: "missing",
    unusable,
  });
}

const FINDING_BINDING_FIELDS = new Set([
  "finding_set_id",
  "finding_set_version",
  "evidence_document_id",
  "evidence_document_sha256",
  "evidence_schema",
  "evidence_schema_version",
]);

function withoutFindingBinding(findingValue) {
  return Object.fromEntries(Object.entries(findingValue).filter(
    ([key]) => !FINDING_BINDING_FIELDS.has(key),
  ));
}

/**
 * Canonical, content-addressed identity of one validated evidence document.
 * Property order and insignificant JSON whitespace cannot change the digest;
 * any semantic JSON change does.
 */
export function canonicalEvidenceDocumentSha256(evidenceDocument) {
  return `sha256:${createHash("sha256")
    .update(canonicalizeJson(evidenceDocument), "utf8").digest("hex")}`;
}

/**
 * Derive the deterministic finding-set ID from the complete set content
 * except for the circular ID/member-binding fields themselves.
 */
export function canonicalFindingSetId(findingSet) {
  const projection = {
    schema: findingSet.schema,
    finding_set_version: findingSet.finding_set_version,
    evidence_set_id: findingSet.evidence_set_id,
    evidence_document_id: findingSet.evidence_document_id,
    evidence_document_sha256: findingSet.evidence_document_sha256,
    evidence_schema: findingSet.evidence_schema,
    evidence_schema_version: findingSet.evidence_schema_version,
    diagnosed_units: findingSet.diagnosed_units,
    evaluator_version: findingSet.evaluator_version,
    evaluated_timestamp: findingSet.evaluated_timestamp,
    max_evidence_age_days: findingSet.max_evidence_age_days,
    finding_count: findingSet.finding_count,
    findings: findingSet.findings.map(withoutFindingBinding),
  };
  return `mgfs-${createHash("sha256")
    .update(canonicalizeJson(projection), "utf8").digest("hex")}`;
}

function diagnosedUnitsFor(evidenceDocument) {
  return evidenceDocument.units.map((unit) => Object.freeze({
    unit_type: unit.unit_type,
    unit_id: unit.unit_id,
  })).sort((left, right) => (
    `${left.unit_type}|${left.unit_id}` < `${right.unit_type}|${right.unit_id}`
      ? -1
      : `${left.unit_type}|${left.unit_id}` > `${right.unit_type}|${right.unit_id}`
        ? 1
        : 0
  ));
}

function assertEvaluationContext(
  evidenceDocument, evaluatedAt, maxEvidenceAgeDays,
) {
  if (evidenceDocument?.schema !== GOVERNABILITY_EVIDENCE_SCHEMA) {
    throw new TypeError("governability_evidence_invalid");
  }
  if (evidenceDocument.sanitization_confirmed !== true) {
    throw new TypeError("governability_evidence_unsanitized");
  }
  const evidenceContract = validateArtifact(
    GOVERNABILITY_EVIDENCE_SCHEMA, evidenceDocument,
  );
  if (!evidenceContract.ok) {
    const error = new TypeError("governability_evidence_invalid");
    error.contractErrors = evidenceContract.errors;
    throw error;
  }
  if (!isTimestamp(evaluatedAt)) {
    throw new TypeError("evaluated_timestamp_invalid");
  }
  if (!Number.isInteger(maxEvidenceAgeDays) || maxEvidenceAgeDays < 1
      || maxEvidenceAgeDays > 3650) {
    throw new TypeError("max_evidence_age_invalid");
  }
  const capturedAt = Date.parse(evidenceDocument.captured_at);
  const evaluatedAtMs = Date.parse(evaluatedAt);
  if (capturedAt > evaluatedAtMs) {
    throw new TypeError("governability_capture_after_evaluation");
  }
  for (const unit of evidenceDocument.units) {
    for (const section of Object.values(unit.evidence ?? {})) {
      if (!section || typeof section !== "object" || Array.isArray(section)) {
        continue;
      }
      for (const raw of Object.values(section)) {
        if (!raw || raw.status === "absent") continue;
        if (Date.parse(raw.observed_at) > capturedAt) {
          throw new TypeError("governability_observation_after_capture");
        }
      }
    }
  }
}

function deriveFindings(evidenceDocument, evaluatedAt, maxEvidenceAgeDays) {
  const maxAgeMs = maxEvidenceAgeDays * 24 * 60 * 60 * 1000;
  const findings = [];
  const units = [...evidenceDocument.units].sort((left, right) => (
    `${left.unit_type}|${left.unit_id}` < `${right.unit_type}|${right.unit_id}`
      ? -1
      : `${left.unit_type}|${left.unit_id}` > `${right.unit_type}|${right.unit_id}`
        ? 1
        : 0
  ));
  for (const unit of units) {
    if (!UNIT_TYPE_VALUES.includes(unit?.unit_type)
        || typeof unit?.unit_id !== "string"
        || !WIRE_SAFE_ID_RE.test(unit.unit_id.replaceAll(".", "-"))) {
      continue;
    }
    const reusedRefs = crossCriterionReusedRefs(unit);
    const perCriterionStates = new Map();
    for (const criterion of CRITERION_VALUES) {
      perCriterionStates.set(criterion,
        collectStates(unit, criterion, evaluatedAt, maxAgeMs, reusedRefs));
    }
    reconcileUnitFacts(unit, perCriterionStates);
    for (const criterion of CRITERION_VALUES) {
      findings.push(evaluateCriterion(
        criterion, unit, perCriterionStates.get(criterion), evaluatedAt,
      ));
    }
  }
  return findings;
}

function buildFindingSetFromValidatedEvidence({
  evidenceDocument,
  evaluatedAt,
  maxEvidenceAgeDays,
}) {
  const rawFindings = deriveFindings(
    evidenceDocument, evaluatedAt, maxEvidenceAgeDays,
  );
  const evidenceDocumentId = evidenceDocument.evidence_set_id;
  const evidenceDocumentSha256 =
    canonicalEvidenceDocumentSha256(evidenceDocument);
  const diagnosedUnits = diagnosedUnitsFor(evidenceDocument);
  const provisional = {
    schema: GOVERNABILITY_FINDING_SET_SCHEMA,
    finding_set_version: GOVERNABILITY_FINDING_SET_VERSION,
    evidence_set_id: evidenceDocumentId,
    evidence_document_id: evidenceDocumentId,
    evidence_document_sha256: evidenceDocumentSha256,
    evidence_schema: evidenceDocument.schema,
    evidence_schema_version: GOVERNABILITY_EVIDENCE_SCHEMA_VERSION,
    diagnosed_units: diagnosedUnits,
    evaluator_version: GOVERNOR_EVALUATOR_VERSION,
    evaluated_timestamp: evaluatedAt,
    max_evidence_age_days: maxEvidenceAgeDays,
    finding_count: rawFindings.length,
    findings: rawFindings,
  };
  const findingSetId = canonicalFindingSetId(provisional);
  const findings = rawFindings.map((rawFinding) => Object.freeze({
    ...rawFinding,
    finding_set_id: findingSetId,
    finding_set_version: GOVERNABILITY_FINDING_SET_VERSION,
    evidence_document_id: evidenceDocumentId,
    evidence_document_sha256: evidenceDocumentSha256,
    evidence_schema: evidenceDocument.schema,
    evidence_schema_version: GOVERNABILITY_EVIDENCE_SCHEMA_VERSION,
  }));
  return Object.freeze({
    ...provisional,
    finding_set_id: findingSetId,
    findings,
  });
}

function invalidFindingSet(reason, detail = null) {
  return Object.freeze({
    ok: false,
    reason,
    ...(detail === null ? {} : { detail }),
  });
}

/**
 * Consumer-side semantic validation for Governor output. Shape validation is
 * not acceptance: callers must supply the exact evidence document, whose
 * canonical hash, identity, schema/version, units, criterion references, and
 * deterministically rederived results are composed against the finding set.
 */
export function validateFindingSet(
  findingSet, { evidenceDocument } = {},
) {
  const contract = validateEnvelope(
    GOVERNABILITY_FINDING_SET_SCHEMA, findingSet,
  );
  if (!contract.ok) {
    return invalidFindingSet("finding_set_contract_invalid", contract.errors);
  }
  if (findingSet.evaluator_version !== GOVERNOR_EVALUATOR_VERSION) {
    return invalidFindingSet("finding_set_evaluator_version_unsupported");
  }
  if (evidenceDocument === undefined || evidenceDocument === null) {
    return invalidFindingSet("finding_set_evidence_required");
  }
  try {
    assertEvaluationContext(
      evidenceDocument,
      findingSet.evaluated_timestamp,
      findingSet.max_evidence_age_days,
    );
  } catch (error) {
    return invalidFindingSet(
      "finding_set_evidence_invalid",
      String(error?.message ?? "governability_evidence_invalid"),
    );
  }
  let evidenceDocumentSha256;
  try {
    evidenceDocumentSha256 =
      canonicalEvidenceDocumentSha256(evidenceDocument);
  } catch (error) {
    return invalidFindingSet(
      "finding_set_evidence_not_canonical",
      String(error?.message ?? "non_canonical_json"),
    );
  }
  if (findingSet.evidence_set_id !== evidenceDocument.evidence_set_id
      || findingSet.evidence_document_id !== evidenceDocument.evidence_set_id) {
    return invalidFindingSet("finding_set_evidence_document_id_mismatch");
  }
  if (findingSet.evidence_document_sha256 !== evidenceDocumentSha256) {
    return invalidFindingSet("finding_set_evidence_hash_mismatch");
  }
  if (findingSet.evidence_schema !== evidenceDocument.schema
      || findingSet.evidence_schema !== GOVERNABILITY_EVIDENCE_SCHEMA
      || findingSet.evidence_schema_version
        !== GOVERNABILITY_EVIDENCE_SCHEMA_VERSION
      || findingSet.finding_set_version
        !== GOVERNABILITY_FINDING_SET_VERSION) {
    return invalidFindingSet("finding_set_evidence_schema_mismatch");
  }
  const expectedDiagnosedUnits = diagnosedUnitsFor(evidenceDocument);
  if (canonicalizeJson(findingSet.diagnosed_units)
      !== canonicalizeJson(expectedDiagnosedUnits)) {
    return invalidFindingSet("finding_set_diagnosed_units_mismatch");
  }
  const expectedFindingSet = buildFindingSetFromValidatedEvidence({
    evidenceDocument,
    evaluatedAt: findingSet.evaluated_timestamp,
    maxEvidenceAgeDays: findingSet.max_evidence_age_days,
  });
  const byUnit = new Map();
  const referenceCriteriaByUnit = new Map();
  for (const finding of findingSet.findings) {
    const unitKey =
      `${finding.evaluated_unit_type}|${finding.evaluated_unit_id}`;
    if (!referenceCriteriaByUnit.has(unitKey)) {
      referenceCriteriaByUnit.set(unitKey, new Map());
    }
    const byReference = referenceCriteriaByUnit.get(unitKey);
    for (const reference of finding.evidence_references) {
      if (!byReference.has(reference)) {
        byReference.set(reference, new Set());
      }
      byReference.get(reference).add(finding.criterion);
    }
  }
  const seen = new Set();
  for (const finding of findingSet.findings) {
    if (finding.finding_set_id !== findingSet.finding_set_id
        || finding.finding_set_version !== findingSet.finding_set_version
        || finding.evidence_document_id !== findingSet.evidence_document_id
        || finding.evidence_document_sha256
          !== findingSet.evidence_document_sha256
        || finding.evidence_schema !== findingSet.evidence_schema
        || finding.evidence_schema_version
          !== findingSet.evidence_schema_version) {
      return invalidFindingSet("finding_set_member_binding_mismatch");
    }
    if (finding.evaluator_version !== findingSet.evaluator_version
        || finding.evaluated_timestamp !== findingSet.evaluated_timestamp) {
      return invalidFindingSet("finding_set_member_context_mismatch");
    }
    const key = `${finding.evaluated_unit_type}|${finding.evaluated_unit_id}`;
    const findingKey = `${key}|${finding.criterion}`;
    if (seen.has(findingKey)) {
      return invalidFindingSet("finding_set_duplicate_criterion");
    }
    seen.add(findingKey);
    if (!byUnit.has(key)) byUnit.set(key, new Set());
    byUnit.get(key).add(finding.criterion);
    const observed = new Set(finding.observed_fields);
    const missing = new Set(finding.missing_fields);
    const confirmedAbsent = new Set(finding.confirmed_absent_fields);
    const independenceConflicts =
      new Set(finding.independence_conflict_fields);
    const partition = new Set([...observed, ...missing]);
    const baseFields = CRITERION_FIELDS[finding.criterion];
    const allowedFields = new Set([
      ...baseFields,
      ...Object.keys(CONDITIONAL_FIELDS[finding.criterion] ?? {}),
    ]);
    if (observed.size !== finding.observed_fields.length
        || missing.size !== finding.missing_fields.length
        || [...observed].some((field) => missing.has(field))
        || baseFields.some((field) => !partition.has(field))
        || [...partition].some((field) => !allowedFields.has(field))) {
      return invalidFindingSet("finding_field_partition_invalid");
    }
    if (confirmedAbsent.size !== finding.confirmed_absent_fields.length
        || [...confirmedAbsent].some(
          (field) => !missing.has(field)
            || !hasOwn(finding.field_owners, field),
        )) {
      return invalidFindingSet("finding_confirmed_absence_state_inconsistent");
    }
    if (independenceConflicts.size
          !== finding.independence_conflict_fields.length
        || (independenceConflicts.size > 0
          && (finding.criterion !== "INDEPENDENTLY_REVOCABLE"
            || independenceConflicts.size
              !== REVOCABILITY_PROOF_FIELDS.length
            || REVOCABILITY_PROOF_FIELDS.some(
              (field) => !independenceConflicts.has(field)
                || !observed.has(field),
            )))) {
      return invalidFindingSet("finding_independence_state_inconsistent");
    }
    const references = new Set(finding.evidence_references);
    if (references.size !== finding.evidence_references.length
        || finding.evidence_references.some(
          (reference) => sensitiveValueReason(reference) !== null,
        )) {
      return invalidFindingSet("finding_reference_state_inconsistent");
    }
    const ownerFields = Object.keys(finding.field_owners);
    if (ownerFields.some((field) => !partition.has(field))
        || [...observed].some(
          (field) => !hasOwn(finding.field_owners, field),
        )) {
      return invalidFindingSet("finding_field_owner_state_inconsistent");
    }
    const unusableFields = new Set();
    for (const entry of finding.unusable_evidence) {
      if (unusableFields.has(entry.field) || !missing.has(entry.field)) {
        return invalidFindingSet("finding_unusable_state_inconsistent");
      }
      unusableFields.add(entry.field);
    }
    const hasCrossCriterionReference =
      finding.evidence_references.some(
        (reference) => referenceCriteriaByUnit.get(key)
          ?.get(reference)?.size > 1,
      );
    if (hasCrossCriterionReference
        && !finding.unusable_evidence.some(
          (entry) => entry.reason
            === "evidence_reference_reused_across_criteria",
        )) {
      return invalidFindingSet(
        "finding_reference_reused_across_criteria",
      );
    }
    const contradictionFields = new Set();
    for (const entry of finding.contradictory_evidence) {
      const contradictionRefs = new Set(entry.refs);
      if (contradictionFields.has(entry.field)
          || !missing.has(entry.field)
          || unusableFields.has(entry.field)
          || !hasOwn(finding.field_owners, entry.field)
          || !isMeaningfulNote(entry.note)
          || contradictionRefs.size !== entry.refs.length
          || contradictionRefs.size < 2
          || entry.refs.some((reference) => !references.has(reference))) {
        return invalidFindingSet("finding_contradiction_state_inconsistent");
      }
      contradictionFields.add(entry.field);
    }

    let expectedResult;
    if (confirmedAbsent.size > 0 || contradictionFields.size > 0) {
      expectedResult = "FAIL";
    } else if (independenceConflicts.size > 0) {
      expectedResult = "PARTIAL";
    } else if (finding.criterion === "INDEPENDENTLY_REVOCABLE") {
      expectedResult = REVOCABILITY_PROOF_FIELDS.every(
        (field) => observed.has(field),
      )
        ? "PASS"
        : observed.size > 0
          ? "PARTIAL"
          : "UNKNOWN";
    } else {
      expectedResult = missing.size === 0
        ? "PASS"
        : observed.size > 0
          ? "PARTIAL"
          : "UNKNOWN";
    }
    if (finding.result !== expectedResult) {
      return invalidFindingSet("finding_result_not_reproducible");
    }
    const problemFields = findingProblemFields({
      criterion: finding.criterion,
      result: finding.result,
      observed: finding.observed_fields,
      missing: finding.missing_fields,
      contradictions: finding.contradictory_evidence,
      confirmedAbsent: finding.confirmed_absent_fields,
      independenceConflicts: finding.independence_conflict_fields,
    });
    const expectedReason = canonicalFindingReason({
      criterion: finding.criterion,
      result: finding.result,
      observed: finding.observed_fields,
      missing: finding.missing_fields,
      unusable: finding.unusable_evidence,
      independenceConflicts: finding.independence_conflict_fields,
    });
    const expectedRemediation = canonicalRemediation({
      criterion: finding.criterion,
      unitId: finding.evaluated_unit_id,
      result: finding.result,
      problemFields,
      contradictions: finding.contradictory_evidence,
    });
    const expectedGapOwners = finding.result === "PASS"
      ? []
      : ownersOf(finding.field_owners, problemFields);
    if (finding.reason !== expectedReason
        || finding.remediation_suggestion !== expectedRemediation
        || finding.gap_owners.length !== expectedGapOwners.length
        || finding.gap_owners.some(
          (owner, index) => owner !== expectedGapOwners[index],
        )) {
      return invalidFindingSet("finding_derived_narrative_inconsistent");
    }
    if (finding.result === "PASS") {
      // The administrative claim is intentionally not a proof layer:
      // independently revocable may PASS from the three independently
      // sourced authoritative/execution/refusal proofs even when no separate
      // administrative claim was supplied.
      const allowedMissing = finding.criterion === "INDEPENDENTLY_REVOCABLE"
        && finding.missing_fields.length === 1
        && finding.missing_fields[0] === "administrative_claim";
      if (finding.observed_fields.length === 0
          || finding.evidence_references.length === 0
          || (!allowedMissing && finding.missing_fields.length !== 0)
          || finding.unusable_evidence.length !== 0
          || finding.contradictory_evidence.length !== 0
          || finding.confirmed_absent_fields.length !== 0
          || finding.independence_conflict_fields.length !== 0
          || finding.gap_owners.length !== 0
          || finding.gap_impact !== null
          || finding.remediation_suggestion !== null) {
        return invalidFindingSet("finding_pass_state_inconsistent");
      }
    } else {
      if (finding.gap_owners.length === 0
          || finding.gap_impact !== CRITERION_GAP_IMPACT[finding.criterion]
          || finding.remediation_suggestion === null) {
        return invalidFindingSet("finding_gap_state_inconsistent");
      }
      if (finding.result === "PARTIAL"
          && (finding.observed_fields.length === 0
            || finding.evidence_references.length === 0
            || finding.contradictory_evidence.length !== 0
            || (finding.missing_fields.length === 0
              && finding.independence_conflict_fields.length === 0))) {
        return invalidFindingSet("finding_partial_state_inconsistent");
      }
      if (finding.result === "UNKNOWN"
          && (finding.observed_fields.length !== 0
            || finding.contradictory_evidence.length !== 0
            || (finding.evidence_references.length !== 0
              && finding.unusable_evidence.length === 0))) {
        return invalidFindingSet("finding_unknown_state_inconsistent");
      }
      if (finding.result !== "FAIL"
          && finding.contradictory_evidence.length !== 0) {
        return invalidFindingSet("finding_contradiction_state_inconsistent");
      }
      if (finding.result === "FAIL"
          && (finding.missing_fields.length === 0
            || finding.evidence_references.length === 0)) {
        return invalidFindingSet("finding_fail_state_inconsistent");
      }
    }
  }
  for (const criteria of byUnit.values()) {
    if (criteria.size !== CRITERION_VALUES.length
        || CRITERION_VALUES.some((criterion) => !criteria.has(criterion))) {
      return invalidFindingSet("finding_set_unit_criteria_incomplete");
    }
  }
  const expectedByKey = new Map(expectedFindingSet.findings.map((finding) => [
    `${finding.evaluated_unit_type}|${finding.evaluated_unit_id}|${finding.criterion}`,
    finding,
  ]));
  if (findingSet.findings.length !== expectedFindingSet.findings.length) {
    return invalidFindingSet("finding_set_evidence_composition_incomplete");
  }
  for (const finding of findingSet.findings) {
    const key =
      `${finding.evaluated_unit_type}|${finding.evaluated_unit_id}|${finding.criterion}`;
    const expected = expectedByKey.get(key);
    if (!expected) {
      return invalidFindingSet("finding_subject_not_in_evidence_document");
    }
    if (canonicalizeJson(finding.evidence_references)
        !== canonicalizeJson(expected.evidence_references)) {
      return invalidFindingSet("finding_criterion_evidence_references_mismatch");
    }
    if (finding.result === "PASS" && expected.result !== "PASS") {
      return invalidFindingSet("finding_pass_unsupported_by_evidence");
    }
    if (canonicalizeJson(withoutFindingBinding(finding))
        !== canonicalizeJson(withoutFindingBinding(expected))) {
      return invalidFindingSet("finding_not_reproducible_from_evidence");
    }
  }
  let canonicalId;
  try {
    canonicalId = canonicalFindingSetId(findingSet);
  } catch (error) {
    return invalidFindingSet(
      "finding_set_identity_not_canonical",
      String(error?.message ?? "non_canonical_json"),
    );
  }
  if (findingSet.finding_set_id !== canonicalId
      || findingSet.finding_set_id !== expectedFindingSet.finding_set_id) {
    return invalidFindingSet("finding_set_id_mismatch");
  }
  if (canonicalizeJson(findingSet) !== canonicalizeJson(expectedFindingSet)) {
    return invalidFindingSet("finding_set_evidence_composition_mismatch");
  }
  return Object.freeze({ ok: true });
}

/**
 * Evaluate a governability evidence document. Connector-level and
 * capability-level units are evaluated separately and never merged. Returns
 * deterministic findings ordered by unit type, unit id, then criterion.
 * The evidence document is never mutated.
 */
export function evaluateGovernability({
  evidenceDocument,
  evaluatedAt,
  maxEvidenceAgeDays = DEFAULT_MAX_EVIDENCE_AGE_DAYS,
  observationDirectory = null,
  packageManifestPath = null,
  profileBindingPath = null,
  profileBindingId = null,
}) {
  // Direct-library callers receive the same strict contract enforcement as
  // the CLI: unknown fields, invalid calendar dates, malformed units, and
  // invalid evidence-field shapes are rejected before any field can
  // influence a finding.
  assertEvaluationContext(
    evidenceDocument, evaluatedAt, maxEvidenceAgeDays,
  );
  if (evidenceDocument.observation_id !== undefined) {
    if (typeof observationDirectory !== "string") {
      throw new TypeError("live_observation_directory_required");
    }
    const verified = readVerifiedOpenClawLiveArtifact({
      outDir: observationDirectory,
      filename: LIVE_OUTPUT_FILES.evidence,
      packageManifestPath,
      profileBindingPath,
      profileBindingId,
    });
    if (canonicalizeJson(evidenceDocument)
        !== canonicalizeJson(verified.value)) {
      throw new TypeError("live_evidence_observation_binding_mismatch");
    }
  }
  const findingSet = buildFindingSetFromValidatedEvidence({
    evidenceDocument,
    evaluatedAt,
    maxEvidenceAgeDays,
  });
  // Producer output contract: the finding set and every member finding must
  // validate and compose back to the exact evidence document before return.
  assertValidArtifact(GOVERNABILITY_FINDING_SET_SCHEMA, findingSet);
  const semantic = validateFindingSet(findingSet, { evidenceDocument });
  if (!semantic.ok) {
    const error = new TypeError(`governability_output_invalid:${semantic.reason}`);
    error.detail = semantic;
    throw error;
  }
  return findingSet;
}

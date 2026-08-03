// v0.6 diagnostics-only vocabulary. Everything here is additive and versioned.
// The implemented v0.5 repository vocabulary remains authoritative and is
// imported, never redefined. Conceptual mapping between the two is documented
// in docs/v0.6-diagnostics.md; nothing in this package feeds the runtime.

import {
  ACTION_CLASS_VALUES,
  ACTION_CLASSES,
} from "../governance-core/classify.mjs";

export const AUTOMAP_VERSION = "0.6.0";
export const DIAGNOSTICS_INSTRUMENTATION_VERSION = "0.6.0";

export const CANDIDATE_SCHEMA = "mcpherson-governance-capability-candidate/v1";
export const SNAPSHOT_SCHEMA = "mcpherson-governance-capability-snapshot/v1";
export const LIVE_SNAPSHOT_SCHEMA =
  "mcpherson-governance-live-capability-snapshot/v1";
export const REGISTRY_SCHEMA = "mcpherson-governance-code-owned-tool-registry/v1";
export const ADVISORY_SCHEMA =
  "mcpherson-governance-advisory-classification-suggestion/v1";
export const CONFIRMATION_SCHEMA =
  "mcpherson-governance-human-classification-confirmation/v1";
export const APPROVAL_SCHEMA = "mcpherson-governance-mapping-approval/v1";
export const DRIFT_SCHEMA = "mcpherson-governance-schema-drift-event/v1";
export const CANDIDATE_SET_SCHEMA =
  "mcpherson-governance-capability-candidate-set/v1";

// v0.6 diagnostic effect labels. The nearest existing repository concept is
// the single-valued `action_class`; no implemented effect-set vocabulary
// exists, so this enum is new, versioned, and isolated to diagnostics.
export const EFFECT_VALUES = Object.freeze([
  "READ", "WRITE", "SEND", "DELETE", "EXECUTE", "UNKNOWN",
]);
export const EFFECTS = new Set(EFFECT_VALUES);

export const CLASSIFICATION_STATUS_VALUES = Object.freeze([
  "CONFIRMED_DETERMINISTIC",
  "CONFIRMED_HUMAN",
  "MODEL_SUGGESTED_UNCONFIRMED",
  "UNKNOWN",
]);
export const CLASSIFICATION_STATUSES = new Set(CLASSIFICATION_STATUS_VALUES);

// v0.6 mapping lifecycle. Deliberately unrepresentable states: "shadow active"
// is the v0.5-owned presence of a tool in the connector `toolMetadata` /
// server `tools` registry, and "enforcement eligible" does not exist anywhere
// in v0.5 or v0.6 (see contracts/decision-tiers.md, later gated tier). No
// diagnostics value exists for either state, so no diagnostics record can
// claim them.
export const MAPPING_STATUS_VALUES = Object.freeze([
  "DISCOVERED", "PROPOSED", "APPROVED_DOCUMENTATION_ONLY",
]);
export const MAPPING_STATUSES = new Set(MAPPING_STATUS_VALUES);

export const RISK_STATUS_VALUES = Object.freeze(["PROPOSED", "UNKNOWN"]);
export const RISK_STATUSES = new Set(RISK_STATUS_VALUES);

export const REVERSIBILITY_VALUES = Object.freeze([
  "reversible", "irreversible", "unknown",
]);
export const REVERSIBILITIES = new Set(REVERSIBILITY_VALUES);

// Conforms to the implemented receipt-mode vocabulary (POST_HOOK,
// ATTEMPT_ONLY) plus honest absence.
export const COMPLETION_EVIDENCE_VALUES = Object.freeze([
  "POST_HOOK", "ATTEMPT_ONLY", "UNKNOWN",
]);
export const COMPLETION_EVIDENCES = new Set(COMPLETION_EVIDENCE_VALUES);

export const DISCOVERY_METHOD_VALUES = Object.freeze([
  "sanitized_static_snapshot_v1",
  "openclaw_live_gateway_v1",
  "openclaw_plugin_manifest",
  "committed_registry_v1",
]);
export const DISCOVERY_METHODS = new Set(DISCOVERY_METHOD_VALUES);

export const MAPPING_CONFIDENCE_VALUES = Object.freeze([
  "deterministic", "declared_unverified", "unknown",
]);
export const MAPPING_CONFIDENCES = new Set(MAPPING_CONFIDENCE_VALUES);

// Severity order for the diagnostic action-class proposal, highest first.
// The proposal always takes the highest class implied by any signal; a
// multi-effect capability is never collapsed toward its lowest-risk effect,
// and UNKNOWN never lowers toward read_only_internal.
export const ACTION_CLASS_SEVERITY_ORDER = Object.freeze([
  "credential_secret_access",
  "destructive_irreversible",
  "command_execution",
  "service_gateway_control",
  "external_outbound",
  "configuration_modification",
  "file_modification",
  "reversible_internal_write",
  "read_only_internal",
]);

const SEVERITY_RANK = new Map(
  ACTION_CLASS_SEVERITY_ORDER.map((value, index) => [value, index]),
);

export function highestSeverityClass(classes) {
  let best = null;
  for (const candidate of classes) {
    if (!SEVERITY_RANK.has(candidate)) continue;
    if (best === null || SEVERITY_RANK.get(candidate) < SEVERITY_RANK.get(best)) {
      best = candidate;
    }
  }
  return best ?? "unknown";
}

// Deterministic effects implied by an authoritative existing action class.
// Documented conformance mapping; command_execution keeps UNKNOWN because its
// transitive effects are argument-dependent and must never be narrowed.
export const ACTION_CLASS_EFFECTS = Object.freeze({
  read_only_internal: Object.freeze(["READ"]),
  reversible_internal_write: Object.freeze(["WRITE"]),
  file_modification: Object.freeze(["WRITE"]),
  command_execution: Object.freeze(["EXECUTE", "UNKNOWN"]),
  configuration_modification: Object.freeze(["WRITE"]),
  service_gateway_control: Object.freeze(["WRITE", "UNKNOWN"]),
  external_outbound: Object.freeze(["SEND"]),
  credential_secret_access: Object.freeze(["READ", "UNKNOWN"]),
  destructive_irreversible: Object.freeze(["DELETE"]),
  unknown: Object.freeze(["UNKNOWN"]),
});

export { ACTION_CLASS_VALUES, ACTION_CLASSES };

export function normalizeEffects(values) {
  if (!Array.isArray(values) || values.length === 0) return null;
  const unique = [...new Set(values)];
  if (!unique.every((value) => EFFECTS.has(value))) return null;
  return Object.freeze(
    [...unique].sort(
      (left, right) => EFFECT_VALUES.indexOf(left) - EFFECT_VALUES.indexOf(right),
    ),
  );
}

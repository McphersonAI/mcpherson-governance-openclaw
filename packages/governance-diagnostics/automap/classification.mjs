// Classification and diagnostic risk-proposal rules.
//
// Trust discipline: only an exact, path-contained, hash-pinned code-owned
// registry under the explicitly selected trusted root yields
// CONFIRMED_DETERMINISTIC; this is content binding, not proof of Git state,
// repository identity, authorship, or signature. Only a valid bound human artifact yields
// CONFIRMED_HUMAN; advisory (model-suggested) fixtures remain
// MODEL_SUGGESTED_UNCONFIRMED and never change effects, risk trust, or
// lifecycle; everything else is UNKNOWN. UNKNOWN never narrows to READ, and a
// multi-effect set is never collapsed toward its lowest-risk member.

import {
  ACTION_CLASSES,
  EFFECTS,
  RISK_STATUSES,
  highestSeverityClass,
  normalizeEffects,
} from "../vocabulary.mjs";

const CREDENTIAL_DATA_CLASSES = new Set([
  "credential", "credentials", "secret", "secrets", "token", "tokens", "key",
  "keys", "credential_material",
]);

export function classificationFromDeclaration({ declaredEffects, evidenceRef }) {
  const effects = normalizeEffects(declaredEffects);
  if (effects === null) {
    return Object.freeze({
      effects: Object.freeze(["UNKNOWN"]),
      status: "UNKNOWN",
      method: "none",
      evidence: Object.freeze([]),
      confirmed_by: null,
      confirmed_at: null,
      rationale: "no usable declared effects; UNKNOWN preserved, never defaulted to READ",
    });
  }
  return Object.freeze({
    effects,
    status: "UNKNOWN",
    method: "static_manifest_declaration",
    evidence: Object.freeze(evidenceRef ? [evidenceRef] : []),
    confirmed_by: null,
    confirmed_at: null,
    rationale:
      "effects declared by sanitized static source; declaration preserved but unverified",
  });
}

export function classificationFromCodeOwnedRegistry({ effects, evidence, rationale }) {
  const normalized = normalizeEffects(effects);
  if (normalized === null || !Array.isArray(evidence) || evidence.length === 0) {
    return null;
  }
  return Object.freeze({
    effects: normalized,
    status: "CONFIRMED_DETERMINISTIC",
    method: "committed_code_owned_registry",
    evidence: Object.freeze([...evidence]),
    confirmed_by: null,
    confirmed_at: null,
    rationale: rationale
      ?? "effects derived deterministically from the exact hash-pinned code-owned registry content",
  });
}

/**
 * Attach an advisory (model-suggested) classification fixture to a candidate
 * classification. The suggestion is stored verbatim for review; the effects
 * set, trust status ceiling, and risk treatment of the candidate do not
 * improve. No model is called anywhere in v0.6.
 */
export function withAdvisorySuggestion(classification, suggestion) {
  const suggested = normalizeEffects(suggestion?.suggested_effects);
  if (suggested === null) return classification;
  if (classification.status === "CONFIRMED_DETERMINISTIC"
      || classification.status === "CONFIRMED_HUMAN") {
    // A confirmed classification is never overwritten by a suggestion; the
    // suggestion is preserved for comparison only.
    return Object.freeze({
      ...classification,
      advisory_suggestion: freezeSuggestion(suggestion, suggested),
    });
  }
  return Object.freeze({
    ...classification,
    status: "MODEL_SUGGESTED_UNCONFIRMED",
    advisory_suggestion: freezeSuggestion(suggestion, suggested),
    rationale: `${classification.rationale}; advisory suggestion attached, unconfirmed`,
  });
}

function freezeSuggestion(suggestion, suggested) {
  return Object.freeze({
    suggested_effects: suggested,
    suggestion_source: String(suggestion.suggestion_source ?? "advisory_fixture"),
    model_invoked_in_build: false,
    rationale: String(suggestion.rationale ?? ""),
  });
}

/**
 * Diagnostic-only risk proposal. Preserves any authoritative action class
 * supplied by exact pinned registry content (cited in risk_basis) and
 * otherwise proposes the highest-severity class implied by the effects.
 * risk_status is PROPOSED only for confirmed classifications; anything
 * unconfirmed stays UNKNOWN with the gap recorded, and an UNKNOWN effect
 * forces the proposal to the existing `unknown` action class.
 */
export function proposeRisk({
  classification,
  reversibility,
  targetResourceClass,
  dataClasses,
  authoritativeActionClass = null,
  authoritativeSource = null,
}) {
  const basis = [];
  const unresolved = [];
  const effects = classification.effects;
  let proposedClass;

  if (authoritativeActionClass !== null
      && ACTION_CLASSES.has(authoritativeActionClass)) {
    proposedClass = authoritativeActionClass;
    basis.push(`authoritative_action_class:${authoritativeSource ?? "registry"}`);
  } else if (effects.includes("UNKNOWN")) {
    proposedClass = "unknown";
    basis.push("unknown_effect_present");
    unresolved.push("effects_incomplete");
  } else {
    const implied = [];
    const classes = Array.isArray(dataClasses) ? dataClasses : [];
    if (classes.some((value) => CREDENTIAL_DATA_CLASSES.has(String(value)))) {
      implied.push("credential_secret_access");
      basis.push("data_class_credential_material");
    }
    if (effects.includes("DELETE")) {
      if (reversibility === "reversible" && targetResourceClass !== "external") {
        implied.push("reversible_internal_write");
        basis.push("delete_declared_reversible_internal");
      } else {
        implied.push("destructive_irreversible");
        basis.push(reversibility === "irreversible"
          ? "delete_irreversible"
          : "delete_unknown_reversibility_treated_irreversible");
        if (reversibility !== "irreversible") unresolved.push("reversibility_unknown");
      }
    }
    if (effects.includes("EXECUTE")) {
      implied.push("command_execution");
      basis.push("execute_effect");
    }
    if (effects.includes("SEND")) {
      implied.push("external_outbound");
      basis.push("send_effect");
    }
    if (effects.includes("WRITE")) {
      if (targetResourceClass === "configuration") {
        implied.push("configuration_modification");
        basis.push("write_configuration_target");
      } else if (reversibility === "irreversible") {
        implied.push("destructive_irreversible");
        basis.push("write_irreversible");
      } else if (reversibility === "reversible"
          && targetResourceClass === "internal_record") {
        implied.push("reversible_internal_write");
        basis.push("write_reversible_internal_record");
      } else {
        implied.push("file_modification");
        basis.push("write_effect_conservative_default");
        if (reversibility === "unknown" || reversibility === undefined) {
          unresolved.push("reversibility_unknown");
        }
        if (targetResourceClass === undefined || targetResourceClass === "unknown") {
          unresolved.push("target_resource_class_unknown");
        }
      }
    }
    if (effects.includes("READ") && implied.length === 0) {
      implied.push("read_only_internal");
      basis.push("read_only_effects");
    }
    proposedClass = highestSeverityClass(implied);
    if (proposedClass === "unknown") {
      basis.push("no_deterministic_class_signal");
      unresolved.push("effects_incomplete");
    }
  }

  const confirmed = classification.status === "CONFIRMED_DETERMINISTIC"
    || classification.status === "CONFIRMED_HUMAN";
  if (!confirmed) unresolved.push("classification_unconfirmed");
  const riskStatus = confirmed && !effects.includes("UNKNOWN")
    ? "PROPOSED"
    : "UNKNOWN";
  if (!RISK_STATUSES.has(riskStatus)) throw new TypeError("risk_status_invalid");

  return Object.freeze({
    proposed_action_class: proposedClass,
    risk_status: riskStatus,
    risk_basis: Object.freeze([...new Set(basis)].sort()),
    unresolved_risk_factors: Object.freeze([...new Set(unresolved)].sort()),
  });
}

export function assertEffectsShape(effects) {
  return Array.isArray(effects) && effects.length > 0
    && effects.every((value) => EFFECTS.has(value))
    && new Set(effects).size === effects.length;
}

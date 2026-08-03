// Boundary validation for candidate sets.
//
// Sol repair: no candidate-derived field is trusted merely because it
// appears in a local JSON file. Every CLI and API boundary reconstructs and
// verifies: the schema contract (strict, so unknown activation-shaped
// fields are rejected), candidate identity, the semantic content hash, the
// deterministic risk proposal, the outbound preview, effects/classification
// consistency, and duplicate exclusion. Trust ceilings are enforced:
// CONFIRMED_DETERMINISTIC only with committed-registry provenance shape and
// exact effects/action-class conformance; CONFIRMED_HUMAN only with a
// complete confirmation trail on the record itself (and any trust-consuming
// operation additionally requires the bound artifact).
//
// Known limitation, documented: v0.6 artifacts are unsigned local files.
// This validator makes an internally inconsistent forgery detectable; it
// cannot prove reviewer identity. That requires a later signing phase.

import { basename } from "node:path";
import {
  ACTION_CLASS_EFFECTS,
  AUTOMAP_VERSION,
  CANDIDATE_SET_SCHEMA,
  CLASSIFICATION_STATUSES,
  MAPPING_STATUSES,
  normalizeEffects,
} from "../vocabulary.mjs";
import { validateArtifact } from "../contracts.mjs";
import { proposeRisk } from "./classification.mjs";
import {
  buildOutboundMetadataPreview,
  candidateContentHash,
  candidateId,
} from "./discovery.mjs";
import {
  loadPinnedRegistryCandidateSemanticSet,
  loadPinnedRegistryCandidateSemantics,
  PINNED_REGISTRY_BINDINGS,
  registryEntryInconsistency,
} from "./pinned-content.mjs";
import { validateApprovalRecord } from "./approval.mjs";

export const CANDIDATE_SET_STAGES = Object.freeze(["discovery", "proposal", "any"]);

function reject(reason, candidate = null, detail = null) {
  return Object.freeze({
    ok: false,
    reason,
    ...(candidate ? { candidate_id: candidate.candidate_id ?? null } : {}),
    ...(detail ? { detail } : {}),
  });
}

function sameArray(left, right) {
  return Array.isArray(left) && Array.isArray(right)
    && left.length === right.length
    && left.every((value, index) => right[index] === value);
}

function deepEqualCanonical(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

const PINNED_REGISTRY_STATIC_FIELDS = Object.freeze([
  "automap_version",
  "source_id",
  "native_tool_name",
  "native_operation_name",
  "normalized_capability",
  "discovery_method",
  "native_schema_ref",
  "source_document_sha256",
  "structural_schema_fingerprint",
  "metadata_fingerprint",
  "structural_paths",
  "target_resource_class",
  "reversibility",
  "possible_side_effects",
  "data_classes",
  "completion_evidence_availability",
  "required_policy_attributes",
  "mapping_confidence",
  "unresolved_questions",
]);

function baseClassification(classification) {
  return {
    status: classification.status,
    method: classification.method,
    evidence: classification.evidence,
    confirmed_by: classification.confirmed_by,
    confirmed_at: classification.confirmed_at,
    rationale: classification.rationale,
  };
}

function pinnedRegistryDerivationProblem(candidate) {
  if (candidate.discovery_method !== "committed_registry_v1") return null;
  const derived = loadPinnedRegistryCandidateSemantics({
    sourceKind: candidate.discovery_method,
    sourceId: candidate.source_id,
    sourceDocumentSha256: candidate.source_document_sha256,
    tool: candidate.native_tool_name,
  });
  if (!derived.ok) {
    return {
      reason: "pinned_registry_derivation_unavailable",
      detail: { source_reason: derived.reason },
    };
  }
  const expectedSource = derived.binding.repository_relative_path
    .split("/").at(-1);
  if (candidate.discovery_source !== expectedSource) {
    return {
      reason: "pinned_registry_derivation_mismatch",
      detail: { field: "discovery_source" },
    };
  }
  for (const field of PINNED_REGISTRY_STATIC_FIELDS) {
    if (!deepEqualCanonical(candidate[field], derived.fields[field])) {
      return {
        reason: "pinned_registry_derivation_mismatch",
        detail: { field },
      };
    }
  }
  if (candidate.classification.status === "CONFIRMED_DETERMINISTIC") {
    for (const field of ["effects", "proposed_risk"]) {
      if (!deepEqualCanonical(candidate[field], derived.fields[field])) {
        return {
          reason: "pinned_registry_derivation_mismatch",
          detail: { field },
        };
      }
    }
    if (!deepEqualCanonical(
      baseClassification(candidate.classification),
      derived.fields.classification,
    )) {
      return {
        reason: "pinned_registry_derivation_mismatch",
        detail: { field: "classification" },
      };
    }
  } else if (candidate.classification.status !== "CONFIRMED_HUMAN") {
    return {
      reason: "pinned_registry_derivation_mismatch",
      detail: { field: "classification.status" },
    };
  }
  return null;
}

function pinnedRegistrySetExpectation(candidateSet) {
  let sourceId;
  let sourceDocumentSha256;
  if (candidateSet.candidates.length > 0) {
    sourceId = candidateSet.candidates[0].source_id;
    sourceDocumentSha256 =
      candidateSet.candidates[0].source_document_sha256;
  } else {
    const sourceName = basename(String(candidateSet.discovery_source));
    const matches = PINNED_REGISTRY_BINDINGS.filter((binding) => (
      binding.source_kind === candidateSet.discovery_method
      && basename(binding.repository_relative_path) === sourceName
    ));
    if (matches.length !== 1) {
      return {
        ok: false,
        reason: "pinned_registry_candidate_set_unavailable",
        detail: { source_reason: "pinned_registry_binding_not_resolvable" },
      };
    }
    sourceId = matches[0].source_id;
    sourceDocumentSha256 = `sha256:${matches[0].sha256}`;
  }
  const semanticSet = loadPinnedRegistryCandidateSemanticSet({
    sourceKind: candidateSet.discovery_method,
    sourceId,
    sourceDocumentSha256,
  });
  if (!semanticSet.ok) {
    return {
      ok: false,
      reason: "pinned_registry_candidate_set_unavailable",
      detail: { source_reason: semanticSet.reason },
    };
  }
  const expectedIds = semanticSet.fields.map((fields) => candidateId({
    sourceId: fields.source_id,
    nativeTool: fields.native_tool_name,
    nativeOperation: fields.native_operation_name,
    discoveryMethod: fields.discovery_method,
  })).sort();
  const actualIds = candidateSet.candidates.map(
    (candidate) => candidate.candidate_id,
  );
  if (!sameArray(actualIds, expectedIds)) {
    return {
      ok: false,
      reason: "pinned_registry_candidate_set_mismatch",
      detail: {
        expected_candidate_ids: expectedIds,
        actual_candidate_ids: actualIds,
      },
    };
  }
  return { ok: true };
}

function classificationConsistency(candidate) {
  const classification = candidate.classification;
  if (!CLASSIFICATION_STATUSES.has(classification.status)) {
    return "classification_status_invalid";
  }
  const effects = normalizeEffects(candidate.effects);
  if (effects === null || !sameArray(effects, candidate.effects)) {
    return "effects_not_normalized";
  }
  if (classification.status === "CONFIRMED_DETERMINISTIC") {
    if (candidate.discovery_method !== "committed_registry_v1") {
      return "deterministic_trust_requires_committed_registry";
    }
    if (classification.method !== "committed_code_owned_registry"
        || classification.evidence.length === 0) {
      return "deterministic_trust_evidence_missing";
    }
    const binding = PINNED_REGISTRY_BINDINGS.find((entry) => (
      entry.source_kind === candidate.discovery_method
      && entry.source_id === candidate.source_id
      && candidate.source_document_sha256 === `sha256:${entry.sha256}`
    ));
    if (!binding) return "deterministic_source_not_pinned";
    const expectedPin =
      `pinned_content:${binding.repository_relative_path}#sha256:${binding.sha256}`;
    if (classification.evidence[0] !== expectedPin) {
      return "deterministic_pinned_evidence_mismatch";
    }
    const sourceName = binding.repository_relative_path.split("/").at(-1);
    if (candidate.discovery_source !== sourceName
        || candidate.native_operation_name !== null
        || candidate.native_schema_ref
          !== `registry[${candidate.native_tool_name}].parameters`) {
      return "deterministic_registry_identity_mismatch";
    }
    const registryProblem = registryEntryInconsistency({
      tool: candidate.native_tool_name,
      action_class: candidate.proposed_risk.proposed_action_class,
      effects: candidate.effects,
    });
    if (registryProblem !== null) {
      return `deterministic_${registryProblem}`;
    }
    const expected = ACTION_CLASS_EFFECTS[
      candidate.proposed_risk.proposed_action_class
    ];
    if (!expected || !sameArray(expected, candidate.effects)) {
      return "deterministic_effects_action_class_inconsistent";
    }
  }
  if (classification.status === "CONFIRMED_HUMAN") {
    if (classification.method !== "human_confirmation_artifact"
        || typeof classification.confirmed_by !== "string"
        || typeof classification.confirmed_at !== "string"
        || classification.evidence.length === 0) {
      return "human_trust_trail_missing";
    }
    if (candidate.effects.includes("UNKNOWN")) {
      return "human_trust_unknown_effects";
    }
  }
  if (classification.status === "MODEL_SUGGESTED_UNCONFIRMED") {
    if (classification.advisory_suggestion?.model_invoked_in_build !== false) {
      return "advisory_suggestion_trail_missing";
    }
  }
  if (candidate.effects.includes("UNKNOWN")) {
    if (candidate.proposed_risk.proposed_action_class !== "unknown"
        && !candidate.proposed_risk.risk_basis
          .some((entry) => entry.startsWith("authoritative_action_class"))) {
      return "unknown_effects_risk_inconsistent";
    }
    if (candidate.proposed_risk.risk_status !== "UNKNOWN") {
      return "unknown_effects_risk_status_inconsistent";
    }
  }
  return null;
}

function riskConsistency(candidate) {
  const basis = candidate.proposed_risk.risk_basis ?? [];
  const authoritative = basis.some(
    (entry) => entry.startsWith("authoritative_action_class"),
  );
  const recomputed = proposeRisk({
    classification: {
      ...candidate.classification,
      effects: candidate.effects,
    },
    reversibility: candidate.reversibility,
    targetResourceClass: candidate.target_resource_class,
    dataClasses: candidate.data_classes,
    authoritativeActionClass: authoritative
      ? candidate.proposed_risk.proposed_action_class
      : null,
    authoritativeSource: authoritative
      ? candidate.classification.evidence[0] ?? null
      : null,
  });
  if (!deepEqualCanonical(recomputed, candidate.proposed_risk)) {
    return "proposed_risk_not_reproducible";
  }
  if (authoritative && candidate.classification.status !== "CONFIRMED_DETERMINISTIC") {
    return "authoritative_risk_without_registry_trust";
  }
  return null;
}

function approvedCandidateBindingProblem(candidate, approvalRecords) {
  if (candidate.mapping_status !== "APPROVED_DOCUMENTATION_ONLY") return null;
  if (!Array.isArray(approvalRecords)) {
    return "approval_context_invalid";
  }

  // The pre-approval candidate is deterministically recoverable because the
  // documentation-only transition changes only mapping_status and the
  // excluded content-hash field. This binds both sides of the transition,
  // not merely an attacker-supplied post-transition hash.
  const proposedCandidate = {
    ...candidate,
    mapping_status: "PROPOSED",
  };
  delete proposedCandidate.candidate_content_hash;
  const proposedContentHash = candidateContentHash(proposedCandidate);
  const classificationStatus = candidate.classification.status;
  const expectedClassificationConfirmed =
    classificationStatus === "CONFIRMED_DETERMINISTIC"
    || classificationStatus === "CONFIRMED_HUMAN";
  const expectedConfirmationBound =
    classificationStatus === "CONFIRMED_HUMAN";

  const bound = approvalRecords.some((record) => (
    validateApprovalRecord(record).ok
    && record.candidate_id === candidate.candidate_id
    && record.candidate_content_hash === proposedContentHash
    && record.approved_candidate_content_hash
      === candidate.candidate_content_hash
    && record.structural_schema_fingerprint
      === candidate.structural_schema_fingerprint
    && record.classification_confirmed
      === expectedClassificationConfirmed
    && record.confirmation_bound === expectedConfirmationBound
  ));
  return bound ? null : "approved_candidate_requires_bound_approval";
}

/** Validate one candidate's contract and reconstructed semantic fields. */
export function validateCandidate(candidate, {
  stage = "any",
  approvalRecords = [],
} = {}) {
  if (!CANDIDATE_SET_STAGES.includes(stage)) {
    throw new TypeError("candidate_set_stage_invalid");
  }
  const memberContract = validateArtifact(
    "mcpherson-governance-capability-candidate/v1", candidate,
  );
  if (!memberContract.ok) {
    return reject("candidate_contract_invalid", candidate, memberContract.errors);
  }
  const expectedId = candidateId({
    sourceId: candidate.source_id,
    nativeTool: candidate.native_tool_name,
    nativeOperation: candidate.native_operation_name,
    discoveryMethod: candidate.discovery_method,
  });
  if (candidate.candidate_id !== expectedId) {
    return reject("candidate_id_not_reproducible", candidate);
  }
  const expectedNormalized = candidate.native_operation_name === null
    ? candidate.native_tool_name
    : `${candidate.native_tool_name}.${candidate.native_operation_name}`;
  if (candidate.normalized_capability !== expectedNormalized) {
    return reject("normalized_capability_inconsistent", candidate);
  }
  if (!MAPPING_STATUSES.has(candidate.mapping_status)) {
    return reject("mapping_status_invalid", candidate);
  }
  if (stage === "discovery" && (candidate.mapping_status !== "DISCOVERED"
      || candidate.outbound_metadata_preview !== undefined)) {
    return reject("discovery_stage_shape_invalid", candidate);
  }
  if (stage === "proposal") {
    if (candidate.mapping_status !== "PROPOSED") {
      return reject("proposal_stage_requires_proposed", candidate);
    }
    if (candidate.outbound_metadata_preview === undefined) {
      return reject("proposal_preview_missing", candidate);
    }
  }
  const classificationProblem = classificationConsistency(candidate);
  if (classificationProblem !== null) {
    return reject(classificationProblem, candidate);
  }
  const pinnedProblem = pinnedRegistryDerivationProblem(candidate);
  if (pinnedProblem !== null) {
    return reject(pinnedProblem.reason, candidate, pinnedProblem.detail);
  }
  const riskProblem = riskConsistency(candidate);
  if (riskProblem !== null) return reject(riskProblem, candidate);
  if (candidate.outbound_metadata_preview !== undefined) {
    const recomputedPreview = buildOutboundMetadataPreview(candidate);
    if (!deepEqualCanonical(recomputedPreview, candidate.outbound_metadata_preview)) {
      return reject("outbound_preview_not_reproducible", candidate);
    }
  }
  if (candidate.candidate_content_hash !== candidateContentHash(candidate)) {
    return reject("candidate_content_hash_not_reproducible", candidate);
  }
  const approvalProblem = approvedCandidateBindingProblem(
    candidate, approvalRecords,
  );
  if (approvalProblem !== null) {
    return reject(approvalProblem, candidate);
  }
  return Object.freeze({ ok: true });
}

/**
 * Validate one candidate set at a boundary. Returns `{ok:true}` or the
 * first deterministic rejection. `stage` selects lifecycle expectations:
 * `discovery` (DISCOVERED, no preview), `proposal` (PROPOSED only, preview
 * required), `any`. At every `any`/direct boundary, an
 * APPROVED_DOCUMENTATION_ONLY member additionally requires a complete
 * approval record bound to both the reconstructed proposal and the exact
 * approved candidate.
 */
export function validateCandidateSet(candidateSet, {
  stage = "any",
  approvalRecords = [],
} = {}) {
  if (!CANDIDATE_SET_STAGES.includes(stage)) {
    throw new TypeError("candidate_set_stage_invalid");
  }
  const contract = validateArtifact(CANDIDATE_SET_SCHEMA, candidateSet);
  if (!contract.ok) {
    return reject("candidate_set_contract_invalid", null, contract.errors);
  }
  if (candidateSet.candidate_count !== candidateSet.candidates.length) {
    return reject("candidate_count_mismatch");
  }
  if (candidateSet.automap_version !== AUTOMAP_VERSION) {
    return reject("candidate_set_automap_version_unsupported");
  }
  // A refused/unreadable registry legitimately produces an empty diagnostic
  // set plus error records. Once any registry candidate is emitted (or a
  // supposedly successful set has no errors), membership and order must
  // exactly match the pinned source.
  if (candidateSet.discovery_method === "committed_registry_v1"
      && (candidateSet.candidates.length > 0
        || candidateSet.errors.length === 0)) {
    const expectedSet = pinnedRegistrySetExpectation(candidateSet);
    if (!expectedSet.ok) {
      return reject(expectedSet.reason, null, expectedSet.detail);
    }
  }
  const seen = new Set();
  for (const candidate of candidateSet.candidates) {
    if (seen.has(candidate.candidate_id)) {
      return reject("duplicate_candidate_id", candidate);
    }
    seen.add(candidate.candidate_id);
    if (candidate.automap_version !== candidateSet.automap_version
        || candidate.discovery_method !== candidateSet.discovery_method) {
      return reject("candidate_set_member_context_mismatch", candidate);
    }
    const result = validateCandidate(candidate, { stage, approvalRecords });
    if (!result.ok) return result;
  }
  return Object.freeze({ ok: true });
}

// Human classification confirmation, bound to an exact candidate.
//
// A confirmation is valid only against the precise candidate it names: same
// candidate ID, same candidate content hash, same structural schema
// fingerprint. Structural drift therefore makes an existing confirmation
// stale and rejected. A general mapping approval never substitutes for this
// artifact.

import {
  WIRE_SAFE_ID_RE,
  HASH_RE,
  RFC3339_UTC_RE,
} from "../../governance-core/contracts.mjs";
import { CONFIRMATION_SCHEMA, normalizeEffects } from "../vocabulary.mjs";
import { proposeRisk } from "./classification.mjs";
import {
  buildOutboundMetadataPreview,
  candidateContentHash,
} from "./discovery.mjs";
import { validateCandidate } from "./candidate-validate.mjs";
import { validateArtifact, assertValidArtifact } from "../contracts.mjs";

export const CONFIRMATION_ARTIFACT_VERSION = "1";

const REJECTION_REASONS = Object.freeze([
  "artifact_malformed",
  "artifact_contract_invalid",
  "artifact_schema_unsupported",
  "artifact_version_unsupported",
  "candidate_id_unknown",
  "candidate_invalid",
  "candidate_id_mismatch",
  "candidate_hash_mismatch",
  "structural_fingerprint_mismatch",
  "stale_after_structural_drift",
  "reviewer_identity_missing",
  "reviewer_evidence_missing",
  "selected_effects_invalid",
  "selected_effects_unknown_not_confirmable",
  "confirmed_at_invalid",
  "rationale_missing",
  "confirmed_candidate_hash_invalid",
]);
export const CONFIRMATION_REJECTION_REASONS = new Set(REJECTION_REASONS);

function reject(reason) {
  if (!CONFIRMATION_REJECTION_REASONS.has(reason)) {
    throw new TypeError("unknown_rejection_reason");
  }
  return Object.freeze({ ok: false, reason });
}

function isNonEmptyString(value, maximum = 256) {
  return typeof value === "string" && value.length > 0 && value.length <= maximum
    && !/[\r\n]/.test(value);
}

/**
 * Validate the intrinsic semantics of a confirmation artifact or emitted
 * confirmation record without selecting a candidate. `requirePostBinding`
 * distinguishes an emitted record (which must bind the recomputed confirmed
 * candidate) from a pre-confirmation review artifact.
 */
export function validateConfirmationRecord(
  artifact, { requirePostBinding = false } = {},
) {
  if (!artifact || typeof artifact !== "object" || Array.isArray(artifact)) {
    return reject("artifact_malformed");
  }
  if (artifact.schema !== CONFIRMATION_SCHEMA) {
    return reject("artifact_schema_unsupported");
  }
  const contract = validateArtifact(CONFIRMATION_SCHEMA, artifact);
  if (!contract.ok) return reject("artifact_contract_invalid");
  if (artifact.artifact_version !== CONFIRMATION_ARTIFACT_VERSION) {
    return reject("artifact_version_unsupported");
  }
  if (!isNonEmptyString(artifact.candidate_id, 96)
      || !HASH_RE.test(artifact.candidate_content_hash ?? "")
      || !HASH_RE.test(artifact.structural_schema_fingerprint ?? "")) {
    return reject("artifact_malformed");
  }
  const hasPostBinding =
    Object.prototype.hasOwnProperty.call(artifact, "confirmed_candidate_content_hash");
  if (requirePostBinding !== hasPostBinding
      || hasPostBinding
        && (!HASH_RE.test(artifact.confirmed_candidate_content_hash ?? "")
          || artifact.confirmed_candidate_content_hash
            === artifact.candidate_content_hash)) {
    return reject("confirmed_candidate_hash_invalid");
  }
  const effects = normalizeEffects(artifact.selected_effects);
  if (effects === null) return reject("selected_effects_invalid");
  if (effects.includes("UNKNOWN")) {
    return reject("selected_effects_unknown_not_confirmable");
  }
  if (!isNonEmptyString(artifact.reviewer_identity, 96)
      || !WIRE_SAFE_ID_RE.test(artifact.reviewer_identity)) {
    return reject("reviewer_identity_missing");
  }
  if (!Array.isArray(artifact.evidence_refs) || artifact.evidence_refs.length === 0
      || new Set(artifact.evidence_refs).size !== artifact.evidence_refs.length
      || !artifact.evidence_refs.every((ref) => isNonEmptyString(ref, 256))) {
    return reject("reviewer_evidence_missing");
  }
  if (typeof artifact.confirmed_at !== "string"
      || !RFC3339_UTC_RE.test(artifact.confirmed_at)) {
    return reject("confirmed_at_invalid");
  }
  if (!isNonEmptyString(artifact.rationale, 512)) return reject("rationale_missing");
  return Object.freeze({ ok: true, effects });
}

/**
 * Validate a human-confirmation artifact against the exact candidate list it
 * claims to confirm. `previousStructuralFingerprint` may be supplied by drift
 * evaluation so a confirmation minted before known structural drift is
 * reported as stale rather than merely mismatched.
 */
export function validateConfirmation(artifact, candidates, options = {}) {
  const record = validateConfirmationRecord(artifact);
  if (!record.ok) return record;
  const candidate = candidates.find(
    (entry) => entry.candidate_id === artifact.candidate_id,
  );
  if (!candidate) return reject("candidate_id_unknown");
  const candidateValidation = validateCandidate(candidate, { stage: "any" });
  if (!candidateValidation.ok) return reject("candidate_invalid");
  if (candidate.candidate_id !== artifact.candidate_id) {
    return reject("candidate_id_mismatch");
  }
  const structuralDrifted = candidate.structural_schema_fingerprint
    !== artifact.structural_schema_fingerprint;
  if (structuralDrifted) {
    return reject(options.knownPreviousFingerprint !== undefined
      && options.knownPreviousFingerprint === artifact.structural_schema_fingerprint
      ? "stale_after_structural_drift"
      : "structural_fingerprint_mismatch");
  }
  if (candidate.candidate_content_hash !== artifact.candidate_content_hash) {
    return reject("candidate_hash_mismatch");
  }
  return Object.freeze({ ok: true, candidate, effects: record.effects });
}

/**
 * Apply a validated confirmation to its candidate, yielding the updated
 * candidate record (CONFIRMED_HUMAN, selected effects preserved as a set)
 * plus a confirmation record for the audit trail. Pure: inputs are not
 * mutated, and nothing becomes runtime-active.
 *
 * Every derived field is recomputed rather than copied (Sol repair): the
 * risk proposal, the outbound metadata preview, and the candidate content
 * hash are rebuilt from the confirmed effects, so a confirmation can never
 * produce an internally inconsistent candidate whose risk or preview still
 * reflect the pre-confirmation classification.
 */
export function applyConfirmation(artifact, candidates, options = {}) {
  const validation = validateConfirmation(artifact, candidates, options);
  if (!validation.ok) return validation;
  const { candidate, effects } = validation;
  const classification = {
    status: "CONFIRMED_HUMAN",
    method: "human_confirmation_artifact",
    evidence: [...artifact.evidence_refs],
    confirmed_by: artifact.reviewer_identity,
    confirmed_at: artifact.confirmed_at,
    rationale: artifact.rationale,
    ...(candidate.classification.advisory_suggestion
      ? { advisory_suggestion: { ...candidate.classification.advisory_suggestion } }
      : {}),
  };
  const updated = {
    ...candidate,
    effects: [...effects],
    classification,
  };
  updated.proposed_risk = proposeRisk({
    classification: { ...classification, effects: updated.effects },
    reversibility: updated.reversibility,
    targetResourceClass: updated.target_resource_class,
    dataClasses: updated.data_classes,
    authoritativeActionClass: null,
    authoritativeSource: null,
  });
  delete updated.candidate_content_hash;
  updated.outbound_metadata_preview = buildOutboundMetadataPreview(updated);
  updated.candidate_content_hash = candidateContentHash(updated);
  const confirmationRecord = Object.freeze({
    schema: CONFIRMATION_SCHEMA,
    artifact_version: CONFIRMATION_ARTIFACT_VERSION,
    candidate_id: artifact.candidate_id,
    candidate_content_hash: artifact.candidate_content_hash,
    // Post-recompute binding: commits to the exact confirmed candidate so
    // a later approval can verify the whole chain, not just the
    // pre-confirmation state.
    confirmed_candidate_content_hash: updated.candidate_content_hash,
    structural_schema_fingerprint: artifact.structural_schema_fingerprint,
    selected_effects: [...effects],
    reviewer_identity: artifact.reviewer_identity,
    confirmed_at: artifact.confirmed_at,
    rationale: artifact.rationale,
    evidence_refs: [...artifact.evidence_refs],
  });
  // Producer output contract: both the recomputed candidate and the
  // confirmation record must validate before returning.
  assertValidArtifact("mcpherson-governance-capability-candidate/v1", updated);
  const updatedValidation = validateCandidate(updated, { stage: "proposal" });
  if (!updatedValidation.ok) {
    const error = new TypeError(
      `confirmed_candidate_output_invalid:${updatedValidation.reason}`,
    );
    error.detail = updatedValidation;
    throw error;
  }
  assertValidArtifact(CONFIRMATION_SCHEMA, confirmationRecord);
  return Object.freeze({
    ok: true,
    updated_candidate: updated,
    confirmation_record: confirmationRecord,
  });
}

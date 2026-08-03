// Generated LIVE_SHADOW classification confirmation.
//
// This is the only producer for the live confirmation contract. Operators
// select effects through the bounded effect enum; the producer derives every
// proposal and observation binding and emits no activation-shaped field.

import { createHash } from "node:crypto";
import { canonicalizeJson } from "../../governance-core/canonical.mjs";
import { RFC3339_UTC_RE, WIRE_SAFE_ID_RE } from "../../governance-core/contracts.mjs";
import { validateArtifact, validateEnvelope, assertValidArtifact } from "../contracts.mjs";
import { AUTOMAP_VERSION, normalizeEffects } from "../vocabulary.mjs";
import { validateCandidateSet } from "./candidate-validate.mjs";
import {
  applyConfirmation,
  validateConfirmationRecord,
} from "./confirmation.mjs";

export const LIVE_CONFIRMATION_SCHEMA =
  "mcpherson-governance-live-classification-confirmation/v1";
export const LIVE_CONFIRMATION_VERSION = "1";
export const LIVE_AUTHORITY_FIELDS = Object.freeze({
  authority: "NONE",
  enforcement: false,
  automatic_mapping_activation: false,
  outbound_actions: false,
});

function reject(reason) {
  return Object.freeze({ ok: false, reason });
}

function confirmationIdFor(record) {
  const bound = {};
  for (const key of Object.keys(record)) {
    if (key === "confirmation_id"
        || key === "confirmed_candidate_content_hash") continue;
    bound[key] = record[key];
  }
  return `live-confirm-${createHash("sha256")
    .update(canonicalizeJson(bound), "utf8").digest("hex").slice(0, 24)}`;
}

function expectedObservationBinding(observation) {
  return Object.freeze({
    manifest_schema: "mcpherson-governance-live-observation-manifest/v1",
    observation_id: observation.observation_id,
    manifest_sha256: observation.manifest_sha256,
    snapshot_sha256:
      observation.artifacts?.["capability-snapshot.json"]?.sha256,
    source_id: observation.source_id,
    captured_at: observation.captured_at,
  });
}

function sameJson(left, right) {
  return canonicalizeJson(left) === canonicalizeJson(right);
}

export function validateLiveObservationBinding(binding, observation) {
  if (!observation?.ok) return reject("observation_not_verified");
  if (!sameJson(binding, expectedObservationBinding(observation))) {
    return reject("observation_binding_mismatch");
  }
  return Object.freeze({ ok: true });
}

export function validateLiveClassificationConfirmation(
  artifact,
  {
    requirePostBinding = false,
    proposalSet = null,
    observation = null,
  } = {},
) {
  const contract = validateArtifact(LIVE_CONFIRMATION_SCHEMA, artifact);
  if (!contract.ok) return reject("confirmation_contract_invalid");
  const hasPost = Object.prototype.hasOwnProperty.call(
    artifact, "confirmed_candidate_content_hash",
  );
  if (hasPost !== requirePostBinding
      || hasPost
        && artifact.confirmed_candidate_content_hash
          === artifact.candidate_content_hash) {
    return reject("confirmation_post_binding_invalid");
  }
  if (artifact.confirmation_id !== confirmationIdFor(artifact)) {
    return reject("confirmation_id_mismatch");
  }
  const effects = normalizeEffects(artifact.selected_effects);
  if (effects === null || effects.includes("UNKNOWN")) {
    return reject("confirmation_effects_invalid");
  }
  if (!WIRE_SAFE_ID_RE.test(artifact.reviewer_identity)
      || !RFC3339_UTC_RE.test(artifact.confirmed_at)
      || typeof artifact.rationale !== "string"
      || artifact.rationale.length === 0
      || /[\r\n]/.test(artifact.rationale)) {
    return reject("confirmation_operator_fields_invalid");
  }
  if (proposalSet !== null) {
    const envelope = validateEnvelope(
      "mcpherson-governance-capability-candidate-set/v1", proposalSet,
    );
    const semantic = envelope.ok
      ? validateCandidateSet(proposalSet, { stage: "proposal" })
      : reject("proposal_contract_invalid");
    if (!envelope.ok || !semantic.ok
        || proposalSet.automap_version !== artifact.automap_version
        || proposalSet.discovery_method !== "openclaw_live_gateway_v1") {
      return reject("proposal_binding_invalid");
    }
    const candidate = proposalSet.candidates.find(
      (entry) => entry.candidate_id === artifact.candidate_id,
    );
    if (!candidate
        || candidate.candidate_content_hash !== artifact.candidate_content_hash
        || candidate.structural_schema_fingerprint
          !== artifact.structural_schema_fingerprint
        || candidate.source_document_sha256 !== artifact.source_document_sha256
        || candidate.source_id !== artifact.observation_binding.source_id) {
      return reject("proposal_binding_invalid");
    }
  }
  if (observation !== null) {
    const binding = validateLiveObservationBinding(
      artifact.observation_binding, observation,
    );
    if (!binding.ok
        || artifact.source_document_sha256
          !== observation.artifacts?.["capability-snapshot.json"]?.sha256) {
      return reject("observation_binding_invalid");
    }
  }
  return Object.freeze({ ok: true, effects });
}

export function createLiveClassificationConfirmation({
  proposalSet,
  candidateId,
  selectedEffects,
  reviewerIdentity,
  confirmedAt,
  rationale,
  observation,
}) {
  const proposalContract = validateEnvelope(
    "mcpherson-governance-capability-candidate-set/v1", proposalSet,
  );
  const proposalSemantic = proposalContract.ok
    ? validateCandidateSet(proposalSet, { stage: "proposal" })
    : reject("proposal_contract_invalid");
  if (!proposalContract.ok || !proposalSemantic.ok
      || proposalSet.discovery_method !== "openclaw_live_gateway_v1"
      || proposalSet.automap_version !== AUTOMAP_VERSION) {
    return reject("proposal_invalid");
  }
  const candidate = proposalSet.candidates.find(
    (entry) => entry.candidate_id === candidateId,
  );
  if (!candidate) return reject("candidate_unknown");
  const effects = normalizeEffects(selectedEffects);
  if (effects === null || effects.includes("UNKNOWN")) {
    return reject("selected_effects_invalid");
  }
  const binding = expectedObservationBinding(observation ?? {});
  if (!observation?.ok
      || candidate.source_id !== binding.source_id
      || candidate.source_document_sha256 !== binding.snapshot_sha256) {
    return reject("source_observation_binding_invalid");
  }
  const record = {
    schema: LIVE_CONFIRMATION_SCHEMA,
    artifact_version: LIVE_CONFIRMATION_VERSION,
    proposal_schema: proposalSet.schema,
    automap_version: proposalSet.automap_version,
    candidate_id: candidate.candidate_id,
    candidate_content_hash: candidate.candidate_content_hash,
    structural_schema_fingerprint: candidate.structural_schema_fingerprint,
    source_document_sha256: candidate.source_document_sha256,
    observation_binding: binding,
    selected_effects: [...effects],
    reviewer_identity: reviewerIdentity,
    confirmed_at: confirmedAt,
    rationale,
    evidence_refs: [
      `observation:${binding.observation_id}`,
      `snapshot:${binding.snapshot_sha256}`,
    ],
    ...LIVE_AUTHORITY_FIELDS,
  };
  record.confirmation_id = confirmationIdFor(record);
  const validation = validateLiveClassificationConfirmation(record, {
    proposalSet,
    observation,
  });
  if (!validation.ok) return validation;
  assertValidArtifact(LIVE_CONFIRMATION_SCHEMA, record);
  return Object.freeze({ ok: true, confirmation: Object.freeze(record) });
}

function legacyArtifact(artifact) {
  return Object.freeze({
    schema: "mcpherson-governance-human-classification-confirmation/v1",
    artifact_version: "1",
    candidate_id: artifact.candidate_id,
    candidate_content_hash: artifact.candidate_content_hash,
    structural_schema_fingerprint: artifact.structural_schema_fingerprint,
    selected_effects: [...artifact.selected_effects],
    reviewer_identity: artifact.reviewer_identity,
    confirmed_at: artifact.confirmed_at,
    rationale: artifact.rationale,
    evidence_refs: [...artifact.evidence_refs],
  });
}

export function applyLiveClassificationConfirmation({
  artifact,
  proposalSet,
  observation,
}) {
  const validation = validateLiveClassificationConfirmation(artifact, {
    proposalSet,
    observation,
  });
  if (!validation.ok) return validation;
  const applied = applyConfirmation(legacyArtifact(artifact), proposalSet.candidates);
  if (!applied.ok) return applied;
  const confirmation = Object.freeze({
    ...artifact,
    confirmed_candidate_content_hash:
      applied.updated_candidate.candidate_content_hash,
  });
  if (confirmation.confirmation_id !== confirmationIdFor(confirmation)) {
    return reject("confirmation_id_mismatch");
  }
  assertValidArtifact(LIVE_CONFIRMATION_SCHEMA, confirmation);
  const emitted = validateLiveClassificationConfirmation(confirmation, {
    requirePostBinding: true,
    proposalSet,
    observation,
  });
  if (!emitted.ok) return emitted;
  return Object.freeze({
    ok: true,
    updated_candidate: applied.updated_candidate,
    confirmation_record: confirmation,
  });
}

export function legacyConfirmationForApproval(artifact) {
  const legacy = {
    ...legacyArtifact(artifact),
    ...(artifact.confirmed_candidate_content_hash
      ? {
        confirmed_candidate_content_hash:
          artifact.confirmed_candidate_content_hash,
      }
      : {}),
  };
  const validation = validateConfirmationRecord(legacy, {
    requirePostBinding: artifact.confirmed_candidate_content_hash !== undefined,
  });
  return validation.ok ? Object.freeze(legacy) : null;
}

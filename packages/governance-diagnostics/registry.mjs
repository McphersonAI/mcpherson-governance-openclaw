// Inert registry-ready shadow mapping export, validation, preview, and lookup.
//
// There is intentionally no registry application function in v0.6. A patch
// can be generated, independently validated, previewed, and overlaid in memory
// by the shadow lookup evaluator. It cannot write a registry or execute an
// action.

import { createHash } from "node:crypto";
import { canonicalizeJson } from "../governance-core/canonical.mjs";
import { isCalendarUtcTimestamp } from "./schema-validate.mjs";
import { assertValidArtifact, validateArtifact, validateEnvelope } from "./contracts.mjs";
import { validateCandidateSet } from "./automap/candidate-validate.mjs";
import { candidateContentHash } from "./automap/discovery.mjs";
import { validateApprovalRecord } from "./automap/approval.mjs";
import {
  applyLiveClassificationConfirmation,
  validateLiveClassificationConfirmation,
  LIVE_AUTHORITY_FIELDS,
} from "./automap/live-confirmation.mjs";

export const REGISTRY_READY_SCHEMA =
  "mcpherson-governance-registry-ready-shadow-mapping/v1";
export const SHADOW_REGISTRY_SCHEMA =
  "mcpherson-governance-shadow-mapping-registry/v1";
export const REGISTRY_PATCH_SCHEMA =
  "mcpherson-governance-shadow-registry-patch/v1";
export const MAX_LIVE_OBSERVATION_AGE_MS = 48 * 60 * 60 * 1000;

function reject(reason) {
  return Object.freeze({ ok: false, reason });
}

export function deterministicArtifactHash(value) {
  return `sha256:${createHash("sha256")
    .update(canonicalizeJson(value), "utf8").digest("hex")}`;
}

function deterministicId(prefix, value) {
  return `${prefix}-${createHash("sha256")
    .update(canonicalizeJson(value), "utf8").digest("hex").slice(0, 24)}`;
}

function sameJson(left, right) {
  return canonicalizeJson(left) === canonicalizeJson(right);
}

export function validateObservationFreshness(observation, now) {
  if (!observation?.ok || !isCalendarUtcTimestamp(now)
      || !isCalendarUtcTimestamp(observation.captured_at)) {
    return reject("observation_time_invalid");
  }
  const age = Date.parse(now) - Date.parse(observation.captured_at);
  if (age < 0) return reject("observation_from_future");
  if (age > MAX_LIVE_OBSERVATION_AGE_MS) return reject("observation_stale");
  return Object.freeze({ ok: true, age_ms: age });
}

export function validateRegistryReadyRecord(record) {
  const contract = validateArtifact(REGISTRY_READY_SCHEMA, record);
  if (!contract.ok) return reject("registry_record_contract_invalid");
  const expectedId = deterministicId("shadow-map", {
    candidate_id: record.candidate_id,
    proposal_content_hash: record.proposal_content_hash,
    confirmation_id: record.classification_binding.confirmation_id,
    approval_id: record.approval_binding.approval_id,
    observation_id: record.observation_binding.observation_id,
    manifest_sha256: record.observation_binding.manifest_sha256,
    registry_record_version: record.record_version,
  });
  if (record.mapping_id !== expectedId) {
    return reject("registry_record_id_mismatch");
  }
  return Object.freeze({ ok: true });
}

export function validateShadowRegistry(registry) {
  const contract = validateArtifact(SHADOW_REGISTRY_SCHEMA, registry);
  if (!contract.ok) return reject("shadow_registry_contract_invalid");
  const mappingIds = new Set();
  const capabilities = new Set();
  for (const record of registry.records) {
    const validation = validateRegistryReadyRecord(record);
    if (!validation.ok) return validation;
    if (mappingIds.has(record.mapping_id)) {
      return reject("shadow_registry_duplicate_mapping");
    }
    if (capabilities.has(record.normalized_capability)) {
      return reject("shadow_registry_conflicting_capability");
    }
    mappingIds.add(record.mapping_id);
    capabilities.add(record.normalized_capability);
  }
  return Object.freeze({ ok: true });
}

function expectedApprovedCandidate(confirmedCandidate) {
  const approved = {
    ...confirmedCandidate,
    mapping_status: "APPROVED_DOCUMENTATION_ONLY",
  };
  delete approved.candidate_content_hash;
  approved.candidate_content_hash = candidateContentHash(approved);
  return approved;
}

function validateBoundInputs({
  proposalSet, candidateId, confirmation, approval, observation, now,
}) {
  const proposalContract = validateEnvelope(
    "mcpherson-governance-capability-candidate-set/v1", proposalSet,
  );
  const proposalSemantic = proposalContract.ok
    ? validateCandidateSet(proposalSet, { stage: "proposal" })
    : reject("proposal_contract_invalid");
  if (!proposalContract.ok || !proposalSemantic.ok
      || proposalSet.discovery_method !== "openclaw_live_gateway_v1") {
    return reject("proposal_invalid");
  }
  const freshness = validateObservationFreshness(observation, now);
  if (!freshness.ok) return freshness;
  const confirmationValidation = validateLiveClassificationConfirmation(
    confirmation,
    {
      requirePostBinding: true,
      proposalSet,
      observation,
    },
  );
  if (!confirmationValidation.ok) return confirmationValidation;
  const approvalValidation = validateApprovalRecord(approval);
  if (!approvalValidation.ok) return reject(`approval_invalid:${approvalValidation.reason}`);
  if (approval.classification_confirmed !== true
      || approval.confirmation_bound !== true
      || approval.runtime_active !== false
      || approval.enforcement_eligible !== false) {
    return reject("approval_not_exportable");
  }
  const applied = applyLiveClassificationConfirmation({
    artifact: (() => {
      const request = { ...confirmation };
      delete request.confirmed_candidate_content_hash;
      return request;
    })(),
    proposalSet,
    observation,
  });
  if (!applied.ok
      || applied.confirmation_record.confirmed_candidate_content_hash
        !== confirmation.confirmed_candidate_content_hash) {
    return reject("classification_binding_invalid");
  }
  const candidate = proposalSet.candidates.find(
    (entry) => entry.candidate_id === candidateId,
  );
  const approvedCandidate = expectedApprovedCandidate(applied.updated_candidate);
  if (!candidate
      || candidate.candidate_id !== confirmation.candidate_id
      || approval.candidate_id !== candidate.candidate_id
      || approval.candidate_content_hash
        !== applied.updated_candidate.candidate_content_hash
      || approval.approved_candidate_content_hash
        !== approvedCandidate.candidate_content_hash
      || approval.structural_schema_fingerprint
        !== candidate.structural_schema_fingerprint) {
    return reject("approval_binding_mismatch");
  }
  return Object.freeze({
    ok: true,
    candidate,
    confirmed_candidate: applied.updated_candidate,
    approved_candidate: approvedCandidate,
  });
}

function registryReadyRecord({
  candidate, confirmedCandidate, confirmation, approval,
}) {
  const record = {
    schema: REGISTRY_READY_SCHEMA,
    record_version: "1",
    status: "APPROVED_SHADOW_ONLY",
    candidate_id: candidate.candidate_id,
    proposal_content_hash: candidate.candidate_content_hash,
    proposal_schema: "mcpherson-governance-capability-candidate-set/v1",
    automap_version: candidate.automap_version,
    normalized_capability: candidate.normalized_capability,
    native_tool_name: candidate.native_tool_name,
    native_operation_name: candidate.native_operation_name,
    effects: [...confirmation.selected_effects],
    proposed_action_class:
      confirmedCandidate.proposed_risk.proposed_action_class,
    classification_binding: {
      schema: confirmation.schema,
      artifact_version: confirmation.artifact_version,
      confirmation_id: confirmation.confirmation_id,
      candidate_content_hash: confirmation.candidate_content_hash,
      confirmed_candidate_content_hash:
        confirmation.confirmed_candidate_content_hash,
      structural_schema_fingerprint:
        confirmation.structural_schema_fingerprint,
    },
    approval_binding: {
      schema: approval.schema,
      artifact_version: approval.artifact_version,
      approval_id: approval.approval_id,
      approved_candidate_content_hash:
        approval.approved_candidate_content_hash,
      approval_scope: approval.approval_scope,
    },
    observation_binding: { ...confirmation.observation_binding },
    ...LIVE_AUTHORITY_FIELDS,
    runtime_active: false,
    direct_activation: false,
    shadow_only: true,
  };
  record.mapping_id = deterministicId("shadow-map", {
    candidate_id: record.candidate_id,
    proposal_content_hash: record.proposal_content_hash,
    confirmation_id: record.classification_binding.confirmation_id,
    approval_id: record.approval_binding.approval_id,
    observation_id: record.observation_binding.observation_id,
    manifest_sha256: record.observation_binding.manifest_sha256,
    registry_record_version: record.record_version,
  });
  assertValidArtifact(REGISTRY_READY_SCHEMA, record);
  return Object.freeze(record);
}

function conflictReason(registry, record) {
  if (registry.records.some((entry) => entry.mapping_id === record.mapping_id)) {
    return "registry_patch_duplicate_mapping";
  }
  const sameCapability = registry.records.find(
    (entry) => entry.normalized_capability === record.normalized_capability,
  );
  return sameCapability ? "registry_patch_conflicting_mapping" : null;
}

export function buildRegistryPatch({
  proposalSet,
  candidateId,
  confirmation,
  approval,
  observation,
  registry,
  now,
}) {
  const registryValidation = validateShadowRegistry(registry);
  if (!registryValidation.ok) return registryValidation;
  const bindings = validateBoundInputs({
    proposalSet, candidateId, confirmation, approval, observation, now,
  });
  if (!bindings.ok) return bindings;
  const record = registryReadyRecord({
    candidate: bindings.candidate,
    confirmedCandidate: bindings.confirmed_candidate,
    confirmation,
    approval,
  });
  const conflict = conflictReason(registry, record);
  if (conflict !== null) return reject(conflict);
  const patch = {
    schema: REGISTRY_PATCH_SCHEMA,
    patch_version: "1",
    registry_schema: registry.schema,
    registry_version: registry.registry_version,
    base_registry_sha256: deterministicArtifactHash(registry),
    operation: "ADD",
    record,
    status: "VALIDATED_NOT_APPLIED",
    ...LIVE_AUTHORITY_FIELDS,
    application_requires_confirmation: true,
    applied: false,
  };
  patch.patch_id = deterministicId("shadow-patch", {
    patch_version: patch.patch_version,
    registry_schema: patch.registry_schema,
    registry_version: patch.registry_version,
    base_registry_sha256: patch.base_registry_sha256,
    operation: patch.operation,
    record_id: record.mapping_id,
  });
  assertValidArtifact(REGISTRY_PATCH_SCHEMA, patch);
  return Object.freeze({ ok: true, patch: Object.freeze(patch) });
}

export function validateRegistryPatch({
  patch,
  proposalSet,
  confirmation,
  approval,
  observation,
  registry,
  now,
}) {
  const patchContract = validateArtifact(REGISTRY_PATCH_SCHEMA, patch);
  if (!patchContract.ok) return reject("registry_patch_contract_invalid");
  const recordValidation = validateRegistryReadyRecord(patch.record);
  if (!recordValidation.ok) return recordValidation;
  const rebuilt = buildRegistryPatch({
    proposalSet,
    candidateId: patch.record.candidate_id,
    confirmation,
    approval,
    observation,
    registry,
    now,
  });
  if (!rebuilt.ok) return rebuilt;
  if (!sameJson(rebuilt.patch, patch)) {
    return reject("registry_patch_binding_mismatch");
  }
  return Object.freeze({
    ok: true,
    patch_id: patch.patch_id,
    mapping_id: patch.record.mapping_id,
    status: patch.status,
    authority: "NONE",
    enforcement: false,
    mutates_registry: false,
  });
}

export function previewRegistryPatch({ patch, registry, validation }) {
  if (!validation?.ok) return reject("registry_patch_not_validated");
  const registryValidation = validateShadowRegistry(registry);
  if (!registryValidation.ok) return registryValidation;
  if (patch.base_registry_sha256 !== deterministicArtifactHash(registry)) {
    return reject("registry_patch_base_changed");
  }
  return Object.freeze({
    ok: true,
    patch_id: patch.patch_id,
    mutates_registry: false,
    application_requires_confirmation: true,
    applied: false,
    exact_diff: Object.freeze({
      operation: "ADD",
      before: null,
      after: patch.record,
    }),
  });
}

export function shadowLookup({ normalizedCapability, registry, patch = null }) {
  const validation = validateShadowRegistry(registry);
  if (!validation.ok) return validation;
  const records = [...registry.records];
  if (patch !== null) {
    const patchContract = validateArtifact(REGISTRY_PATCH_SCHEMA, patch);
    const recordValidation = patchContract.ok
      ? validateRegistryReadyRecord(patch.record)
      : reject("registry_patch_contract_invalid");
    if (!patchContract.ok || !recordValidation.ok
        || patch.base_registry_sha256 !== deterministicArtifactHash(registry)
        || conflictReason(registry, patch.record) !== null) {
      return reject("registry_patch_not_lookup_eligible");
    }
    records.push(patch.record);
  }
  const record = records.find(
    (entry) => entry.normalized_capability === normalizedCapability,
  ) ?? null;
  return Object.freeze({
    ok: true,
    lookup: record === null ? "MISS" : "RESOLVED",
    normalized_capability: normalizedCapability,
    mapping_id: record?.mapping_id ?? null,
    mapping_status: record?.status ?? "UNMAPPED",
    authority: "NONE",
    enforcement: false,
    automatic_mapping_activation: false,
    outbound_actions: false,
    action_taken: false,
    registry_mutated: false,
  });
}

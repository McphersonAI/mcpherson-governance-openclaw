// Deterministic schema-drift detection between two candidate sets.
//
// One coherent per-candidate semantic identity rule (Sol re-audit repair):
// the material identity is `candidate_content_hash` — the exact value a human
// confirmation and a documentation-only approval bind to. Drift and
// confirmation invalidation therefore trigger on the same change:
//
//   - content hash equal, metadata fingerprint equal    -> no drift
//   - content hash equal, metadata fingerprint differs  -> DESCRIPTIVE / INFORMATIONAL
//   - content hash differs, structural fingerprint differs -> STRUCTURAL / MATERIAL
//   - content hash differs, structural fingerprint equal   -> SEMANTIC / MATERIAL
//   - candidate added or removed                        -> STRUCTURAL / MATERIAL
//   - malformed/incomparable candidate                  -> UNKNOWN
//
// So an effects-only change (which changes the content hash but not the
// structural fingerprint) now produces a MATERIAL drift event AND invalidates
// a bound confirmation, closing the divergence Sol reproduced. Bound
// confirmation/approval artifacts are contract-validated before they are
// counted; a schema-invalid artifact can no longer influence staleness.
// Drift never updates, approves, rejects, or activates anything by itself.

import { createHash } from "node:crypto";
import { canonicalizeJson } from "../../governance-core/canonical.mjs";
import { HASH_RE } from "../../governance-core/contracts.mjs";
import {
  AUTOMAP_VERSION,
  CONFIRMATION_SCHEMA,
  APPROVAL_SCHEMA,
  DRIFT_SCHEMA,
} from "../vocabulary.mjs";
import { isCalendarUtcTimestamp } from "../schema-validate.mjs";
import { validateArtifact, assertValidArtifact } from "../contracts.mjs";
import { validateCandidateSet } from "./candidate-validate.mjs";
import { validateConfirmationRecord } from "./confirmation.mjs";
import { validateApprovalRecord } from "./approval.mjs";

export const DRIFT_TYPE_VALUES = Object.freeze([
  "STRUCTURAL", "SEMANTIC", "DESCRIPTIVE", "UNKNOWN",
]);
export const DRIFT_SEVERITY_VALUES = Object.freeze([
  "MATERIAL", "INFORMATIONAL", "UNKNOWN",
]);
export const DRIFT_CHANGE_KIND_VALUES = Object.freeze([
  "MODIFIED", "ADDED", "REMOVED",
]);
export const DRIFT_EVENT_SET_SCHEMA =
  "mcpherson-governance-schema-drift-event-set/v1";

function pathKey(entry) {
  const separator = entry.lastIndexOf("=");
  return separator === -1 ? entry : entry.slice(0, separator);
}

function diffStructuralPaths(previousPaths, currentPaths) {
  const previous = new Map();
  for (const entry of previousPaths) previous.set(pathKey(entry), entry);
  const current = new Map();
  for (const entry of currentPaths) current.set(pathKey(entry), entry);
  const added = [];
  const removed = [];
  const changed = [];
  for (const [key, entry] of current) {
    if (!previous.has(key)) added.push(key);
    else if (previous.get(key) !== entry) changed.push(key);
  }
  for (const key of previous.keys()) {
    if (!current.has(key)) removed.push(key);
  }
  return {
    fields_added: added.sort(),
    fields_removed: removed.sort(),
    fields_changed: changed.sort(),
  };
}

function candidateComparable(candidate) {
  return candidate && typeof candidate === "object"
    && typeof candidate.candidate_id === "string"
    && HASH_RE.test(candidate.structural_schema_fingerprint ?? "")
    && HASH_RE.test(candidate.metadata_fingerprint ?? "")
    && HASH_RE.test(candidate.candidate_content_hash ?? "")
    && Array.isArray(candidate.structural_paths);
}

function driftId(fields) {
  return `mgd-${createHash("sha256")
    .update(canonicalizeJson(fields), "utf8").digest("hex").slice(0, 24)}`;
}

// Only contract-valid confirmation/approval artifacts are counted. Each
// exposes the content hash and structural fingerprint it bound to.
function boundIdentity(artifact) {
  if (artifact?.schema === CONFIRMATION_SCHEMA
      && validateConfirmationRecord(artifact, {
        requirePostBinding: Object.prototype.hasOwnProperty.call(
          artifact, "confirmed_candidate_content_hash",
        ),
      }).ok) {
    return {
      kind: "confirmation",
      candidateId: artifact.candidate_id,
      contentHash: artifact.confirmed_candidate_content_hash
        ?? artifact.candidate_content_hash,
      structuralFingerprint: artifact.structural_schema_fingerprint,
    };
  }
  if (artifact?.schema === APPROVAL_SCHEMA
      && validateApprovalRecord(artifact).ok) {
    return {
      kind: "approval",
      candidateId: artifact.candidate_id,
      contentHash: artifact.approved_candidate_content_hash,
      structuralFingerprint: artifact.structural_schema_fingerprint,
    };
  }
  return null;
}

function invalidDrift(reason, detail = null) {
  return Object.freeze({
    ok: false,
    reason,
    ...(detail === null ? {} : { detail }),
  });
}

function sortedUnique(values) {
  return new Set(values).size === values.length
    && values.every((value, index) => index === 0 || values[index - 1] < value);
}

/** Validate one drift event's cross-field semantics and content-derived ID. */
export function validateDriftRecord(record) {
  const contract = validateArtifact(DRIFT_SCHEMA, record);
  if (!contract.ok) {
    return invalidDrift("drift_record_contract_invalid", contract.errors);
  }
  const clone = { ...record };
  delete clone.drift_id;
  if (record.drift_id !== driftId(clone)) {
    return invalidDrift("drift_id_mismatch");
  }
  for (const values of [
    record.fields_added, record.fields_removed, record.fields_changed,
  ]) {
    if (!sortedUnique(values)) return invalidDrift("drift_fields_not_normalized");
  }
  const addedFields = new Set(record.fields_added);
  const removedFields = new Set(record.fields_removed);
  if (record.fields_removed.some((field) => addedFields.has(field))
      || record.fields_changed.some(
        (field) => addedFields.has(field) || removedFields.has(field),
      )) {
    return invalidDrift("drift_field_sets_overlap");
  }
  const material = record.drift_type === "STRUCTURAL"
    || record.drift_type === "SEMANTIC"
    || record.drift_type === "UNKNOWN";
  const expectedSeverity = record.drift_type === "DESCRIPTIVE"
    ? "INFORMATIONAL"
    : record.drift_type === "UNKNOWN" ? "UNKNOWN" : "MATERIAL";
  if (record.drift_severity !== expectedSeverity
      || record.human_review_required !== material
      || record.approval_stale
        && (!material || record.bound_artifacts_considered === 0)) {
    return invalidDrift("drift_state_inconsistent");
  }
  // Both input candidate sets pass complete semantic validation before any
  // event is emitted, so the v0.6 producer has no incomparable-candidate path.
  // Retaining UNKNOWN in the wire vocabulary does not make a hand-forged
  // comparable event valid.
  if (record.drift_type === "UNKNOWN") {
    return invalidDrift("drift_unknown_not_emittable");
  }
  const previousPresent = record.previous_content_hash !== null
    && record.previous_structural_fingerprint !== null
    && record.previous_metadata_fingerprint !== null;
  const currentPresent = record.current_content_hash !== null
    && record.current_structural_fingerprint !== null
    && record.current_metadata_fingerprint !== null;
  const previousAbsent = record.previous_content_hash === null
    && record.previous_structural_fingerprint === null
    && record.previous_metadata_fingerprint === null;
  const currentAbsent = record.current_content_hash === null
    && record.current_structural_fingerprint === null
    && record.current_metadata_fingerprint === null;
  if (record.change_kind === "ADDED") {
    if (!previousAbsent || !currentPresent || record.drift_type !== "STRUCTURAL") {
      return invalidDrift("drift_added_state_inconsistent");
    }
    if (record.fields_added.length === 0
        || record.fields_removed.length !== 0
        || record.fields_changed.length !== 0) {
      return invalidDrift("drift_added_fields_inconsistent");
    }
  } else if (record.change_kind === "REMOVED") {
    if (!previousPresent || !currentAbsent || record.drift_type !== "STRUCTURAL") {
      return invalidDrift("drift_removed_state_inconsistent");
    }
    if (record.fields_removed.length === 0
        || record.fields_added.length !== 0
        || record.fields_changed.length !== 0) {
      return invalidDrift("drift_removed_fields_inconsistent");
    }
  } else if (!previousPresent || !currentPresent) {
    return invalidDrift("drift_modified_state_inconsistent");
  }
  if (record.drift_type === "DESCRIPTIVE") {
    if (record.change_kind !== "MODIFIED"
        || record.previous_content_hash !== record.current_content_hash
        || record.previous_structural_fingerprint
          !== record.current_structural_fingerprint
        || record.previous_metadata_fingerprint
          === record.current_metadata_fingerprint
        || record.fields_added.length !== 0
        || record.fields_removed.length !== 0
        || record.fields_changed.length !== 0) {
      return invalidDrift("drift_descriptive_state_inconsistent");
    }
  } else if (record.drift_type === "SEMANTIC") {
    if (record.change_kind !== "MODIFIED"
        || record.previous_content_hash === record.current_content_hash
        || record.previous_structural_fingerprint
          !== record.current_structural_fingerprint
        || record.fields_added.length !== 0
        || record.fields_removed.length !== 0
        || record.fields_changed.length !== 0) {
      return invalidDrift("drift_semantic_state_inconsistent");
    }
  } else if (record.drift_type === "STRUCTURAL"
      && record.change_kind === "MODIFIED"
      && (record.previous_content_hash === record.current_content_hash
        || record.previous_structural_fingerprint
          === record.current_structural_fingerprint
        || record.fields_added.length + record.fields_removed.length
          + record.fields_changed.length === 0)) {
    return invalidDrift("drift_structural_state_inconsistent");
  }
  return Object.freeze({ ok: true });
}

/** Validate the drift-event envelope, member semantics, and shared context. */
export function validateDriftEventSet(eventSet) {
  const contract = validateArtifact(DRIFT_EVENT_SET_SCHEMA, eventSet);
  if (!contract.ok) {
    return invalidDrift("drift_event_set_contract_invalid", contract.errors);
  }
  if (eventSet.automap_version !== AUTOMAP_VERSION
      || eventSet.drift_event_schema !== DRIFT_SCHEMA
      || eventSet.drift_count !== eventSet.drift_events.length) {
    return invalidDrift("drift_event_set_context_invalid");
  }
  const candidates = new Set();
  for (const event of eventSet.drift_events) {
    const semantic = validateDriftRecord(event);
    if (!semantic.ok) return semantic;
    if (event.detection_timestamp !== eventSet.detected_at) {
      return invalidDrift("drift_event_set_timestamp_mismatch");
    }
    if (candidates.has(event.candidate_id)) {
      return invalidDrift("drift_event_set_duplicate_candidate");
    }
    candidates.add(event.candidate_id);
  }
  return Object.freeze({ ok: true });
}

function staleness(candidateId, current, boundArtifacts) {
  const bound = boundArtifacts.filter((entry) => entry.candidateId === candidateId);
  if (bound.length === 0) return { boundArtifacts: 0, stale: false };
  if (!current) return { boundArtifacts: bound.length, stale: true };
  const stale = bound.some((entry) => (
    entry.contentHash !== current.candidate_content_hash
    || entry.structuralFingerprint !== current.structural_schema_fingerprint
  ));
  return { boundArtifacts: bound.length, stale };
}

function makeRecord({
  candidate_id, change_kind, drift_type, drift_severity, previous, current,
  diff, detectedAt, mappingState, boundArtifacts,
}) {
  const { boundArtifacts: consideredCount, stale } = staleness(
    candidate_id, current, boundArtifacts,
  );
  const material = drift_type === "STRUCTURAL" || drift_type === "SEMANTIC"
    || drift_type === "UNKNOWN";
  const record = {
    schema: DRIFT_SCHEMA,
    candidate_id,
    change_kind,
    drift_type,
    drift_severity,
    previous_structural_fingerprint: previous?.structural_schema_fingerprint ?? null,
    current_structural_fingerprint: current?.structural_schema_fingerprint ?? null,
    previous_metadata_fingerprint: previous?.metadata_fingerprint ?? null,
    current_metadata_fingerprint: current?.metadata_fingerprint ?? null,
    previous_content_hash: previous?.candidate_content_hash ?? null,
    current_content_hash: current?.candidate_content_hash ?? null,
    fields_added: diff?.fields_added ?? [],
    fields_removed: diff?.fields_removed ?? [],
    fields_changed: diff?.fields_changed ?? [],
    detection_timestamp: detectedAt,
    existing_mapping_state: mappingState ?? "DISCOVERED",
    bound_artifacts_considered: consideredCount,
    approval_stale: material && stale,
    human_review_required: material,
  };
  record.drift_id = driftId(record);
  assertValidArtifact(DRIFT_SCHEMA, record);
  const semantic = validateDriftRecord(record);
  if (!semantic.ok) {
    throw new TypeError(`drift_output_invalid:${semantic.reason}`);
  }
  return Object.freeze(record);
}

/**
 * Compare a previous and a current candidate set. `artifacts` may contain
 * confirmation and approval records; only contract-valid artifacts bound to a
 * materially drifted candidate are flagged stale. Deterministic: identical
 * inputs yield identical records in identical order.
 */
export function detectDrift({
  previousSet,
  currentSet,
  artifacts = [],
  detectedAt,
}) {
  if (!isCalendarUtcTimestamp(detectedAt)) {
    throw new TypeError("detection_timestamp_invalid");
  }
  if (!Array.isArray(artifacts)) throw new TypeError("bound_artifacts_invalid");
  const boundArtifacts = artifacts.map((artifact) => {
    const identity = boundIdentity(artifact);
    if (identity === null) throw new TypeError("bound_artifact_invalid");
    return identity;
  });
  const approvalRecords = artifacts.filter(
    (artifact) => artifact?.schema === APPROVAL_SCHEMA,
  );
  // Both candidate sets receive the full semantic reconstruction used by
  // every other AutoMap boundary, not only envelope/member shape checks.
  // Forged identities, content hashes, risks, previews, or duplicate IDs
  // therefore cannot influence drift. Approved lifecycle members additionally
  // receive the already validated approval artifacts as their trust context.
  const previousValidation = validateCandidateSet(previousSet, {
    stage: "any",
    approvalRecords,
  });
  const currentValidation = validateCandidateSet(currentSet, {
    stage: "any",
    approvalRecords,
  });
  if (!previousValidation.ok || !currentValidation.ok) {
    if (previousValidation.reason === "approved_candidate_requires_bound_approval"
        || currentValidation.reason
          === "approved_candidate_requires_bound_approval") {
      throw new TypeError("approved_candidate_requires_bound_approval");
    }
    throw new TypeError("candidate_set_invalid");
  }
  const approvedById = new Map();
  for (const candidate of [
    ...previousSet.candidates, ...currentSet.candidates,
  ]) {
    if (candidate.mapping_status !== "APPROVED_DOCUMENTATION_ONLY") continue;
    if (!approvedById.has(candidate.candidate_id)) {
      approvedById.set(candidate.candidate_id, []);
    }
    approvedById.get(candidate.candidate_id).push(candidate);
  }
  for (const [candidateId, versions] of approvedById) {
    const bound = boundArtifacts.some((artifact) => (
      artifact.kind === "approval"
      && artifact.candidateId === candidateId
      && versions.some((candidate) => (
        artifact.contentHash === candidate.candidate_content_hash
        && artifact.structuralFingerprint
          === candidate.structural_schema_fingerprint
      ))
    ));
    if (!bound) {
      throw new TypeError("approved_candidate_requires_bound_approval");
    }
  }
  const previousById = new Map(
    previousSet.candidates.map((candidate) => [candidate.candidate_id, candidate]),
  );
  const currentById = new Map(
    currentSet.candidates.map((candidate) => [candidate.candidate_id, candidate]),
  );
  const ids = [...new Set([...previousById.keys(), ...currentById.keys()])].sort();
  const records = [];
  for (const id of ids) {
    const previous = previousById.get(id);
    const current = currentById.get(id);
    if (previous && current) {
      if (!candidateComparable(previous) || !candidateComparable(current)) {
        records.push(makeRecord({
          candidate_id: id,
          change_kind: "MODIFIED",
          drift_type: "UNKNOWN",
          drift_severity: "UNKNOWN",
          previous: candidateComparable(previous) ? previous : null,
          current: candidateComparable(current) ? current : null,
          diff: null,
          detectedAt,
          mappingState: current?.mapping_status ?? previous?.mapping_status,
          boundArtifacts,
        }));
        continue;
      }
      const contentChanged = previous.candidate_content_hash
        !== current.candidate_content_hash;
      const structuralChanged = previous.structural_schema_fingerprint
        !== current.structural_schema_fingerprint;
      const descriptiveChanged = previous.metadata_fingerprint
        !== current.metadata_fingerprint;
      if (!contentChanged && !descriptiveChanged) continue;
      let driftType;
      let severity;
      let diff;
      if (contentChanged && structuralChanged) {
        driftType = "STRUCTURAL";
        severity = "MATERIAL";
        diff = diffStructuralPaths(previous.structural_paths, current.structural_paths);
      } else if (contentChanged) {
        // Content changed with an unchanged structural fingerprint: a
        // validation-relevant semantic field (e.g. declared effects, labels,
        // risk inputs) changed. Material, and it invalidates confirmations.
        driftType = "SEMANTIC";
        severity = "MATERIAL";
        diff = { fields_added: [], fields_removed: [], fields_changed: [] };
      } else {
        driftType = "DESCRIPTIVE";
        severity = "INFORMATIONAL";
        diff = { fields_added: [], fields_removed: [], fields_changed: [] };
      }
      records.push(makeRecord({
        candidate_id: id,
        change_kind: "MODIFIED",
        drift_type: driftType,
        drift_severity: severity,
        previous,
        current,
        diff,
        detectedAt,
        mappingState: current.mapping_status,
        boundArtifacts,
      }));
    } else if (previous && !current) {
      records.push(makeRecord({
        candidate_id: id,
        change_kind: "REMOVED",
        drift_type: "STRUCTURAL",
        drift_severity: "MATERIAL",
        previous: candidateComparable(previous) ? previous : null,
        current: null,
        diff: candidateComparable(previous)
          ? diffStructuralPaths(previous.structural_paths, [])
          : null,
        detectedAt,
        mappingState: previous?.mapping_status,
        boundArtifacts,
      }));
    } else if (!previous && current) {
      records.push(makeRecord({
        candidate_id: id,
        change_kind: "ADDED",
        drift_type: "STRUCTURAL",
        drift_severity: "MATERIAL",
        previous: null,
        current: candidateComparable(current) ? current : null,
        diff: candidateComparable(current)
          ? diffStructuralPaths([], current.structural_paths)
          : null,
        detectedAt,
        mappingState: current?.mapping_status,
        boundArtifacts,
      }));
    }
  }
  return Object.freeze(records);
}

/**
 * Produce the versioned drift-event-set envelope used by the CLI and any
 * direct library consumer. The envelope and every member are contract
 * validated before return, including drift_count/array agreement.
 */
export function buildDriftEventSet({
  previousSet,
  currentSet,
  artifacts = [],
  detectedAt,
}) {
  const records = detectDrift({
    previousSet, currentSet, artifacts, detectedAt,
  });
  const eventSet = Object.freeze({
    schema: DRIFT_EVENT_SET_SCHEMA,
    automap_version: AUTOMAP_VERSION,
    drift_event_schema: DRIFT_SCHEMA,
    detected_at: detectedAt,
    drift_count: records.length,
    drift_events: records,
  });
  assertValidArtifact(DRIFT_EVENT_SET_SCHEMA, eventSet);
  const semantic = validateDriftEventSet(eventSet);
  if (!semantic.ok) {
    throw new TypeError(`drift_event_set_output_invalid:${semantic.reason}`);
  }
  return eventSet;
}

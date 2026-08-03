// v0.6 shadow coverage report.
//
// Cross-references AutoMap candidates with a sanitized shadow receipt
// summary. It is a coverage description, not a governance score and not
// proof that any capability is safe or governed.
//
// Sol re-audit repairs:
//   - Each receipt entry has a unique `receipt_id` and one explicit
//     `granularity` (OPERATION_LEVEL or TOOL_LEVEL). Duplicate receipt IDs,
//     multiple IDs for one operation identity, and multiple IDs for one
//     native-tool identity are rejected.
//   - A receipt's identifiers must be mutually consistent: an OPERATION_LEVEL
//     entry's normalized_capability must belong to its native_tool_name, and
//     if it carries a capability_id that candidate's tool and operation must
//     agree. An internally inconsistent receipt is rejected, so one receipt
//     can never mark two different operations OBSERVED.
//   - A receipt matches at most one candidate, by its own receipt_id-bound
//     identity; one tool-level receipt never observes an operation.
//   - FIXTURE and LIVE_SHADOW use distinct contracts. A self-relabeled
//     fixture document is still rejected; only the live observer's sanitized
//     live receipt-summary contract crosses the live boundary.
//   - Producer output invariants are enforced (impossible totals rejected)
//     and the report is contract-validated before returning.

import { RFC3339_UTC_RE } from "../governance-core/contracts.mjs";
import { canonicalizeJson } from "../governance-core/canonical.mjs";
import { CANDIDATE_SET_SCHEMA } from "./vocabulary.mjs";
import { validateArtifact, assertValidArtifact } from "./contracts.mjs";
import { validateCandidateSet } from "./automap/candidate-validate.mjs";
import {
  LIVE_OUTPUT_FILES,
  readVerifiedOpenClawLiveArtifact,
} from "../openclaw-live-observer/index.mjs";

export const RECEIPT_SUMMARY_SCHEMA =
  "mcpherson-governance-shadow-receipt-summary/v1";
export const LIVE_RECEIPT_SUMMARY_SCHEMA =
  "mcpherson-governance-live-shadow-receipt-summary/v1";
export const COVERAGE_REPORT_SCHEMA =
  "mcpherson-governance-shadow-coverage-report/v1";
export const LIVE_COVERAGE_REPORT_SCHEMA =
  "mcpherson-governance-live-shadow-coverage-report/v1";
export const COVERAGE_NOTE =
  "This report describes discovery and shadow-observation coverage only. It "
  + "is not a governance score, not proof of safety, and not evidence that "
  + "any capability is enforced or enforceable.";
export const FIXTURE_COVERAGE_NOTE =
  "All inputs to this report are synthetic fixture data. Nothing in it "
  + "describes real deployment exposure, and no production receipt was read.";
export const LIVE_COVERAGE_NOTE =
  "Inputs are sanitized LIVE_SHADOW metadata from a bounded local OpenClaw "
  + "observation window. Tool-level receipts do not establish operation-level "
  + "coverage, governance, safety, enforcement, or complete deployment exposure.";
export const OPERATION_OBSERVATION_VALUES = Object.freeze([
  "OBSERVED", "NOT_OBSERVED", "UNKNOWN",
]);

function rejectInput(reason, detail = null) {
  const error = new TypeError(reason);
  error.code = reason;
  if (detail) error.detail = detail;
  throw error;
}

function invalidCoverage(reason, detail = null) {
  return Object.freeze({
    ok: false,
    reason,
    ...(detail === null ? {} : { detail }),
  });
}

function toolOfNormalized(normalized) {
  const dot = normalized.indexOf(".");
  return dot === -1 ? normalized : normalized.slice(0, dot);
}

function bindReceiptSignature(signatures, receiptId, signature) {
  const encoded = JSON.stringify(signature);
  const existing = signatures.get(receiptId);
  if (existing !== undefined && existing !== encoded) return false;
  signatures.set(receiptId, encoded);
  return true;
}

function bindIdentityReceipt(identityReceipts, identity, receiptId) {
  const existing = identityReceipts.get(identity);
  if (existing !== undefined && existing !== receiptId) return false;
  identityReceipts.set(identity, receiptId);
  return true;
}

/**
 * Validate a coverage report at a consumer boundary. JSON Schema establishes
 * shape; this function establishes the cross-field facts the schema cannot:
 * totals partition the capability rows, receipt counts and observation
 * states agree, operation receipt IDs are not reused, tool-only observations
 * never become operation observations, classification totals agree, and
 * unmatched receipt identity/granularity is coherent.
 */
export function validateCoverageReport(report) {
  const schema = report?.schema === LIVE_COVERAGE_REPORT_SCHEMA
    ? LIVE_COVERAGE_REPORT_SCHEMA
    : report?.schema === COVERAGE_REPORT_SCHEMA
      ? COVERAGE_REPORT_SCHEMA
      : null;
  if (schema === null) {
    return invalidCoverage("coverage_report_schema_invalid");
  }
  const contract = validateArtifact(schema, report);
  if (!contract.ok) {
    return invalidCoverage("coverage_report_contract_invalid", contract.errors);
  }
  const expectedMeasurement = schema === LIVE_COVERAGE_REPORT_SCHEMA
    ? "LIVE_SHADOW"
    : "FIXTURE";
  const expectedProvenance = expectedMeasurement === "LIVE_SHADOW"
    ? LIVE_COVERAGE_NOTE
    : FIXTURE_COVERAGE_NOTE;
  if (report.measurement_kind !== expectedMeasurement
      || report.coverage_note !== COVERAGE_NOTE
      || report.provenance_note !== expectedProvenance) {
    return invalidCoverage("coverage_report_provenance_invalid");
  }

  const candidateIds = new Set();
  const normalizedCapabilities = new Set();
  const operationReceiptIds = new Set();
  const usedReceiptIds = new Set();
  const receiptSignatures = new Map();
  const toolReceiptIdsByNativeTool = new Map();
  const operationReceiptIdsByIdentity = new Map();
  let operationObserved = 0;
  let toolLevelOnly = 0;
  let notObserved = 0;
  let classificationConfirmed = 0;

  for (const capability of report.capabilities) {
    if (candidateIds.has(capability.candidate_id)) {
      return invalidCoverage("coverage_report_duplicate_candidate_id");
    }
    if (normalizedCapabilities.has(capability.normalized_capability)) {
      return invalidCoverage("coverage_report_duplicate_normalized_capability");
    }
    candidateIds.add(capability.candidate_id);
    normalizedCapabilities.add(capability.normalized_capability);
    if (toolOfNormalized(capability.normalized_capability)
        !== capability.native_tool_name) {
      return invalidCoverage("coverage_report_capability_tool_mismatch");
    }
    if (capability.completion_receipts > capability.attempt_receipts) {
      return invalidCoverage("coverage_report_completion_exceeds_attempts");
    }

    // Coverage receives no human-confirmation artifact. A candidate's embedded
    // CONFIRMED_HUMAN trail is internally checkable but is not a trust
    // substitute for that bound artifact, so this report conservatively
    // counts only deterministic pinned-content classifications as confirmed.
    const confirmed =
      capability.classification_status === "CONFIRMED_DETERMINISTIC";
    if (confirmed) classificationConfirmed += 1;

    if (capability.operation_observation === "OBSERVED") {
      operationObserved += 1;
      if (capability.observing_receipt_id === null
          || capability.observing_receipt_mode === null
          || capability.attempt_receipts <= 0
          || capability.tool_observation !== null
          || capability.observing_receipt_mode === "ATTEMPT_ONLY"
            && capability.completion_receipts !== 0) {
        return invalidCoverage("coverage_report_observed_identity_invalid");
      }
      if (operationReceiptIds.has(capability.observing_receipt_id)) {
        return invalidCoverage("coverage_report_operation_receipt_reused");
      }
      if (!bindIdentityReceipt(
        operationReceiptIdsByIdentity,
        `${capability.native_tool_name}\0${capability.normalized_capability}`,
        capability.observing_receipt_id,
      )) {
        return invalidCoverage(
          "coverage_report_operation_identity_multiple_receipt_ids",
        );
      }
      if (!bindReceiptSignature(
        receiptSignatures,
        capability.observing_receipt_id,
        [
          "OPERATION_LEVEL",
          capability.candidate_id,
          capability.normalized_capability,
          capability.native_tool_name,
          capability.attempt_receipts,
          capability.completion_receipts,
          capability.observing_receipt_mode,
        ],
      )) {
        return invalidCoverage("coverage_report_receipt_signature_mismatch");
      }
      operationReceiptIds.add(capability.observing_receipt_id);
      usedReceiptIds.add(capability.observing_receipt_id);
    } else if (capability.operation_observation === "UNKNOWN") {
      toolLevelOnly += 1;
      if (capability.observing_receipt_id !== null
          || capability.observing_receipt_mode !== null
          || capability.attempt_receipts !== 0
          || capability.completion_receipts !== 0
          || capability.tool_observation === null
          || capability.tool_observation.attempt_receipts <= 0
          || capability.tool_observation.completion_receipts
            > capability.tool_observation.attempt_receipts
          || (capability.tool_observation.receipt_mode === "ATTEMPT_ONLY"
            && capability.tool_observation.completion_receipts !== 0)) {
        return invalidCoverage("coverage_report_tool_only_state_invalid");
      }
      if (!bindReceiptSignature(
        receiptSignatures,
        capability.tool_observation.receipt_id,
        [
          "TOOL_LEVEL",
          capability.native_tool_name,
          capability.tool_observation.attempt_receipts,
          capability.tool_observation.completion_receipts,
          capability.tool_observation.receipt_mode,
        ],
      )) {
        return invalidCoverage("coverage_report_receipt_signature_mismatch");
      }
      if (!bindIdentityReceipt(
        toolReceiptIdsByNativeTool,
        capability.native_tool_name,
        capability.tool_observation.receipt_id,
      )) {
        return invalidCoverage(
          "coverage_report_tool_identity_multiple_receipt_ids",
        );
      }
      usedReceiptIds.add(capability.tool_observation.receipt_id);
    } else {
      notObserved += 1;
      if (capability.observing_receipt_id !== null
          || capability.observing_receipt_mode !== null
          || capability.attempt_receipts !== 0
          || capability.completion_receipts !== 0
          || capability.tool_observation !== null) {
        return invalidCoverage("coverage_report_not_observed_state_invalid");
      }
    }
    const expectedGaps = [];
    if (capability.operation_observation === "NOT_OBSERVED") {
      expectedGaps.push("not_observed_in_shadow");
    }
    if (capability.operation_observation === "UNKNOWN") {
      expectedGaps.push("operation_coverage_unknown_tool_level_only");
    }
    if (capability.classification_status !== "CONFIRMED_DETERMINISTIC") {
      expectedGaps.push("classification_unconfirmed");
    }
    if (capability.completion_evidence_availability === "UNKNOWN") {
      expectedGaps.push("completion_evidence_unknown");
    }
    if (capability.effects.includes("UNKNOWN")) {
      expectedGaps.push("effects_incomplete");
    }
    const observedMode = capability.operation_observation === "OBSERVED"
      ? capability.observing_receipt_mode
      : capability.tool_observation?.receipt_mode ?? null;
    const observedCompletions = capability.operation_observation === "OBSERVED"
      ? capability.completion_receipts
      : capability.tool_observation?.completion_receipts ?? null;
    if (observedMode === "ATTEMPT_ONLY" && observedCompletions === 0) {
      expectedGaps.push("no_completion_evidence_in_attempt_only_mode");
    }
    expectedGaps.sort();
    if (capability.coverage_gaps.length !== expectedGaps.length
        || capability.coverage_gaps.some(
          (gap, index) => gap !== expectedGaps[index],
        )) {
      return invalidCoverage("coverage_report_gaps_inconsistent");
    }
  }

  const unmappedIds = new Set();
  for (const receipt of report.unmapped_observed_receipts) {
    if (unmappedIds.has(receipt.receipt_id)
        || usedReceiptIds.has(receipt.receipt_id)) {
      return invalidCoverage("coverage_report_receipt_identity_reused");
    }
    unmappedIds.add(receipt.receipt_id);
    if (receipt.attempt_receipts <= 0
        || receipt.completion_receipts > receipt.attempt_receipts) {
      return invalidCoverage("coverage_report_unmapped_count_invalid");
    }
    if (!bindReceiptSignature(
      receiptSignatures,
      receipt.receipt_id,
      [
        receipt.granularity,
        receipt.native_tool_name,
        receipt.normalized_capability,
        receipt.attempt_receipts,
        receipt.completion_receipts,
      ],
    )) {
      return invalidCoverage("coverage_report_receipt_signature_mismatch");
    }
    if (receipt.granularity === "TOOL_LEVEL") {
      if (receipt.normalized_capability !== null) {
        return invalidCoverage("coverage_report_tool_level_identity_invalid");
      }
      if (!bindIdentityReceipt(
        toolReceiptIdsByNativeTool,
        receipt.native_tool_name,
        receipt.receipt_id,
      )) {
        return invalidCoverage(
          "coverage_report_tool_identity_multiple_receipt_ids",
        );
      }
    } else if (receipt.normalized_capability === null
        || toolOfNormalized(receipt.normalized_capability)
          !== receipt.native_tool_name) {
      return invalidCoverage("coverage_report_operation_identity_invalid");
    } else if (!bindIdentityReceipt(
      operationReceiptIdsByIdentity,
      `${receipt.native_tool_name}\0${receipt.normalized_capability}`,
      receipt.receipt_id,
    )) {
      return invalidCoverage(
        "coverage_report_operation_identity_multiple_receipt_ids",
      );
    }
  }

  const totals = report.totals;
  if (totals.candidates !== report.capabilities.length
      || totals.operation_observed !== operationObserved
      || totals.tool_level_only !== toolLevelOnly
      || totals.not_observed !== notObserved
      || operationObserved + toolLevelOnly + notObserved
        !== report.capabilities.length
      || totals.classification_confirmed !== classificationConfirmed
      || totals.classification_unconfirmed
        !== report.capabilities.length - classificationConfirmed
      || totals.unmapped_observed_receipts
        !== report.unmapped_observed_receipts.length) {
    return invalidCoverage("coverage_report_totals_inconsistent");
  }
  return Object.freeze({ ok: true });
}

/**
 * Strictly validate the receipt summary against its contract and semantic
 * invariants. Every violation rejects the whole document; nothing is coerced.
 * Returns the receipts indexed by receipt_id.
 */
function validatedReceiptSummary(receiptSummary, candidateSet) {
  const schema = receiptSummary?.schema === LIVE_RECEIPT_SUMMARY_SCHEMA
    ? LIVE_RECEIPT_SUMMARY_SCHEMA
    : receiptSummary?.schema === RECEIPT_SUMMARY_SCHEMA
      ? RECEIPT_SUMMARY_SCHEMA
      : null;
  if (schema === null) rejectInput("receipt_summary_schema_invalid");
  const contract = validateArtifact(schema, receiptSummary);
  if (!contract.ok) rejectInput("receipt_summary_invalid", contract.errors);
  const expectedMeasurement = schema === LIVE_RECEIPT_SUMMARY_SCHEMA
    ? "LIVE_SHADOW"
    : "FIXTURE";
  if (receiptSummary.measurement_kind !== expectedMeasurement) {
    rejectInput("receipt_summary_measurement_kind_mismatch");
  }
  if (expectedMeasurement === "LIVE_SHADOW"
      && (Date.parse(receiptSummary.window_start)
          > Date.parse(receiptSummary.window_end)
        || Date.parse(receiptSummary.captured_at)
          < Date.parse(receiptSummary.window_end))) {
    rejectInput("receipt_summary_live_window_invalid");
  }
  const candidateByNormalized = new Map(
    candidateSet.candidates.map((c) => [c.normalized_capability, c]),
  );
  const candidateById = new Map(
    candidateSet.candidates.map((c) => [c.candidate_id, c]),
  );
  const receiptIds = new Set();
  const operationReceiptIdsByNormalized = new Map();
  const operationReceiptIdsByCapabilityId = new Map();
  const toolReceiptIdsByNativeTool = new Map();
  for (const entry of receiptSummary.receipts) {
    if (receiptIds.has(entry.receipt_id)) {
      rejectInput("receipt_summary_duplicate_receipt_id");
    }
    receiptIds.add(entry.receipt_id);
    if (entry.completion_receipts > entry.attempt_receipts) {
      rejectInput("receipt_summary_completion_exceeds_attempts");
    }
    if (entry.receipt_mode === "ATTEMPT_ONLY" && entry.completion_receipts !== 0) {
      rejectInput("receipt_summary_attempt_only_with_completions");
    }
    if (entry.granularity === "TOOL_LEVEL") {
      if (entry.normalized_capability !== undefined
          || entry.capability_id !== undefined) {
        rejectInput("receipt_summary_tool_level_with_operation_identity");
      }
      const existingToolReceipt = toolReceiptIdsByNativeTool.get(
        entry.native_tool_name,
      );
      if (existingToolReceipt !== undefined
          && existingToolReceipt !== entry.receipt_id) {
        rejectInput("receipt_summary_tool_identity_multiple_receipt_ids");
      }
      toolReceiptIdsByNativeTool.set(
        entry.native_tool_name,
        entry.receipt_id,
      );
    } else {
      // OPERATION_LEVEL: normalized_capability is required and must belong to
      // native_tool_name; a capability_id must name the same operation.
      if (entry.normalized_capability === undefined) {
        rejectInput("receipt_summary_operation_level_missing_normalized");
      }
      if (toolOfNormalized(entry.normalized_capability) !== entry.native_tool_name) {
        rejectInput("receipt_summary_operation_tool_mismatch");
      }
      if (entry.capability_id !== undefined) {
        const candidate = candidateById.get(entry.capability_id);
        if (candidate
            && (candidate.normalized_capability !== entry.normalized_capability
              || candidate.native_tool_name !== entry.native_tool_name)) {
          rejectInput("receipt_summary_capability_id_identity_mismatch");
        }
      }
      const operationIdentity =
        `${entry.native_tool_name}\0${entry.normalized_capability}`;
      const existingOperationReceipt =
        operationReceiptIdsByNormalized.get(operationIdentity);
      if (existingOperationReceipt !== undefined
          && existingOperationReceipt !== entry.receipt_id) {
        rejectInput("receipt_summary_operation_identity_multiple_receipt_ids");
      }
      operationReceiptIdsByNormalized.set(
        operationIdentity,
        entry.receipt_id,
      );
      if (entry.capability_id !== undefined) {
        const existingCapabilityReceipt =
          operationReceiptIdsByCapabilityId.get(entry.capability_id);
        if (existingCapabilityReceipt !== undefined
            && existingCapabilityReceipt !== entry.receipt_id) {
          rejectInput(
            "receipt_summary_operation_identity_multiple_receipt_ids",
          );
        }
        operationReceiptIdsByCapabilityId.set(
          entry.capability_id,
          entry.receipt_id,
        );
      }
    }
  }
  return {
    receipts: receiptSummary.receipts,
    candidateByNormalized,
    candidateById,
    measurementKind: expectedMeasurement,
  };
}

/**
 * Match a candidate to at most one receipt by consistent identity. An
 * OPERATION_LEVEL receipt matches only its exact operation (by capability_id
 * when present, else normalized_capability). A TOOL_LEVEL receipt matches
 * only by native_tool_name and only yields tool-level observation.
 */
function matchReceipt(candidate, receipts) {
  const operationMatch = receipts.find(
    (entry) => entry.granularity === "OPERATION_LEVEL"
      && (entry.capability_id === candidate.candidate_id
        || (entry.capability_id === undefined
          && entry.normalized_capability === candidate.normalized_capability
          && entry.native_tool_name === candidate.native_tool_name)),
  );
  if (operationMatch) return { entry: operationMatch, granularity: "operation" };
  const toolMatch = receipts.find(
    (entry) => entry.granularity === "TOOL_LEVEL"
      && entry.native_tool_name === candidate.native_tool_name,
  );
  if (toolMatch) return { entry: toolMatch, granularity: "tool" };
  return { entry: null, granularity: null };
}

export function buildShadowCoverageReport({
  candidateSet,
  receiptSummary,
  generatedAt,
  observationDirectory = null,
  packageManifestPath = null,
  profileBindingPath = null,
  profileBindingId = null,
}) {
  let liveVerification = null;
  if (candidateSet?.schema !== CANDIDATE_SET_SCHEMA) {
    rejectInput("candidate_set_invalid");
  }
  // This producer has no approval-artifact input. An embedded documentation
  // approval status is therefore not repeated on the candidate's own say-so;
  // callers must use a PROPOSED/DISCOVERED set or a future coverage boundary
  // that explicitly accepts and validates approval records.
  if (Array.isArray(candidateSet.candidates) && candidateSet.candidates.some(
    (candidate) => candidate.mapping_status === "APPROVED_DOCUMENTATION_ONLY",
  )) {
    rejectInput("coverage_approved_candidate_requires_bound_approval");
  }
  const candidateValidation = validateCandidateSet(candidateSet, { stage: "any" });
  if (!candidateValidation.ok) {
    rejectInput("candidate_set_invalid", candidateValidation);
  }
  if (typeof generatedAt !== "string" || !RFC3339_UTC_RE.test(generatedAt)) {
    rejectInput("generated_at_invalid");
  }
  if (receiptSummary?.schema === LIVE_RECEIPT_SUMMARY_SCHEMA) {
    if (typeof observationDirectory !== "string") {
      rejectInput("live_observation_directory_required");
    }
    const verified = readVerifiedOpenClawLiveArtifact({
      outDir: observationDirectory,
      filename: LIVE_OUTPUT_FILES.receipts,
      packageManifestPath,
      profileBindingPath,
      profileBindingId,
    });
    liveVerification = verified.verification;
    const snapshotHash = verified.verification
      .artifacts[LIVE_OUTPUT_FILES.snapshot].sha256;
    if (canonicalizeJson(receiptSummary) !== canonicalizeJson(verified.value)
        || candidateSet.discovery_method !== "openclaw_live_gateway_v1"
        || candidateSet.candidates.some(
          (candidate) => candidate.source_document_sha256 !== snapshotHash,
        )) {
      rejectInput("live_receipt_observation_binding_mismatch");
    }
  }
  const { receipts, measurementKind } = validatedReceiptSummary(
    receiptSummary, candidateSet,
  );
  const usedReceiptIds = new Set();
  const entries = candidateSet.candidates.map((candidate) => {
    const { entry, granularity } = matchReceipt(candidate, receipts);
    const observedOperation = granularity === "operation" && entry.attempt_receipts > 0;
    const toolObservation = granularity === "tool" && entry.attempt_receipts > 0
      ? Object.freeze({
        receipt_id: entry.receipt_id,
        attempt_receipts: entry.attempt_receipts,
        completion_receipts: entry.completion_receipts,
        receipt_mode: entry.receipt_mode,
      })
      : null;
    if (entry && entry.attempt_receipts > 0) usedReceiptIds.add(entry.receipt_id);
    const operationObservation = observedOperation
      ? "OBSERVED"
      : toolObservation !== null
        ? "UNKNOWN"
        : "NOT_OBSERVED";
    const gaps = [];
    if (operationObservation === "NOT_OBSERVED") gaps.push("not_observed_in_shadow");
    if (operationObservation === "UNKNOWN") {
      gaps.push("operation_coverage_unknown_tool_level_only");
    }
    if (candidate.classification.status !== "CONFIRMED_DETERMINISTIC") {
      gaps.push("classification_unconfirmed");
    }
    if (candidate.completion_evidence_availability === "UNKNOWN") {
      gaps.push("completion_evidence_unknown");
    }
    if (candidate.effects.includes("UNKNOWN")) gaps.push("effects_incomplete");
    const modeSource = observedOperation ? entry : toolObservation;
    if (modeSource && modeSource.receipt_mode === "ATTEMPT_ONLY"
        && modeSource.completion_receipts === 0) {
      gaps.push("no_completion_evidence_in_attempt_only_mode");
    }
    return Object.freeze({
      candidate_id: candidate.candidate_id,
      normalized_capability: candidate.normalized_capability,
      native_tool_name: candidate.native_tool_name,
      mapping_status: candidate.mapping_status,
      classification_status: candidate.classification.status,
      effects: [...candidate.effects],
      proposed_action_class: candidate.proposed_risk.proposed_action_class,
      risk_status: candidate.proposed_risk.risk_status,
      completion_evidence_availability: candidate.completion_evidence_availability,
      operation_observation: operationObservation,
      observing_receipt_id: observedOperation ? entry.receipt_id : null,
      observing_receipt_mode: observedOperation ? entry.receipt_mode : null,
      attempt_receipts: observedOperation ? entry.attempt_receipts : 0,
      completion_receipts: observedOperation ? entry.completion_receipts : 0,
      tool_observation: toolObservation,
      coverage_gaps: gaps.sort(),
    });
  }).sort((left, right) => (
    left.candidate_id < right.candidate_id ? -1 : 1
  ));
  const unmappedObserved = receipts
    .filter((entry) => entry.attempt_receipts > 0
      && !usedReceiptIds.has(entry.receipt_id))
    .map((entry) => Object.freeze({
      receipt_id: entry.receipt_id,
      granularity: entry.granularity,
      native_tool_name: entry.native_tool_name,
      normalized_capability: entry.normalized_capability ?? null,
      attempt_receipts: entry.attempt_receipts,
      completion_receipts: entry.completion_receipts,
      note: "present in the supplied receipt summary but bound to no candidate "
        + "in the supplied candidate set; within these inputs it has no AutoMap "
        + "inventory entry",
    }))
    .sort((left, right) => (left.receipt_id < right.receipt_id ? -1 : 1));
  const totals = {
    candidates: entries.length,
    operation_observed: entries.filter(
      (entry) => entry.operation_observation === "OBSERVED",
    ).length,
    tool_level_only: entries.filter(
      (entry) => entry.operation_observation === "UNKNOWN",
    ).length,
    not_observed: entries.filter(
      (entry) => entry.operation_observation === "NOT_OBSERVED",
    ).length,
    classification_confirmed: entries.filter(
      (entry) => entry.classification_status === "CONFIRMED_DETERMINISTIC",
    ).length,
    classification_unconfirmed: entries.filter(
      (entry) => entry.classification_status !== "CONFIRMED_DETERMINISTIC",
    ).length,
    unmapped_observed_receipts: unmappedObserved.length,
  };
  // Producer output invariants: the three observation buckets must partition
  // the candidates exactly. This makes an impossible total unconstructible.
  if (totals.operation_observed + totals.tool_level_only + totals.not_observed
      !== totals.candidates) {
    rejectInput("coverage_totals_inconsistent");
  }
  const report = Object.freeze({
    schema: measurementKind === "LIVE_SHADOW"
      ? LIVE_COVERAGE_REPORT_SCHEMA
      : COVERAGE_REPORT_SCHEMA,
    generated_at: generatedAt,
    measurement_kind: measurementKind,
    ...(measurementKind === "LIVE_SHADOW" ? {
      observation_id: liveVerification.observation_id,
      source_id: liveVerification.source_id,
      authority: "NONE",
      enforcement: false,
      automatic_mapping_activation: false,
      outbound_actions: false,
    } : {}),
    coverage_note: COVERAGE_NOTE,
    provenance_note: measurementKind === "LIVE_SHADOW"
      ? LIVE_COVERAGE_NOTE
      : FIXTURE_COVERAGE_NOTE,
    totals: Object.freeze(totals),
    capabilities: entries,
    unmapped_observed_receipts: unmappedObserved,
  });
  assertValidArtifact(report.schema, report);
  const semantic = validateCoverageReport(report);
  if (!semantic.ok) rejectInput(semantic.reason, semantic.detail ?? null);
  return report;
}

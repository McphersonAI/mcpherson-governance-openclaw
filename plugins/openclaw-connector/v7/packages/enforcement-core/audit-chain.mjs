// v0.7 unsigned, integrity-evident audit chain (D4).
//
// Decision records form an append-only hash chain per (tenant, workspace,
// policy_bundle) scope: each record binds prev_record_hash to the previous
// record's evidence_hash. Segments carry a monotonic segment_seq and bind
// prev_segment_last_hash to the previous segment's last_hash, so reorder /
// omission / splice of whole segments WITHIN a scope is detectable.
//
// HONEST SCOPE: this is UNSIGNED integrity evidence, not producer
// authentication. authentication is const NONE and signed is const false on
// every segment and export. A coherently rebuilt unsigned copy with recomputed
// hashes/ids and a new anchor remains indistinguishable by structure alone.

import { canonicalHash, canonicalHashWithout, contentId } from "./hashing.mjs";
import { MAX_AUDIT_SEGMENT_RECORDS } from "./bounds.mjs";
import { AUTHENTICATION_NONE, SIGNED } from "./vocabulary.mjs";
import {
  assertValidArtifact, validateArtifact, validateEnvelope,
} from "./contracts.mjs";
import { buildEvaluationContext } from "./evaluation-context.mjs";

export const SEGMENT_SCHEMA_ID = "mcpherson-governance-enforcement-decision-log-segment/v1";
export const AUDIT_EXPORT_SCHEMA_ID = "mcpherson-governance-enforcement-audit-export/v1";
const DECISION_SCHEMA_ID = "mcpherson-governance-enforcement-decision/v1";
const SHA256_RE = /^sha256:[a-f0-9]{64}$/;

/** Genesis descriptor hash for a scope (the value a first record chains from). */
export function genesisHash(scope) {
  return canonicalHash({ genesis: true, scope });
}

/**
 * Thread a chain: evaluate each case in order, feeding the previous record's
 * evidence_hash as the next prev_record_hash. Returns the produced records.
 * `startPrevHash` links a continuation segment to a prior segment's last_hash
 * (or null for the very first record of a scope).
 */
export function threadChain(evaluateFn, cases, startPrevHash = null) {
  const records = [];
  let prev = startPrevHash;
  for (const c of cases) {
    const record = evaluateFn(c.envelope, c.bundle, c.approvals ?? [],
      buildEvaluationContext({
      evaluated_at: c.evaluated_at,
      engine_version: c.engine_version,
      prev_record_hash: prev,
      approval_verifications: c.approval_verifications ?? [],
      consumed_approval_ids: c.consumed_approval_ids ?? [],
    }));
    records.push(record);
    prev = record.evidence_hash;
  }
  return records;
}

/** Explicit genesis anchor for the first accepted segment in a scope. */
export function genesisAuditAnchor() {
  return Object.freeze({
    expected_first_segment_seq: 0,
    expected_prev_segment_last_hash: null,
    expected_first_record_prev_hash: null,
  });
}

function validNullableHash(value) {
  return value === null || (typeof value === "string" && SHA256_RE.test(value));
}

function validateAuditAnchor(anchor) {
  if (!anchor || typeof anchor !== "object" || Array.isArray(anchor)) return false;
  const keys = Object.keys(anchor).sort();
  if (keys.join(",") !== [
    "expected_first_record_prev_hash",
    "expected_first_segment_seq",
    "expected_prev_segment_last_hash",
  ].join(",")) return false;
  return Number.isInteger(anchor.expected_first_segment_seq)
    && anchor.expected_first_segment_seq >= 0
    && validNullableHash(anchor.expected_prev_segment_last_hash)
    && validNullableHash(anchor.expected_first_record_prev_hash);
}

/** Recompute a record's canonical evidence hash and content-derived id. */
export function validateRecordIntegrity(record) {
  const shape = validateArtifact(DECISION_SCHEMA_ID, record);
  if (!shape.ok) {
    return { ok: false, reason: "record_invalid", detail: shape.errors[0] ?? null };
  }
  let expectedEvidenceHash;
  let expectedDecisionId;
  try {
    expectedEvidenceHash = canonicalHashWithout(
      record,
      ["decision_id", "evidence_hash"],
    );
    const body = {};
    for (const key of Object.keys(record)) {
      if (key === "decision_id" || key === "evidence_hash") continue;
      body[key] = record[key];
    }
    expectedDecisionId = contentId("ench-dec-", body);
  } catch {
    return { ok: false, reason: "record_canonicalization_failed" };
  }
  if (record.evidence_hash !== expectedEvidenceHash) {
    return { ok: false, reason: "record_evidence_hash_mismatch" };
  }
  if (record.decision_id !== expectedDecisionId) {
    return { ok: false, reason: "record_decision_id_mismatch" };
  }
  return { ok: true };
}

/**
 * Validate every record hash/id and every prev_record_hash link. The second
 * argument is mandatory: null is the explicit genesis marker.
 */
export function validateChainContinuity(records, expectedFirstPrev) {
  if (arguments.length < 2 || !validNullableHash(expectedFirstPrev)) {
    return { ok: false, brokenAt: 0, reason: "first_record_anchor_required" };
  }
  if (!Array.isArray(records)) {
    return { ok: false, brokenAt: 0, reason: "records_not_array" };
  }
  for (let i = 0; i < records.length; i += 1) {
    const integrity = validateRecordIntegrity(records[i]);
    if (!integrity.ok) {
      return { ok: false, brokenAt: i, reason: integrity.reason };
    }
    const expected = i === 0 ? expectedFirstPrev : records[i - 1].evidence_hash;
    if ((records[i].prev_record_hash ?? null) !== (expected ?? null)) {
      return { ok: false, brokenAt: i, reason: "prev_record_hash_mismatch" };
    }
  }
  return { ok: true };
}

function segmentScope(segment) {
  return {
    tenant_id: segment.tenant_id,
    workspace_id: segment.workspace_id,
    policy_bundle_id: segment.policy_bundle_id,
  };
}

function sameScope(left, right) {
  return left.tenant_id === right.tenant_id
    && left.workspace_id === right.workspace_id
    && left.policy_bundle_id === right.policy_bundle_id;
}

function validateRecordScope(records, scope) {
  for (let i = 0; i < records.length; i += 1) {
    if (!sameScope(records[i], scope)) {
      return { ok: false, brokenAt: i, reason: "record_scope_mismatch" };
    }
  }
  return { ok: true };
}

/** Full validation of one segment, including all derived metadata. */
export function validateSegmentIntegrity(segment, expectedFirstRecordPrev, expectedScope = null) {
  const shape = validateEnvelope(SEGMENT_SCHEMA_ID, segment);
  if (!shape.ok) {
    return { ok: false, reason: "segment_invalid", detail: shape.errors[0] ?? null };
  }
  const scope = segmentScope(segment);
  if (expectedScope !== null && !sameScope(scope, expectedScope)) {
    return { ok: false, reason: "segment_scope_mismatch" };
  }
  const recordScope = validateRecordScope(segment.records, scope);
  if (!recordScope.ok) return recordScope;

  const firstHash = segment.records.length > 0
    ? segment.records[0].evidence_hash
    : null;
  const lastHash = segment.records.length > 0
    ? segment.records[segment.records.length - 1].evidence_hash
    : null;
  if (segment.count !== segment.records.length) {
    return { ok: false, reason: "segment_count_mismatch" };
  }
  if (segment.first_hash !== firstHash) {
    return { ok: false, reason: "segment_first_hash_mismatch" };
  }
  if (segment.last_hash !== lastHash) {
    return { ok: false, reason: "segment_last_hash_mismatch" };
  }
  const expectedSegmentId = contentId("seg-", {
    scope,
    segmentSeq: segment.segment_seq,
    first_hash: firstHash,
    last_hash: lastHash,
    count: segment.records.length,
  });
  if (segment.segment_id !== expectedSegmentId) {
    return { ok: false, reason: "segment_id_mismatch" };
  }
  return validateChainContinuity(segment.records, expectedFirstRecordPrev);
}

/**
 * Build a decision-log segment from records. `prev_segment_last_hash` binds the
 * previous segment's last_hash (or null for the first segment).
 */
export function buildSegment({ records, segmentSeq, prevSegmentLastHash, scope }) {
  if (!Array.isArray(records) || records.length > MAX_AUDIT_SEGMENT_RECORDS) {
    const error = new TypeError("failsafe:invalid:oversize:segment");
    error.code = "failsafe:invalid:oversize:segment";
    throw error;
  }
  const continuity = validateChainContinuity(records, prevSegmentLastHash ?? null);
  if (!continuity.ok) {
    const error = new TypeError(`audit_segment_records_invalid:${continuity.reason}`);
    error.code = `audit_segment_records_invalid:${continuity.reason}`;
    throw error;
  }
  const recordScope = validateRecordScope(records, scope);
  if (!recordScope.ok) {
    const error = new TypeError(`audit_segment_records_invalid:${recordScope.reason}`);
    error.code = `audit_segment_records_invalid:${recordScope.reason}`;
    throw error;
  }
  const first_hash = records.length > 0 ? records[0].evidence_hash : null;
  const last_hash = records.length > 0 ? records[records.length - 1].evidence_hash : null;
  const segment = {
    schema: SEGMENT_SCHEMA_ID,
    segment_version: "1",
    segment_id: contentId("seg-", { scope, segmentSeq, first_hash, last_hash, count: records.length }),
    segment_seq: segmentSeq,
    prev_segment_last_hash: prevSegmentLastHash ?? null,
    tenant_id: scope.tenant_id,
    workspace_id: scope.workspace_id,
    policy_bundle_id: scope.policy_bundle_id,
    count: records.length,
    first_hash,
    last_hash,
    records,
    authentication: AUTHENTICATION_NONE,
    signed: SIGNED,
  };
  const validated = assertValidArtifact(SEGMENT_SCHEMA_ID, segment);
  const integrity = validateSegmentIntegrity(
    validated,
    prevSegmentLastHash ?? null,
    scope,
  );
  if (!integrity.ok) {
    const error = new TypeError(`audit_segment_invalid:${integrity.reason}`);
    error.code = `audit_segment_invalid:${integrity.reason}`;
    throw error;
  }
  return validated;
}

/**
 * Validate cross-segment continuity within a scope: segment_seq must be
 * contiguous and increasing, and prev_segment_last_hash must bind the previous
 * segment's last_hash. Also validates each segment (and its member records) by
 * contract composition.
 */
export function validateSegmentContinuity(segments, anchor, scope = null) {
  if (!Array.isArray(segments)) {
    return { ok: false, brokenAt: 0, reason: "segments_not_array" };
  }
  if (!validateAuditAnchor(anchor)) {
    return { ok: false, brokenAt: 0, reason: "audit_anchor_required" };
  }
  for (let i = 0; i < segments.length; i += 1) {
    const expectedSeq = i === 0
      ? anchor.expected_first_segment_seq
      : segments[i - 1].segment_seq + 1;
    const expectedPrevSegment = i === 0
      ? anchor.expected_prev_segment_last_hash
      : segments[i - 1].last_hash;
    const expectedFirstRecordPrev = i === 0
      ? anchor.expected_first_record_prev_hash
      : segments[i - 1].last_hash;

    if (segments[i]?.segment_seq !== expectedSeq) {
      return { ok: false, brokenAt: i, reason: "segment_seq_noncontiguous" };
    }
    if ((segments[i]?.prev_segment_last_hash ?? null) !== (expectedPrevSegment ?? null)) {
      return { ok: false, brokenAt: i, reason: "prev_segment_last_hash_mismatch" };
    }
    const segmentResult = validateSegmentIntegrity(
      segments[i],
      expectedFirstRecordPrev,
      scope,
    );
    if (!segmentResult.ok) {
      return { ok: false, brokenAt: i, reason: segmentResult.reason };
    }
  }
  return { ok: true };
}

/** Verify a complete audit export from its embedded anchor. */
export function verifyAuditExport(auditExport) {
  const shape = validateEnvelope(AUDIT_EXPORT_SCHEMA_ID, auditExport);
  if (!shape.ok) {
    return { ok: false, reason: "audit_export_invalid", detail: shape.errors[0] ?? null };
  }
  const scope = {
    tenant_id: auditExport.tenant_id,
    workspace_id: auditExport.workspace_id,
    policy_bundle_id: auditExport.policy_bundle_id,
  };
  return validateSegmentContinuity(
    auditExport.segments,
    auditExport.audit_anchor,
    scope,
  );
}

/** Build a scoped, unsigned audit export only after full continuity verification. */
export function buildAuditExport({ segments, scope, anchor }) {
  const continuity = validateSegmentContinuity(segments, anchor, scope);
  if (!continuity.ok) {
    const error = new TypeError(`audit_export_continuity_invalid:${continuity.reason}`);
    error.code = `audit_export_continuity_invalid:${continuity.reason}`;
    throw error;
  }
  const auditExport = {
    schema: AUDIT_EXPORT_SCHEMA_ID,
    export_version: "1",
    tenant_id: scope.tenant_id,
    workspace_id: scope.workspace_id,
    policy_bundle_id: scope.policy_bundle_id,
    audit_anchor: anchor,
    segment_count: segments.length,
    segments,
    authentication: AUTHENTICATION_NONE,
    signed: SIGNED,
  };
  const validated = assertValidArtifact(AUDIT_EXPORT_SCHEMA_ID, auditExport);
  const verified = verifyAuditExport(validated);
  if (!verified.ok) {
    const error = new TypeError(`audit_export_continuity_invalid:${verified.reason}`);
    error.code = `audit_export_continuity_invalid:${verified.reason}`;
    throw error;
  }
  return validated;
}

// Documentation-only mapping approval.
//
// An approval record acknowledges that a human reviewed a mapping proposal.
// It is structurally incapable of expressing activation: the only valid
// approval scope is `documentation_only`, and `runtime_active` /
// `enforcement_eligible` admit only `false`. Approval does not mean active,
// does not mean safe, does not mean enforced, and does not confirm effect
// classification.
//
// Sol repairs: validation covers the complete record (exact fields, unknown
// fields rejected, approval_id recomputed); `classification_confirmed` can
// be true only for a registry-deterministic candidate or a candidate whose
// human confirmation record is supplied and bound; and a successful approval
// produces the updated candidate in the `APPROVED_DOCUMENTATION_ONLY`
// lifecycle state with a recomputed content hash, so the documented
// lifecycle state actually exists.

import { createHash } from "node:crypto";
import { canonicalizeJson } from "../../governance-core/canonical.mjs";
import {
  WIRE_SAFE_ID_RE,
  HASH_RE,
  RFC3339_UTC_RE,
} from "../../governance-core/contracts.mjs";
import { APPROVAL_SCHEMA, CONFIRMATION_SCHEMA } from "../vocabulary.mjs";
import { candidateContentHash } from "./discovery.mjs";
import { validateCandidate } from "./candidate-validate.mjs";
import { validateConfirmationRecord } from "./confirmation.mjs";
import {
  LIVE_CONFIRMATION_SCHEMA,
  validateLiveClassificationConfirmation,
} from "./live-confirmation.mjs";
import { validateArtifact, assertValidArtifact } from "../contracts.mjs";
import { sensitiveValueReason } from "../sensitive-values.mjs";

export const APPROVAL_ARTIFACT_VERSION = "1";
export const APPROVAL_SCOPE = "documentation_only";

const APPROVAL_FIELDS = Object.freeze([
  "schema", "artifact_version", "approval_id", "candidate_id",
  "candidate_content_hash", "approved_candidate_content_hash",
  "structural_schema_fingerprint", "approval_scope",
  "runtime_active", "enforcement_eligible", "approved_by", "approved_at",
  "rationale", "classification_confirmed", "confirmation_bound",
  "unresolved_cautions",
]);

function reject(reason) {
  return Object.freeze({ ok: false, reason });
}

// Approval rationale is persisted verbatim in a local approval artifact and
// can subsequently be rendered to stdout or exported by the CLI. It therefore
// receives the same bounded semantic sensitive-value screen used by other
// diagnostic free-text values, plus approval-specific exclusions for
// private-key boundaries, credential assignments and weak-value shapes,
// unsafe URI schemes, common PII forms, and filesystem paths. Filesystem
// detection is deliberately limited to absolute, home-relative, dot-relative,
// drive-qualified, and UNC forms: ordinary domain prose such as `read/write`
// is not a path.
//
// This remains a bounded shape policy, not a claim of universal secret or PII
// detection. Returning one public rejection code also avoids reflecting the
// rejected rationale or its detected class into output.
const RESTRICTED_PATH_RE =
  /(?:^|[\s"'([{:=`,;])(?:~[\\/]|\.{1,2}[\\/]|[A-Za-z]:[\\/]|[\\/]{2}|\/)[^\s"'`<>|?*]+/;
const CREDENTIAL_ASSIGNMENT_RE =
  /(?:^|[\s"'([{,;`])(?:pass(?:word|wd)?|secret|token|api[_ -]?key|access[_ -]?key|credential|authorization|bearer|cookie|session(?:[_ -]?id)?|client[_ -]?secret|private[_ -]?key)\s*[:=]\s*\S+/i;
const LONG_HEX_TOKEN_RE =
  /(?:^|[^A-Fa-f0-9])[A-Fa-f0-9]{32,}(?:$|[^A-Fa-f0-9])/;
const UNSAFE_URI_SCHEME_RE =
  /(?:^|[\s"'([{:=`,;])(?:javascript|vbscript|data|file|mailto|tel|sms):/i;
const PII_LABEL_RE =
  /(?:^|[\s"'([{:=`,;])(?:e-?mail(?:[_ -]?address)?|phone(?:[_ -]?(?:number|no))?|mobile(?:[_ -]?(?:number|no))?|date[_ -]?of[_ -]?birth|birth[_ -]?date|dob|full[_ -]?name|first[_ -]?name|last[_ -]?name|home[_ -]?address|street[_ -]?address|passport(?:[_ -]?(?:number|no))?|driver(?:s)?[_ -]?licen[cs]e|tax[_ -]?id|employee[_ -]?id)(?:$|[\s"'})\]:=`,;])/i;
const FORMATTED_PHONE_RE =
  /(?:^|\D)(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}(?:$|\D)/;

// Split at runtime so source/material scans never retain a usable weak
// credential probe as one literal. These are exact whole-token matches, not
// substring matches against ordinary domain terminology.
const KNOWN_WEAK_CREDENTIAL_VALUES = new Set([
  ["change", "me"].join(""),
  ["let", "mein"].join(""),
  ["qwer", "ty"].join(""),
  ["admin", "123"].join(""),
  ["welcome", "1"].join(""),
]);

function containsKnownWeakCredential(value) {
  const tokens = value.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  return tokens.some((token) => KNOWN_WEAK_CREDENTIAL_VALUES.has(token));
}

function containsPrivateKeyBoundary(value) {
  const upper = value.toUpperCase();
  const prefix = ["-----", "BEGIN "].join("");
  const suffix = ["PRIVATE", " KEY", "-----"].join("");
  const begin = upper.indexOf(prefix);
  if (begin === -1) return false;
  const end = upper.indexOf(suffix, begin + prefix.length);
  return end !== -1 && end - begin <= 48;
}

function approvalRationalePrivacyReason(value) {
  return sensitiveValueReason(value)
    ?? (containsPrivateKeyBoundary(value) ? "private_key_shape" : null)
    ?? (CREDENTIAL_ASSIGNMENT_RE.test(value)
      ? "credential_assignment_shape" : null)
    ?? (LONG_HEX_TOKEN_RE.test(value) ? "long_hex_token_shape" : null)
    ?? (containsKnownWeakCredential(value)
      ? "known_weak_credential_shape" : null)
    ?? (UNSAFE_URI_SCHEME_RE.test(value) ? "unsafe_uri_scheme" : null)
    ?? (PII_LABEL_RE.test(value) ? "pii_label_shape" : null)
    ?? (FORMATTED_PHONE_RE.test(value) ? "formatted_phone_shape" : null)
    ?? (RESTRICTED_PATH_RE.test(value) ? "filesystem_path_shape" : null);
}

function validateApprovalRationale(value) {
  if (typeof value !== "string" || value.length === 0
      || value.length > 512 || /[\r\n]/.test(value)) {
    return "rationale_invalid";
  }
  return approvalRationalePrivacyReason(value) === null
    ? null
    : "rationale_sensitive";
}

function approvalIdFor(record) {
  const clone = {};
  for (const key of Object.keys(record)) {
    if (key === "approval_id") continue;
    clone[key] = record[key];
  }
  return `map-appr-${createHash("sha256")
    .update(canonicalizeJson(clone), "utf8").digest("hex").slice(0, 24)}`;
}

function boundConfirmation(confirmationRecord, candidate) {
  if (confirmationRecord === null || confirmationRecord === undefined) {
    return false;
  }
  const confirmationValidation = confirmationRecord.schema === LIVE_CONFIRMATION_SCHEMA
    ? validateLiveClassificationConfirmation(
      confirmationRecord, { requirePostBinding: true },
    )
    : validateConfirmationRecord(
      confirmationRecord, { requirePostBinding: true },
    );
  if (!confirmationValidation.ok) {
    return false;
  }
  const confirmedCandidate = candidate.classification?.status === "CONFIRMED_HUMAN";
  const hashBound = confirmedCandidate
    // For a confirmed candidate, bind against the post-recompute hash the
    // confirmation itself committed to.
    ? confirmationRecord.confirmed_candidate_content_hash
      === candidate.candidate_content_hash
    : confirmationRecord.candidate_content_hash === candidate.candidate_content_hash;
  const effectsBound = !confirmedCandidate
    || (Array.isArray(confirmationRecord.selected_effects)
      && Array.isArray(candidate.effects)
      && confirmationRecord.selected_effects.length === candidate.effects.length
      && confirmationRecord.selected_effects
        .every((value, index) => candidate.effects[index] === value)
      && confirmationRecord.reviewer_identity
        === candidate.classification.confirmed_by
      && confirmationRecord.confirmed_at
        === candidate.classification.confirmed_at
      && confirmationRecord.rationale
        === candidate.classification.rationale
      && confirmationRecord.evidence_refs.length
        === candidate.classification.evidence.length
      && confirmationRecord.evidence_refs.every(
        (value, index) => value === candidate.classification.evidence[index],
      ));
  return [CONFIRMATION_SCHEMA, LIVE_CONFIRMATION_SCHEMA]
    .includes(confirmationRecord.schema)
    && confirmationRecord.candidate_id === candidate.candidate_id
    && hashBound
    && effectsBound
    && confirmationRecord.structural_schema_fingerprint
      === candidate.structural_schema_fingerprint
    && typeof confirmationRecord.reviewer_identity === "string"
    && Array.isArray(confirmationRecord.evidence_refs)
    && confirmationRecord.evidence_refs.length > 0;
}

export function createDocumentationOnlyApproval({
  candidate,
  approvedBy,
  approvedAt,
  rationale,
  confirmationRecord = null,
}) {
  if (!candidate || typeof candidate !== "object") {
    return reject("candidate_missing");
  }
  const candidateValidation = validateCandidate(candidate, { stage: "proposal" });
  if (!candidateValidation.ok) {
    return reject(`candidate_invalid:${candidateValidation.reason}`);
  }
  if (candidate.mapping_status !== "PROPOSED") {
    return reject("approval_requires_proposed_candidate");
  }
  if (typeof approvedBy !== "string" || !WIRE_SAFE_ID_RE.test(approvedBy)) {
    return reject("approver_identity_invalid");
  }
  if (typeof approvedAt !== "string" || !RFC3339_UTC_RE.test(approvedAt)) {
    return reject("approved_at_invalid");
  }
  const rationaleProblem = validateApprovalRationale(rationale);
  if (rationaleProblem !== null) return reject(rationaleProblem);
  const status = candidate.classification?.status;
  const confirmationBound = boundConfirmation(confirmationRecord, candidate);
  if (status === "CONFIRMED_HUMAN" && !confirmationBound) {
    // A humanly confirmed candidate can only be approved together with the
    // exact confirmation artifact that produced it; the trust claim is
    // never repeated on the candidate's own say-so.
    return reject("approval_requires_bound_confirmation");
  }
  const classificationConfirmed = status === "CONFIRMED_DETERMINISTIC"
    || (status === "CONFIRMED_HUMAN" && confirmationBound);
  const approvedCandidate = {
    ...candidate,
    mapping_status: "APPROVED_DOCUMENTATION_ONLY",
  };
  delete approvedCandidate.candidate_content_hash;
  approvedCandidate.candidate_content_hash = candidateContentHash(approvedCandidate);
  const record = {
    schema: APPROVAL_SCHEMA,
    artifact_version: APPROVAL_ARTIFACT_VERSION,
    candidate_id: candidate.candidate_id,
    candidate_content_hash: candidate.candidate_content_hash,
    // Bind both sides of the lifecycle transition. The pre-approval hash
    // proves what was reviewed; this post-transition hash lets drift compare
    // the approval to the exact APPROVED_DOCUMENTATION_ONLY candidate without
    // declaring a freshly applied approval stale.
    approved_candidate_content_hash: approvedCandidate.candidate_content_hash,
    structural_schema_fingerprint: candidate.structural_schema_fingerprint,
    approval_scope: APPROVAL_SCOPE,
    runtime_active: false,
    enforcement_eligible: false,
    approved_by: approvedBy,
    approved_at: approvedAt,
    rationale,
    classification_confirmed: classificationConfirmed,
    confirmation_bound: confirmationBound,
    unresolved_cautions: [
      "approval_is_documentation_only",
      "approval_does_not_mean_active",
      "approval_does_not_mean_safe",
      "approval_does_not_mean_enforced",
      ...(classificationConfirmed ? [] : ["classification_unconfirmed"]),
    ].sort(),
  };
  record.approval_id = approvalIdFor(record);
  const validation = validateApprovalRecord(record);
  if (!validation.ok) return validation;
  // Producer output contract: the approval record and the approved candidate
  // must both validate before returning.
  assertValidArtifact(APPROVAL_SCHEMA, record);
  assertValidArtifact("mcpherson-governance-capability-candidate/v1", approvedCandidate);
  const approvedValidation = validateCandidate(
    approvedCandidate, {
      stage: "any",
      approvalRecords: [record],
    },
  );
  if (!approvedValidation.ok) {
    const error = new TypeError(
      `approved_candidate_output_invalid:${approvedValidation.reason}`,
    );
    error.detail = approvedValidation;
    throw error;
  }
  return Object.freeze({
    ok: true,
    approval_record: Object.freeze(record),
    approved_candidate: Object.freeze(approvedCandidate),
  });
}

/**
 * Validate a complete approval record: exact field set (unknown fields
 * rejected), every field checked, approval_id recomputed from content. Any
 * record claiming a scope other than documentation_only, or claiming
 * runtime activation or enforcement eligibility, is rejected outright —
 * there is no accepted spelling of an activating approval in v0.6.
 */
export function validateApprovalRecord(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    return reject("approval_malformed");
  }
  // The exported validator delegates structure to the shared contract so it
  // can never diverge from the schema's bounds (e.g. the caution-array
  // maximum): a record the schema rejects is rejected here too.
  const contract = validateArtifact(APPROVAL_SCHEMA, record);
  if (!contract.ok) return reject("approval_contract_invalid");
  const keys = Object.keys(record);
  if (keys.some((key) => !APPROVAL_FIELDS.includes(key))) {
    return reject("approval_unknown_field");
  }
  for (const field of APPROVAL_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(record, field)) {
      return reject(`approval_field_missing:${field}`);
    }
  }
  if (record.schema !== APPROVAL_SCHEMA) return reject("approval_schema_unsupported");
  if (record.artifact_version !== APPROVAL_ARTIFACT_VERSION) {
    return reject("approval_version_unsupported");
  }
  if (record.approval_scope !== APPROVAL_SCOPE) {
    return reject("approval_scope_not_documentation_only");
  }
  if (record.runtime_active !== false) {
    return reject("runtime_active_claim_rejected");
  }
  if (record.enforcement_eligible !== false) {
    return reject("enforcement_eligibility_claim_rejected");
  }
  if (typeof record.candidate_id !== "string"
      || !/^mgc-[a-f0-9]{24}$/.test(record.candidate_id)
      || !HASH_RE.test(record.candidate_content_hash ?? "")
      || !HASH_RE.test(record.approved_candidate_content_hash ?? "")
      || !HASH_RE.test(record.structural_schema_fingerprint ?? "")) {
    return reject("approval_binding_invalid");
  }
  if (record.approved_candidate_content_hash === record.candidate_content_hash) {
    return reject("approval_transition_binding_invalid");
  }
  if (typeof record.approved_by !== "string"
      || !WIRE_SAFE_ID_RE.test(record.approved_by)) {
    return reject("approver_identity_invalid");
  }
  if (typeof record.approved_at !== "string"
      || !RFC3339_UTC_RE.test(record.approved_at)) {
    return reject("approved_at_invalid");
  }
  const rationaleProblem = validateApprovalRationale(record.rationale);
  if (rationaleProblem !== null) return reject(rationaleProblem);
  if (typeof record.classification_confirmed !== "boolean"
      || typeof record.confirmation_bound !== "boolean") {
    return reject("approval_malformed");
  }
  if (record.confirmation_bound && !record.classification_confirmed) {
    return reject("approval_confirmation_claim_inconsistent");
  }
  if (record.classification_confirmed === true
      && record.confirmation_bound === false) {
    // classification_confirmed without a bound confirmation is legal only
    // for registry-deterministic candidates; that legitimacy is proven at
    // creation time. A free-standing record cannot distinguish itself, so
    // the constructor embeds the caution list; here the pair must at least
    // be accompanied by the deterministic-caution absence.
    if (record.unresolved_cautions.includes("classification_unconfirmed")) {
      return reject("approval_confirmation_claim_inconsistent");
    }
  }
  if (!Array.isArray(record.unresolved_cautions)
      || record.unresolved_cautions.length === 0
      || !record.unresolved_cautions.every((entry) => typeof entry === "string"
        && entry.length > 0 && entry.length <= 128)) {
    return reject("approval_cautions_invalid");
  }
  const expectedCautions = [
    "approval_is_documentation_only",
    "approval_does_not_mean_active",
    "approval_does_not_mean_safe",
    "approval_does_not_mean_enforced",
    ...(record.classification_confirmed ? [] : ["classification_unconfirmed"]),
  ].sort();
  if (record.unresolved_cautions.length !== expectedCautions.length
      || record.unresolved_cautions.some(
        (entry, index) => entry !== expectedCautions[index],
      )) {
    return reject("approval_cautions_invalid");
  }
  if (record.approval_id !== approvalIdFor(record)) {
    return reject("approval_id_mismatch");
  }
  return Object.freeze({ ok: true });
}

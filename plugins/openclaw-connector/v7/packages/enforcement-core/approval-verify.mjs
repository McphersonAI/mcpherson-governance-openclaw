// v0.7 approval-artifact rederivation (requirement 1).
//
// A REQUIRE_APPROVAL outcome becomes a permit ONLY when an applicable approval
// artifact is supplied AND the evaluator rederives its complete binding, matches
// it to an explicit supplied VERIFIED issuer-trust result, confirms its id is
// not supplied as consumed, and enforces chronology/freshness PURELY from
// supplied timestamps. The unsigned artifact alone is never sufficient.

import { canonicalHash } from "./hashing.mjs";
import { toEpochSeconds } from "./time.mjs";
import { APPROVAL_DEFAULT_TTL_SECONDS, APPROVAL_MAX_TTL_SECONDS } from "./bounds.mjs";
import { validateArtifact } from "./contracts.mjs";

export const APPROVAL_SCHEMA_ID = "mcpherson-governance-enforcement-approval/v1";

// Ordered by specificity so the evaluator surfaces the most informative reason.
const STALENESS_REASON = Object.freeze({
  FRESH: "approval_satisfied",
  MISMATCH: "approval_mismatch",
  EXPIRED: "approval_expired",
  STALE: "approval_stale",
  UNVERIFIABLE: "approval_unverifiable",
  REPLAYED: "approval_replayed",
  MISSING: "approval_missing",
});

function emptyBinding(staleness, requiredState = "APPROVED") {
  return Object.freeze({
    required_state: requiredState,
    bound_approval_ref: null,
    verified: false,
    staleness,
    bound_envelope_hash: null,
    bound_bundle_id: null,
    bound_bundle_version: null,
    bound_bundle_hash: null,
    bound_tenant_id: null,
    bound_workspace_id: null,
    approval_issuer: null,
    approval_subject: null,
    approval_scope: null,
    issued_at: null,
    expires_at: null,
    trust_verification_hash: null,
    trust_verified: false,
    consumption_status: requiredState === null ? "NOT_APPLICABLE" : "UNKNOWN",
  });
}

// Rank so a more-specific failure is preferred over MISSING when several
// approvals are supplied.
const SPECIFICITY = Object.freeze({
  MISSING: 0, UNVERIFIABLE: 1, MISMATCH: 2, STALE: 3, EXPIRED: 4,
  REPLAYED: 5, FRESH: 6,
});

const TRUST_BOUND_FIELDS = Object.freeze([
  "approval_id", "issuer_id", "tenant_id", "workspace_id",
  "bound_envelope_hash", "bound_bundle_id", "bound_bundle_version",
  "bound_bundle_hash", "approval_subject", "approval_scope", "approval_state",
  "issued_at", "expires_at",
]);

function trustMatches(verification, approval) {
  return verification?.verification_state === "VERIFIED"
    && verification?.verification_method === "SUPPLIED_TRUST_RESULT"
    && TRUST_BOUND_FIELDS.every((field) => verification[field] === approval[field]);
}

function approvalBinding(approval, over = {}) {
  return Object.freeze({
    required_state: "APPROVED",
    bound_approval_ref: approval.approval_id,
    verified: false,
    staleness: "MISMATCH",
    bound_envelope_hash: approval.bound_envelope_hash,
    bound_bundle_id: approval.bound_bundle_id,
    bound_bundle_version: approval.bound_bundle_version,
    bound_bundle_hash: approval.bound_bundle_hash,
    bound_tenant_id: approval.tenant_id,
    bound_workspace_id: approval.workspace_id,
    approval_issuer: approval.issuer_id,
    approval_subject: approval.approval_subject,
    approval_scope: approval.approval_scope,
    issued_at: approval.issued_at,
    expires_at: approval.expires_at,
    trust_verification_hash: null,
    trust_verified: false,
    consumption_status: "UNKNOWN",
    ...over,
  });
}

/**
 * Verify approvals for one REQUIRE_APPROVAL evaluation.
 * @returns {{binding, reason, verified}} binding is the approval_binding record
 * field; reason is the enforcement reason; verified is true ONLY for a FRESH,
 * fully-bound, issuer-trusted, unconsumed APPROVED artifact.
 */
export function verifyApproval(approvals, envelope, bundle, evaluationContext, requirement = {}) {
  const requiredSubject = requirement.requiredSubject ?? null;
  const requiredScope = requirement.requiredScope ?? null;
  const list = Array.isArray(approvals) ? approvals : [];
  if (list.length === 0) {
    return { binding: emptyBinding("MISSING"), reason: STALENESS_REASON.MISSING, verified: false };
  }

  const envelopeHash = canonicalHash(envelope);
  const ttlSeconds = Math.min(
    bundle.approval_ttl_seconds ?? APPROVAL_DEFAULT_TTL_SECONDS,
    APPROVAL_MAX_TTL_SECONDS,
  );
  const observedAt = toEpochSeconds(envelope.observed_at);
  const evaluatedAt = toEpochSeconds(evaluationContext.evaluated_at);
  const verifications = Array.isArray(evaluationContext.approval_verifications)
    ? evaluationContext.approval_verifications
    : [];
  const consumed = new Set(
    Array.isArray(evaluationContext.consumed_approval_ids)
      ? evaluationContext.consumed_approval_ids
      : [],
  );
  const approvalIdCounts = new Map();
  for (const approval of list) {
    const id = approval?.approval_id;
    if (typeof id === "string") approvalIdCounts.set(id, (approvalIdCounts.get(id) ?? 0) + 1);
  }

  let best = {
    staleness: "MISSING",
    binding: emptyBinding("MISSING"),
    reason: STALENESS_REASON.MISSING,
  };
  const consider = (candidate) => {
    if (SPECIFICITY[candidate.staleness] > SPECIFICITY[best.staleness]) best = candidate;
  };

  for (const approval of list) {
    const schemaOk = validateArtifact(APPROVAL_SCHEMA_ID, approval).ok;
    if (!schemaOk) {
      consider({
        staleness: "UNVERIFIABLE",
        binding: emptyBinding("UNVERIFIABLE"),
        reason: STALENESS_REASON.UNVERIFIABLE,
      });
      continue;
    }

    // Artifact binding checks (envelope / policy / tenant / subject / scope).
    const envelopeBound = approval.bound_envelope_hash === envelopeHash;
    const bundleBound = approval.bound_bundle_id === bundle.bundle_id
      && approval.bound_bundle_version === bundle.bundle_version
      && approval.bound_bundle_hash === bundle.bundle_hash;
    const tenantBound = approval.tenant_id === envelope.tenant_id
      && approval.workspace_id === envelope.workspace_id;
    const subjectBound = requiredSubject === null || approval.approval_subject === requiredSubject;
    const scopeBound = requiredScope === null || approval.approval_scope === requiredScope;

    if (!envelopeBound || !bundleBound || !tenantBound || !subjectBound || !scopeBound) {
      consider({
        staleness: "MISMATCH",
        binding: approvalBinding(approval, { staleness: "MISMATCH" }),
        reason: STALENESS_REASON.MISMATCH,
      });
      continue;
    }

    // State is still only a claim; a matching supplied trust result is checked
    // below. A non-APPROVED claim can never permit.
    if (approval.approval_state !== "APPROVED") {
      const staleness = approval.approval_state === "EXPIRED" ? "EXPIRED" : "MISMATCH";
      consider({
        staleness,
        binding: approvalBinding(approval, { staleness }),
        reason: STALENESS_REASON[staleness],
      });
      continue;
    }

    // Trust is an explicit deterministic input. Exact matching binds issuer,
    // scope, subject, tenant/workspace, policy, envelope, and both timestamps.
    const verification = verifications.find((entry) => trustMatches(entry, approval));
    if (verification === undefined) {
      consider({
        staleness: "UNVERIFIABLE",
        binding: approvalBinding(approval, { staleness: "UNVERIFIABLE" }),
        reason: "approval_untrusted",
      });
      continue;
    }

    const trustedBinding = {
      trust_verification_hash: verification.verification_hash,
      trust_verified: true,
      consumption_status: "AVAILABLE",
    };

    // Duplicate presentation is a replay even if the id is not yet listed as
    // consumed. Cross-evaluation consumption is supplied explicitly below.
    if ((approvalIdCounts.get(approval.approval_id) ?? 0) > 1
        || consumed.has(approval.approval_id)) {
      consider({
        staleness: "REPLAYED",
        binding: approvalBinding(approval, {
          ...trustedBinding,
          staleness: "REPLAYED",
          consumption_status: "CONSUMED",
        }),
        reason: STALENESS_REASON.REPLAYED,
      });
      continue;
    }

    // Chronology/freshness purely from supplied timestamps.
    const issuedAt = toEpochSeconds(approval.issued_at);
    const expiresAt = toEpochSeconds(approval.expires_at);
    if (issuedAt === null || expiresAt === null || observedAt === null || evaluatedAt === null) {
      consider({
        staleness: "UNVERIFIABLE",
        binding: approvalBinding(approval, {
          ...trustedBinding,
          staleness: "UNVERIFIABLE",
        }),
        reason: STALENESS_REASON.UNVERIFIABLE,
      });
      continue;
    }
    if (issuedAt < observedAt || issuedAt > evaluatedAt || expiresAt <= issuedAt) {
      consider({
        staleness: "UNVERIFIABLE",
        binding: approvalBinding(approval, {
          ...trustedBinding,
          staleness: "UNVERIFIABLE",
        }),
        reason: STALENESS_REASON.UNVERIFIABLE,
      });
      continue;
    }
    if (evaluatedAt >= expiresAt) {
      consider({
        staleness: "EXPIRED",
        binding: approvalBinding(approval, {
          ...trustedBinding,
          staleness: "EXPIRED",
        }),
        reason: STALENESS_REASON.EXPIRED,
      });
      continue;
    }
    if (evaluatedAt - issuedAt > ttlSeconds
        || expiresAt - issuedAt > APPROVAL_MAX_TTL_SECONDS) {
      consider({
        staleness: "STALE",
        binding: approvalBinding(approval, {
          ...trustedBinding,
          staleness: "STALE",
        }),
        reason: STALENESS_REASON.STALE,
      });
      continue;
    }

    // Fully bound, externally trusted, unconsumed, chronologically valid, fresh.
    return {
      binding: approvalBinding(approval, {
        ...trustedBinding,
        verified: true,
        staleness: "FRESH",
      }),
      reason: STALENESS_REASON.FRESH,
      verified: true,
    };
  }

  return {
    binding: best.binding,
    reason: best.reason,
    verified: false,
  };
}

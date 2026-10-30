// Deterministic fourth-input contract for v0.7 evaluation.
//
// Approval authenticity and replay state are deliberately supplied here rather
// than discovered through ambient authority. enforcement-core performs no key
// custody, signature verification, filesystem/network lookup, mutable nonce
// store, or database access. A caller that has verified an issuer supplies a
// closed VERIFIED result binding every approval field; a caller that has
// consumed an approval supplies its id in consumed_approval_ids.

import { canonicalHash, canonicalHashWithout } from "./hashing.mjs";
import { validateArtifact } from "./contracts.mjs";

export const EVALUATION_CONTEXT_SCHEMA_ID =
  "mcpherson-governance-enforcement-evaluation-context/v1";

/** Canonical integrity hash of a supplied trust result minus its own hash. */
export function approvalVerificationHash(verification) {
  return canonicalHashWithout(verification, ["verification_hash"]);
}

/**
 * Fixture/helper builder for a supplied trust result. This computes integrity
 * binding only; it does NOT authenticate an issuer or create runtime authority.
 */
export function buildApprovalVerification(input) {
  const draft = {
    verification_method: "SUPPLIED_TRUST_RESULT",
    verification_state: "VERIFIED",
    ...input,
  };
  delete draft.verification_hash;
  return Object.freeze({
    ...draft,
    verification_hash: canonicalHash(draft),
  });
}

/** Build the closed deterministic evaluation context with explicit empty state. */
export function buildEvaluationContext(input) {
  return Object.freeze({
    schema: EVALUATION_CONTEXT_SCHEMA_ID,
    context_version: "1",
    evaluated_at: input?.evaluated_at,
    engine_version: input?.engine_version,
    prev_record_hash: input?.prev_record_hash ?? null,
    approval_verifications: Object.freeze([...(input?.approval_verifications ?? [])]),
    consumed_approval_ids: Object.freeze([...(input?.consumed_approval_ids ?? [])]),
  });
}

/**
 * Schema + semantic validation. Approval ids in trust results must be unique,
 * and every verification_hash must bind the exact supplied result.
 */
export function validateEvaluationContext(context) {
  const shape = validateArtifact(EVALUATION_CONTEXT_SCHEMA_ID, context);
  if (!shape.ok) {
    return Object.freeze({
      ok: false,
      reason: "failsafe:invalid:evaluation_context",
      detail: shape.errors[0] ?? null,
    });
  }

  const seenApprovalIds = new Set();
  for (const verification of context.approval_verifications) {
    if (seenApprovalIds.has(verification.approval_id)) {
      return Object.freeze({
        ok: false,
        reason: "failsafe:invalid:evaluation_context",
        detail: { rule: "duplicate_approval_verification", approval_id: verification.approval_id },
      });
    }
    seenApprovalIds.add(verification.approval_id);
    if (verification.verification_hash !== approvalVerificationHash(verification)) {
      return Object.freeze({
        ok: false,
        reason: "failsafe:invalid:evaluation_context",
        detail: { rule: "approval_verification_hash_mismatch", approval_id: verification.approval_id },
      });
    }
  }

  return Object.freeze({ ok: true, context });
}

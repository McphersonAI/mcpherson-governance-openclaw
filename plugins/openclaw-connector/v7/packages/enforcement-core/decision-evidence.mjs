// v0.7 decision-evidence rederivation (consumer-side acceptance != shape).
//
// A decision record is accepted ONLY when supplied together with the exact
// envelope, policy bundle, applicable approvals, and the deterministic
// evaluation context (the record's own evaluated_at + engine_version). The
// consumer re-runs the PINNED engine_version evaluator (never silently the
// newest) and confirms the rederived record matches byte-for-byte. A record
// claiming a permit that rederivation does not support is rejected with
// decision_permit_unsupported_by_policy (analogous to v0.6
// finding_pass_unsupported_by_evidence).

import { canonicalizeJson } from "./hashing.mjs";
import { evaluate } from "./evaluate.mjs";
import { ENFORCEMENT_ENGINE_VERSION } from "./vocabulary.mjs";
import { buildEvaluationContext } from "./evaluation-context.mjs";
import { validateArtifact } from "./contracts.mjs";

const DECISION_SCHEMA_ID = "mcpherson-governance-enforcement-decision/v1";

// The set of engine versions this build can rederive with. Historical replay
// selects the PINNED version recorded on the record; it never silently upgrades
// to the newest. v0.7 ships exactly one engine.
const KNOWN_ENGINES = Object.freeze({
  [ENFORCEMENT_ENGINE_VERSION]: evaluate,
});

export function selectEvaluator(engineVersion) {
  return Object.prototype.hasOwnProperty.call(KNOWN_ENGINES, engineVersion)
    ? KNOWN_ENGINES[engineVersion]
    : null;
}

/**
 * Rederive a decision record from its inputs. Returns
 * `{ok:true}` on a byte-identical rederivation, or `{ok:false, reason, detail}`.
 */
export function rederiveDecision(
  record,
  envelope,
  bundle,
  approvals,
  evaluationContext = null,
) {
  if (!record || typeof record !== "object") {
    return { ok: false, reason: "artifact_not_object", detail: null };
  }
  const shape = validateArtifact(DECISION_SCHEMA_ID, record);
  if (!shape.ok) return { ok: false, reason: "schema_invalid", detail: shape.errors[0] ?? null };

  const evaluator = selectEvaluator(record.engine_version);
  if (evaluator === null) {
    // Cannot rederive against the pinned engine; never fall back to the newest.
    return { ok: false, reason: "engine_range_unsupported", detail: record.engine_version };
  }

  let rederived;
  try {
    const context = evaluationContext ?? buildEvaluationContext({
      evaluated_at: record.evaluated_at,
      engine_version: record.engine_version,
      prev_record_hash: record.prev_record_hash,
      approval_verifications: [],
      consumed_approval_ids: [],
    });
    rederived = evaluator(envelope, bundle, approvals, context);
  } catch (error) {
    return { ok: false, reason: "rederivation_threw", detail: String(error.message ?? error) };
  }

  if (canonicalizeJson(rederived) === canonicalizeJson(record)) {
    return { ok: true };
  }

  // The record diverges from a faithful rederivation. If it asserts a permit the
  // rederivation does not support, name that specifically.
  if (record.decision_permit === true && rederived.decision_permit === false) {
    return { ok: false, reason: "decision_permit_unsupported_by_policy", detail: null };
  }
  return { ok: false, reason: "rederivation_mismatch", detail: {
    field_permit: [record.decision_permit, rederived.decision_permit],
    field_decision: [record.abstract_decision, rederived.abstract_decision],
    field_reason: [record.reason_code, rederived.reason_code],
  } };
}

/** Accept a record only when its shape is valid AND it rederives byte-for-byte. */
export function acceptDecisionRecord(
  record,
  envelope,
  bundle,
  approvals,
  evaluationContext = null,
) {
  return rederiveDecision(
    record,
    envelope,
    bundle,
    approvals,
    evaluationContext,
  );
}

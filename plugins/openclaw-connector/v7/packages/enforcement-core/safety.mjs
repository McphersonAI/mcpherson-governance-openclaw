// v0.7 safety controls: fail-closed vs fail-safe helpers and non-authority
// assertions. Most fail-closed decision logic lives in evaluate.mjs; this module
// exposes the reusable predicates and the process-level fail-safe wrapper.
//
// Fail-closed (decision correctness): any failure to reach a confident permit is
// a non-permit. Fail-safe (availability): one bad input is isolated and counted,
// never crashing a batch, and NEVER upgrades a non-permit to a permit.

import { AUTHORITY_NONE, RUNTIME_ACTIVE, ENFORCEMENT_ELIGIBLE } from "./vocabulary.mjs";

export const MODELED_SAFETY_STATES = Object.freeze([
  "KILL_SWITCH_ACTIVE", "SYSTEM_LOCK_ACTIVE", "CIRCUIT_OPEN",
]);

/** The only permit signal. True iff the record carries decision_permit === true. */
export function isPermit(record) {
  return record != null && record.decision_permit === true;
}

/** Assert a record carries the non-authority constants. Throws on violation. */
export function assertNonAuthority(record) {
  if (record.authority !== AUTHORITY_NONE
      || record.runtime_active !== RUNTIME_ACTIVE
      || record.enforcement_eligible !== ENFORCEMENT_ELIGIBLE
      || record.evaluation_mode !== "SIMULATION") {
    const error = new TypeError("non_authority_invariant_violated");
    error.code = "non_authority_invariant_violated";
    throw error;
  }
  return record;
}

/**
 * Fail-safe batch runner. Applies `fn` to each item, isolating and counting
 * failures so one bad item never crashes the batch. Returns
 * `{results, skipped}`. A caught failure produces NO record (it is skipped),
 * so it can never be mistaken for a permit.
 */
export function runFailSafe(items, fn) {
  const results = [];
  const skipped = [];
  items.forEach((item, index) => {
    try {
      results.push(fn(item, index));
    } catch (error) {
      skipped.push({ index, code: error.code ?? "error", message: String(error.message ?? error) });
    }
  });
  return { results, skipped };
}

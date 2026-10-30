// v0.7 abstract decision model and the mgp/1 wire mapping (D1).
//
// decision_permit is the SINGLE load-bearing permit signal. No consumer may
// infer permission from an abstract value's name, the wire value, or a reason
// code. The abstract->wire map is a TOTAL function that is NOT injective, so
// the wire value alone is lossy: consumers read the carried abstract_decision +
// decision_permit + reason_code, never reconstruct from wire.

import {
  ABSTRACT_DECISIONS,
  WIRE_DECISIONS,
} from "./vocabulary.mjs";

// Base permit signal per abstract decision, BEFORE approval verification.
// - ALLOW is the only base permit.
// - REQUIRE_APPROVAL is a non-permit AS EMITTED; it becomes a permit ONLY via a
//   trusted, fresh, unconsumed, envelope-bound approval (approval-verify.mjs).
// - Every other value is a non-permit.
const BASE_PERMIT = Object.freeze({
  ALLOW: true,
  DENY: false,
  REQUIRE_APPROVAL: false,
  ABSTAIN: false,
  INDETERMINATE: false,
  ERROR: false,
});

export function basePermit(abstractDecision) {
  if (!ABSTRACT_DECISIONS.has(abstractDecision)) {
    throw new TypeError(`unknown_abstract_decision:${abstractDecision}`);
  }
  return BASE_PERMIT[abstractDecision];
}

// The abstract->wire conformance table. ALLOW maps to ALLOW, or to ALLOW_AND_LOG
// when a log obligation is attached. INDETERMINATE and ERROR both map to HOLD
// (fail-closed). This map is TOTAL but NOT injective.
export const WIRE_MAPPING = Object.freeze({
  ALLOW: Object.freeze({ default: "ALLOW", withLogObligation: "ALLOW_AND_LOG" }),
  DENY: Object.freeze({ default: "DENY" }),
  REQUIRE_APPROVAL: Object.freeze({ default: "REQUIRE_APPROVAL" }),
  ABSTAIN: Object.freeze({ default: "SHADOW_ONLY" }),
  INDETERMINATE: Object.freeze({ default: "HOLD" }),
  ERROR: Object.freeze({ default: "HOLD" }),
});

/**
 * Map an abstract decision to its mgp/1 wire value. Pure and total over the six
 * abstract values. `logObligation` only affects ALLOW (ALLOW_AND_LOG).
 */
export function toWire(abstractDecision, { logObligation = false } = {}) {
  const entry = WIRE_MAPPING[abstractDecision];
  if (entry === undefined) {
    throw new TypeError(`unknown_abstract_decision:${abstractDecision}`);
  }
  const wire = abstractDecision === "ALLOW" && logObligation
    ? entry.withLogObligation
    : entry.default;
  if (!WIRE_DECISIONS.has(wire)) {
    // Defensive: the map may only ever produce sealed wire values.
    throw new TypeError(`wire_value_not_in_sealed_enum:${wire}`);
  }
  return wire;
}

// The set of wire values v0.7 can EMIT. This is a subset of the sealed enum
// (v0.7 never emits a raw ALLOW/HOLD without the carried abstract value); it
// does not modify the sealed enum, which remains fully imported.
export const EMITTED_WIRE_VALUES = Object.freeze([
  "ALLOW", "ALLOW_AND_LOG", "REQUIRE_APPROVAL", "DENY", "SHADOW_ONLY", "HOLD",
]);

// Demonstrates non-injectivity for the conformance test: multiple abstract
// values collapse onto HOLD.
export const WIRE_TO_ABSTRACT_MULTIPLICITY = Object.freeze({
  HOLD: Object.freeze(["INDETERMINATE", "ERROR"]),
});

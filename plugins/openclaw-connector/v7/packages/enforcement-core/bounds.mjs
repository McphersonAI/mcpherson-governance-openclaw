// v0.7 enforcement concrete bounds (named constants) — requirement 4.
//
// One authoritative constants table. Every value is a CONSERVATIVE
// FIXTURE/SIMULATION default and a fail-closed safety limit. These are NOT
// production capacity or latency claims (V0.7_ARCHITECTURE.md §9). Over-bound
// input is rejected at validation, never evaluated, and never crashes a batch.
//
// A "step" is one predicate evaluation; a set-membership test counts as one
// step (bounded O(1) lookup), so the step budget is decoupled from set
// cardinality.

export const MAX_BUNDLE_BYTES = 1048576; // 1 MiB
export const MAX_RULES_PER_BUNDLE = 1024;
export const MAX_MATCH_PREDICATES_PER_RULE = 32;
export const MAX_ENVELOPE_BYTES = 65536; // 64 KiB
export const MAX_METADATA_ENTRIES = 64;
export const MAX_METADATA_KEY_BYTES = 128;
export const MAX_METADATA_VALUE_BYTES = 512;
export const MAX_SET_CARDINALITY = 256;
export const MAX_EVALUATION_STEPS = 65536;
export const MAX_AUDIT_SEGMENT_RECORDS = 1024;
export const APPROVAL_DEFAULT_TTL_SECONDS = 900; // 15 min
export const APPROVAL_MAX_TTL_SECONDS = 86400; // 24 h
export const MAX_REPLAY_RECORDS = 10000;
export const MAX_REPLAY_BYTES = 16777216; // 16 MiB

// Machine-readable descriptor of every bound: its value, its rationale, and the
// exact fail-closed reason produced when it is exceeded. The bounds test suite
// (tests/enforcement/bounds.test.mjs) iterates this table so that EVERY named
// bound is covered by a boundary / over-boundary / hostile test (test plan
// §1.10). `failureReason` is the reason_code emitted; `failureDecision` is the
// abstract decision.
export const BOUNDS = Object.freeze([
  Object.freeze({
    name: "MAX_BUNDLE_BYTES", value: MAX_BUNDLE_BYTES,
    rationale: "Bounds bundle parse/validate cost; fixtures are far smaller.",
    failureReason: "failsafe:invalid:oversize:bundle", failureDecision: "ERROR",
  }),
  Object.freeze({
    name: "MAX_RULES_PER_BUNDLE", value: MAX_RULES_PER_BUNDLE,
    rationale: "Bounds evaluation steps and ordering cost; ample for real policy sets.",
    failureReason: "failsafe:invalid:oversize:rules", failureDecision: "ERROR",
  }),
  Object.freeze({
    name: "MAX_MATCH_PREDICATES_PER_RULE", value: MAX_MATCH_PREDICATES_PER_RULE,
    rationale: "Bounds per-rule match cost; keeps rules x predicates small.",
    failureReason: "failsafe:invalid:oversize:predicates", failureDecision: "ERROR",
  }),
  Object.freeze({
    name: "MAX_ENVELOPE_BYTES", value: MAX_ENVELOPE_BYTES,
    rationale: "Envelopes are metadata + digests, not payloads (arguments are digest-only).",
    failureReason: "failsafe:invalid:oversize:envelope", failureDecision: "ERROR",
  }),
  Object.freeze({
    name: "MAX_METADATA_ENTRIES", value: MAX_METADATA_ENTRIES,
    rationale: "Bounds the allow-listed metadata map; blocks metadata as a smuggling/DoS vector.",
    failureReason: "failsafe:invalid:oversize:metadata", failureDecision: "ERROR",
  }),
  Object.freeze({
    name: "MAX_METADATA_KEY_BYTES", value: MAX_METADATA_KEY_BYTES,
    rationale: "Bounded, wire-safe keys.",
    failureReason: "failsafe:invalid:oversize:metadata_key", failureDecision: "ERROR",
  }),
  Object.freeze({
    name: "MAX_METADATA_VALUE_BYTES", value: MAX_METADATA_VALUE_BYTES,
    rationale: "Short enum/label values only; no free-text payloads.",
    failureReason: "failsafe:invalid:oversize:metadata_value", failureDecision: "ERROR",
  }),
  Object.freeze({
    name: "MAX_SET_CARDINALITY", value: MAX_SET_CARDINALITY,
    rationale: "Bounds set-valued fields and set-membership operands per predicate.",
    failureReason: "failsafe:invalid:oversize:set", failureDecision: "ERROR",
  }),
  Object.freeze({
    name: "MAX_EVALUATION_STEPS", value: MAX_EVALUATION_STEPS,
    rationale: "Deterministic budget above worst case within the above bounds (1024 x 32 = 32768) with headroom.",
    failureReason: "budget_exceeded", failureDecision: "INDETERMINATE",
  }),
  Object.freeze({
    name: "MAX_AUDIT_SEGMENT_RECORDS", value: MAX_AUDIT_SEGMENT_RECORDS,
    rationale: "Bounds segment size for validation/rederivation; larger histories span multiple segment_seq-chained segments.",
    failureReason: "failsafe:invalid:oversize:segment", failureDecision: "ERROR",
  }),
  Object.freeze({
    name: "APPROVAL_DEFAULT_TTL_SECONDS", value: APPROVAL_DEFAULT_TTL_SECONDS,
    rationale: "Conservative fixture freshness window; short by design.",
    failureReason: "approval_stale", failureDecision: "REQUIRE_APPROVAL",
  }),
  Object.freeze({
    name: "APPROVAL_MAX_TTL_SECONDS", value: APPROVAL_MAX_TTL_SECONDS,
    rationale: "Hard ceiling a bundle's approval-TTL rule may declare.",
    failureReason: "failsafe:invalid:approval_ttl", failureDecision: "ERROR",
  }),
  Object.freeze({
    name: "MAX_REPLAY_RECORDS", value: MAX_REPLAY_RECORDS,
    rationale: "Bounds a replay stream for deterministic iteration.",
    failureReason: "failsafe:invalid:oversize:replay_records", failureDecision: "ERROR",
  }),
  Object.freeze({
    name: "MAX_REPLAY_BYTES", value: MAX_REPLAY_BYTES,
    rationale: "Bounds replay input size.",
    failureReason: "failsafe:invalid:oversize:replay_bytes", failureDecision: "ERROR",
  }),
]);

// Byte length of a value's canonical UTF-8 JSON encoding is measured by callers
// with a TextEncoder; this helper centralizes it so every size bound is
// measured identically.
const ENCODER = new TextEncoder();
export function utf8ByteLength(text) {
  return ENCODER.encode(typeof text === "string" ? text : String(text)).length;
}

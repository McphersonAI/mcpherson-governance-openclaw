// v0.7 normalized action envelope: build + strict validation.
//
// The envelope is the sole input surface for a request. It carries argument
// DIGEST + bounded SHAPE only (never raw arguments), no model/ML-derived field
// (D8), and evaluation_mode fixed to SIMULATION. Validation is fail-closed:
// any structural, bound, privacy, model-field, or hash-integrity violation is a
// non-permitting ERROR, never a silent pass.

import {
  ACTION_CLASS_EFFECTS,
} from "../governance-diagnostics/vocabulary.mjs";
import { sensitiveValueReason } from "../governance-diagnostics/sensitive-values.mjs";
import { canonicalizeJson, canonicalHash, canonicalHashWithout } from "./hashing.mjs";
import {
  MAX_ENVELOPE_BYTES, MAX_METADATA_ENTRIES, MAX_METADATA_KEY_BYTES,
  MAX_METADATA_VALUE_BYTES, utf8ByteLength,
} from "./bounds.mjs";
import { EVALUATION_MODE } from "./vocabulary.mjs";
import { validateArtifact } from "./contracts.mjs";

export const ENVELOPE_SCHEMA_ID = "mcpherson-governance-enforcement-envelope/v1";

// Model/ML-derived field names are structurally forbidden (D8). The closed
// schema already rejects unknown fields, but this explicit denylist yields a
// precise reason and defends the invariant independently of the schema.
const MODEL_FIELD_RE =
  /(?:^|_)(model|ml|llm|inference|embedding|logit|logits|prediction|predicted|classifier|advisory|prompt|completion|confidence)(?:_|$)/i;

// Free-text / label fields subject to the bounded privacy screen. Pure wire-safe
// structural identifiers and sha256 hashes are exempt (constrained by pattern).
const SCREENED_STRING_FIELDS = Object.freeze([
  "resource_class", "resource_ref", "data_sensitivity_label",
  "reversibility_label", "recipient_type", "risk_tier",
]);
const SCREENED_ARRAY_FIELDS = Object.freeze(["risk_basis"]);

function fail(reason, detail) {
  return Object.freeze({ ok: false, decision: "ERROR", reason, detail: detail ?? null });
}

/** The canonical hash of the full envelope artifact (used as envelope_hash). */
export function envelopeHash(envelope) {
  return canonicalHash(envelope);
}

/** Recompute the envelope's own request_hash from its canonical projection. */
export function computeEnvelopeRequestHash(envelope) {
  return canonicalHashWithout(envelope, ["request_hash"]);
}

/**
 * Build a complete envelope from an input object by computing request_hash.
 * For fixtures/tests only; the evaluator never mutates its inputs.
 */
export function buildEnvelope(input) {
  const draft = { ...input };
  delete draft.request_hash;
  return Object.freeze({ ...draft, request_hash: canonicalHash(draft) });
}

/** True when every declared effect is within the action_class's effect set. */
export function effectsConsistentWithClass(envelope) {
  if (!Array.isArray(envelope.effects)) return true; // effects optional
  const allowed = ACTION_CLASS_EFFECTS[envelope.action_class];
  if (!allowed) return false;
  const allowedSet = new Set(allowed);
  return envelope.effects.every((effect) => allowedSet.has(effect));
}

/** Privacy screen over free-text/label fields. Returns null or a reason detail. */
export function screenEnvelopePrivacy(envelope) {
  for (const field of SCREENED_STRING_FIELDS) {
    const value = envelope[field];
    if (typeof value === "string") {
      const reason = sensitiveValueReason(value);
      if (reason) return { field, reason };
    }
  }
  for (const field of SCREENED_ARRAY_FIELDS) {
    const arr = envelope[field];
    if (Array.isArray(arr)) {
      for (const value of arr) {
        const reason = sensitiveValueReason(value);
        if (reason) return { field, reason };
      }
    }
  }
  const shape = envelope.argument_shape;
  if (shape && Array.isArray(shape.sensitivity_labels)) {
    for (const value of shape.sensitivity_labels) {
      const reason = sensitiveValueReason(value);
      if (reason) return { field: "argument_shape.sensitivity_labels", reason };
    }
  }
  if (envelope.metadata && typeof envelope.metadata === "object") {
    for (const [key, value] of Object.entries(envelope.metadata)) {
      const keyReason = sensitiveValueReason(key);
      if (keyReason) return { field: `metadata.key:${key}`, reason: keyReason };
      if (typeof value === "string") {
        const valueReason = sensitiveValueReason(value);
        if (valueReason) return { field: `metadata.value:${key}`, reason: valueReason };
      }
    }
  }
  return null;
}

/**
 * Strict, fail-closed validation of an action envelope. Returns
 * `{ok:true, envelope}` or `{ok:false, decision:"ERROR", reason, detail}`.
 * (The effects<->action_class consistency check is a SEPARATE evaluation-time
 * check that yields INDETERMINATE, not an ERROR; see evaluate.mjs.)
 */
export function validateActionEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    return fail("failsafe:invalid:envelope_schema", "not_object");
  }
  // 1) Model/ML-derived field denylist (D8), before schema for a precise reason.
  for (const key of Object.keys(envelope)) {
    if (MODEL_FIELD_RE.test(key)) {
      return fail("failsafe:invalid:model_field", key);
    }
  }
  // 2) Closed-schema validation (rejects unknown/activation-shaped fields,
  //    enforces evaluation_mode const SIMULATION, timestamps, patterns).
  const schemaResult = validateArtifact(ENVELOPE_SCHEMA_ID, envelope);
  if (!schemaResult.ok) {
    return fail("failsafe:invalid:envelope_schema", schemaResult.errors[0] ?? null);
  }
  // 3) Defensive evaluation_mode check (schema already enforces the const).
  if (envelope.evaluation_mode !== EVALUATION_MODE) {
    return fail("failsafe:invalid:evaluation_mode", envelope.evaluation_mode ?? null);
  }
  // 4) Size bound.
  const bytes = utf8ByteLength(canonicalizeJson(envelope));
  if (bytes > MAX_ENVELOPE_BYTES) {
    return fail("failsafe:invalid:oversize:envelope", bytes);
  }
  // 5) Metadata bounds.
  if (envelope.metadata && typeof envelope.metadata === "object") {
    const keys = Object.keys(envelope.metadata);
    if (keys.length > MAX_METADATA_ENTRIES) {
      return fail("failsafe:invalid:oversize:metadata", keys.length);
    }
    for (const key of keys) {
      if (utf8ByteLength(key) > MAX_METADATA_KEY_BYTES) {
        return fail("failsafe:invalid:oversize:metadata_key", key);
      }
      const value = envelope.metadata[key];
      if (typeof value === "string" && utf8ByteLength(value) > MAX_METADATA_VALUE_BYTES) {
        return fail("failsafe:invalid:oversize:metadata_value", key);
      }
    }
  }
  // 6) Privacy screen.
  const privacy = screenEnvelopePrivacy(envelope);
  if (privacy) {
    return fail("failsafe:invalid:privacy_screen", privacy);
  }
  // 7) request_hash integrity.
  if (envelope.request_hash !== computeEnvelopeRequestHash(envelope)) {
    return fail("failsafe:invalid:request_hash", null);
  }
  return Object.freeze({ ok: true, envelope });
}

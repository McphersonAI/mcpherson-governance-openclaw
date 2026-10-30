// v0.7 versioned policy registry: bundle load / validate / hash / engine_range.
//
// A bundle is content-addressed by bundle_hash. Validation is fail-closed: an
// invalid or over-bound bundle never evaluates. default_decision is limited to
// {DENY, REQUIRE_APPROVAL, ABSTAIN} (ALLOW-by-default prohibited, D2).

import { canonicalizeJson, canonicalHash, canonicalHashWithout } from "./hashing.mjs";
import {
  MAX_BUNDLE_BYTES, MAX_RULES_PER_BUNDLE, MAX_MATCH_PREDICATES_PER_RULE,
  APPROVAL_MAX_TTL_SECONDS, utf8ByteLength,
} from "./bounds.mjs";
import { ALLOWED_DEFAULT_DECISIONS } from "./vocabulary.mjs";
import { validatePredicate, MATCHABLE_FIELD_TYPES } from "./policy-match.mjs";
import { validateArtifact } from "./contracts.mjs";

export const BUNDLE_SCHEMA_ID = "mcpherson-governance-enforcement-policy-bundle/v1";

function fail(reason, detail) {
  return Object.freeze({ ok: false, decision: "ERROR", reason, detail: detail ?? null });
}

/** Parse a dotted version string into a numeric segment array. */
export function parseVersion(version) {
  if (typeof version !== "string") return null;
  const segments = version.split(/[^0-9]+/).filter((s) => s.length > 0).map(Number);
  if (segments.length === 0 || segments.some((n) => !Number.isInteger(n))) return null;
  return segments;
}

/** Compare two parsed versions. Returns -1, 0, 1. */
export function compareVersions(a, b) {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (pa === null || pb === null) return null;
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i += 1) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

/** True when engineVersion is within [min_inclusive, max_inclusive]. */
export function engineInRange(engineVersion, engineRange) {
  if (!engineRange || typeof engineRange !== "object") return false;
  const lo = compareVersions(engineVersion, engineRange.min_inclusive);
  const hi = compareVersions(engineVersion, engineRange.max_inclusive);
  if (lo === null || hi === null) return false;
  return lo >= 0 && hi <= 0;
}

/** Canonical bundle hash (of the bundle without its own bundle_hash field). */
export function bundleHash(bundle) {
  return canonicalHashWithout(bundle, ["bundle_hash"]);
}

/** Build a bundle from an input object by computing bundle_hash (fixtures/tests). */
export function buildBundle(input) {
  const draft = { ...input };
  delete draft.bundle_hash;
  return Object.freeze({ ...draft, bundle_hash: canonicalHash(draft) });
}

/**
 * Fail-closed bundle validation. Returns `{ok:true, bundle}` or
 * `{ok:false, decision:"ERROR", reason, detail}`.
 */
export function validateBundle(bundle) {
  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) {
    return fail("failsafe:invalid:bundle_schema", "not_object");
  }
  // Size bound first (bounds parse cost).
  const bytes = utf8ByteLength(canonicalizeJson(bundle));
  if (bytes > MAX_BUNDLE_BYTES) return fail("failsafe:invalid:oversize:bundle", bytes);

  // Closed-schema validation.
  const schemaResult = validateArtifact(BUNDLE_SCHEMA_ID, bundle);
  if (!schemaResult.ok) {
    return fail("failsafe:invalid:bundle_schema", schemaResult.errors[0] ?? null);
  }
  // default_decision must be an allowed default (ALLOW-by-default prohibited).
  if (!ALLOWED_DEFAULT_DECISIONS.has(bundle.default_decision)) {
    return fail("failsafe:invalid:missing_default", bundle.default_decision ?? null);
  }
  // Rule-count and predicate-count bounds (schema also bounds; explicit reasons).
  if (bundle.rules.length > MAX_RULES_PER_BUNDLE) {
    return fail("failsafe:invalid:oversize:rules", bundle.rules.length);
  }
  const seenRuleIds = new Set();
  for (const rule of bundle.rules) {
    if (seenRuleIds.has(rule.rule_id)) {
      return fail("failsafe:invalid:duplicate_rule_id", rule.rule_id);
    }
    seenRuleIds.add(rule.rule_id);
    const predicates = rule.match?.all ?? [];
    if (predicates.length > MAX_MATCH_PREDICATES_PER_RULE) {
      return fail("failsafe:invalid:oversize:predicates", rule.rule_id);
    }
    for (const predicate of predicates) {
      const problem = validatePredicate(predicate);
      if (problem) {
        if (problem.rule === "failsafe:invalid:oversize:set") {
          return fail("failsafe:invalid:oversize:set", { rule_id: rule.rule_id, ...problem });
        }
        return fail("failsafe:invalid:bad_matcher", { rule_id: rule.rule_id, ...problem });
      }
    }
  }
  // engine_range well-formed and ordered.
  const order = compareVersions(bundle.engine_range.min_inclusive, bundle.engine_range.max_inclusive);
  if (order === null || order > 0) {
    return fail("failsafe:invalid:bad_engine_range", bundle.engine_range);
  }
  // required_context fields must be matchable/known envelope fields.
  if (Array.isArray(bundle.required_context)) {
    for (const field of bundle.required_context) {
      if (MATCHABLE_FIELD_TYPES[field] === undefined) {
        return fail("failsafe:invalid:bad_matcher", { required_context: field });
      }
    }
  }
  // approval TTL ceiling.
  if (bundle.approval_ttl_seconds !== undefined
      && bundle.approval_ttl_seconds > APPROVAL_MAX_TTL_SECONDS) {
    return fail("failsafe:invalid:approval_ttl", bundle.approval_ttl_seconds);
  }
  // bundle_hash integrity.
  if (bundle.bundle_hash !== bundleHash(bundle)) {
    return fail("failsafe:invalid:bundle_hash", null);
  }
  return Object.freeze({ ok: true, bundle });
}

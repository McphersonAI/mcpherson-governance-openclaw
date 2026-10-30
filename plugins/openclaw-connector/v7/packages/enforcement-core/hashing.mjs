// Canonical hashing for v0.7 enforcement artifacts.
//
// Reuses the frozen v0.5 canonical JSON encoder (sorted keys, no insignificant
// whitespace, rejects non-plain objects / cycles / non-finite numbers). All
// hashing is a pure function of the supplied value; nothing here reads a clock,
// network, filesystem, or randomness.

import { createHash } from "node:crypto";
import { canonicalizeJson } from "../governance-core/canonical.mjs";

/** `sha256:` + hex digest of the canonical JSON of `value`. */
export function canonicalHash(value) {
  const digest = createHash("sha256")
    .update(new TextEncoder().encode(canonicalizeJson(value)))
    .digest("hex");
  return `sha256:${digest}`;
}

/** Hash of `value` with the named keys removed (shallow), for self-hash fields. */
export function canonicalHashWithout(value, omitKeys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("canonical_hash_without_requires_object");
  }
  const omit = new Set(omitKeys);
  const clone = {};
  for (const key of Object.keys(value)) {
    if (omit.has(key)) continue;
    clone[key] = value[key];
  }
  return canonicalHash(clone);
}

/** Short content id: `<prefix>` + first 24 hex chars of sha256(canonical). */
export function contentId(prefix, value) {
  const digest = createHash("sha256")
    .update(new TextEncoder().encode(canonicalizeJson(value)))
    .digest("hex")
    .slice(0, 24);
  return `${prefix}${digest}`;
}

export { canonicalizeJson };

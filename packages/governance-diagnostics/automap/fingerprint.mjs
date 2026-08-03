// Deterministic structural and descriptive fingerprinting for capability
// parameter schemas.
//
// The structural view preserves validation-semantic content (property names,
// types, required sets, enum values, array-item structure, additional-
// properties behavior, constraints, operation name and parameter location)
// and ignores prose (descriptions, titles, examples, comments), formatting,
// and non-semantic ordering. The descriptive view captures exactly the prose
// the structural view ignores, so descriptive-only edits are distinguishable
// from structural drift. Neither fingerprint is a raw whole-document hash; a
// raw document hash is recorded separately and labeled as such.

import { createHash } from "node:crypto";
import { canonicalizeJson } from "../../governance-core/canonical.mjs";

// v2 (Sol repair): unrecognized keywords no longer fall out of the
// structural view. Anything this module cannot prove to be prose enters the
// structural view verbatim, so adding `dependencies`, `$dynamicRef`,
// `nullable`, or any unknown keyword is structural drift rather than
// silently no drift. OpenAPI `nullable:true` is additionally normalized into
// the type union so the two spellings of nullability fingerprint equally.
export const STRUCTURAL_FINGERPRINT_ALGORITHM = "mgp-structural-fingerprint/v2";
export const DESCRIPTIVE_FINGERPRINT_ALGORITHM = "mgp-descriptive-fingerprint/v2";

const DESCRIPTIVE_KEYS = new Set([
  "description", "title", "examples", "example", "$comment", "deprecated",
]);

// Keys whose values are itself schemas.
const SCHEMA_VALUE_KEYS = new Set([
  "items", "additionalProperties", "additionalItems", "contains", "not",
  "propertyNames", "if", "then", "else", "unevaluatedProperties",
  "unevaluatedItems",
]);
// Keys mapping names to schemas.
const SCHEMA_MAP_KEYS = new Set([
  "properties", "patternProperties", "definitions", "$defs",
  "dependentSchemas",
]);
// Keys holding arrays of schemas whose order is not semantic.
const SCHEMA_LIST_UNORDERED_KEYS = new Set(["oneOf", "anyOf", "allOf"]);
// Keys holding arrays of schemas whose order is semantic (tuple positions).
const SCHEMA_LIST_ORDERED_KEYS = new Set(["prefixItems"]);
// Scalar or scalar-list constraint keys preserved verbatim.
const CONSTRAINT_KEYS = new Set([
  "const", "pattern", "format", "minimum", "maximum", "exclusiveMinimum",
  "exclusiveMaximum", "multipleOf", "minLength", "maxLength", "minItems",
  "maxItems", "uniqueItems", "minProperties", "maxProperties", "$ref",
  "readOnly", "writeOnly", "contentEncoding", "contentMediaType",
  "minContains", "maxContains", "dependentRequired", "$dynamicRef",
  "$dynamicAnchor", "$anchor", "$recursiveRef", "$recursiveAnchor",
]);

// Keys consumed by the view construction itself and therefore not re-walked
// in the unknown-keyword pass.
const HANDLED_KEYS = new Set(["type", "required", "enum", "default", "$schema", "$id", "nullable"]);

function sortedByCanonical(values) {
  return [...values].sort((left, right) => {
    const leftKey = canonicalizeJson(left);
    const rightKey = canonicalizeJson(right);
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
}

function normalizeType(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    const unique = [...new Set(value.filter((entry) => typeof entry === "string"))];
    unique.sort();
    return unique.length === 1 ? unique[0] : unique;
  }
  return null;
}

function isPlainValue(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Produce the deterministic structural view of a JSON-Schema-like object.
 * Unknown keys are ignored (recorded upstream as unresolved questions when
 * relevant); descriptive keys never enter the structural view.
 */
export function structuralView(schema) {
  if (schema === true || schema === false) return schema;
  if (!isPlainValue(schema)) return null;
  const view = {};
  if ("type" in schema || schema.nullable === true) {
    let normalized = normalizeType(schema.type ?? null);
    // OpenAPI nullable:true is validation-semantic: fold it into the type
    // union so `type:"string", nullable:true` fingerprints identically to
    // `type:["string","null"]`.
    if (schema.nullable === true) {
      const members = normalized === null
        ? ["null"]
        : [...new Set([
          ...(Array.isArray(normalized) ? normalized : [normalized]), "null",
        ])].sort();
      normalized = members.length === 1 ? members[0] : members;
    }
    if (normalized !== null) view.type = normalized;
  }
  if (Array.isArray(schema.required)) {
    view.required = [...new Set(
      schema.required.filter((entry) => typeof entry === "string"),
    )].sort();
  }
  if (Array.isArray(schema.enum)) {
    view.enum = sortedByCanonical(schema.enum);
  }
  for (const key of Object.keys(schema).sort()) {
    const value = schema[key];
    if (DESCRIPTIVE_KEYS.has(key) || HANDLED_KEYS.has(key)) {
      continue;
    }
    if (key === "dependencies" && isPlainValue(value)) {
      // Legacy dependencies: each entry is either a required-name list or a
      // schema. Both forms are validation-semantic.
      const map = {};
      for (const name of Object.keys(value).sort()) {
        map[name] = Array.isArray(value[name])
          ? [...new Set(value[name].filter((entry) => typeof entry === "string"))].sort()
          : structuralView(value[name]);
      }
      view.dependencies = map;
    } else if (SCHEMA_MAP_KEYS.has(key) && isPlainValue(value)) {
      const map = {};
      for (const name of Object.keys(value).sort()) {
        map[name] = structuralView(value[name]);
      }
      view[key] = map;
    } else if (SCHEMA_VALUE_KEYS.has(key)) {
      if (key === "items" && Array.isArray(value)) {
        view[key] = value.map((entry) => structuralView(entry));
      } else {
        view[key] = structuralView(value);
      }
    } else if (SCHEMA_LIST_ORDERED_KEYS.has(key) && Array.isArray(value)) {
      view[key] = value.map((entry) => structuralView(entry));
    } else if (SCHEMA_LIST_UNORDERED_KEYS.has(key) && Array.isArray(value)) {
      view[key] = sortedByCanonical(value.map((entry) => structuralView(entry)));
    } else if (CONSTRAINT_KEYS.has(key)) {
      view[key] = value;
    } else {
      // Unknown keyword: conservatively structural. Encode its exact
      // canonical value under a marked name so it can never collide with a
      // recognized keyword's semantics.
      view[`unknown_keyword.${key}`] = canonicalizeJson(value ?? null);
    }
  }
  // Absent additionalProperties behaves as permitted in JSON Schema; the
  // equivalent representations are normalized so adding an explicit `true`
  // is not structural drift, while tightening to `false` or a schema is.
  if (isPlainValue(schema) && !("additionalProperties" in view)
      && (view.type === "object" || "properties" in view)) {
    view.additionalProperties = true;
  }
  return view;
}

/** Collect the prose the structural view ignores, keyed by stable paths. */
export function descriptiveView(schema, path = "", into = {}) {
  if (!isPlainValue(schema)) return into;
  for (const key of Object.keys(schema).sort()) {
    const value = schema[key];
    const here = path === "" ? key : `${path}.${key}`;
    if (DESCRIPTIVE_KEYS.has(key)) {
      into[here] = value;
    } else if (SCHEMA_MAP_KEYS.has(key) && isPlainValue(value)) {
      for (const name of Object.keys(value).sort()) {
        descriptiveView(value[name], `${here}.${name}`, into);
      }
    } else if (SCHEMA_VALUE_KEYS.has(key) && isPlainValue(value)) {
      descriptiveView(value, here, into);
    } else if ((SCHEMA_LIST_UNORDERED_KEYS.has(key)
        || SCHEMA_LIST_ORDERED_KEYS.has(key) || key === "items")
        && Array.isArray(value)) {
      value.forEach((entry, index) => {
        descriptiveView(entry, `${here}.${index}`, into);
      });
    }
  }
  return into;
}

/**
 * Flatten a structural view into sorted `path=signature` strings used for
 * deterministic drift field diffs.
 */
export function structuralPaths(view, prefix = "structure") {
  const paths = [];
  if (view === null || typeof view !== "object") {
    paths.push(`${prefix}=${canonicalizeJson(view ?? null)}`);
    return paths;
  }
  if (Array.isArray(view)) {
    view.forEach((entry, index) => {
      paths.push(...structuralPaths(entry, `${prefix}.${index}`));
    });
    return paths;
  }
  const keys = Object.keys(view).sort();
  if (keys.length === 0) {
    paths.push(`${prefix}={}`);
    return paths;
  }
  for (const key of keys) {
    const value = view[key];
    if (value !== null && typeof value === "object") {
      paths.push(...structuralPaths(value, `${prefix}.${key}`));
    } else {
      paths.push(`${prefix}.${key}=${canonicalizeJson(value ?? null)}`);
    }
  }
  return paths.sort();
}

function digest(algorithm, body) {
  const framed = canonicalizeJson({ fingerprint_algorithm: algorithm, body });
  return `sha256:${createHash("sha256").update(framed, "utf8").digest("hex")}`;
}

/**
 * Fingerprint one operation-level capability surface. The frame includes the
 * native operation name and parameter location so renaming an operation or
 * moving parameters is structural drift even when the parameter schema bytes
 * are unchanged.
 */
export function fingerprintOperation({ operationName, parameterLocation, parameters }) {
  const structure = {
    operation: operationName ?? null,
    parameter_location: parameterLocation ?? null,
    parameters: structuralView(parameters ?? null),
  };
  const prose = descriptiveView(parameters ?? null);
  return Object.freeze({
    structural_fingerprint: digest(STRUCTURAL_FINGERPRINT_ALGORITHM, structure),
    metadata_fingerprint: digest(DESCRIPTIVE_FINGERPRINT_ALGORITHM, {
      operation: operationName ?? null,
      prose,
    }),
    structural_paths: Object.freeze(structuralPaths(structure)),
  });
}

/** Raw provenance hash over the exact source bytes; never a fingerprint. */
export function rawDocumentSha256(bytes) {
  const hash = createHash("sha256");
  if (Buffer.isBuffer(bytes)) hash.update(bytes);
  else hash.update(String(bytes), "utf8");
  return `sha256:${hash.digest("hex")}`;
}

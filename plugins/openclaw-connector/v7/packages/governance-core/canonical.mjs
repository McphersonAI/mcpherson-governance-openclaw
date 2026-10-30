import { createHash } from "node:crypto";

const PLAIN_OBJECT_PROTOTYPES = new Set([Object.prototype, null]);

function fail(kind) {
  throw new TypeError(`non_canonical_json:${kind}`);
}

function encodeCanonical(value, ancestors) {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) fail("non_finite_number");
      return JSON.stringify(value);
    case "undefined":
    case "bigint":
    case "symbol":
    case "function":
      fail(typeof value);
      break;
    case "object":
      break;
    default:
      fail("unknown_type");
  }

  if (ancestors.has(value)) fail("cycle");
  ancestors.add(value);
  try {
    if (Object.getOwnPropertySymbols(value).length !== 0) {
      fail("symbol_key");
    }
    if (Array.isArray(value)) {
      if (Object.keys(value).length !== value.length) fail("array_property");
      const parts = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !("value" in descriptor)) {
          fail("sparse_array");
        }
        parts.push(encodeCanonical(descriptor.value, ancestors));
      }
      return `[${parts.join(",")}]`;
    }

    if (!PLAIN_OBJECT_PROTOTYPES.has(Object.getPrototypeOf(value))) {
      fail("non_plain_object");
    }
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor)) fail("accessor_property");
      parts.push(`${JSON.stringify(key)}:${encodeCanonical(descriptor.value, ancestors)}`);
    }
    return `{${parts.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

/** Sorted-key, UTF-8 JSON with no insignificant whitespace. */
export function canonicalizeJson(value) {
  return encodeCanonical(value, new Set());
}

function requestWithoutHash(request) {
  if (request === null || typeof request !== "object" || Array.isArray(request)
      || !PLAIN_OBJECT_PROTOTYPES.has(Object.getPrototypeOf(request))) {
    fail("request_not_object");
  }
  if (Object.getOwnPropertySymbols(request).length !== 0) fail("symbol_key");
  const clone = Object.create(null);
  for (const key of Object.keys(request)) {
    if (key === "request_hash") continue;
    const descriptor = Object.getOwnPropertyDescriptor(request, key);
    if (!descriptor || !("value" in descriptor)) fail("accessor_property");
    clone[key] = descriptor.value;
  }
  return clone;
}

export function canonicalRequestBytes(request) {
  return new TextEncoder().encode(canonicalizeJson(requestWithoutHash(request)));
}

export function requestHash(request) {
  const digest = createHash("sha256")
    .update(canonicalRequestBytes(request))
    .digest("hex");
  return `sha256:${digest}`;
}

export function verifyRequestHash(request, supplied = request?.request_hash) {
  return typeof supplied === "string" && supplied === requestHash(request);
}

/** Exact v0.4.1 toolCallRef one-way hashing semantics. */
export function correlationRef(value) {
  if (typeof value !== "string" || value.length === 0) return null;
  return `sha256:${createHash("sha256").update(value).digest("hex").slice(0, 24)}`;
}

export const toolCallRef = correlationRef;

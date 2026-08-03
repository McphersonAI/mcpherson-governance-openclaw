// Dependency-free strict validator for the JSON Schema subset used by the
// v0.6 diagnostic contract inventory.
//
// Supported keywords: type, const, enum, required, properties,
// additionalProperties (boolean or schema), propertyNames, items (schema),
// prefixItems, minItems, maxItems, uniqueItems, pattern, minLength,
// maxLength, minimum, maximum, exclusiveMinimum, exclusiveMaximum, oneOf,
// format ("date-time-utc" only), $ref (local "#/$defs/..." only), $defs.
// Unknown keywords in a schema are a hard error at load time, so a schema
// cannot silently promise more than this validator enforces. Any object
// schema (one that declares `properties`, or `type:"object"`) MUST also
// declare an explicit `additionalProperties` policy at load time, so a schema
// can never silently accept unknown fields. Validation never coerces: a
// mismatch is an error, never a default.

const SUPPORTED_KEYWORDS = new Set([
  "$schema", "$id", "$defs", "$ref", "title", "description",
  "type", "const", "enum", "required", "properties", "additionalProperties",
  "propertyNames", "items", "prefixItems", "minItems", "maxItems",
  "uniqueItems", "pattern", "minLength", "maxLength", "minimum", "maximum",
  "exclusiveMinimum", "exclusiveMaximum", "oneOf", "format",
]);

const SUPPORTED_FORMATS = new Set(["date-time-utc"]);

const RFC3339_UTC_RE =
  /^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(?:\.(\d{1,9}))?Z$/;

/**
 * Real calendar validation for an RFC 3339 UTC timestamp: rejects impossible
 * dates (month 13, day 32, Feb 30/31, invalid leap days) that a digit-shape
 * pattern admits. This is the shared calendar check used by every diagnostic
 * timestamp field via `format: "date-time-utc"`.
 */
export function isCalendarUtcTimestamp(value) {
  if (typeof value !== "string" || value.length > 40) return false;
  const match = RFC3339_UTC_RE.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= days[month - 1];
}

function schemaError(message) {
  const error = new TypeError(`diagnostic_schema_unsupported:${message}`);
  return error;
}

// A property-bearing object schema must declare its unknown-field policy.
// A bare `{ type: "object" }` with no declared properties is an intentional
// "any object" (e.g. an embedded arbitrary JSON-Schema `parameters` field)
// and is allowed without additionalProperties.
function requiresAdditionalPropertiesPolicy(schema) {
  return schema.properties !== undefined;
}

/** Assert every keyword in a schema document is enforceable. */
export function assertSupportedSchema(schema, path = "#") {
  if (schema === true || schema === false) return;
  if (schema === null || typeof schema !== "object" || Array.isArray(schema)) {
    throw schemaError(`non_object_schema:${path}`);
  }
  for (const key of Object.keys(schema)) {
    if (!SUPPORTED_KEYWORDS.has(key)) throw schemaError(`${key}:${path}`);
  }
  if (schema.format !== undefined && !SUPPORTED_FORMATS.has(schema.format)) {
    throw schemaError(`format_unsupported:${schema.format}:${path}`);
  }
  // Load-time unknown-field policy: a property-bearing object schema must
  // decide, explicitly, whether unknown fields are allowed. A missing
  // additionalProperties there is a load-time error, not a silent "allow".
  if (requiresAdditionalPropertiesPolicy(schema)
      && !("additionalProperties" in schema)) {
    throw schemaError(`missing_additional_properties_policy:${path}`);
  }
  for (const key of ["properties", "$defs"]) {
    if (schema[key] !== undefined) {
      for (const [name, child] of Object.entries(schema[key])) {
        assertSupportedSchema(child, `${path}/${key}/${name}`);
      }
    }
  }
  for (const key of ["items", "propertyNames"]) {
    if (schema[key] !== undefined) assertSupportedSchema(schema[key], `${path}/${key}`);
  }
  if (typeof schema.additionalProperties === "object"
      && schema.additionalProperties !== null) {
    assertSupportedSchema(schema.additionalProperties, `${path}/additionalProperties`);
  }
  for (const key of ["oneOf", "prefixItems"]) {
    if (schema[key] !== undefined) {
      if (!Array.isArray(schema[key])) throw schemaError(`${key}_not_array:${path}`);
      schema[key].forEach((child, index) => {
        assertSupportedSchema(child, `${path}/${key}/${index}`);
      });
    }
  }
}

function typeOf(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "number") {
    return Number.isInteger(value) ? "integer" : "number";
  }
  return typeof value;
}

function typeMatches(expected, value) {
  const actual = typeOf(value);
  if (expected === "number") return actual === "number" || actual === "integer";
  return expected === actual;
}

function resolveRef(ref, rootSchema) {
  if (typeof ref !== "string" || !ref.startsWith("#/$defs/")) {
    throw schemaError(`external_or_invalid_ref:${ref}`);
  }
  const name = ref.slice("#/$defs/".length);
  const target = rootSchema.$defs?.[name];
  if (target === undefined) throw schemaError(`unresolved_ref:${ref}`);
  return target;
}

function validateNode(schema, value, rootSchema, path, errors, depth) {
  if (depth > 64) {
    errors.push({ path, rule: "validation_depth_exceeded" });
    return;
  }
  if (schema === true) return;
  if (schema === false) {
    errors.push({ path, rule: "schema_false" });
    return;
  }
  if (schema.$ref !== undefined) {
    validateNode(resolveRef(schema.$ref, rootSchema), value, rootSchema, path,
      errors, depth + 1);
    return;
  }
  if (schema.oneOf !== undefined) {
    let matches = 0;
    for (const option of schema.oneOf) {
      const optionErrors = [];
      validateNode(option, value, rootSchema, path, optionErrors, depth + 1);
      if (optionErrors.length === 0) matches += 1;
    }
    if (matches !== 1) {
      errors.push({ path, rule: `one_of_matched_${matches}` });
      return;
    }
  }
  if (schema.type !== undefined && !typeMatches(schema.type, value)) {
    errors.push({ path, rule: `type_${schema.type}` });
    return;
  }
  if (schema.const !== undefined && value !== schema.const) {
    errors.push({ path, rule: "const_mismatch" });
    return;
  }
  if (schema.enum !== undefined && !schema.enum.includes(value)) {
    errors.push({ path, rule: "enum_mismatch" });
    return;
  }
  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errors.push({ path, rule: "min_length" });
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      errors.push({ path, rule: "max_length" });
    }
    if (schema.pattern !== undefined && !new RegExp(schema.pattern).test(value)) {
      errors.push({ path, rule: "pattern" });
    }
    if (schema.format === "date-time-utc" && !isCalendarUtcTimestamp(value)) {
      errors.push({ path, rule: "format_date_time_utc" });
    }
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      errors.push({ path, rule: "non_finite_number" });
      return;
    }
    if (schema.minimum !== undefined && value < schema.minimum) {
      errors.push({ path, rule: "minimum" });
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      errors.push({ path, rule: "maximum" });
    }
    if (schema.exclusiveMinimum !== undefined && value <= schema.exclusiveMinimum) {
      errors.push({ path, rule: "exclusive_minimum" });
    }
    if (schema.exclusiveMaximum !== undefined && value >= schema.exclusiveMaximum) {
      errors.push({ path, rule: "exclusive_maximum" });
    }
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      errors.push({ path, rule: "min_items" });
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      errors.push({ path, rule: "max_items" });
    }
    if (schema.uniqueItems === true) {
      const seen = new Set(value.map((entry) => JSON.stringify(entry)));
      if (seen.size !== value.length) errors.push({ path, rule: "unique_items" });
    }
    if (schema.prefixItems !== undefined) {
      schema.prefixItems.forEach((child, index) => {
        if (index < value.length) {
          validateNode(child, value[index], rootSchema, `${path}/${index}`,
            errors, depth + 1);
        }
      });
    }
    if (schema.items !== undefined) {
      const start = schema.prefixItems?.length ?? 0;
      for (let index = start; index < value.length; index += 1) {
        validateNode(schema.items, value[index], rootSchema, `${path}/${index}`,
          errors, depth + 1);
      }
    }
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const properties = schema.properties ?? {};
    if (Array.isArray(schema.required)) {
      for (const name of schema.required) {
        if (!Object.prototype.hasOwnProperty.call(value, name)) {
          errors.push({ path: `${path}/${name}`, rule: "required" });
        }
      }
    }
    for (const [name, entry] of Object.entries(value)) {
      if (schema.propertyNames !== undefined) {
        validateNode(schema.propertyNames, name, rootSchema,
          `${path}/${name}`, errors, depth + 1);
      }
      if (Object.prototype.hasOwnProperty.call(properties, name)) {
        validateNode(properties[name], entry, rootSchema, `${path}/${name}`,
          errors, depth + 1);
      } else if (schema.additionalProperties === false) {
        errors.push({ path: `${path}/${name}`, rule: "additional_property" });
      } else if (typeof schema.additionalProperties === "object"
          && schema.additionalProperties !== null) {
        validateNode(schema.additionalProperties, entry, rootSchema,
          `${path}/${name}`, errors, depth + 1);
      } else if (schema.additionalProperties === undefined
          && schema.properties !== undefined) {
        // Contract-inventory policy: an object schema that declares
        // properties but no additionalProperties keyword is a load-time
        // error, so unknown-field acceptance is always explicit.
        errors.push({ path: `${path}/${name}`, rule: "unknown_field_policy_missing" });
      }
    }
  }
}

/**
 * Validate a value against a supported schema. Returns
 * `{ok: true}` or `{ok: false, errors: [...]}` with deterministic error
 * paths; never mutates or coerces the value.
 */
export function validateAgainstSchema(schema, value) {
  assertSupportedSchema(schema);
  const errors = [];
  validateNode(schema, value, schema, "#", errors, 0);
  errors.sort((left, right) => (
    `${left.path}|${left.rule}` < `${right.path}|${right.rule}` ? -1 : 1
  ));
  return errors.length === 0
    ? Object.freeze({ ok: true })
    : Object.freeze({ ok: false, errors: Object.freeze(errors.slice(0, 32)) });
}

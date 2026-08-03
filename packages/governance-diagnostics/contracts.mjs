// Versioned diagnostic contract inventory.
//
// One authoritative mapping from every v0.6 diagnostic envelope schema ID to
// its schema file under `contracts/diagnostics/`. The CLI, exported
// validators, producers, and consumers all validate through this module, so
// the schema files are enforced contracts, not decoration. The inventory is
// isolated from the sealed v0.5 top-level `contracts/` inventory: it does
// not alter or pretend to replace it, and its integration into a release
// inventory is a later, separately reviewed step.
//
// Mapping-state note: mapping lifecycle state is not a separate artifact; it
// is the `mapping_status` field of the capability candidate (values
// DISCOVERED, PROPOSED, APPROVED_DOCUMENTATION_ONLY — no runtime-active or
// enforcement-eligible value exists).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { assertSupportedSchema, validateAgainstSchema } from "./schema-validate.mjs";

export const DIAGNOSTIC_CONTRACT_INVENTORY_VERSION = "1";
const SCHEMA_DIRECTORY = fileURLToPath(new URL("../../contracts/diagnostics/", import.meta.url));

export const DIAGNOSTIC_CONTRACT_INVENTORY = Object.freeze({
  "mcpherson-governance-capability-snapshot/v1":
    "mcpherson-governance-capability-snapshot-v1.schema.json",
  "mcpherson-governance-capability-candidate/v1":
    "mcpherson-governance-capability-candidate-v1.schema.json",
  "mcpherson-governance-capability-candidate-set/v1":
    "mcpherson-governance-capability-candidate-set-v1.schema.json",
  "mcpherson-governance-code-owned-tool-registry/v1":
    "mcpherson-governance-code-owned-tool-registry-v1.schema.json",
  "mcpherson-governance-advisory-classification-suggestion/v1":
    "mcpherson-governance-advisory-classification-suggestion-v1.schema.json",
  "mcpherson-governance-human-classification-confirmation/v1":
    "mcpherson-governance-human-classification-confirmation-v1.schema.json",
  "mcpherson-governance-live-classification-confirmation/v1":
    "mcpherson-governance-live-classification-confirmation-v1.schema.json",
  "mcpherson-governance-mapping-approval/v1":
    "mcpherson-governance-mapping-approval-v1.schema.json",
  "mcpherson-governance-registry-ready-shadow-mapping/v1":
    "mcpherson-governance-registry-ready-shadow-mapping-v1.schema.json",
  "mcpherson-governance-shadow-mapping-registry/v1":
    "mcpherson-governance-shadow-mapping-registry-v1.schema.json",
  "mcpherson-governance-shadow-registry-patch/v1":
    "mcpherson-governance-shadow-registry-patch-v1.schema.json",
  "mcpherson-governance-schema-drift-event/v1":
    "mcpherson-governance-schema-drift-event-v1.schema.json",
  "mcpherson-governance-schema-drift-event-set/v1":
    "mcpherson-governance-schema-drift-event-set-v1.schema.json",
  "mcpherson-governance-governability-evidence/v1":
    "mcpherson-governance-governability-evidence-v1.schema.json",
  "mcpherson-governance-governability-result/v1":
    "mcpherson-governance-governability-result-v1.schema.json",
  "mcpherson-governance-governability-finding-set/v1":
    "mcpherson-governance-governability-finding-set-v1.schema.json",
  "mcpherson-governance-governability-diagnosis/v1":
    "mcpherson-governance-governability-diagnosis-v1.schema.json",
  "mcpherson-governance-latency-event/v1":
    "mcpherson-governance-latency-event-v1.schema.json",
  "mcpherson-governance-latency-event-set/v1":
    "mcpherson-governance-latency-event-set-v1.schema.json",
  "mcpherson-governance-latency-summary/v1":
    "mcpherson-governance-latency-summary-v1.schema.json",
  "mcpherson-governance-shadow-receipt-summary/v1":
    "mcpherson-governance-shadow-receipt-summary-v1.schema.json",
  "mcpherson-governance-shadow-coverage-report/v1":
    "mcpherson-governance-shadow-coverage-report-v1.schema.json",
  "mcpherson-governance-live-capability-snapshot/v1":
    "mcpherson-governance-live-capability-snapshot-v1.schema.json",
  "mcpherson-governance-live-shadow-receipt-summary/v1":
    "mcpherson-governance-live-shadow-receipt-summary-v1.schema.json",
  "mcpherson-governance-live-latency-event/v1":
    "mcpherson-governance-live-latency-event-v1.schema.json",
  "mcpherson-governance-live-latency-event-set/v1":
    "mcpherson-governance-live-latency-event-set-v1.schema.json",
  "mcpherson-governance-live-observation-manifest/v1":
    "mcpherson-governance-live-observation-manifest-v1.schema.json",
  "mcpherson-governance-live-shadow-coverage-report/v1":
    "mcpherson-governance-live-shadow-coverage-report-v1.schema.json",
  "mcpherson-governance-live-latency-summary/v1":
    "mcpherson-governance-live-latency-summary-v1.schema.json",
});

const cache = new Map();

export function loadDiagnosticSchema(schemaId) {
  const file = DIAGNOSTIC_CONTRACT_INVENTORY[schemaId];
  if (file === undefined) {
    throw new TypeError(`diagnostic_schema_unknown:${schemaId}`);
  }
  if (!cache.has(schemaId)) {
    const parsed = JSON.parse(readFileSync(`${SCHEMA_DIRECTORY}${file}`, "utf8"));
    assertSupportedSchema(parsed);
    cache.set(schemaId, parsed);
  }
  return cache.get(schemaId);
}

/**
 * Validate an artifact against its declared contract. The artifact's own
 * `schema` field must equal the requested schema ID. Malformed artifacts are
 * rejected, never coerced.
 */
export function validateArtifact(schemaId, value) {
  const schema = loadDiagnosticSchema(schemaId);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return Object.freeze({
      ok: false,
      errors: Object.freeze([{ path: "#", rule: "artifact_not_object" }]),
    });
  }
  if (value.schema !== schemaId) {
    return Object.freeze({
      ok: false,
      errors: Object.freeze([{ path: "#/schema", rule: "schema_id_mismatch" }]),
    });
  }
  return validateAgainstSchema(schema, value);
}

// Envelope schema ID -> { arrayField, memberSchema, countField? }.
// Every envelope's members are additionally validated against their member
// schema (contract composition), so an envelope never legitimizes a
// malformed member and a count field can never disagree with the array.
export const ENVELOPE_COMPOSITIONS = Object.freeze({
  "mcpherson-governance-capability-candidate-set/v1": {
    arrayField: "candidates",
    memberSchema: "mcpherson-governance-capability-candidate/v1",
    countField: "candidate_count",
  },
  "mcpherson-governance-schema-drift-event-set/v1": {
    arrayField: "drift_events",
    memberSchema: "mcpherson-governance-schema-drift-event/v1",
    countField: "drift_count",
  },
  "mcpherson-governance-governability-finding-set/v1": {
    arrayField: "findings",
    memberSchema: "mcpherson-governance-governability-result/v1",
    countField: "finding_count",
  },
  "mcpherson-governance-latency-event-set/v1": {
    arrayField: "events",
    memberSchema: "mcpherson-governance-latency-event/v1",
    countField: null,
  },
  "mcpherson-governance-live-latency-event-set/v1": {
    arrayField: "events",
    memberSchema: "mcpherson-governance-live-latency-event/v1",
    countField: null,
  },
});

/**
 * Validate an envelope AND every member against its member schema (contract
 * composition), plus count-field agreement. Returns `{ok:true}` or
 * `{ok:false, errors}`.
 */
export function validateEnvelope(schemaId, value) {
  const envelope = validateArtifact(schemaId, value);
  if (!envelope.ok) return envelope;
  const composition = ENVELOPE_COMPOSITIONS[schemaId];
  if (!composition) return envelope;
  const members = value[composition.arrayField];
  if (!Array.isArray(members)) {
    return Object.freeze({
      ok: false,
      errors: Object.freeze([{ path: `#/${composition.arrayField}`, rule: "not_array" }]),
    });
  }
  if (composition.countField
      && value[composition.countField] !== members.length) {
    return Object.freeze({
      ok: false,
      errors: Object.freeze([
        { path: `#/${composition.countField}`, rule: "count_mismatch" },
      ]),
    });
  }
  const errors = [];
  members.forEach((member, index) => {
    const memberResult = validateArtifact(composition.memberSchema, member);
    if (!memberResult.ok) {
      errors.push({
        path: `#/${composition.arrayField}/${index}`,
        rule: `member_invalid:${memberResult.errors[0]?.rule ?? "unknown"}`,
      });
    }
  });
  return errors.length === 0
    ? Object.freeze({ ok: true })
    : Object.freeze({ ok: false, errors: Object.freeze(errors.slice(0, 32)) });
}

/**
 * Producer guard: validate an artifact (with envelope composition when
 * applicable) and throw a deterministic error if it is invalid. Producers
 * call this before returning or writing any artifact, so an invalid artifact
 * can never leave a producer or be written to disk.
 */
export function assertValidArtifact(schemaId, value) {
  const result = ENVELOPE_COMPOSITIONS[schemaId]
    ? validateEnvelope(schemaId, value)
    : validateArtifact(schemaId, value);
  if (!result.ok) {
    const error = new TypeError(`diagnostic_output_contract_invalid:${schemaId}`);
    error.code = `diagnostic_output_contract_invalid:${schemaId}`;
    error.contractErrors = result.errors;
    throw error;
  }
  return value;
}

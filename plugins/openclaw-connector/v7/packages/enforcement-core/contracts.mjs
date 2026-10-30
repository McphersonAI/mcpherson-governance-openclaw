// Versioned v0.7 enforcement contract inventory.
//
// One authoritative mapping from every enforcement schema ID to its schema
// file under `contracts/enforcement/`. Producers, consumers, and the CLI all
// validate through this module, so the schema files are enforced contracts.
// The inventory is ISOLATED from the sealed v0.5 top-level `contracts/`
// inventory and the v0.6 `contracts/diagnostics/` inventory: it neither alters
// nor replaces them.
//
// The strict, dependency-free JSON Schema validator is REUSED by import from
// the frozen v0.6 diagnostics package (schema-validate.mjs); it is not
// reimplemented. That validator does not support `allOf`, so the closed-schema
// strategy (requirement 3) is structurally enforced: any schema attempting
// `allOf` composition is a load-time error.
//
// Every schema module is statically imported, validated, and deeply frozen
// during module initialization. Validation never reads a schema file lazily:
// the evaluator, approval verifier, envelope/bundle validators, and decision
// producer use only these immutable in-memory definitions. Removing or changing
// repository schema files after initialization cannot affect an evaluation.

import {
  assertSupportedSchema,
  validateAgainstSchema,
} from "../governance-diagnostics/schema-validate.mjs";
import agentRegistrationSchema
  from "../../contracts/enforcement/mcpherson-governance-enforcement-agent-registration-v1.schema.json"
  with { type: "json" };
import approvalSchema
  from "../../contracts/enforcement/mcpherson-governance-enforcement-approval-v1.schema.json"
  with { type: "json" };
import auditExportSchema
  from "../../contracts/enforcement/mcpherson-governance-enforcement-audit-export-v1.schema.json"
  with { type: "json" };
import comparisonReportSchema
  from "../../contracts/enforcement/mcpherson-governance-enforcement-comparison-report-v1.schema.json"
  with { type: "json" };
import counterexampleSchema
  from "../../contracts/enforcement/mcpherson-governance-enforcement-counterexample-v1.schema.json"
  with { type: "json" };
import coverageReportSchema
  from "../../contracts/enforcement/mcpherson-governance-enforcement-coverage-report-v1.schema.json"
  with { type: "json" };
import decisionLogSegmentSchema
  from "../../contracts/enforcement/mcpherson-governance-enforcement-decision-log-segment-v1.schema.json"
  with { type: "json" };
import decisionSchema
  from "../../contracts/enforcement/mcpherson-governance-enforcement-decision-v1.schema.json"
  with { type: "json" };
import envelopeSchema
  from "../../contracts/enforcement/mcpherson-governance-enforcement-envelope-v1.schema.json"
  with { type: "json" };
import evaluationContextSchema
  from "../../contracts/enforcement/mcpherson-governance-enforcement-evaluation-context-v1.schema.json"
  with { type: "json" };
import policyBundleSchema
  from "../../contracts/enforcement/mcpherson-governance-enforcement-policy-bundle-v1.schema.json"
  with { type: "json" };
import policyTestFixtureSchema
  from "../../contracts/enforcement/mcpherson-governance-enforcement-policy-test-fixture-v1.schema.json"
  with { type: "json" };
import replayStreamSchema
  from "../../contracts/enforcement/mcpherson-governance-enforcement-replay-stream-v1.schema.json"
  with { type: "json" };
import tenantSchema
  from "../../contracts/enforcement/mcpherson-governance-enforcement-tenant-v1.schema.json"
  with { type: "json" };
import workspaceSchema
  from "../../contracts/enforcement/mcpherson-governance-enforcement-workspace-v1.schema.json"
  with { type: "json" };

export const ENFORCEMENT_CONTRACT_INVENTORY_VERSION = "1";

export const ENFORCEMENT_CONTRACT_INVENTORY = Object.freeze({
  "mcpherson-governance-enforcement-envelope/v1":
    "mcpherson-governance-enforcement-envelope-v1.schema.json",
  "mcpherson-governance-enforcement-policy-bundle/v1":
    "mcpherson-governance-enforcement-policy-bundle-v1.schema.json",
  "mcpherson-governance-enforcement-approval/v1":
    "mcpherson-governance-enforcement-approval-v1.schema.json",
  "mcpherson-governance-enforcement-evaluation-context/v1":
    "mcpherson-governance-enforcement-evaluation-context-v1.schema.json",
  "mcpherson-governance-enforcement-decision/v1":
    "mcpherson-governance-enforcement-decision-v1.schema.json",
  "mcpherson-governance-enforcement-decision-log-segment/v1":
    "mcpherson-governance-enforcement-decision-log-segment-v1.schema.json",
  "mcpherson-governance-enforcement-audit-export/v1":
    "mcpherson-governance-enforcement-audit-export-v1.schema.json",
  "mcpherson-governance-enforcement-tenant/v1":
    "mcpherson-governance-enforcement-tenant-v1.schema.json",
  "mcpherson-governance-enforcement-workspace/v1":
    "mcpherson-governance-enforcement-workspace-v1.schema.json",
  "mcpherson-governance-enforcement-agent-registration/v1":
    "mcpherson-governance-enforcement-agent-registration-v1.schema.json",
  "mcpherson-governance-enforcement-replay-stream/v1":
    "mcpherson-governance-enforcement-replay-stream-v1.schema.json",
  "mcpherson-governance-enforcement-comparison-report/v1":
    "mcpherson-governance-enforcement-comparison-report-v1.schema.json",
  "mcpherson-governance-enforcement-coverage-report/v1":
    "mcpherson-governance-enforcement-coverage-report-v1.schema.json",
  "mcpherson-governance-enforcement-policy-test-fixture/v1":
    "mcpherson-governance-enforcement-policy-test-fixture-v1.schema.json",
  "mcpherson-governance-enforcement-counterexample/v1":
    "mcpherson-governance-enforcement-counterexample-v1.schema.json",
});

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

const ENFORCEMENT_SCHEMA_DEFINITIONS = Object.freeze({
  "mcpherson-governance-enforcement-envelope/v1": deepFreeze(envelopeSchema),
  "mcpherson-governance-enforcement-policy-bundle/v1": deepFreeze(policyBundleSchema),
  "mcpherson-governance-enforcement-approval/v1": deepFreeze(approvalSchema),
  "mcpherson-governance-enforcement-evaluation-context/v1":
    deepFreeze(evaluationContextSchema),
  "mcpherson-governance-enforcement-decision/v1": deepFreeze(decisionSchema),
  "mcpherson-governance-enforcement-decision-log-segment/v1":
    deepFreeze(decisionLogSegmentSchema),
  "mcpherson-governance-enforcement-audit-export/v1": deepFreeze(auditExportSchema),
  "mcpherson-governance-enforcement-tenant/v1": deepFreeze(tenantSchema),
  "mcpherson-governance-enforcement-workspace/v1": deepFreeze(workspaceSchema),
  "mcpherson-governance-enforcement-agent-registration/v1":
    deepFreeze(agentRegistrationSchema),
  "mcpherson-governance-enforcement-replay-stream/v1": deepFreeze(replayStreamSchema),
  "mcpherson-governance-enforcement-comparison-report/v1":
    deepFreeze(comparisonReportSchema),
  "mcpherson-governance-enforcement-coverage-report/v1":
    deepFreeze(coverageReportSchema),
  "mcpherson-governance-enforcement-policy-test-fixture/v1":
    deepFreeze(policyTestFixtureSchema),
  "mcpherson-governance-enforcement-counterexample/v1":
    deepFreeze(counterexampleSchema),
});

for (const schemaId of Object.keys(ENFORCEMENT_CONTRACT_INVENTORY)) {
  const schema = ENFORCEMENT_SCHEMA_DEFINITIONS[schemaId];
  if (schema === undefined) {
    throw new TypeError(`enforcement_schema_definition_missing:${schemaId}`);
  }
  assertSupportedSchema(schema);
}

export function loadEnforcementSchema(schemaId) {
  const schema = ENFORCEMENT_SCHEMA_DEFINITIONS[schemaId];
  if (schema === undefined) {
    throw new TypeError(`enforcement_schema_unknown:${schemaId}`);
  }
  return schema;
}

/**
 * Validate an artifact against its declared contract. The artifact's own
 * `schema` field must equal the requested schema ID. Malformed artifacts are
 * rejected, never coerced.
 */
export function validateArtifact(schemaId, value) {
  const schema = loadEnforcementSchema(schemaId);
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

// Envelope schema ID -> { arrayField, memberSchema, countField? }. Every
// envelope's members are additionally validated against their member schema
// (contract composition), so an envelope never legitimizes a malformed member
// and a count field can never disagree with the array.
export const ENVELOPE_COMPOSITIONS = Object.freeze({
  "mcpherson-governance-enforcement-decision-log-segment/v1": {
    arrayField: "records",
    memberSchema: "mcpherson-governance-enforcement-decision/v1",
    countField: "count",
  },
  "mcpherson-governance-enforcement-audit-export/v1": {
    arrayField: "segments",
    memberSchema: "mcpherson-governance-enforcement-decision-log-segment/v1",
    countField: "segment_count",
  },
  "mcpherson-governance-enforcement-replay-stream/v1": {
    arrayField: "envelopes",
    memberSchema: "mcpherson-governance-enforcement-envelope/v1",
    countField: "record_count",
  },
});

/**
 * Validate an envelope AND every member against its member schema, plus
 * count-field agreement. Returns `{ok:true}` or `{ok:false, errors}`.
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
    const memberResult = ENVELOPE_COMPOSITIONS[composition.memberSchema]
      ? validateEnvelope(composition.memberSchema, member)
      : validateArtifact(composition.memberSchema, member);
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
 * applicable) and throw a deterministic error if it is invalid. Producers call
 * this before returning or writing any artifact, so an invalid artifact can
 * never leave a producer.
 */
export function assertValidArtifact(schemaId, value) {
  const result = ENVELOPE_COMPOSITIONS[schemaId]
    ? validateEnvelope(schemaId, value)
    : validateArtifact(schemaId, value);
  if (!result.ok) {
    const error = new TypeError(`enforcement_output_contract_invalid:${schemaId}`);
    error.code = `enforcement_output_contract_invalid:${schemaId}`;
    error.contractErrors = result.errors;
    throw error;
  }
  return value;
}

export { assertSupportedSchema, validateAgainstSchema };

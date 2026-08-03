// Governability Diagnosis renderer.
//
// The output is a diagnosis, not a grade. There is no aggregate governance
// score, and connector-level findings, capability-level findings, platform
// gaps, runtime-integration gaps, policy-configuration gaps, and
// missing-evidence gaps are reported separately, never collapsed.
//
// Sol repairs: the finding set is contract-validated before rendering; the
// "what McPherson Governance can presently do" statement is derived from a
// separately supplied shadow coverage report instead of being hardcoded
// (with an honest unknown when no coverage evidence covers the unit);
// contradictions and evidence references are preserved in the rendered
// markdown; and multi-owner gaps list every actual owner.

import {
  CRITERION_VALUES, RESULT_VALUES, validateFindingSet,
} from "./diagnose-evidence.mjs";
import { validateArtifact, assertValidArtifact } from "../contracts.mjs";
import { validateCoverageReport } from "../coverage.mjs";

export const DIAGNOSIS_SCHEMA = "mcpherson-governance-governability-diagnosis/v1";
export const DIAGNOSIS_FRAMING =
  "Here is what the current setup exposes, including capabilities that cannot "
  + "yet be reliably inventoried, attributed, scoped, or revoked.";
export const NO_SCORE_STATEMENT =
  "This diagnosis is not a grade. No aggregate governance score exists, and "
  + "none should be derived from these counts.";
export const CANNOT_DO_STATEMENT =
  "McPherson Governance cannot presently enforce, block, approve, revoke, or "
  + "constrain this unit, cannot see operations outside its hook boundary, "
  + "and cannot verify claims for which evidence was not supplied.";
export const NO_COVERAGE_STATEMENT =
  "No coverage evidence was supplied for this unit; McPherson observation "
  + "status is unknown and no observation claim is made.";
export const EVIDENCE_COMPLETENESS_NOTE =
  "UNKNOWN findings mean evidence was insufficient, not that the control "
  + "failed; FAIL findings mean evidence demonstrated a broken or absent "
  + "control. The two are never interchangeable.";

function countBy(findings, key) {
  const counts = Object.fromEntries(RESULT_VALUES.map((result) => [result, 0]));
  for (const finding of findings) {
    counts[finding[key]] = (counts[finding[key]] ?? 0) + 1;
  }
  return counts;
}

function invalidDiagnosis(reason, detail = null) {
  return Object.freeze({
    ok: false,
    reason,
    ...(detail === null ? {} : { detail }),
  });
}

/**
 * Consumer-side semantic validation for a diagnosis. The contract enforces
 * shape; these checks require the exact evidence document, reconstruct and
 * rederive the bound finding set, and bind section counts and nested finding
 * identities so a hand-forged but shape-valid diagnosis cannot be accepted.
 */
export function validateDiagnosisDocument(
  diagnosis, { evidenceDocument, coverageReport = null } = {},
) {
  const contract = validateArtifact(DIAGNOSIS_SCHEMA, diagnosis);
  if (!contract.ok) {
    return invalidDiagnosis("diagnosis_contract_invalid", contract.errors);
  }
  if (evidenceDocument === undefined || evidenceDocument === null) {
    return invalidDiagnosis("diagnosis_evidence_required");
  }
  if (diagnosis.framing !== DIAGNOSIS_FRAMING
      || diagnosis.no_aggregate_score !== NO_SCORE_STATEMENT
      || diagnosis.evidence_completeness_note !== EVIDENCE_COMPLETENESS_NOTE) {
    return invalidDiagnosis("diagnosis_fixed_statement_mismatch");
  }
  if (diagnosis.coverage_evidence_supplied
      !== (diagnosis.coverage_evidence_kind === "FIXTURE"
        || diagnosis.coverage_evidence_kind === "LIVE_SHADOW")
      || diagnosis.coverage_evidence_supplied !== (coverageReport !== null)) {
    return invalidDiagnosis("diagnosis_coverage_state_inconsistent");
  }
  if (coverageReport !== null) {
    const coverage = validateCoverageReport(coverageReport);
    if (!coverage.ok
        || !["FIXTURE", "LIVE_SHADOW"].includes(
          coverageReport.measurement_kind,
        )) {
      return invalidDiagnosis("diagnosis_coverage_report_invalid", coverage);
    }
  }
  const sectionTypes = new Set();
  const allFindings = [];
  const expectedSectionOrder = ["connector", "capability"];
  for (const [sectionIndex, section] of diagnosis.sections.entries()) {
    if (section.unit_type !== expectedSectionOrder[sectionIndex]) {
      return invalidDiagnosis("diagnosis_section_order_invalid");
    }
    if (sectionTypes.has(section.unit_type)) {
      return invalidDiagnosis("diagnosis_duplicate_section_type");
    }
    sectionTypes.add(section.unit_type);
    if (section.unit_count !== section.units.length) {
      return invalidDiagnosis("diagnosis_unit_count_mismatch");
    }
    const findings = [];
    const unitIds = new Set();
    for (const unit of section.units) {
      if (unitIds.has(unit.unit_id)) {
        return invalidDiagnosis("diagnosis_duplicate_unit");
      }
      unitIds.add(unit.unit_id);
      const criteria = new Set();
      for (const finding of unit.findings) {
        const member = validateArtifact(
          "mcpherson-governance-governability-result/v1", finding,
        );
        if (!member.ok) {
          return invalidDiagnosis("diagnosis_finding_invalid", member.errors);
        }
        if (finding.evaluated_unit_type !== section.unit_type
            || finding.evaluated_unit_id !== unit.unit_id
            || criteria.has(finding.criterion)) {
          return invalidDiagnosis("diagnosis_finding_identity_inconsistent");
        }
        criteria.add(finding.criterion);
        findings.push(finding);
        allFindings.push(finding);
      }
      if (criteria.size !== CRITERION_VALUES.length
          || CRITERION_VALUES.some((criterion) => !criteria.has(criterion))) {
        return invalidDiagnosis("diagnosis_unit_criteria_incomplete");
      }
      const expectedAttention = unit.findings.filter(
        (finding) => finding.result !== "PASS",
      );
      if (unit.attention.length !== expectedAttention.length
          || unit.attention.some((attention, index) => {
            const finding = expectedAttention[index];
            const expected = {
              criterion: finding.criterion,
              result: finding.result,
              what_was_observed: finding.observed_fields.length > 0
                ? `observed evidence: ${finding.observed_fields.join(", ")}`
                : "no usable evidence was observed",
              what_could_not_be_verified: finding.missing_fields.length > 0
                ? `unverified: ${finding.missing_fields.join(", ")}`
                : "all required fields were supplied but the evidence is not consistent",
              why_the_gap_matters: finding.gap_impact,
              likely_gap_owners: finding.gap_owners,
              smallest_reasonable_remediation: finding.remediation_suggestion,
              what_mcpherson_can_do:
                coverageStatementFor(
                  section.unit_type, unit.unit_id, coverageReport,
                ),
              what_mcpherson_cannot_do: CANNOT_DO_STATEMENT,
            };
            return JSON.stringify(attention) !== JSON.stringify(expected);
          })) {
        return invalidDiagnosis("diagnosis_attention_inconsistent");
      }
    }
    for (const result of RESULT_VALUES) {
      const actual = findings.filter((finding) => finding.result === result).length;
      if ((section.result_counts[result] ?? 0) !== actual) {
        return invalidDiagnosis("diagnosis_result_count_mismatch");
      }
    }
  }
  if (!sectionTypes.has("connector") || !sectionTypes.has("capability")) {
    return invalidDiagnosis("diagnosis_sections_incomplete");
  }
  const canonicalFindings = [...allFindings].sort((left, right) => {
    const leftUnit = `${left.evaluated_unit_type}|${left.evaluated_unit_id}`;
    const rightUnit = `${right.evaluated_unit_type}|${right.evaluated_unit_id}`;
    if (leftUnit !== rightUnit) return leftUnit < rightUnit ? -1 : 1;
    return CRITERION_VALUES.indexOf(left.criterion)
      - CRITERION_VALUES.indexOf(right.criterion);
  });
  const findingSet = {
    schema: "mcpherson-governance-governability-finding-set/v1",
    finding_set_id: diagnosis.finding_set_id,
    finding_set_version: diagnosis.finding_set_version,
    evidence_set_id: diagnosis.evidence_set_id,
    evidence_document_id: diagnosis.evidence_document_id,
    evidence_document_sha256: diagnosis.evidence_document_sha256,
    evidence_schema: diagnosis.evidence_schema,
    evidence_schema_version: diagnosis.evidence_schema_version,
    diagnosed_units: diagnosis.diagnosed_units,
    evaluator_version: diagnosis.evaluator_version,
    evaluated_timestamp: diagnosis.evaluated_timestamp,
    max_evidence_age_days: diagnosis.max_evidence_age_days,
    finding_count: canonicalFindings.length,
    findings: canonicalFindings,
  };
  const findingValidation = validateFindingSet(
    findingSet, { evidenceDocument },
  );
  if (!findingValidation.ok) {
    return invalidDiagnosis("diagnosis_finding_set_invalid", findingValidation);
  }
  const expectedGaps = {};
  for (const finding of allFindings) {
    if (finding.result === "PASS") continue;
    for (const owner of finding.gap_owners) {
      expectedGaps[owner] = expectedGaps[owner] ?? [];
      expectedGaps[owner].push(
        `${finding.evaluated_unit_type}:${finding.evaluated_unit_id}:${finding.criterion}:${finding.result}`,
      );
    }
  }
  for (const owner of Object.keys(expectedGaps)) {
    expectedGaps[owner] = [...new Set(expectedGaps[owner])].sort();
  }
  const actualGapKeys = Object.keys(diagnosis.gaps_by_owner).sort();
  const expectedGapKeys = Object.keys(expectedGaps).sort();
  if (JSON.stringify(actualGapKeys) !== JSON.stringify(expectedGapKeys)
      || expectedGapKeys.some((owner) => (
        JSON.stringify(diagnosis.gaps_by_owner[owner])
          !== JSON.stringify(expectedGaps[owner])
      ))) {
    return invalidDiagnosis("diagnosis_gap_owner_index_inconsistent");
  }
  return Object.freeze({ ok: true });
}

/**
 * Derive the per-unit McPherson coverage statement from a separately
 * supplied, contract-validated shadow coverage report. Without coverage
 * evidence the statement is an explicit unknown — never an observation
 * claim.
 */
function coverageStatementFor(unitType, unitId, coverageReport) {
  if (coverageReport === null) return NO_COVERAGE_STATEMENT;
  const capability = unitType === "capability"
    ? coverageReport.capabilities.find(
      (entry) => entry.normalized_capability === unitId
        || entry.candidate_id === unitId,
    )
    : null;
  if (capability) {
    const kind = coverageReport.measurement_kind === "FIXTURE"
      ? "fixture-only synthetic coverage evidence"
      : "shadow coverage evidence";
    if (capability.operation_observation === "OBSERVED") {
      return `Per ${kind}, this operation was observed in shadow `
        + `(${capability.attempt_receipts} attempt receipt(s)); this is `
        + "observation, not enforcement.";
    }
    if (capability.tool_observation !== null) {
      return `Per ${kind}, only tool-level receipts exist for its native tool `
        + `(${capability.tool_observation.attempt_receipts} attempt receipt(s)); `
        + "operation-level coverage is unknown.";
    }
    return `Per ${kind}, this capability was not observed in shadow.`;
  }
  const tool = unitType === "connector"
    ? coverageReport.capabilities.find(
      (entry) => entry.native_tool_name === unitId,
    )
    : null;
  if (tool) {
    return coverageReport.measurement_kind === "FIXTURE"
      ? "Fixture-only synthetic coverage evidence exists for this tool's operations; see the coverage report for per-operation status."
      : "Shadow coverage evidence exists for this tool's operations; see the coverage report for per-operation status.";
  }
  return NO_COVERAGE_STATEMENT;
}

/**
 * Build the structured diagnosis document from a finding set composed
 * against its exact evidence document and an optional, contract-validated
 * shadow coverage report.
 */
export function buildDiagnosis(
  findingSet, { evidenceDocument, coverageReport = null } = {},
) {
  const findingValidation = validateFindingSet(
    findingSet, { evidenceDocument },
  );
  if (!findingValidation.ok) {
    const error = new TypeError("finding_set_invalid");
    error.detail = findingValidation;
    throw error;
  }
  if (coverageReport !== null) {
    const coverage = validateCoverageReport(coverageReport);
    if (!coverage.ok) {
      const error = new TypeError("coverage_report_invalid");
      error.detail = coverage;
      throw error;
    }
  }
  const findings = findingSet.findings;
  const unitTypes = ["connector", "capability"];
  const sections = unitTypes.map((unitType) => {
    const scoped = findings.filter(
      (finding) => finding.evaluated_unit_type === unitType,
    );
    const units = [...new Set(scoped.map((finding) => finding.evaluated_unit_id))]
      .sort()
      .map((unitId) => {
        const unitFindings = scoped.filter(
          (finding) => finding.evaluated_unit_id === unitId,
        );
        return Object.freeze({
          unit_id: unitId,
          findings: unitFindings,
          attention: unitFindings.filter((finding) => finding.result !== "PASS")
            .map((finding) => Object.freeze({
              criterion: finding.criterion,
              result: finding.result,
              what_was_observed: finding.observed_fields.length > 0
                ? `observed evidence: ${finding.observed_fields.join(", ")}`
                : "no usable evidence was observed",
              what_could_not_be_verified: finding.missing_fields.length > 0
                ? `unverified: ${finding.missing_fields.join(", ")}`
                : "all required fields were supplied but the evidence is not consistent",
              why_the_gap_matters: finding.gap_impact,
              likely_gap_owners: finding.gap_owners,
              smallest_reasonable_remediation: finding.remediation_suggestion,
              what_mcpherson_can_do:
                coverageStatementFor(unitType, unitId, coverageReport),
              what_mcpherson_cannot_do: CANNOT_DO_STATEMENT,
            })),
        });
      });
    return Object.freeze({
      unit_type: unitType,
      unit_count: units.length,
      result_counts: countBy(scoped, "result"),
      units,
    });
  });
  const gapOwners = {};
  for (const finding of findings) {
    if (finding.result === "PASS") continue;
    for (const owner of finding.gap_owners) {
      gapOwners[owner] = gapOwners[owner] ?? [];
      gapOwners[owner].push(
        `${finding.evaluated_unit_type}:${finding.evaluated_unit_id}:${finding.criterion}:${finding.result}`,
      );
    }
  }
  for (const owner of Object.keys(gapOwners)) {
    gapOwners[owner] = [...new Set(gapOwners[owner])].sort();
  }
  const diagnosis = Object.freeze({
    schema: DIAGNOSIS_SCHEMA,
    finding_set_id: findingSet.finding_set_id,
    finding_set_version: findingSet.finding_set_version,
    evidence_set_id: findingSet.evidence_set_id,
    evidence_document_id: findingSet.evidence_document_id,
    evidence_document_sha256: findingSet.evidence_document_sha256,
    evidence_schema: findingSet.evidence_schema,
    evidence_schema_version: findingSet.evidence_schema_version,
    diagnosed_units: findingSet.diagnosed_units,
    evaluator_version: findingSet.evaluator_version,
    evaluated_timestamp: findingSet.evaluated_timestamp,
    max_evidence_age_days: findingSet.max_evidence_age_days,
    framing: DIAGNOSIS_FRAMING,
    no_aggregate_score: NO_SCORE_STATEMENT,
    coverage_evidence_supplied: coverageReport !== null,
    coverage_evidence_kind: coverageReport === null
      ? null
      : coverageReport.measurement_kind,
    sections,
    gaps_by_owner: gapOwners,
    evidence_completeness_note: EVIDENCE_COMPLETENESS_NOTE,
  });
  // Producer output contract.
  assertValidArtifact(DIAGNOSIS_SCHEMA, diagnosis);
  const semantic = validateDiagnosisDocument(
    diagnosis, { evidenceDocument, coverageReport },
  );
  if (!semantic.ok) {
    const error = new TypeError("diagnosis_output_invalid");
    error.detail = semantic;
    throw error;
  }
  return diagnosis;
}

function renderFindingLine(finding) {
  return `- ${finding.criterion}: **${finding.result}** — ${finding.reason}`;
}

/** Render the diagnosis as markdown for human review. */
export function renderDiagnosisMarkdown(
  diagnosis, { evidenceDocument, coverageReport = null } = {},
) {
  const validation = validateDiagnosisDocument(
    diagnosis, { evidenceDocument, coverageReport },
  );
  if (!validation.ok) {
    throw new TypeError("diagnosis_invalid");
  }
  const lines = [];
  lines.push("# Governability Diagnosis");
  lines.push("");
  lines.push(diagnosis.framing);
  lines.push("");
  lines.push(`Finding set: \`${diagnosis.finding_set_id}\` (version `
    + `\`${diagnosis.finding_set_version}\`) — evaluator `
    + `\`${diagnosis.evaluator_version}\` — evaluated ${diagnosis.evaluated_timestamp}`);
  lines.push("");
  lines.push(`Evidence document: \`${diagnosis.evidence_document_id}\` — schema `
    + `\`${diagnosis.evidence_schema}\` (version `
    + `\`${diagnosis.evidence_schema_version}\`) — canonical SHA-256 `
    + `\`${diagnosis.evidence_document_sha256}\``);
  lines.push("");
  lines.push(`> ${diagnosis.no_aggregate_score}`);
  lines.push("");
  if (!diagnosis.coverage_evidence_supplied) {
    lines.push("Coverage evidence: none supplied. No McPherson observation "
      + "claim is made anywhere in this diagnosis.");
  } else {
    lines.push(`Coverage evidence: ${diagnosis.coverage_evidence_kind === "FIXTURE"
      ? "fixture-only synthetic coverage report (not production observations)"
      : "shadow coverage report"}.`);
  }
  lines.push("");
  for (const section of diagnosis.sections) {
    lines.push(`## ${section.unit_type === "connector"
      ? "Connector-level findings"
      : "Capability-level findings"}`);
    lines.push("");
    const counts = RESULT_VALUES
      .map((result) => `${result} ${section.result_counts[result] ?? 0}`)
      .join(" · ");
    lines.push(`${section.unit_count} unit(s); results by count (not a score): ${counts}`);
    lines.push("");
    for (const unit of section.units) {
      lines.push(`### ${section.unit_type} \`${unit.unit_id}\``);
      lines.push("");
      for (const criterion of CRITERION_VALUES) {
        const finding = unit.findings.find(
          (entry) => entry.criterion === criterion,
        );
        if (finding) lines.push(renderFindingLine(finding));
      }
      lines.push("");
      for (const finding of unit.findings) {
        if (finding.contradictory_evidence.length > 0) {
          lines.push(`Contradictory evidence (${finding.criterion}):`);
          for (const entry of finding.contradictory_evidence) {
            lines.push(`- \`${entry.field}\`: ${entry.note}`
              + (entry.refs.length > 0 ? ` (refs: ${entry.refs.join(", ")})` : ""));
          }
          lines.push("");
        }
        if (finding.evidence_references.length > 0) {
          lines.push(`Evidence references (${finding.criterion}): `
            + finding.evidence_references.map((ref) => `\`${ref}\``).join(", "));
          lines.push("");
        }
      }
      for (const attention of unit.attention) {
        lines.push(`#### ${attention.criterion} is ${attention.result}`);
        lines.push("");
        lines.push(`- What was observed: ${attention.what_was_observed}`);
        lines.push(`- What could not be verified: ${attention.what_could_not_be_verified}`);
        lines.push(`- Why the gap matters: ${attention.why_the_gap_matters}`);
        lines.push(`- Likely gap owner(s): ${attention.likely_gap_owners
          .map((owner) => `\`${owner}\``).join(", ")}`);
        lines.push(`- Smallest reasonable remediation: ${attention.smallest_reasonable_remediation}`);
        lines.push(`- What McPherson Governance can presently do: ${attention.what_mcpherson_can_do}`);
        lines.push(`- What McPherson Governance cannot presently do: ${attention.what_mcpherson_cannot_do}`);
        lines.push("");
      }
    }
  }
  lines.push("## Gaps by likely owner");
  lines.push("");
  lines.push("Platform governability, connector limitations, runtime-integration "
    + "coverage, policy configuration, and evidence completeness are listed "
    + "separately below and must not be collapsed into one another. A finding "
    + "with several owners appears under each of them.");
  lines.push("");
  const owners = Object.keys(diagnosis.gaps_by_owner).sort();
  if (owners.length === 0) {
    lines.push("No gaps were recorded for any owner in this evidence set.");
  }
  for (const owner of owners) {
    lines.push(`- \`${owner}\`:`);
    for (const entry of diagnosis.gaps_by_owner[owner]) {
      lines.push(`  - ${entry}`);
    }
  }
  lines.push("");
  lines.push(`> ${diagnosis.evidence_completeness_note}`);
  lines.push("");
  return lines.join("\n");
}

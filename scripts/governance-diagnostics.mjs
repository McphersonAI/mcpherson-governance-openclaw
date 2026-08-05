#!/usr/bin/env node
// v0.6 diagnostics CLI: AutoMap discovery/proposal, classification
// confirmation, documentation-only approval, schema-drift detection,
// Governability Diagnosis, latency summaries, and shadow coverage.
//
// Every command is read-only against the repository and runtime. Writes are
// restricted to brand-new local diagnostic artifacts; existing files are
// never overwritten. `observe-live` is the one live observation command. It
// pins OpenClaw 2026.6.5, issues only agents.list and tools.catalog
// operator.read calls to the local gateway, and reads the existing connector
// receipt ledger. There is no command that deploys, activates, blocks,
// enforces, revokes, accepts a caller credential, emits a stored credential,
// calls an external service, reads session content, or creates a
// runtime-active/enforcement-eligible mapping.
//
// Boundary discipline (Sol repair): every input file is read with the
// bounded, symlink-refusing, TOCTOU-resistant reader and validated against
// its contract in the diagnostic contract inventory before use. Candidate
// sets are additionally semantically revalidated (identity, hashes, risk,
// preview reconstruction, duplicate exclusion). Malformed artifacts are
// rejected, never coerced.

import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { realpathSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  discoverFromSource,
  proposeMappings,
  buildOutboundMetadataPreview,
  applyConfirmation,
  createDocumentationOnlyApproval,
  validateApprovalRecord,
  buildDriftEventSet,
  evaluateGovernability,
  validateFindingSet,
  buildDiagnosis,
  renderDiagnosisMarkdown,
  summarizeLatency,
  validateLatencyEventSet,
  buildShadowCoverageReport,
  validateCandidateSet,
  validateArtifact,
  validateEnvelope,
  readBoundedArtifact,
  createLiveClassificationConfirmation,
  applyLiveClassificationConfirmation,
  validateLiveClassificationConfirmation,
  LIVE_CONFIRMATION_SCHEMA,
  validateShadowRegistry,
  buildRegistryPatch,
  validateRegistryPatch,
  previewRegistryPatch,
  shadowLookup,
  redactSecretsWithReport,
  scanForSecrets,
} from "../packages/governance-diagnostics/index.mjs";
import {
  LIVE_OUTPUT_FILES,
  initializeOpenClawProfileBinding,
  observeOpenClawLive,
  verifyOpenClawProfileBinding,
  verifyOpenClawLiveObservationDirectory,
} from "../packages/openclaw-live-observer/index.mjs";

export const DIAGNOSTICS_COMMANDS = Object.freeze([
  "discover", "propose", "preview", "confirm-classification",
  "generate-classification-confirmation", "approve-mapping",
  "export-registry-patch", "validate-registry-patch",
  "preview-registry-patch", "shadow-lookup", "verify-observation", "drift",
  "govern", "render-diagnosis", "latency-summarize", "coverage",
  "init-profile-binding", "verify-profile-binding", "observe-live",
]);

function fail(code, detail = null) {
  const error = new Error(code);
  error.code = code;
  if (detail) error.detail = detail;
  throw error;
}

function publicError(error) {
  const code = error && typeof error === "object" && "code" in error
    ? String(error.code)
    : String(error?.message ?? "DIAGNOSTICS_FAILED");
  const normalized = code.toUpperCase().replaceAll(/[^A-Z0-9_]/g, "_").slice(0, 64);
  return Object.freeze({
    ok: false,
    code: /^[A-Z][A-Z0-9_]{0,63}$/.test(normalized) ? normalized : "DIAGNOSTICS_FAILED",
  });
}

function required(values, name) {
  const value = values[name];
  if (typeof value !== "string" || value.length === 0) {
    fail(`OPTION_REQUIRED_${name.replaceAll("-", "_").toUpperCase()}`);
  }
  return value;
}

function readJsonArgument(path) {
  const read = readBoundedArtifact(path);
  if (!read.ok) fail(`INPUT_${read.reason.toUpperCase()}`);
  return read.value;
}

function readValidatedArtifact(path, schemaId) {
  const value = readJsonArgument(path);
  // validateEnvelope delegates to validateArtifact for non-envelope schemas
  // and additionally composes member contracts/counts for envelope schemas.
  const validation = validateEnvelope(schemaId, value);
  if (!validation.ok) fail("INPUT_CONTRACT_INVALID", validation.errors);
  return value;
}

function readValidatedApproval(path) {
  const value = readValidatedArtifact(
    path, "mcpherson-governance-mapping-approval/v1",
  );
  const semantic = validateApprovalRecord(value);
  if (!semantic.ok) {
    fail("INPUT_APPROVAL_INVALID", semantic);
  }
  return value;
}

function readValidatedLiveConfirmation(path, { requirePostBinding = true } = {}) {
  const value = readValidatedArtifact(path, LIVE_CONFIRMATION_SCHEMA);
  const semantic = validateLiveClassificationConfirmation(value, {
    requirePostBinding,
  });
  if (!semantic.ok) fail("INPUT_LIVE_CONFIRMATION_INVALID", semantic);
  return value;
}

function readValidatedShadowRegistry(path) {
  const value = readValidatedArtifact(
    path, "mcpherson-governance-shadow-mapping-registry/v1",
  );
  const semantic = validateShadowRegistry(value);
  if (!semantic.ok) fail("INPUT_SHADOW_REGISTRY_INVALID", semantic);
  return value;
}

function verifiedObservation(values) {
  return verifyOpenClawLiveObservationDirectory({
    outDir: required(values, "observation-dir"),
    packageManifestPath: required(values, "package-manifest"),
    profileBindingPath: required(values, "profile-binding"),
    profileBindingId: required(values, "profile-binding-id"),
  });
}

function assertObservationArtifactPath(values, optionName, filename) {
  const observationDir = required(values, "observation-dir");
  const supplied = required(values, optionName);
  let expected;
  let actual;
  try {
    expected = realpathSync(join(observationDir, filename));
    actual = realpathSync(supplied);
  } catch {
    fail("LIVE_OBSERVATION_ARTIFACT_UNREADABLE");
  }
  if (expected !== actual) fail("LIVE_OBSERVATION_ARTIFACT_MISMATCH");
}

function candidateSetArgument(path, stage, options = {}) {
  const value = readValidatedArtifact(
    path, "mcpherson-governance-capability-candidate-set/v1",
  );
  const semantic = validateCandidateSet(value, { stage, ...options });
  if (!semantic.ok) {
    fail(`CANDIDATE_SET_${semantic.reason.toUpperCase().slice(0, 48)}`, semantic);
  }
  return value;
}

function nowArgument(values) {
  const supplied = values.now;
  if (supplied === undefined) {
    return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  }
  return supplied;
}

// Final-output gate for every CLI artifact, whether written to `--out` or
// printed to stdout. Diagnostic artifacts are built from allowlisted metadata
// and so are already clean; redaction here is defence in depth against a
// credential reaching an operator's terminal or evidence directory, and the
// re-scan makes an unneutralisable shape fail closed rather than be emitted.
function redactedOutputText(result) {
  const { value: redacted } = redactSecretsWithReport(result);
  if (scanForSecrets(redacted).length > 0) fail("SECRET_MATERIAL_DETECTED");
  return `${JSON.stringify(redacted, null, 2)}\n`;
}

function emit(result, values) {
  const text = redactedOutputText(result);
  if (typeof values.out === "string" && values.out.length > 0) {
    try {
      // wx: refuse to overwrite anything that already exists.
      writeFileSync(values.out, text, { flag: "wx", mode: 0o600 });
    } catch (error) {
      fail(error?.code === "EEXIST" ? "OUT_FILE_EXISTS" : "OUT_UNWRITABLE");
    }
    return Object.freeze({ ok: true, wrote: values.out });
  }
  return result;
}

function emitArtifact(result, artifact, values) {
  return typeof values.out === "string" && values.out.length > 0
    ? emit(artifact, values)
    : result;
}

function emitText(text, values) {
  // Rendered Markdown is an output boundary too: scrub credential shapes out
  // of the prose while leaving the surrounding report readable.
  const { value: redacted } = redactSecretsWithReport(text);
  try {
    writeFileSync(values.out, `${redacted}\n`, { flag: "wx", mode: 0o600 });
  } catch (error) {
    fail(error?.code === "EEXIST" ? "OUT_FILE_EXISTS" : "OUT_UNWRITABLE");
  }
  return Object.freeze({ ok: true, wrote: values.out });
}

export async function runGovernanceDiagnostics(argv) {
  const command = argv[0] || "help";
  const { values } = parseArgs({
    args: argv.slice(1),
    options: {
      source: { type: "string" },
      method: { type: "string" },
      candidates: { type: "string" },
      previous: { type: "string" },
      current: { type: "string" },
      advisory: { type: "string" },
      artifact: { type: "string" },
      confirmation: { type: "string" },
      approval: { type: "string" },
      registry: { type: "string" },
      patch: { type: "string" },
      candidate: { type: "string" },
      capability: { type: "string" },
      "approved-by": { type: "string" },
      "reviewed-by": { type: "string" },
      effect: { type: "string", multiple: true },
      rationale: { type: "string" },
      evidence: { type: "string" },
      findings: { type: "string" },
      coverage: { type: "string" },
      events: { type: "string" },
      receipts: { type: "string" },
      "package-manifest": { type: "string" },
      "profile-binding": { type: "string" },
      "profile-binding-id": { type: "string" },
      "profile-home": { type: "string" },
      "profile-mode": { type: "string" },
      profile: { type: "string" },
      "out-dir": { type: "string" },
      "observation-dir": { type: "string" },
      start: { type: "string" },
      end: { type: "string" },
      agent: { type: "string", multiple: true },
      format: { type: "string" },
      now: { type: "string" },
      out: { type: "string" },
    },
    strict: true,
  });

  if (command === "help") {
    return Object.freeze({
      ok: true,
      commands: DIAGNOSTICS_COMMANDS,
      note: "all commands are diagnostic and read-only; --out creates one "
        + "new local file and observe-live creates one new private directory",
      observe_live_profiles: Object.freeze({
        DEFAULT: "explicit local binding/id plus --profile-mode DEFAULT",
        NAMED: "explicit local binding/id plus --profile-mode NAMED --profile <validated-name>",
      }),
    });
  }

  if (command === "init-profile-binding") {
    return initializeOpenClawProfileBinding({
      profileMode: required(values, "profile-mode"),
      profile: values.profile,
      profileHome: required(values, "profile-home"),
      profileBindingPath: required(values, "profile-binding"),
      packageManifestPath: required(values, "package-manifest"),
    });
  }

  if (command === "verify-profile-binding") {
    return verifyOpenClawProfileBinding({
      profileMode: required(values, "profile-mode"),
      profile: values.profile,
      profileHome: required(values, "profile-home"),
      profileBindingPath: required(values, "profile-binding"),
      profileBindingId: required(values, "profile-binding-id"),
      packageManifestPath: required(values, "package-manifest"),
    });
  }

  if (command === "observe-live") {
    return observeOpenClawLive({
      profileMode: required(values, "profile-mode"),
      profile: values.profile,
      profileHome: required(values, "profile-home"),
      profileBindingPath: required(values, "profile-binding"),
      profileBindingId: required(values, "profile-binding-id"),
      packageManifestPath: required(values, "package-manifest"),
      receiptPath: required(values, "receipts"),
      outDir: required(values, "out-dir"),
      start: required(values, "start"),
      end: required(values, "end"),
      agentIds: values.agent ?? [],
      now: () => nowArgument(values),
    });
  }

  if (command === "verify-observation") {
    return verifiedObservation(values);
  }

  if (command === "discover") {
    const method = values.method || "sanitized_static_snapshot_v1";
    if (method === "openclaw_live_gateway_v1") {
      verifiedObservation(values);
      assertObservationArtifactPath(
        values, "source", LIVE_OUTPUT_FILES.snapshot,
      );
    }
    const result = discoverFromSource({
      sourcePath: required(values, "source"),
      method,
      now: nowArgument(values),
      observationDirectory: method === "openclaw_live_gateway_v1"
        ? required(values, "observation-dir")
        : undefined,
      packageManifestPath: method === "openclaw_live_gateway_v1"
        ? required(values, "package-manifest")
        : undefined,
      profileBindingPath: method === "openclaw_live_gateway_v1"
        ? required(values, "profile-binding")
        : undefined,
      profileBindingId: method === "openclaw_live_gateway_v1"
        ? required(values, "profile-binding-id")
        : undefined,
    });
    return emit(result, values);
  }

  if (command === "propose") {
    const candidateSet = candidateSetArgument(
      required(values, "candidates"), "discovery",
    );
    const isLive = candidateSet.discovery_method
      === "openclaw_live_gateway_v1";
    if (isLive) verifiedObservation(values);
    const advisoryDocument = values.advisory
      ? readValidatedArtifact(values.advisory,
        "mcpherson-governance-advisory-classification-suggestion/v1")
      : null;
    const result = proposeMappings({
      candidateSet,
      advisoryDocument,
      now: nowArgument(values),
      observationDirectory: isLive
        ? required(values, "observation-dir")
        : null,
      packageManifestPath: isLive
        ? required(values, "package-manifest")
        : null,
      profileBindingPath: isLive
        ? required(values, "profile-binding")
        : null,
      profileBindingId: isLive
        ? required(values, "profile-binding-id")
        : null,
    });
    return emit(result, values);
  }

  if (command === "preview") {
    const candidateSet = candidateSetArgument(
      required(values, "candidates"), "any",
    );
    const selected = values.candidate
      ? candidateSet.candidates.filter(
        (entry) => entry.candidate_id === values.candidate,
      )
      : candidateSet.candidates;
    if (values.candidate && selected.length === 0) fail("CANDIDATE_UNKNOWN");
    const previews = selected.map((candidate) => Object.freeze({
      candidate_id: candidate.candidate_id,
      normalized_capability: candidate.normalized_capability,
      outbound_metadata_preview: candidate.outbound_metadata_preview
        ?? buildOutboundMetadataPreview(candidate),
    }));
    return emit(Object.freeze({ ok: true, previews }), values);
  }

  if (command === "confirm-classification") {
    const candidateSet = candidateSetArgument(
      required(values, "candidates"), "proposal",
    );
    const artifact = readJsonArgument(required(values, "artifact"));
    let result;
    if (artifact?.schema === LIVE_CONFIRMATION_SCHEMA) {
      const contract = validateEnvelope(LIVE_CONFIRMATION_SCHEMA, artifact);
      if (!contract.ok) fail("INPUT_CONTRACT_INVALID", contract.errors);
      const observation = verifiedObservation(values);
      result = applyLiveClassificationConfirmation({
        artifact,
        proposalSet: candidateSet,
        observation,
      });
    } else {
      const contract = validateEnvelope(
        "mcpherson-governance-human-classification-confirmation/v1", artifact,
      );
      if (!contract.ok) fail("INPUT_CONTRACT_INVALID", contract.errors);
      result = applyConfirmation(artifact, candidateSet.candidates);
    }
    if (!result.ok) {
      return Object.freeze({ ok: false, rejected: true, reason: result.reason });
    }
    const response = Object.freeze({
      ok: true,
      confirmation_record: result.confirmation_record,
      updated_candidate: result.updated_candidate,
    });
    return emitArtifact(response, result.confirmation_record, values);
  }

  if (command === "generate-classification-confirmation") {
    const candidateSet = candidateSetArgument(
      required(values, "candidates"), "proposal",
    );
    const observation = verifiedObservation(values);
    const result = createLiveClassificationConfirmation({
      proposalSet: candidateSet,
      candidateId: required(values, "candidate"),
      selectedEffects: values.effect ?? [],
      reviewerIdentity: required(values, "reviewed-by"),
      confirmedAt: nowArgument(values),
      rationale: required(values, "rationale"),
      observation,
    });
    if (!result.ok) {
      return Object.freeze({ ok: false, rejected: true, reason: result.reason });
    }
    return emit(result.confirmation, values);
  }

  if (command === "approve-mapping") {
    const candidateSet = candidateSetArgument(
      required(values, "candidates"), "proposal",
    );
    const candidateIdWanted = required(values, "candidate");
    let candidate = candidateSet.candidates.find(
      (entry) => entry.candidate_id === candidateIdWanted,
    );
    if (!candidate) fail("CANDIDATE_UNKNOWN");
    let confirmationRecord = null;
    if (values.confirmation) {
      const raw = readJsonArgument(values.confirmation);
      if (raw?.schema === LIVE_CONFIRMATION_SCHEMA) {
        const observation = verifiedObservation(values);
        confirmationRecord = readValidatedLiveConfirmation(values.confirmation);
        const request = { ...confirmationRecord };
        delete request.confirmed_candidate_content_hash;
        const applied = applyLiveClassificationConfirmation({
          artifact: request,
          proposalSet: candidateSet,
          observation,
        });
        if (!applied.ok
            || applied.confirmation_record.confirmed_candidate_content_hash
              !== confirmationRecord.confirmed_candidate_content_hash) {
          fail("INPUT_LIVE_CONFIRMATION_BINDING_INVALID");
        }
        candidate = applied.updated_candidate;
      } else {
        confirmationRecord = readValidatedArtifact(
          values.confirmation,
          "mcpherson-governance-human-classification-confirmation/v1",
        );
      }
    }
    const result = createDocumentationOnlyApproval({
      candidate,
      approvedBy: required(values, "approved-by"),
      approvedAt: nowArgument(values),
      rationale: required(values, "rationale"),
      confirmationRecord,
    });
    if (!result.ok) {
      return Object.freeze({ ok: false, rejected: true, reason: result.reason });
    }
    // Output boundary: do not render or write the approval unless the complete
    // semantic validator (including rationale privacy) accepts it.
    const approvalValidation = validateApprovalRecord(result.approval_record);
    if (!approvalValidation.ok) fail("APPROVAL_OUTPUT_INVALID", approvalValidation);
    const response = Object.freeze({
      ok: true,
      approval_record: result.approval_record,
      approved_candidate: result.approved_candidate,
    });
    return emitArtifact(response, result.approval_record, values);
  }

  if ([
    "export-registry-patch",
    "validate-registry-patch",
    "preview-registry-patch",
  ].includes(command)) {
    const candidateSet = candidateSetArgument(
      required(values, "candidates"), "proposal",
    );
    const confirmation = readValidatedLiveConfirmation(
      required(values, "confirmation"),
    );
    const approval = readValidatedApproval(required(values, "approval"));
    const registry = readValidatedShadowRegistry(required(values, "registry"));
    const observation = verifiedObservation(values);
    if (command === "export-registry-patch") {
      const generated = buildRegistryPatch({
        proposalSet: candidateSet,
        candidateId: required(values, "candidate"),
        confirmation,
        approval,
        observation,
        registry,
        now: nowArgument(values),
      });
      if (!generated.ok) {
        return Object.freeze({
          ok: false, rejected: true, reason: generated.reason,
        });
      }
      return emit(generated.patch, values);
    }
    const patch = readValidatedArtifact(
      required(values, "patch"),
      "mcpherson-governance-shadow-registry-patch/v1",
    );
    const validation = validateRegistryPatch({
      patch,
      proposalSet: candidateSet,
      confirmation,
      approval,
      observation,
      registry,
      now: nowArgument(values),
    });
    if (!validation.ok) {
      return Object.freeze({
        ok: false, rejected: true, reason: validation.reason,
      });
    }
    return command === "validate-registry-patch"
      ? validation
      : previewRegistryPatch({ patch, registry, validation });
  }

  if (command === "shadow-lookup") {
    const registry = readValidatedShadowRegistry(required(values, "registry"));
    const normalizedCapability = required(values, "capability");
    if (!values.patch) {
      return shadowLookup({ normalizedCapability, registry });
    }
    const patch = readValidatedArtifact(
      values.patch, "mcpherson-governance-shadow-registry-patch/v1",
    );
    const candidateSet = candidateSetArgument(
      required(values, "candidates"), "proposal",
    );
    const confirmation = readValidatedLiveConfirmation(
      required(values, "confirmation"),
    );
    const approval = readValidatedApproval(required(values, "approval"));
    const observation = verifiedObservation(values);
    const validation = validateRegistryPatch({
      patch,
      proposalSet: candidateSet,
      confirmation,
      approval,
      observation,
      registry,
      now: nowArgument(values),
    });
    if (!validation.ok) {
      return Object.freeze({
        ok: false, rejected: true, reason: validation.reason,
      });
    }
    return shadowLookup({ normalizedCapability, registry, patch });
  }

  if (command === "drift") {
    const artifacts = [];
    if (values.confirmation) {
      artifacts.push(readValidatedArtifact(
        values.confirmation,
        "mcpherson-governance-human-classification-confirmation/v1",
      ));
    }
    if (values.approval) {
      artifacts.push(readValidatedApproval(values.approval));
    }
    const approvalRecords = artifacts.filter(
      (artifact) => artifact.schema
        === "mcpherson-governance-mapping-approval/v1",
    );
    const previousSet = candidateSetArgument(
      required(values, "previous"), "any", { approvalRecords },
    );
    const currentSet = candidateSetArgument(
      required(values, "current"), "any", { approvalRecords },
    );
    const detectedAt = nowArgument(values);
    const eventSet = buildDriftEventSet({
      previousSet,
      currentSet,
      artifacts,
      detectedAt,
    });
    return emit(eventSet, values);
  }

  if (command === "govern") {
    const evidencePath = required(values, "evidence");
    const evidenceDocument = readValidatedArtifact(
      evidencePath,
      "mcpherson-governance-governability-evidence/v1",
    );
    if (evidenceDocument.observation_id !== undefined) {
      verifiedObservation(values);
      assertObservationArtifactPath(
        { ...values, evidence: evidencePath },
        "evidence",
        LIVE_OUTPUT_FILES.evidence,
      );
    }
    const findingSet = evaluateGovernability({
      evidenceDocument,
      evaluatedAt: nowArgument(values),
      observationDirectory: evidenceDocument.observation_id === undefined
        ? null
        : required(values, "observation-dir"),
      packageManifestPath: evidenceDocument.observation_id === undefined
        ? null
        : required(values, "package-manifest"),
      profileBindingPath: evidenceDocument.observation_id === undefined
        ? null
        : required(values, "profile-binding"),
      profileBindingId: evidenceDocument.observation_id === undefined
        ? null
        : required(values, "profile-binding-id"),
    });
    const composition = validateFindingSet(
      findingSet, { evidenceDocument },
    );
    if (!composition.ok) {
      fail("FINDING_SET_EVIDENCE_COMPOSITION_INVALID", composition);
    }
    return emit(findingSet, values);
  }

  if (command === "render-diagnosis") {
    const findingSet = readValidatedArtifact(
      required(values, "findings"),
      "mcpherson-governance-governability-finding-set/v1",
    );
    const evidenceDocument = readValidatedArtifact(
      required(values, "evidence"),
      "mcpherson-governance-governability-evidence/v1",
    );
    if (evidenceDocument.observation_id !== undefined) {
      verifiedObservation(values);
      assertObservationArtifactPath(
        values, "evidence", LIVE_OUTPUT_FILES.evidence,
      );
    }
    const composition = validateFindingSet(
      findingSet, { evidenceDocument },
    );
    if (!composition.ok) {
      fail("FINDING_SET_EVIDENCE_COMPOSITION_INVALID", composition);
    }
    const coverageReport = values.coverage
      ? (() => {
        const value = readJsonArgument(values.coverage);
        const schema = value?.schema ===
          "mcpherson-governance-live-shadow-coverage-report/v1"
          ? "mcpherson-governance-live-shadow-coverage-report/v1"
          : "mcpherson-governance-shadow-coverage-report/v1";
        const validation = validateEnvelope(schema, value);
        if (!validation.ok) fail("INPUT_CONTRACT_INVALID", validation.errors);
        return value;
      })()
      : null;
    const diagnosis = buildDiagnosis(
      findingSet, { evidenceDocument, coverageReport },
    );
    if ((values.format ?? "json") === "md") {
      const markdown = renderDiagnosisMarkdown(
        diagnosis, { evidenceDocument, coverageReport },
      );
      if (typeof values.out === "string" && values.out.length > 0) {
        return emitText(markdown, values);
      }
      return Object.freeze({ ok: true, format: "md", markdown });
    }
    return emit(diagnosis, values);
  }

  if (command === "latency-summarize") {
    const document = readJsonArgument(required(values, "events"));
    const eventSetSchema = document?.schema ===
      "mcpherson-governance-live-latency-event-set/v1"
      ? "mcpherson-governance-live-latency-event-set/v1"
      : "mcpherson-governance-latency-event-set/v1";
    if (eventSetSchema === "mcpherson-governance-live-latency-event-set/v1") {
      verifiedObservation(values);
      assertObservationArtifactPath(
        values, "events", LIVE_OUTPUT_FILES.latency,
      );
    }
    const eventContract = validateEnvelope(eventSetSchema, document);
    if (!eventContract.ok) {
      fail("INPUT_CONTRACT_INVALID", eventContract.errors);
    }
    // Cross-member validation prevents duplicate/reordered sequences and
    // mixed or unsupported instrumentation contexts from inflating a
    // summary, while applying the same imported-tag privacy screen as the
    // recorder. summarizeLatency repeats this validation at its direct API.
    const semantic = validateLatencyEventSet(document, {
      observationDirectory: eventSetSchema
        === "mcpherson-governance-live-latency-event-set/v1"
        ? required(values, "observation-dir")
        : null,
      packageManifestPath: eventSetSchema
        === "mcpherson-governance-live-latency-event-set/v1"
        ? required(values, "package-manifest")
        : null,
      profileBindingPath: eventSetSchema
        === "mcpherson-governance-live-latency-event-set/v1"
        ? required(values, "profile-binding")
        : null,
      profileBindingId: eventSetSchema
        === "mcpherson-governance-live-latency-event-set/v1"
        ? required(values, "profile-binding-id")
        : null,
    });
    if (!semantic.ok) {
      if (semantic.reason === "latency_event_sensitive_value") {
        fail("INPUT_LATENCY_EVENT_SENSITIVE_VALUE", semantic.detail);
      }
      if (semantic.reason === "latency_event_measurement_context_mismatch") {
        fail("INPUT_LATENCY_PROVENANCE_MISMATCH", semantic);
      }
      if (semantic.reason === "latency_event_invalid") {
        fail("INPUT_LATENCY_EVENT_INVALID", semantic.detail);
      }
      fail("INPUT_LATENCY_EVENT_SET_SEMANTIC_INVALID", semantic);
    }
    return emit(summarizeLatency(document.events, {
      measurementKind: document.measurement_kind,
      observationDirectory: eventSetSchema
        === "mcpherson-governance-live-latency-event-set/v1"
        ? required(values, "observation-dir")
        : null,
      packageManifestPath: eventSetSchema
        === "mcpherson-governance-live-latency-event-set/v1"
        ? required(values, "package-manifest")
        : null,
      profileBindingPath: eventSetSchema
        === "mcpherson-governance-live-latency-event-set/v1"
        ? required(values, "profile-binding")
        : null,
      profileBindingId: eventSetSchema
        === "mcpherson-governance-live-latency-event-set/v1"
        ? required(values, "profile-binding-id")
        : null,
    }), values);
  }

  if (command === "coverage") {
    // Coverage has no approval-artifact input and owns an explicit,
    // boundary-specific rejection for embedded approved lifecycle claims.
    // Read only the strict envelope here so the producer can issue that
    // rejection rather than the generic candidate-set boundary masking it.
    const candidateSet = readValidatedArtifact(
      required(values, "candidates"),
      "mcpherson-governance-capability-candidate-set/v1",
    );
    const receiptSummary = readJsonArgument(required(values, "receipts"));
    const receiptSchema = receiptSummary?.schema ===
      "mcpherson-governance-live-shadow-receipt-summary/v1"
      ? "mcpherson-governance-live-shadow-receipt-summary/v1"
      : "mcpherson-governance-shadow-receipt-summary/v1";
    if (receiptSchema
        === "mcpherson-governance-live-shadow-receipt-summary/v1") {
      verifiedObservation(values);
      assertObservationArtifactPath(
        values, "receipts", LIVE_OUTPUT_FILES.receipts,
      );
    }
    const receiptContract = validateEnvelope(receiptSchema, receiptSummary);
    if (!receiptContract.ok) {
      fail("INPUT_CONTRACT_INVALID", receiptContract.errors);
    }
    const report = buildShadowCoverageReport({
      candidateSet,
      receiptSummary,
      generatedAt: nowArgument(values),
      observationDirectory: receiptSchema
        === "mcpherson-governance-live-shadow-receipt-summary/v1"
        ? required(values, "observation-dir")
        : null,
      packageManifestPath: receiptSchema
        === "mcpherson-governance-live-shadow-receipt-summary/v1"
        ? required(values, "package-manifest")
        : null,
      profileBindingPath: receiptSchema
        === "mcpherson-governance-live-shadow-receipt-summary/v1"
        ? required(values, "profile-binding")
        : null,
      profileBindingId: receiptSchema
        === "mcpherson-governance-live-shadow-receipt-summary/v1"
        ? required(values, "profile-binding-id")
        : null,
    });
    return emit(report, values);
  }

  fail("USAGE_UNKNOWN_COMMAND");
  return undefined;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await runGovernanceDiagnostics(process.argv.slice(2));
    // stdout is an output boundary exactly like `--out`; it goes through the
    // same redaction and final-output scan.
    process.stdout.write(redactedOutputText(result));
    if (result && result.ok === false) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`${JSON.stringify(publicError(error))}\n`);
    process.exitCode = 1;
  }
}

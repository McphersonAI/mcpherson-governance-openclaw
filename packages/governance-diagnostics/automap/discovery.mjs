// Read-only AutoMap discovery over static, sanitized, repository-local
// sources. Produces deterministic discovery records and mapping proposals.
// AutoMap may discover and propose; nothing here can activate a mapping,
// register a tool, write connector or server state, or touch a runtime.
//
// Trust discipline (Sol repair): a sanitized snapshot yields only unverified
// declarations; CONFIRMED_DETERMINISTIC exists only for registry documents
// whose provenance is verified by `pinned-content.mjs` (pinned-content
// identity, trusted path, exact raw-byte hash, and per-entry code
// cross-check); CONFIRMED_HUMAN can only be created by
// `applyConfirmation()` with a bound artifact and is rejected here.

import { createHash } from "node:crypto";
import { basename, dirname } from "node:path";
import { lstatSync, readdirSync, realpathSync } from "node:fs";
import { canonicalizeJson } from "../../governance-core/canonical.mjs";
import { WIRE_SAFE_ID_RE, WIRE_SAFE_LABEL_RE, RFC3339_UTC_RE } from "../../governance-core/contracts.mjs";
import {
  buildObservationRequest,
  serializeAllowlistedRequest,
} from "../../../plugins/openclaw-connector/allowlist.mjs";
import { readBoundedJson } from "./input-safety.mjs";
import { fingerprintOperation, rawDocumentSha256 } from "./fingerprint.mjs";
import {
  classificationFromDeclaration,
  proposeRisk,
  withAdvisorySuggestion,
} from "./classification.mjs";
import {
  deriveRegistryCandidateSemantics,
  verifyPinnedContent,
} from "./pinned-content.mjs";
import { validateCandidateSet } from "./candidate-validate.mjs";
import { sensitiveValueReason } from "../sensitive-values.mjs";
import { validateArtifact, validateEnvelope, assertValidArtifact } from "../contracts.mjs";
import {
  LIVE_OUTPUT_FILES,
  readVerifiedOpenClawLiveArtifact,
} from "../../openclaw-live-observer/index.mjs";
import {
  ADVISORY_SCHEMA,
  AUTOMAP_VERSION,
  CANDIDATE_SCHEMA,
  CANDIDATE_SET_SCHEMA,
  COMPLETION_EVIDENCES,
  DISCOVERY_METHODS,
  LIVE_SNAPSHOT_SCHEMA,
  REGISTRY_SCHEMA,
  REVERSIBILITIES,
  SNAPSHOT_SCHEMA,
  normalizeEffects,
} from "../vocabulary.mjs";

export const CANDIDATE_ID_VERSION = "1";
// candidate_content_hash is the canonical hash of the candidate's semantic
// content. These fields are excluded so the hash — and every confirmation or
// approval bound to it — survives prose-only edits and changes to unrelated
// operations in the same source document, while any validation-semantic
// change (structural fingerprint, effects, classification, labels, risk,
// preview) changes the hash. This is the single invalidation rule shared by
// confirmation validation and drift severity.
export const CANDIDATE_CONTENT_HASH_EXCLUSIONS = Object.freeze([
  "candidate_content_hash",
  "discovery_timestamp",
  "discovery_source",
  "source_document_sha256",
  "metadata_fingerprint",
]);
const NORMALIZED_CAPABILITY_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const PREVIEW_PROVIDERS = Object.freeze({
  randomUUID: () => "00000000-0000-4000-8000-000000000000",
  randomBytes: (length) => Buffer.alloc(length, 0),
  now: () => new Date("2026-01-01T00:00:00.000Z"),
});
const PREVIEW_CONFIG = Object.freeze({ policyVersion: 1 });
export const PREVIEW_AGENT_ID = "agent-preview";

function safeId(value) {
  // Identifiers (tool/operation/source IDs) are charset-bounded and are
  // cross-checked against code-owned vocabulary; the semantic sensitive-value
  // keyword screen is applied to free-form LABEL values and latency tag
  // values, not to identifiers — otherwise a legitimate code-owned tool name
  // such as `message` would be wrongly rejected. Secret/token/URL shapes are
  // still impossible here because WIRE_SAFE_ID_RE excludes the characters
  // those shapes require.
  return typeof value === "string" && WIRE_SAFE_ID_RE.test(value);
}

function isTimestamp(value) {
  return typeof value === "string" && RFC3339_UTC_RE.test(value);
}

export function candidateId({ sourceId, nativeTool, nativeOperation, discoveryMethod }) {
  const identity = canonicalizeJson({
    candidate_id_version: CANDIDATE_ID_VERSION,
    source_id: sourceId,
    native_tool_name: nativeTool,
    native_operation_name: nativeOperation ?? null,
    discovery_method: discoveryMethod,
  });
  const digest = createHash("sha256").update(identity, "utf8").digest("hex");
  return `mgc-${digest.slice(0, 24)}`;
}

export function candidateContentHash(candidate) {
  const clone = {};
  for (const key of Object.keys(candidate)) {
    if (CANDIDATE_CONTENT_HASH_EXCLUSIONS.includes(key)) continue;
    clone[key] = candidate[key];
  }
  return `sha256:${createHash("sha256")
    .update(canonicalizeJson(clone), "utf8").digest("hex")}`;
}

/**
 * Deterministic outbound-metadata preview rendered through the real v0.5
 * request builder and privacy guard. A candidate whose labels cannot pass the
 * allowlist yields a REJECTED preview record instead of a request.
 */
export function buildOutboundMetadataPreview(candidate) {
  const summary = {
    agentId: PREVIEW_AGENT_ID,
    toolId: candidate.native_tool_name,
    toolSchemaVersion: "preview",
    toolSchemaHash: candidate.structural_schema_fingerprint,
    actionClass: candidate.proposed_risk?.proposed_action_class ?? "unknown",
    resourceClass: candidate.target_resource_class === "unknown"
      ? undefined
      : candidate.target_resource_class,
    dataSensitivityLabel: candidate.data_classes?.[0] === "unknown"
      ? undefined
      : candidate.data_classes?.[0],
    reversibilityLabel: candidate.reversibility === "unknown"
      ? undefined
      : candidate.reversibility,
    rawCorrelation: "preview-correlation",
  };
  try {
    const request = buildObservationRequest(summary, PREVIEW_CONFIG, PREVIEW_PROVIDERS);
    const bytes = serializeAllowlistedRequest(request);
    return Object.freeze({
      status: "ALLOWLISTED",
      request: Object.freeze({ ...request }),
      serialized_bytes: bytes.length,
    });
  } catch (error) {
    return Object.freeze({
      status: "REJECTED_BY_PRIVACY_GUARD",
      reason_code: String(error?.code ?? "PRIVACY_GUARD_TRIPPED"),
    });
  }
}

function candidateBase({
  sourceId, nativeTool, nativeOperation, normalizedCapability, discoverySource,
  discoveryMethod, schemaRef, fingerprint, sourceDocumentSha256, now,
}) {
  return {
    schema: CANDIDATE_SCHEMA,
    automap_version: AUTOMAP_VERSION,
    candidate_id: candidateId({
      sourceId, nativeTool, nativeOperation, discoveryMethod,
    }),
    source_id: sourceId,
    native_tool_name: nativeTool,
    native_operation_name: nativeOperation ?? null,
    normalized_capability: normalizedCapability,
    discovery_source: discoverySource,
    discovery_method: discoveryMethod,
    native_schema_ref: schemaRef,
    source_document_sha256: sourceDocumentSha256,
    structural_schema_fingerprint: fingerprint.structural_fingerprint,
    metadata_fingerprint: fingerprint.metadata_fingerprint,
    structural_paths: [...fingerprint.structural_paths],
    discovery_timestamp: now,
  };
}

function declaredLabel(value, field, unresolved) {
  if (value === undefined) return undefined;
  if (typeof value === "string" && WIRE_SAFE_LABEL_RE.test(value)) {
    if (sensitiveValueReason(value) !== null) {
      unresolved.push(`declared_${field}_sensitive_value_rejected`);
      return undefined;
    }
    return value;
  }
  unresolved.push(`declared_${field}_invalid`);
  return undefined;
}

function finishCandidate(base, {
  classification, reversibility, targetResourceClass, dataClasses, sideEffects,
  completionEvidence, mappingConfidence, unresolved, authoritativeActionClass,
  authoritativeSource,
}) {
  const candidate = {
    ...base,
    target_resource_class: targetResourceClass ?? "unknown",
    effects: [...classification.effects],
    classification: {
      status: classification.status,
      method: classification.method,
      evidence: [...classification.evidence],
      confirmed_by: classification.confirmed_by,
      confirmed_at: classification.confirmed_at,
      rationale: classification.rationale,
      ...(classification.advisory_suggestion
        ? { advisory_suggestion: { ...classification.advisory_suggestion } }
        : {}),
    },
    reversibility: reversibility ?? "unknown",
    possible_side_effects: sideEffects ?? [],
    data_classes: dataClasses && dataClasses.length > 0 ? dataClasses : ["unknown"],
    completion_evidence_availability: completionEvidence ?? "UNKNOWN",
    required_policy_attributes: [
      "action_class", "agent_id", "policy_version", "tool_id",
      "tool_schema_hash", "tool_schema_version",
    ],
    mapping_confidence: mappingConfidence,
    unresolved_questions: [...new Set(unresolved)].sort(),
    mapping_status: "DISCOVERED",
    proposed_risk: proposeRisk({
      classification,
      reversibility: reversibility ?? "unknown",
      targetResourceClass: targetResourceClass ?? "unknown",
      dataClasses: dataClasses ?? [],
      authoritativeActionClass,
      authoritativeSource,
    }),
  };
  candidate.candidate_content_hash = candidateContentHash(candidate);
  return candidate;
}

function fromSnapshot(document, discoverySource, sourceDocumentSha256, now, errors) {
  const candidates = [];
  // Validate the ENTIRE snapshot document against its shared contract before
  // any field is trusted, so an unknown top-level field (e.g. an
  // activation-shaped `runtime_active`) is rejected rather than silently
  // dropped while trusted-looking candidates are still emitted.
  const contract = validateArtifact(SNAPSHOT_SCHEMA, document);
  if (!contract.ok) {
    errors.push({
      path: discoverySource,
      reason: `snapshot_contract_invalid:${contract.errors[0]?.rule ?? "unknown"}`,
    });
    return candidates;
  }
  if (document.source_kind !== "sanitized_static_snapshot"
      || document.sanitization_confirmed !== true) {
    errors.push({ path: discoverySource, reason: "unsanitized_source_refused" });
    return candidates;
  }
  if (!safeId(document.source_id)) {
    errors.push({ path: discoverySource, reason: "source_id_invalid" });
    return candidates;
  }
  if (!Array.isArray(document.tools)) {
    errors.push({ path: discoverySource, reason: "tools_not_list" });
    return candidates;
  }
  for (const tool of document.tools) {
    if (!tool || typeof tool !== "object" || !safeId(tool.tool)
        || !Array.isArray(tool.operations)) {
      errors.push({ path: discoverySource, reason: "tool_entry_invalid" });
      continue;
    }
    for (const operation of tool.operations) {
      if (!operation || typeof operation !== "object" || !safeId(operation.operation)) {
        errors.push({
          path: discoverySource,
          reason: `operation_entry_invalid:${tool.tool}`,
        });
        continue;
      }
      const unresolved = [];
      const normalized = `${tool.tool}.${operation.operation}`;
      if (!NORMALIZED_CAPABILITY_RE.test(normalized)) {
        errors.push({
          path: discoverySource,
          reason: `normalized_capability_invalid:${tool.tool}`,
        });
        continue;
      }
      const fingerprint = fingerprintOperation({
        operationName: operation.operation,
        parameterLocation: "parameters",
        parameters: operation.parameters ?? null,
      });
      if (operation.parameters === undefined) unresolved.push("parameters_schema_absent");
      const classification = classificationFromDeclaration({
        // Evidence ref keys on the sanitized source_id (like the candidate
        // identity), never the filename, so re-exporting the same connector
        // to a differently named file does not change the semantic content
        // hash. This keeps confirmation invalidation and drift on one rule.
        declaredEffects: operation.declared_effects,
        evidenceRef: `${document.source_id}#${normalized}`,
      });
      if (classification.status === "UNKNOWN"
          && classification.method === "none") {
        unresolved.push("effects_undeclared");
      }
      const reversibility = REVERSIBILITIES.has(operation.reversibility)
        ? operation.reversibility
        : undefined;
      if (operation.reversibility !== undefined && reversibility === undefined) {
        unresolved.push("declared_reversibility_invalid");
      }
      const completion = COMPLETION_EVIDENCES.has(operation.completion_evidence)
        ? operation.completion_evidence
        : undefined;
      if (operation.completion_evidence !== undefined && completion === undefined) {
        unresolved.push("declared_completion_evidence_invalid");
      }
      const dataClasses = Array.isArray(operation.data_classes)
        ? operation.data_classes
          .map((value) => declaredLabel(value, "data_class", unresolved))
          .filter((value) => value !== undefined)
        : [];
      const sideEffects = Array.isArray(operation.side_effects)
        ? operation.side_effects
          .map((value) => declaredLabel(value, "side_effect", unresolved))
          .filter((value) => value !== undefined)
        : [];
      const base = candidateBase({
        sourceId: document.source_id,
        nativeTool: tool.tool,
        nativeOperation: operation.operation,
        normalizedCapability: normalized,
        discoverySource,
        discoveryMethod: "sanitized_static_snapshot_v1",
        schemaRef: `tools[${tool.tool}].operations[${operation.operation}].parameters`,
        fingerprint,
        sourceDocumentSha256,
        now,
      });
      candidates.push(finishCandidate(base, {
        classification,
        reversibility,
        targetResourceClass: declaredLabel(
          operation.target_resource_class, "target_resource_class", unresolved,
        ),
        dataClasses,
        sideEffects,
        completionEvidence: completion,
        mappingConfidence: classification.method === "static_manifest_declaration"
          ? "declared_unverified"
          : "unknown",
        unresolved,
        authoritativeActionClass: null,
        authoritativeSource: null,
      }));
    }
  }
  return candidates;
}

function fromLiveSnapshot(
  document, discoverySource, sourceDocumentSha256, now, errors,
) {
  const contract = validateArtifact(LIVE_SNAPSHOT_SCHEMA, document);
  if (!contract.ok) {
    errors.push({
      path: discoverySource,
      reason: `live_snapshot_contract_invalid:${contract.errors[0]?.rule ?? "unknown"}`,
    });
    return [];
  }
  if (document.source_kind !== "openclaw_live_gateway"
      || document.measurement_kind !== "LIVE_SHADOW"
      || document.sanitization_confirmed !== true) {
    errors.push({ path: discoverySource, reason: "live_snapshot_provenance_invalid" });
    return [];
  }
  // Project only the capability fields accepted by the established static
  // discovery logic. Runtime/agent provenance remains bound by the validated
  // live snapshot and its raw-byte hash, but never becomes a capability
  // effect, classification, or authority claim.
  const projection = {
    schema: SNAPSHOT_SCHEMA,
    source_id: document.source_id,
    source_kind: "sanitized_static_snapshot",
    sanitization_confirmed: true,
    captured_at: document.captured_at,
    tools: document.tools.map((tool) => ({
      tool: tool.tool,
      operations: tool.operations.map((operation) => ({
        operation: operation.operation,
        declared_effects: operation.declared_effects,
        completion_evidence: operation.completion_evidence,
      })),
    })),
  };
  const candidates = fromSnapshot(
    projection, discoverySource, sourceDocumentSha256, now, errors,
  );
  return candidates.map((candidate) => {
    const upgraded = {
      ...candidate,
      candidate_id: candidateId({
        sourceId: candidate.source_id,
        nativeTool: candidate.native_tool_name,
        nativeOperation: candidate.native_operation_name,
        discoveryMethod: "openclaw_live_gateway_v1",
      }),
      discovery_method: "openclaw_live_gateway_v1",
      native_schema_ref:
        `tools[${candidate.native_tool_name}].operations[invoke]`,
      unresolved_questions: [...new Set([
        ...candidate.unresolved_questions,
        "live_catalog_metadata_only",
      ])].sort(),
    };
    delete upgraded.candidate_content_hash;
    upgraded.candidate_content_hash = candidateContentHash(upgraded);
    return upgraded;
  });
}

function fromOpenClawPluginManifest(document, discoverySource, sourceDocumentSha256, now, errors) {
  const candidates = [];
  if (!safeId(document.id)) {
    errors.push({ path: discoverySource, reason: "plugin_id_invalid" });
    return candidates;
  }
  const tools = document.contracts?.tools;
  if (!Array.isArray(tools)) {
    errors.push({ path: discoverySource, reason: "manifest_tools_not_list" });
    return candidates;
  }
  for (const tool of tools) {
    if (!safeId(tool)) {
      errors.push({ path: discoverySource, reason: "manifest_tool_invalid" });
      continue;
    }
    const unresolved = [
      "no_parameter_schema_in_manifest",
      "effects_undeclared",
    ];
    const fingerprint = fingerprintOperation({
      operationName: tool,
      parameterLocation: "manifest_declaration",
      parameters: null,
    });
    const base = candidateBase({
      sourceId: document.id,
      nativeTool: tool,
      nativeOperation: null,
      normalizedCapability: tool,
      discoverySource,
      discoveryMethod: "openclaw_plugin_manifest",
      schemaRef: "contracts.tools[]",
      fingerprint,
      sourceDocumentSha256,
      now,
    });
    candidates.push(finishCandidate(base, {
      classification: classificationFromDeclaration({
        declaredEffects: undefined,
        evidenceRef: null,
      }),
      reversibility: undefined,
      targetResourceClass: undefined,
      dataClasses: [],
      sideEffects: [],
      completionEvidence: undefined,
      mappingConfidence: "unknown",
      unresolved,
      authoritativeActionClass: null,
      authoritativeSource: null,
    }));
  }
  return candidates;
}

function fromCommittedRegistry(document, discoverySource, sourceDocumentSha256, now, errors, provenance) {
  const candidates = [];
  // Validate the whole registry document against its shared contract before
  // trust, rejecting unknown top-level fields.
  const contract = validateArtifact(REGISTRY_SCHEMA, document);
  if (!contract.ok) {
    errors.push({
      path: discoverySource,
      reason: `registry_contract_invalid:${contract.errors[0]?.rule ?? "unknown"}`,
    });
    return candidates;
  }
  if (!provenance || provenance.ok !== true) {
    errors.push({
      path: discoverySource,
      reason: `registry_provenance_unverified:${provenance?.reason ?? "unknown"}`,
    });
    return candidates;
  }
  // The registry is parsed from one descriptor-bound read and the pin is
  // verified through a second descriptor-bound read. Bind those two reads by
  // hash before trusting any parsed value: a concurrent pathname replacement
  // cannot attach a valid pin for bytes B to parsed bytes A.
  if (sourceDocumentSha256 !== `sha256:${provenance.binding.sha256}`) {
    errors.push({
      path: discoverySource,
      reason: "registry_parsed_bytes_do_not_match_verified_pin",
    });
    return candidates;
  }
  if (document.code_owned !== true) {
    errors.push({ path: discoverySource, reason: "unsupported_schema" });
    return candidates;
  }
  if (!safeId(document.source_id)
      || document.source_id !== provenance.binding.source_id
      || !Array.isArray(document.registry)) {
    errors.push({ path: discoverySource, reason: "registry_invalid" });
    return candidates;
  }
  for (const entry of document.registry) {
    if (!entry || typeof entry !== "object" || !safeId(entry.tool)) {
      errors.push({ path: discoverySource, reason: "registry_entry_invalid" });
      continue;
    }
    const derived = deriveRegistryCandidateSemantics({
      document,
      entry,
      provenance,
      sourceDocumentSha256,
    });
    if (!derived.ok) {
      errors.push({
        path: discoverySource,
        reason: `${derived.reason}:${entry.tool}`,
      });
      continue;
    }
    const candidate = {
      schema: CANDIDATE_SCHEMA,
      ...derived.fields,
      candidate_id: candidateId({
        sourceId: derived.fields.source_id,
        nativeTool: derived.fields.native_tool_name,
        nativeOperation: null,
        discoveryMethod: derived.fields.discovery_method,
      }),
      discovery_source: discoverySource,
      discovery_timestamp: now,
      mapping_status: "DISCOVERED",
    };
    candidate.candidate_content_hash = candidateContentHash(candidate);
    candidates.push(candidate);
  }
  return candidates;
}

function sourceFiles(sourcePath) {
  const stat = lstatSync(sourcePath);
  if (stat.isSymbolicLink()) return { root: null, files: [], symlink: true };
  if (stat.isDirectory()) {
    // Resolve the directory realpath once and bind enumeration to it, so a
    // later per-file read is resolved under the same directory identity that
    // was enumerated (rather than re-resolving a path that could have been
    // swapped in between). Node does not expose openat(), so this narrows
    // but does not fully eliminate a directory-swap race; the residual is
    // documented in docs/v0.6-diagnostics.md. This is a local diagnostic
    // tool reading operator-supplied sanitized files, not a privileged path.
    const realDir = realpathSync(sourcePath);
    const names = readdirSync(realDir)
      .filter((name) => name.endsWith(".json"))
      .sort();
    return { root: realDir, files: names, symlink: false };
  }
  return { root: dirname(sourcePath), files: [basename(sourcePath)], symlink: false };
}

/**
 * Discover capabilities from one explicitly supplied static source (a
 * sanitized file or a directory of sanitized files). Returns a deterministic
 * candidate-set document; repeated identical runs produce identical IDs,
 * fingerprints, and ordering. Candidates whose IDs collide are all excluded
 * with an error record — a duplicate identity is never silently retained.
 */
export function discoverFromSource({
  sourcePath,
  method,
  now,
  trustedRoot,
  observationDirectory,
  packageManifestPath,
  profileBindingPath,
  profileBindingId,
}) {
  if (!DISCOVERY_METHODS.has(method)) {
    throw new TypeError("discovery_method_invalid");
  }
  if (!isTimestamp(now)) throw new TypeError("discovery_timestamp_invalid");
  const errors = [];
  let candidates = [];
  let liveEvidence = null;
  if (method === "openclaw_live_gateway_v1") {
    if (typeof observationDirectory !== "string") {
      throw new TypeError("live_observation_directory_required");
    }
    liveEvidence = readVerifiedOpenClawLiveArtifact({
      outDir: observationDirectory,
      filename: LIVE_OUTPUT_FILES.snapshot,
      packageManifestPath,
      profileBindingPath,
      profileBindingId,
    });
    if (realpathSync(sourcePath)
        !== realpathSync(
          `${observationDirectory}/${LIVE_OUTPUT_FILES.snapshot}`,
        )) {
      throw new TypeError("live_snapshot_not_bound_to_observation_directory");
    }
  }
  let listing;
  try {
    listing = sourceFiles(sourcePath);
  } catch {
    listing = { root: null, files: [], symlink: false };
    errors.push({ path: String(sourcePath), reason: "missing" });
  }
  if (listing.symlink) {
    errors.push({ path: String(sourcePath), reason: "symlink_refused" });
  }
  for (const name of listing.files) {
    const read = readBoundedJson(listing.root, name);
    if (!read.ok) {
      errors.push({ path: read.path, reason: read.reason });
      continue;
    }
    // Exact raw source bytes — never a canonicalized re-encoding.
    const raw = rawDocumentSha256(read.rawBytes);
    if (method === "sanitized_static_snapshot_v1") {
      candidates.push(...fromSnapshot(read.value, read.path, raw, now, errors));
    } else if (method === "openclaw_live_gateway_v1") {
      if (canonicalizeJson(read.value) !== canonicalizeJson(liveEvidence.value)
          || raw !== liveEvidence.verification
            .artifacts[LIVE_OUTPUT_FILES.snapshot].sha256) {
        throw new TypeError("live_snapshot_observation_binding_mismatch");
      }
      candidates.push(...fromLiveSnapshot(
        read.value, read.path, raw, now, errors,
      ));
    } else if (method === "openclaw_plugin_manifest") {
      candidates.push(...fromOpenClawPluginManifest(read.value, read.path, raw, now, errors));
    } else {
      const provenance = verifyPinnedContent({
        sourcePath: `${listing.root}/${name}`,
        trustedRoot,
      });
      candidates.push(...fromCommittedRegistry(
        read.value, read.path, raw, now, errors, provenance,
      ));
    }
  }
  candidates.sort((left, right) => (
    left.candidate_id < right.candidate_id ? -1
      : left.candidate_id > right.candidate_id ? 1 : 0
  ));
  const idCounts = new Map();
  for (const candidate of candidates) {
    idCounts.set(candidate.candidate_id,
      (idCounts.get(candidate.candidate_id) ?? 0) + 1);
  }
  const duplicates = [...idCounts.entries()]
    .filter(([, count]) => count > 1)
    .map(([id]) => id);
  if (duplicates.length > 0) {
    candidates = candidates.filter(
      (candidate) => !duplicates.includes(candidate.candidate_id),
    );
    for (const duplicate of duplicates.sort()) {
      errors.push({
        path: String(sourcePath),
        reason: `duplicate_candidate_excluded:${duplicate}`,
      });
    }
  }
  errors.sort((left, right) => (
    `${left.path}|${left.reason}` < `${right.path}|${right.reason}` ? -1 : 1
  ));
  const result = Object.freeze({
    schema: CANDIDATE_SET_SCHEMA,
    automap_version: AUTOMAP_VERSION,
    discovery_method: method,
    discovery_source: String(sourcePath),
    generated_at: now,
    candidate_count: candidates.length,
    candidates,
    errors,
  });
  // Producer output contract: the candidate set and every member candidate
  // must validate before this function returns.
  assertValidArtifact(CANDIDATE_SET_SCHEMA, result);
  const semantic = validateCandidateSet(result, { stage: "discovery" });
  if (!semantic.ok) {
    const error = new TypeError(`candidate_set_output_invalid:${semantic.reason}`);
    error.detail = semantic;
    throw error;
  }
  return result;
}

/**
 * Turn discovery records into mapping proposals. Proposals attach the
 * deterministic outbound-metadata preview and optionally advisory
 * (model-suggested) classification fixtures; nothing here confirms a
 * classification or activates anything. Input candidates claiming
 * CONFIRMED_HUMAN are rejected: human confirmation exists only through
 * `applyConfirmation()` with a bound artifact.
 */
export function proposeMappings({
  candidateSet,
  advisoryDocument = null,
  now,
  observationDirectory = null,
  packageManifestPath = null,
  profileBindingPath = null,
  profileBindingId = null,
}) {
  if (!isTimestamp(now)) throw new TypeError("proposal_timestamp_invalid");
  // Producer input contract: the input candidate set and every member must
  // validate before proposal, so a forged input candidate (e.g. one carrying
  // an activation-shaped field) is rejected at the boundary, not retained.
  const inputContract = validateEnvelope(CANDIDATE_SET_SCHEMA, candidateSet);
  if (!inputContract.ok) {
    throw new TypeError(`candidate_set_invalid:${inputContract.errors[0]?.rule ?? "unknown"}`);
  }
  const inputSemantic = validateCandidateSet(candidateSet, { stage: "discovery" });
  if (!inputSemantic.ok) {
    throw new TypeError(`candidate_set_invalid:${inputSemantic.reason}`);
  }
  if (candidateSet.discovery_method === "openclaw_live_gateway_v1") {
    if (typeof observationDirectory !== "string"
        || typeof packageManifestPath !== "string") {
      throw new TypeError("live_observation_verification_required");
    }
    const verified = readVerifiedOpenClawLiveArtifact({
      outDir: observationDirectory,
      filename: LIVE_OUTPUT_FILES.snapshot,
      packageManifestPath,
      profileBindingPath,
      profileBindingId,
    });
    if (realpathSync(candidateSet.discovery_source)
          !== realpathSync(
            `${observationDirectory}/${LIVE_OUTPUT_FILES.snapshot}`,
          )
        || candidateSet.candidates.some(
          (candidate) => candidate.source_document_sha256
            !== verified.verification
              .artifacts[LIVE_OUTPUT_FILES.snapshot].sha256,
        )) {
      throw new TypeError("live_proposal_observation_binding_mismatch");
    }
  }
  const advisories = new Map();
  const errors = [...candidateSet.errors];
  if (advisoryDocument !== null) {
    // The advisory document must validate against its own contract, rejecting
    // unknown fields, rather than being spot-checked.
    const advisoryContract = validateArtifact(ADVISORY_SCHEMA, advisoryDocument);
    if (!advisoryContract.ok) {
      errors.push({ path: "advisory", reason: "advisory_document_invalid" });
    } else {
      for (const suggestion of advisoryDocument.suggestions) {
        if (suggestion && typeof suggestion === "object"
            && typeof suggestion.candidate_id === "string"
            && normalizeEffects(suggestion.suggested_effects) !== null) {
          advisories.set(suggestion.candidate_id, suggestion);
        } else {
          errors.push({ path: "advisory", reason: "advisory_suggestion_invalid" });
        }
      }
    }
  }
  const proposals = [];
  for (const candidate of candidateSet.candidates) {
    if (candidate?.classification?.status === "CONFIRMED_HUMAN") {
      errors.push({
        path: String(candidate.candidate_id ?? "unknown"),
        reason: "confirmed_human_requires_bound_artifact",
      });
      continue;
    }
    if (candidate?.classification?.status === "CONFIRMED_DETERMINISTIC"
        && candidate.discovery_method !== "committed_registry_v1") {
      errors.push({
        path: String(candidate.candidate_id ?? "unknown"),
        reason: "deterministic_trust_requires_committed_registry",
      });
      continue;
    }
    const advisory = advisories.get(candidate.candidate_id);
    let classification = {
      ...candidate.classification,
      effects: candidate.effects,
    };
    if (advisory) {
      classification = withAdvisorySuggestion(classification, advisory);
    }
    const upgraded = {
      ...candidate,
      effects: [...classification.effects],
      classification: {
        status: classification.status,
        method: classification.method,
        evidence: [...classification.evidence],
        confirmed_by: classification.confirmed_by,
        confirmed_at: classification.confirmed_at,
        rationale: classification.rationale,
        ...(classification.advisory_suggestion
          ? { advisory_suggestion: { ...classification.advisory_suggestion } }
          : {}),
      },
      mapping_status: "PROPOSED",
      discovery_timestamp: candidate.discovery_timestamp,
    };
    upgraded.proposed_risk = proposeRisk({
      classification: { ...upgraded.classification, effects: upgraded.effects },
      reversibility: upgraded.reversibility,
      targetResourceClass: upgraded.target_resource_class,
      dataClasses: upgraded.data_classes,
      authoritativeActionClass: candidate.discovery_method === "committed_registry_v1"
        ? candidate.proposed_risk.proposed_action_class
        : null,
      authoritativeSource: candidate.discovery_method === "committed_registry_v1"
        ? candidate.classification.evidence[0] ?? null
        : null,
    });
    delete upgraded.candidate_content_hash;
    upgraded.outbound_metadata_preview = buildOutboundMetadataPreview(upgraded);
    upgraded.candidate_content_hash = candidateContentHash(upgraded);
    proposals.push(upgraded);
  }
  const result = Object.freeze({
    schema: CANDIDATE_SET_SCHEMA,
    automap_version: AUTOMAP_VERSION,
    discovery_method: candidateSet.discovery_method,
    discovery_source: candidateSet.discovery_source,
    generated_at: now,
    candidate_count: proposals.length,
    candidates: proposals,
    errors,
  });
  // Producer output contract: a proposed candidate carrying any
  // activation-shaped or otherwise unknown field fails member composition
  // here and never leaves the producer.
  assertValidArtifact(CANDIDATE_SET_SCHEMA, result);
  const outputSemantic = validateCandidateSet(result, { stage: "proposal" });
  if (!outputSemantic.ok) {
    const error = new TypeError(`candidate_set_output_invalid:${outputSemantic.reason}`);
    error.detail = outputSemantic;
    throw error;
  }
  return result;
}

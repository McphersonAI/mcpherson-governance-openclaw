// Pinned-content provenance for committed-registry discovery.
//
// Sol re-audit correction: v0.6 does NOT verify repository identity, Git
// tracking, repository authorship, or a cryptographic signature. The earlier
// "repository identity" check (searching classify.mjs for a marker string)
// was a false identity claim: a marker-only fake root passed it. That check
// is removed. The honest, supported claim is exactly:
//
//   "The diagnostic artifact is bound to reviewed repository-local content
//    through an explicitly selected trusted root, a contained relative path,
//    an expected source kind and source ID, and an exact raw-byte hash."
//
// It does NOT prove the content is Git-tracked or committed, the repository
// is authentic, the author is trusted, or the bytes are signed. The operator
// selects the trusted root; the pin is content binding, not provenance of
// origin. Per-entry effect/action-class consistency is still cross-checked
// against the diagnostics package's own imported code-owned classifier, which
// is the authority for that cross-check.

import { createHash } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ACTION_CLASS_EFFECTS,
  ACTION_CLASSES,
  AUTOMAP_VERSION,
  COMPLETION_EVIDENCES,
  REGISTRY_SCHEMA,
  REVERSIBILITIES,
  normalizeEffects,
} from "../vocabulary.mjs";
import { DEFAULT_TOOL_CLASS } from "../../governance-core/classify.mjs";
import { WIRE_SAFE_LABEL_RE } from "../../governance-core/contracts.mjs";
import { validateArtifact } from "../contracts.mjs";
import { sensitiveValueReason } from "../sensitive-values.mjs";
import { fingerprintOperation } from "./fingerprint.mjs";
import {
  classificationFromCodeOwnedRegistry,
  proposeRisk,
} from "./classification.mjs";

export const MAX_PINNED_FILE_BYTES = 1024 * 1024;

// The default trusted root is this repository's root, but the caller may
// supply any trusted root. There is no repository-identity assertion.
export const DEFAULT_TRUSTED_ROOT = fileURLToPath(new URL("../../..", import.meta.url));

// Content pins reviewed at repository-relative paths. Changing a pinned file
// requires changing this pin in the same review.
export const PINNED_REGISTRY_BINDINGS = Object.freeze([
  Object.freeze({
    repository_relative_path:
      "tests/fixtures/diagnostics/registries/mcpherson-code-owned-tools-v1.json",
    sha256: "8bd92d41e19a4d71ab42ed07acd4da78b0292dd5cceac1668d80ea8a8206570b",
    source_id: "mcpherson-code-owned-tools",
    source_kind: "committed_registry_v1",
  }),
]);

export const CODE_OWNED_CONNECTOR_TOOL_CLASSES = Object.freeze({
  mcpherson_connection_test: "read_only_internal",
  mcpherson_governance_canary: "read_only_internal",
});

export const REGISTRY_REQUIRED_POLICY_ATTRIBUTES = Object.freeze([
  "action_class", "agent_id", "policy_version", "tool_id",
  "tool_schema_hash", "tool_schema_version",
]);

function failure(reason) {
  return Object.freeze({ ok: false, reason });
}

function readVerifiedPinnedContent({ sourcePath, trustedRoot }) {
  let root;
  try {
    root = realpathSync(resolve(trustedRoot ?? DEFAULT_TRUSTED_ROOT));
  } catch {
    return failure("trusted_root_unresolvable");
  }
  let linkStat;
  try {
    linkStat = lstatSync(resolve(String(sourcePath)));
  } catch {
    return failure("pinned_source_missing");
  }
  if (linkStat.isSymbolicLink()) return failure("pinned_source_symlink_refused");
  let resolved;
  try {
    resolved = realpathSync(resolve(String(sourcePath)));
  } catch {
    return failure("pinned_source_missing");
  }
  const relativePath = relative(root, resolved).split(sep).join("/");
  if (relativePath.startsWith("..") || isAbsolute(relativePath)) {
    return failure("pinned_source_outside_trusted_root");
  }
  const binding = PINNED_REGISTRY_BINDINGS.find(
    (entry) => entry.repository_relative_path === relativePath,
  );
  if (!binding) return failure("pinned_path_not_bound");
  let descriptor = null;
  let stat;
  let bytes;
  try {
    descriptor = openSync(
      resolved, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
    );
    stat = fstatSync(descriptor);
    if (!stat.isFile()) return failure("pinned_source_not_regular_file");
    // Bind the descriptor to the exact non-symlink entry inspected above.
    // A replacement between lstat and open is rejected.
    if (stat.dev !== linkStat.dev || stat.ino !== linkStat.ino) {
      return failure("pinned_source_changed_during_read");
    }
    if (stat.size > MAX_PINNED_FILE_BYTES) {
      return failure("pinned_source_oversize");
    }
    bytes = readFileSync(descriptor);
  } catch (error) {
    return error?.code === "ELOOP"
      ? failure("pinned_source_symlink_refused")
      : failure("pinned_source_unreadable");
  } finally {
    if (descriptor !== null) closeSync(descriptor);
  }
  if (bytes.length !== stat.size) {
    return failure("pinned_source_changed_during_read");
  }
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (digest !== binding.sha256) return failure("pinned_content_hash_mismatch");
  return Object.freeze({
    ok: true,
    binding,
    provenance_kind: "pinned_content",
    // The evidence reference states the proven fact and nothing stronger.
    evidence_ref: `pinned_content:${relativePath}#sha256:${binding.sha256}`,
    raw_bytes: bytes,
  });
}

/**
 * Verify pinned-content provenance for a registry source file. Returns
 * `{ok:true, binding, evidence_ref, provenance_kind:"pinned_content"}` or
 * `{ok:false, reason}`. The evidence_ref records exactly what was proven:
 * the contained relative path and the exact byte hash under the supplied
 * trusted root — no repository-authenticity claim.
 */
export function verifyPinnedContent({ sourcePath, trustedRoot }) {
  const verified = readVerifiedPinnedContent({ sourcePath, trustedRoot });
  if (!verified.ok) return verified;
  return Object.freeze({
    ok: true,
    binding: verified.binding,
    provenance_kind: verified.provenance_kind,
    evidence_ref: verified.evidence_ref,
  });
}

/**
 * Cross-check one registry entry against the code-owned authoritative
 * mappings and the documented action-class/effects conformance.
 */
export function registryEntryInconsistency(entry) {
  if (!ACTION_CLASSES.has(entry.action_class)) {
    return "registry_entry_action_class_unknown";
  }
  const codeOwned = DEFAULT_TOOL_CLASS[entry.tool]
    ?? CODE_OWNED_CONNECTOR_TOOL_CLASSES[entry.tool];
  if (codeOwned === undefined) return "registry_entry_tool_not_code_owned";
  if (codeOwned !== entry.action_class) {
    return "registry_entry_action_class_contradicts_code";
  }
  const effects = normalizeEffects(entry.effects);
  if (effects === null) return "registry_entry_effects_invalid";
  const expected = ACTION_CLASS_EFFECTS[entry.action_class];
  if (effects.length !== expected.length
      || !expected.every((value, index) => effects[index] === value)) {
    return "registry_entry_effects_inconsistent_with_action_class";
  }
  return null;
}

function safeRegistryLabel(value) {
  return typeof value === "string"
    && WIRE_SAFE_LABEL_RE.test(value)
    && sensitiveValueReason(value) === null;
}

function candidateClassification(classification) {
  return Object.freeze({
    status: classification.status,
    method: classification.method,
    evidence: Object.freeze([...classification.evidence]),
    confirmed_by: classification.confirmed_by,
    confirmed_at: classification.confirmed_at,
    rationale: classification.rationale,
  });
}

/**
 * Pure, non-recursive derivation of every candidate field whose semantics
 * come from one verified registry entry. Both the discovery producer and the
 * consumer validator use this function, so a candidate cannot substitute its
 * own internally consistent story for the exact pinned entry.
 */
export function deriveRegistryCandidateSemantics({
  document, entry, provenance, sourceDocumentSha256,
}) {
  if (!provenance || provenance.ok !== true || !provenance.binding) {
    return failure("registry_provenance_unverified");
  }
  const { binding } = provenance;
  if (binding.source_kind !== "committed_registry_v1"
      || document?.code_owned !== true
      || document?.source_id !== binding.source_id
      || sourceDocumentSha256 !== `sha256:${binding.sha256}`) {
    return failure("registry_source_binding_mismatch");
  }
  const inconsistency = registryEntryInconsistency(entry);
  if (inconsistency !== null) return failure(inconsistency);
  const evidence = [
    provenance.evidence_ref,
    ...(Array.isArray(entry.evidence)
      ? entry.evidence.filter((value) => typeof value === "string"
        && value.length > 0 && value.length <= 256
        && sensitiveValueReason(value) === null)
      : []),
  ];
  const classification = classificationFromCodeOwnedRegistry({
    effects: entry.effects,
    evidence,
    rationale: typeof entry.rationale === "string" ? entry.rationale : undefined,
  });
  if (classification === null) return failure("registry_entry_unclassifiable");
  const fingerprint = fingerprintOperation({
    operationName: entry.tool,
    parameterLocation: "parameters",
    parameters: entry.parameters ?? null,
  });
  const reversibility = REVERSIBILITIES.has(entry.reversibility)
    ? entry.reversibility
    : "unknown";
  const targetResourceClass = safeRegistryLabel(entry.target_resource_class)
    ? entry.target_resource_class
    : "unknown";
  const dataClasses = Array.isArray(entry.data_classes)
    ? entry.data_classes.filter(safeRegistryLabel)
    : [];
  const sideEffects = Array.isArray(entry.side_effects)
    ? entry.side_effects.filter(safeRegistryLabel)
    : [];
  const completionEvidence = COMPLETION_EVIDENCES.has(entry.completion_evidence)
    ? entry.completion_evidence
    : "UNKNOWN";
  const unresolved = entry.parameters === undefined
    ? ["parameters_schema_absent"]
    : [];
  const classificationRecord = candidateClassification(classification);
  const proposedRisk = proposeRisk({
    classification,
    reversibility,
    targetResourceClass,
    dataClasses,
    authoritativeActionClass: entry.action_class,
    authoritativeSource: provenance.evidence_ref,
  });
  return Object.freeze({
    ok: true,
    binding,
    fields: Object.freeze({
      automap_version: AUTOMAP_VERSION,
      source_id: document.source_id,
      native_tool_name: entry.tool,
      native_operation_name: null,
      normalized_capability: entry.tool,
      discovery_method: "committed_registry_v1",
      native_schema_ref: `registry[${entry.tool}].parameters`,
      source_document_sha256: sourceDocumentSha256,
      structural_schema_fingerprint: fingerprint.structural_fingerprint,
      metadata_fingerprint: fingerprint.metadata_fingerprint,
      structural_paths: Object.freeze([...fingerprint.structural_paths]),
      target_resource_class: targetResourceClass,
      effects: Object.freeze([...classification.effects]),
      classification: classificationRecord,
      reversibility,
      possible_side_effects: Object.freeze([...sideEffects]),
      data_classes: Object.freeze(
        dataClasses.length > 0 ? [...dataClasses] : ["unknown"],
      ),
      completion_evidence_availability: completionEvidence,
      required_policy_attributes: REGISTRY_REQUIRED_POLICY_ATTRIBUTES,
      mapping_confidence: "deterministic",
      unresolved_questions: Object.freeze(unresolved),
      proposed_risk: proposedRisk,
    }),
  });
}

/**
 * Load the exact default-root bytes for one binding and derive every valid,
 * unambiguous registry entry. This is the set-level source of truth used to
 * reject deleted, inserted, or reordered committed-registry candidates.
 */
export function loadPinnedRegistryCandidateSemanticSet({
  sourceKind, sourceId, sourceDocumentSha256,
}) {
  const binding = PINNED_REGISTRY_BINDINGS.find((entry) => (
    entry.source_kind === sourceKind
    && entry.source_id === sourceId
    && sourceDocumentSha256 === `sha256:${entry.sha256}`
  ));
  if (!binding) return failure("pinned_registry_binding_not_found");
  const verified = readVerifiedPinnedContent({
    sourcePath: resolve(
      DEFAULT_TRUSTED_ROOT, binding.repository_relative_path,
    ),
    trustedRoot: DEFAULT_TRUSTED_ROOT,
  });
  if (!verified.ok) {
    return failure(`pinned_registry_${verified.reason}`);
  }
  let document;
  try {
    document = JSON.parse(verified.raw_bytes.toString("utf8"));
  } catch {
    return failure("pinned_registry_malformed_json");
  }
  const contract = validateArtifact(REGISTRY_SCHEMA, document);
  if (!contract.ok) return failure("pinned_registry_contract_invalid");
  if (document.code_owned !== true || document.source_id !== binding.source_id) {
    return failure("pinned_registry_identity_mismatch");
  }
  const derivedFields = [];
  for (const entry of document.registry) {
    const derived = deriveRegistryCandidateSemantics({
      document,
      entry,
      provenance: verified,
      sourceDocumentSha256,
    });
    // Mirror the producer: inconsistent entries generate errors and no
    // candidate. The currently pinned registry contains no such entry.
    if (derived.ok) derivedFields.push(derived.fields);
  }
  const toolCounts = new Map();
  for (const fields of derivedFields) {
    toolCounts.set(fields.native_tool_name,
      (toolCounts.get(fields.native_tool_name) ?? 0) + 1);
  }
  // Discovery excludes every duplicate candidate identity rather than
  // retaining whichever occurrence happened to appear first.
  const fields = derivedFields.filter(
    (candidateFields) => toolCounts.get(
      candidateFields.native_tool_name,
    ) === 1,
  );
  return Object.freeze({
    ok: true,
    binding,
    fields: Object.freeze(fields),
  });
}

/**
 * Resolve one tool from the fully derived pinned set without invoking
 * discovery or candidate validation.
 */
export function loadPinnedRegistryCandidateSemantics({
  sourceKind, sourceId, sourceDocumentSha256, tool,
}) {
  const semanticSet = loadPinnedRegistryCandidateSemanticSet({
    sourceKind, sourceId, sourceDocumentSha256,
  });
  if (!semanticSet.ok) return semanticSet;
  const matches = semanticSet.fields.filter(
    (fields) => fields.native_tool_name === tool,
  );
  if (matches.length !== 1) {
    return failure(matches.length === 0
      ? "pinned_registry_entry_not_found"
      : "pinned_registry_entry_ambiguous");
  }
  return Object.freeze({
    ok: true,
    binding: semanticSet.binding,
    fields: matches[0],
  });
}

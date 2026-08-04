import { createHash } from "node:crypto";

import { canonicalizeJson } from "../governance-core/canonical.mjs";

// Host-shape invariants shared by every approved OpenClaw target.
//
// These are the conventions the observer relies on to locate and address a
// runtime. They were re-audited against each approved build; a target whose
// shape differs may not be added here, because the observer's path, endpoint,
// and RPC assumptions would no longer hold.
const OPENCLAW_TARGET_SHAPE = Object.freeze({
  profile_binding_required: true,
  supported_profile_modes: Object.freeze(["DEFAULT", "NAMED"]),
  default_state_identity: ".openclaw",
  named_state_prefix: ".openclaw-",
  config_basename: "openclaw.json",
  runtime_identity: ".local/lib/node_modules/openclaw/openclaw.mjs",
  endpoint_identity: "ws://127.0.0.1:18789",
  rpc_methods: Object.freeze(["agents.list", "tools.catalog"]),
  authority: "NONE",
  enforcement: false,
  automatic_mapping_activation: false,
  outbound_actions: false,
  registry_mutation: false,
});

// Exact per-build identities. Every field here is content-addressed or an
// exact build coordinate. A runtime is approved only when ALL FIVE fields of
// one entry match simultaneously; fields are never combined across entries.
//
// Order is significant only for `OPENCLAW_CANARY_TARGET`, which remains the
// originally audited 2026.6.5 build.
const OPENCLAW_TARGET_IDENTITIES = Object.freeze([
  Object.freeze({
    semantic_version: "2026.6.5",
    full_build_commit: "5181e4f7c82bd373cb215a5619b0fa03c13862b7",
    runtime_entry_sha256:
      "ea04d15e53edc9ea4a1e7761b809703ffbc345e41defb8c6d7d69aa8c0969d1c",
    package_json_sha256:
      "af4e4f145ce5161eeba53c1408ac06c7df183b52edf5d199ddee5b85c492adb0",
    build_info_sha256:
      "6a63416e1a305710d943303019a952100015a6a1b5e515faa2987864878ef6c0",
  }),
  Object.freeze({
    semantic_version: "2026.7.1-2",
    full_build_commit: "0790d9f593ad30c940ed93b5872a8cf6d6f3cf8c",
    runtime_entry_sha256:
      "f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188",
    package_json_sha256:
      "695b6ee36df7fc69606dc390cf97bb2ca809114337b18c573707637cd2a4e3db",
    build_info_sha256:
      "e45942b82f7e17d0be4ce38483f1da99c2dbfdfabad3c55fbfd3b3bb970b9e33",
  }),
  // The published `extended-stable` build. It is a 2026.6 maintenance branch
  // built after the 2026.7 line, so nothing about it is inferred from
  // 2026.6.5: its host shape was re-reviewed and its full live lifecycle was
  // re-proven against this exact build. It does not carry the 2026.7
  // `isLocalCliSharedAuth` device-identity omission, so a local CLI still
  // obtains a device-bound operator token here.
  //
  // Approval is bound to these five fields, never to the `extended-stable`
  // dist-tag, which upstream may move to a different build at any time.
  Object.freeze({
    semantic_version: "2026.6.33",
    full_build_commit: "7af0cfc9c5488e03c4e2f528bdc7ac9f7778b35e",
    runtime_entry_sha256:
      "f1f1c6ae5745ba0cb71bfbb72f4ae43f9b3bdb5ca0af84d5fcdf60eb5ab71430",
    package_json_sha256:
      "3f959e5b4463e603dbe238b4ee47b33ee2c58b71030a17bdeb69e480086f0774",
    build_info_sha256:
      "cfba85b4a9f5997210044a1a6576b50f8839fd974d2951ce027bcd66fcda7925",
  }),
]);

function freezeTarget(identity) {
  return Object.freeze({
    ...OPENCLAW_TARGET_SHAPE,
    supported_profile_modes: Object.freeze([
      ...OPENCLAW_TARGET_SHAPE.supported_profile_modes,
    ]),
    rpc_methods: Object.freeze([...OPENCLAW_TARGET_SHAPE.rpc_methods]),
    ...identity,
  });
}

// Every approved target, in audit order.
export const OPENCLAW_CANARY_TARGETS = Object.freeze(
  OPENCLAW_TARGET_IDENTITIES.map(freezeTarget),
);

// The originally audited target. Consumers that need only the shared host
// shape (paths, endpoint, RPC methods, authority ceilings) may read it from
// here; those values are identical across every approved target. Consumers
// that need a build identity must resolve the target instead.
export const OPENCLAW_CANARY_TARGET = OPENCLAW_CANARY_TARGETS[0];

// Fields that must all match one approved entry for a runtime to be accepted.
const IDENTITY_FIELDS = Object.freeze([
  "semantic_version",
  "full_build_commit",
  "runtime_entry_sha256",
  "package_json_sha256",
  "build_info_sha256",
]);

export const OPENCLAW_APPROVED_RUNTIME_VERSIONS = Object.freeze(
  OPENCLAW_CANARY_TARGETS.map((target) => target.semantic_version),
);

/**
 * Resolve an observed runtime to exactly one approved target.
 *
 * Fails closed: returns null unless every identity field matches the SAME
 * approved entry. A runtime that mixes fields across approved targets — for
 * example one build's commit with another build's entry hash — never
 * resolves.
 */
export function resolveOpenClawCanaryTarget(observed) {
  if (!observed || typeof observed !== "object" || Array.isArray(observed)) {
    return null;
  }
  const matched = OPENCLAW_CANARY_TARGETS.filter((target) => (
    IDENTITY_FIELDS.every((field) => (
      typeof observed[field] === "string"
        && observed[field] === target[field]
    ))
  ));
  return matched.length === 1 ? matched[0] : null;
}

function invalid(code) {
  const error = new TypeError(code);
  error.code = code;
  throw error;
}

function bindingFor(target, sourceCommit) {
  return Object.freeze({
    schema: "mcpherson-governance-openclaw-canary-target-binding/v2",
    ...target,
    supported_profile_modes: Object.freeze([...target.supported_profile_modes]),
    rpc_methods: Object.freeze([...target.rpc_methods]),
    source_commit: sourceCommit,
  });
}

function assertSourceCommit(sourceCommit) {
  if (typeof sourceCommit !== "string"
      || !/^[a-f0-9]{40}$/.test(sourceCommit)) {
    invalid("live_target_source_commit_invalid");
  }
}

/**
 * The originally audited 2026.6.5 binding. Its canonical bytes, and therefore
 * its binding id, are unchanged by the addition of further approved targets.
 */
export function buildOpenClawCanaryTargetBinding(sourceCommit) {
  assertSourceCommit(sourceCommit);
  return bindingFor(OPENCLAW_CANARY_TARGET, sourceCommit);
}

/** One binding per approved target, in audit order. */
export function buildOpenClawCanaryTargetBindings(sourceCommit) {
  assertSourceCommit(sourceCommit);
  return Object.freeze(
    OPENCLAW_CANARY_TARGETS.map((target) => bindingFor(target, sourceCommit)),
  );
}

export function openClawCanaryTargetBindingId(targetBinding) {
  return createHash("sha256")
    .update(canonicalizeJson(targetBinding), "utf8")
    .digest("hex");
}

export function buildOpenClawCanaryTargetManifestFields(sourceCommit) {
  const targetBindings = buildOpenClawCanaryTargetBindings(sourceCommit);
  return Object.freeze({
    target_bindings: targetBindings,
    target_binding_ids: Object.freeze(
      targetBindings.map(openClawCanaryTargetBindingId),
    ),
  });
}

/**
 * Resolve one approved binding by its binding id.
 *
 * Fails closed: returns null for any id outside the approved set.
 */
export function approvedTargetBindingById(sourceCommit, bindingId) {
  if (typeof bindingId !== "string") return null;
  const bindings = buildOpenClawCanaryTargetBindings(sourceCommit);
  const matched = bindings.filter(
    (binding) => openClawCanaryTargetBindingId(binding) === bindingId,
  );
  return matched.length === 1 ? matched[0] : null;
}

/**
 * Binding id of the approved target with this exact build coordinate.
 *
 * Fails closed: returns null unless the version and full commit together name
 * exactly one approved target.
 */
export function approvedTargetBindingIdFor(
  sourceCommit, semanticVersion, fullBuildCommit,
) {
  const bindings = buildOpenClawCanaryTargetBindings(sourceCommit);
  const matched = bindings.filter((binding) => (
    binding.semantic_version === semanticVersion
      && binding.full_build_commit === fullBuildCommit
  ));
  return matched.length === 1
    ? openClawCanaryTargetBindingId(matched[0])
    : null;
}

export function validateOpenClawCanaryTargetManifest(packageManifest) {
  if (!packageManifest || typeof packageManifest !== "object"
      || Array.isArray(packageManifest)
      || packageManifest.schema
        !== "mcpherson-governance-v06-internal-canary-package-manifest/v1"
      || !Array.isArray(packageManifest.source_files)
      || !Array.isArray(packageManifest.target_bindings)
      || !Array.isArray(packageManifest.target_binding_ids)) {
    invalid("live_package_manifest_invalid");
  }
  const expected = buildOpenClawCanaryTargetManifestFields(
    packageManifest.source_commit,
  );
  if (canonicalizeJson(packageManifest.target_bindings)
        !== canonicalizeJson(expected.target_bindings)
      || canonicalizeJson(packageManifest.target_binding_ids)
        !== canonicalizeJson(expected.target_binding_ids)) {
    invalid("live_package_target_binding_invalid");
  }
  return Object.freeze({
    source_commit: packageManifest.source_commit,
    target_bindings: expected.target_bindings,
    target_binding_ids: expected.target_binding_ids,
  });
}

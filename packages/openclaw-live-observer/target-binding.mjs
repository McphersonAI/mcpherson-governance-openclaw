import { createHash } from "node:crypto";

import { canonicalizeJson } from "../governance-core/canonical.mjs";

export const OPENCLAW_CANARY_TARGET = Object.freeze({
  profile_binding_required: true,
  supported_profile_modes: Object.freeze(["DEFAULT", "NAMED"]),
  default_state_identity: ".openclaw",
  named_state_prefix: ".openclaw-",
  config_basename: "openclaw.json",
  runtime_identity: ".local/lib/node_modules/openclaw/openclaw.mjs",
  endpoint_identity: "ws://127.0.0.1:18789",
  semantic_version: "2026.6.5",
  full_build_commit: "5181e4f7c82bd373cb215a5619b0fa03c13862b7",
  runtime_entry_sha256:
    "ea04d15e53edc9ea4a1e7761b809703ffbc345e41defb8c6d7d69aa8c0969d1c",
  package_json_sha256:
    "af4e4f145ce5161eeba53c1408ac06c7df183b52edf5d199ddee5b85c492adb0",
  build_info_sha256:
    "6a63416e1a305710d943303019a952100015a6a1b5e515faa2987864878ef6c0",
  rpc_methods: Object.freeze(["agents.list", "tools.catalog"]),
  authority: "NONE",
  enforcement: false,
  automatic_mapping_activation: false,
  outbound_actions: false,
  registry_mutation: false,
});

function invalid(code) {
  const error = new TypeError(code);
  error.code = code;
  throw error;
}

export function buildOpenClawCanaryTargetBinding(sourceCommit) {
  if (typeof sourceCommit !== "string"
      || !/^[a-f0-9]{40}$/.test(sourceCommit)) {
    invalid("live_target_source_commit_invalid");
  }
  return Object.freeze({
    schema: "mcpherson-governance-openclaw-canary-target-binding/v2",
    ...OPENCLAW_CANARY_TARGET,
    rpc_methods: Object.freeze([...OPENCLAW_CANARY_TARGET.rpc_methods]),
    source_commit: sourceCommit,
  });
}

export function openClawCanaryTargetBindingId(targetBinding) {
  return createHash("sha256")
    .update(canonicalizeJson(targetBinding), "utf8")
    .digest("hex");
}

export function buildOpenClawCanaryTargetManifestFields(sourceCommit) {
  const targetBinding = buildOpenClawCanaryTargetBinding(sourceCommit);
  return Object.freeze({
    target_binding: targetBinding,
    target_binding_id: openClawCanaryTargetBindingId(targetBinding),
  });
}

export function validateOpenClawCanaryTargetManifest(packageManifest) {
  if (!packageManifest || typeof packageManifest !== "object"
      || Array.isArray(packageManifest)
      || packageManifest.schema
        !== "mcpherson-governance-v06-internal-canary-package-manifest/v1"
      || !Array.isArray(packageManifest.source_files)) {
    invalid("live_package_manifest_invalid");
  }
  const expected = buildOpenClawCanaryTargetManifestFields(
    packageManifest.source_commit,
  );
  if (canonicalizeJson(packageManifest.target_binding)
        !== canonicalizeJson(expected.target_binding)
      || packageManifest.target_binding_id !== expected.target_binding_id) {
    invalid("live_package_target_binding_invalid");
  }
  return Object.freeze({
    source_commit: packageManifest.source_commit,
    target_binding: expected.target_binding,
    target_binding_id: expected.target_binding_id,
  });
}

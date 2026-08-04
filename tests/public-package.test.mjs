// Self-test that runs inside the installed package.
//
//   npm test
//
// It re-runs the full package verification and asserts the safety properties
// this package publicly claims, so a user can confirm them without trusting the
// documentation.

import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyPackage } from "../scripts/verify-package.mjs";

const PACKAGE_ROOT = fileURLToPath(new URL("..", import.meta.url));

function read(relativePath) {
  return readFileSync(join(PACKAGE_ROOT, relativePath), "utf8");
}

function readJson(relativePath) {
  return JSON.parse(read(relativePath));
}

test("package verification passes with no failures", () => {
  const result = verifyPackage();
  assert.deepEqual(result.failures, []);
  assert.equal(result.ok, true);
});

test("public identities are preserved", () => {
  const pkg = readJson("package.json");
  const manifest = readJson("openclaw.plugin.json");
  assert.equal(pkg.name, "@mcphersonai/mcpherson-governance-openclaw");
  assert.equal(manifest.id, "mcpherson-governance-connector");
  assert.equal(pkg.version, manifest.version);
  assert.equal(pkg.openclaw.compat.pluginApi, ">=2026.6.5");
  assert.equal(Object.keys(pkg.bin)[0], "mcpherson-connector-ctl");
});

test("remote shadow is off by default and cannot be widened by config", () => {
  const manifest = readJson("openclaw.plugin.json");
  assert.equal(manifest.configSchema.properties.enabled.default, false);
  assert.equal(manifest.configSchema.additionalProperties, false);
});

test("authority ceilings are source constants", () => {
  const constants = read("plugins/openclaw-connector/constants.mjs");
  assert.match(constants, /export const REMOTE_AUTHORITY\s*=\s*false/);
  assert.match(
    constants,
    /export const ENFORCEABLE_REMOTE_DECISIONS\s*=\s*Object\.freeze\(\[\]\)/,
  );
  assert.match(constants, /deny_enforcement:\s*false/);
  assert.match(constants, /approval_enforcement:\s*false/);
});

test("no evaluator or gate filename is packaged and diagnosis is singular", () => {
  const paths = read("PACKAGE-FILES.sha256")
    .split("\n")
    .filter(Boolean)
    .map((line) => line.slice(66));
  assert.deepEqual(
    paths.filter((path) => ["evaluate.mjs", "gate.mjs"].includes(basename(path))),
    [],
  );
  assert.equal(
    paths.filter((path) => (
      path === "packages/governance-diagnostics/governor/diagnose-evidence.mjs"
    )).length,
    1,
  );
  const allowedCore = new Set([
    "packages/governance-core/canonical.mjs",
    "packages/governance-core/classify.mjs",
    "packages/governance-core/contracts.mjs",
    "packages/governance-core/errors.mjs",
    "packages/governance-core/policy-validate.mjs",
  ]);
  assert.deepEqual(
    paths.filter((path) => (
      path.startsWith("packages/governance-core/") && !allowedCore.has(path)
    )),
    [],
  );
});

test("an unconfigured tool is kept local and never reaches the network", () => {
  const hook = read("plugins/openclaw-connector/hook.mjs");
  // The unconfigured branch records locally and returns before the pipeline
  // submit call, so no HTTPS request can occur for that tool.
  assert.match(hook, /if \(!Object\.hasOwn\(this\.#config\.toolMetadata, summary\.toolId\)\)/);
  const branch = hook.slice(hook.indexOf("!Object.hasOwn(this.#config.toolMetadata"));
  const recordLocal = branch.indexOf('recordLocal(summary, "NOT_ATTEMPTED", "SKIPPED")');
  const submit = branch.indexOf("this.#pipeline.submit(");
  assert.ok(recordLocal !== -1, "unconfigured branch must record NOT_ATTEMPTED/SKIPPED");
  assert.ok(recordLocal < submit, "unconfigured branch must return before submit");
});

test("the documented V6 command surface is present", () => {
  const cli = read("scripts/governance-diagnostics.mjs");
  for (const command of [
    "init-profile-binding", "verify-profile-binding",
    "observe-live", "verify-observation", "discover",
    "propose", "govern", "render-diagnosis",
  ]) {
    assert.ok(cli.includes(`"${command}"`), `missing command ${command}`);
  }
  assert.ok(cli.includes('"profile-binding-id"'));
  // There is deliberately no registry-mutation command.
  assert.equal(cli.includes('"apply-registry-patch"'), false);
});

test("package target requires an exact explicit local profile binding", () => {
  const packageManifest = readJson("V6-PACKAGE-MANIFEST.json");
  assert.equal(
    packageManifest.schema,
    "mcpherson-governance-v06-internal-canary-package-manifest/v1",
  );
  assert.equal(
    packageManifest.package_name,
    "@mcphersonai/mcpherson-governance-openclaw",
  );
  assert.equal(packageManifest.plugin_id, "mcpherson-governance-connector");
  assert.equal(packageManifest.plugin_version, "0.6.1");
  assert.equal(packageManifest.target_bindings[0].profile_binding_required, true);
  assert.deepEqual(
    packageManifest.target_bindings[0].supported_profile_modes,
    ["DEFAULT", "NAMED"],
  );
  assert.equal(packageManifest.target_bindings[0].default_state_identity, ".openclaw");
  assert.equal(packageManifest.target_bindings[0].named_state_prefix, ".openclaw-");
  assert.equal(packageManifest.target_bindings[0].config_basename, "openclaw.json");
  // The package carries the full approved target set, and no approved target
  // is a prerelease build.
  assert.equal(packageManifest.target_bindings.length, 3);
  assert.equal(packageManifest.target_binding_ids.length, 3);
  assert.deepEqual(
    packageManifest.target_bindings.map((b) => b.semantic_version),
    ["2026.6.5", "2026.7.1-2", "2026.6.33"],
  );
  for (const binding of packageManifest.target_bindings) {
    assert.doesNotMatch(binding.semantic_version, /alpha|beta|rc/i);
    assert.match(binding.full_build_commit, /^[a-f0-9]{40}$/);
    assert.equal(binding.authority, "NONE");
    assert.equal(binding.enforcement, false);
  }
  assert.equal(
    packageManifest.target_bindings[0].runtime_identity,
    ".local/lib/node_modules/openclaw/openclaw.mjs",
  );
});

test("named-profile documentation and observer bind the exact local ledger", () => {
  const install = read("INSTALL.md");
  for (const required of [
    "secrets.providers.default",
    "--provider-mode singleValue",
    "--ref-source file --ref-id value",
    "gateway call health --json",
    "plugins disable",
    "plugins enable",
    'chmod 0700 "$PROFILE_STATE"',
    "LIVE_STATE_ROOT_INVALID_PERMISSIONS_INSECURE",
    "$PROFILE_STATE/mcpherson-governance-connector/receipts/connector-receipts.jsonl",
  ]) assert.ok(install.includes(required), `INSTALL.md missing ${required}`);
  const observer = read("packages/openclaw-live-observer/index.mjs");
  assert.ok(observer.includes('CONNECTOR_RECEIPT_DIRECTORY = "receipts"'));
  assert.ok(observer.includes('fail("live_receipt_path_binding_mismatch")'));
  assert.ok(observer.includes('fail("live_profile_binding_noncanonical")'));
  assert.ok(observer.includes('fail("live_named_reserved_profile_refused")'));
});

test("provenance records the fixed safety boundary", () => {
  const provenance = readJson("RELEASE-PROVENANCE.json");
  assert.deepEqual(provenance.authority, {
    AUTHORITY: "NONE",
    ENFORCEMENT: "OFF",
    AUTOMATIC_MAPPING_ACTIVATION: "OFF",
    OUTBOUND_ACTIONS: "OFF",
    REGISTRY_MUTATION: "OFF",
    REMOTE_DECISIONS: "SHADOW_ONLY",
  });
  assert.match(provenance.source_commit, /^[a-f0-9]{40}$/);
  assert.match(provenance.source_tree, /^[a-f0-9]{40}$/);
});

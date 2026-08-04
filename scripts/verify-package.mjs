#!/usr/bin/env node
// Verify this installed package against its own checksum manifest, declared
// identities, and safety constants. Fails closed and exits non-zero on any
// mismatch.
//
// Run from the package root:  node scripts/verify-package.mjs

import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import { basename, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE_ROOT = resolve(join(fileURLToPath(new URL(".", import.meta.url)), ".."));
const CHECKSUM_NAME = "PACKAGE-FILES.sha256";
const PROVENANCE_NAME = "RELEASE-PROVENANCE.json";
const PACKAGE_MANIFEST_NAME = "V6-PACKAGE-MANIFEST.json";
const EXPECTED_PACKAGE = "@mcphersonai/mcpherson-governance-openclaw";
const EXPECTED_PLUGIN_ID = "mcpherson-governance-connector";
const EXPECTED_COMPAT = ">=2026.6.5";
const EXPECTED_OPENCLAW_TARGET_SHAPE = Object.freeze({
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

// Every approved OpenClaw build, in audit order. Declared independently here
// so verification never trusts the package's own copy.
const EXPECTED_OPENCLAW_TARGET_IDENTITIES = Object.freeze([
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
const PROHIBITED_CONTENT = Object.freeze([
  ["private home path", /(?:\/Users\/[A-Za-z0-9._-]+\/|\/home\/[A-Za-z0-9._-]+\/|[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\)/],
  ["credential token", /mgd1_[a-f0-9]{32}\.[A-Za-z0-9_-]{43}/],
  ["private key", /-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |DSA )?PRIVATE KEY-----/],
  ["aws access key", /AKIA[0-9A-Z]{16}/],
]);
const PROHIBITED_ENTRYPOINT_BASENAMES = Object.freeze(new Set([
  "evaluate.mjs",
  "gate.mjs",
]));
const DIAGNOSTIC_ASSESSMENT_MODULE =
  "packages/governance-diagnostics/governor/diagnose-evidence.mjs";
const ALLOWED_GOVERNANCE_CORE_MODULES = Object.freeze(new Set([
  "packages/governance-core/canonical.mjs",
  "packages/governance-core/classify.mjs",
  "packages/governance-core/contracts.mjs",
  "packages/governance-core/errors.mjs",
  "packages/governance-core/policy-validate.mjs",
]));
const ALLOWED_BUILTINS = Object.freeze(new Set([
  "node:crypto", "node:fs", "node:https", "node:path", "node:os",
  "node:url", "node:util", "node:child_process", "node:net",
  "node:assert", "node:assert/strict", "node:test", "node:zlib",
  "node:fs/promises", "node:buffer", "node:events", "node:stream",
]));

const failures = [];
const checks = [];

function check(name, condition, detail = "") {
  if (condition) {
    checks.push(name);
    return true;
  }
  failures.push(detail ? `${name}: ${detail}` : name);
  return false;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonicalizeJson(value) {
  if (value === null || typeof value === "string"
      || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalizeJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`
    )).join(",")}}`;
  }
  throw new TypeError("package_target_json_invalid");
}

function validateOpenClawTargetManifest(packageManifest) {
  if (!packageManifest || typeof packageManifest !== "object"
      || Array.isArray(packageManifest)
      || packageManifest.schema
        !== "mcpherson-governance-v06-internal-canary-package-manifest/v1"
      || !Array.isArray(packageManifest.source_files)
      || !/^[a-f0-9]{40}$/.test(packageManifest.source_commit ?? "")) {
    throw new TypeError("package_manifest_invalid");
  }
  const targetBindings = EXPECTED_OPENCLAW_TARGET_IDENTITIES.map((identity) => ({
    schema: "mcpherson-governance-openclaw-canary-target-binding/v2",
    ...EXPECTED_OPENCLAW_TARGET_SHAPE,
    supported_profile_modes: [
      ...EXPECTED_OPENCLAW_TARGET_SHAPE.supported_profile_modes,
    ],
    rpc_methods: [...EXPECTED_OPENCLAW_TARGET_SHAPE.rpc_methods],
    ...identity,
    source_commit: packageManifest.source_commit,
  }));
  const targetBindingIds = targetBindings.map((binding) => (
    sha256(Buffer.from(canonicalizeJson(binding), "utf8"))
  ));
  if (!Array.isArray(packageManifest.target_bindings)
      || !Array.isArray(packageManifest.target_binding_ids)
      || canonicalizeJson(packageManifest.target_bindings)
        !== canonicalizeJson(targetBindings)
      || canonicalizeJson(packageManifest.target_binding_ids)
        !== canonicalizeJson(targetBindingIds)) {
    throw new TypeError("package_target_binding_invalid");
  }
  return Object.freeze({
    target_bindings: Object.freeze(targetBindings.map(Object.freeze)),
    target_binding_ids: Object.freeze(targetBindingIds),
  });
}

function walk(directory, found = []) {
  for (const name of readdirSync(directory).sort()) {
    const absolute = join(directory, name);
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink()) {
      failures.push(`symlink present: ${relative(PACKAGE_ROOT, absolute)}`);
      continue;
    }
    if (stat.isDirectory()) {
      if (name === "node_modules" || name === ".git") continue;
      walk(absolute, found);
    } else if (stat.isFile()) {
      found.push(relative(PACKAGE_ROOT, absolute).split(sep).join("/"));
    }
  }
  return found;
}

function readJson(relativePath) {
  return JSON.parse(readFileSync(join(PACKAGE_ROOT, relativePath), "utf8"));
}

export function verifyPackage() {
  failures.length = 0;
  checks.length = 0;

  for (const required of [CHECKSUM_NAME, PROVENANCE_NAME, PACKAGE_MANIFEST_NAME, "package.json", "openclaw.plugin.json"]) {
    if (!existsSync(join(PACKAGE_ROOT, required))) {
      failures.push(`missing required file: ${required}`);
    }
  }
  if (failures.length > 0) return report();

  // ---- inventory and checksums -------------------------------------------
  const declaredChecksums = new Map();
  for (const line of readFileSync(join(PACKAGE_ROOT, CHECKSUM_NAME), "utf8").split("\n")) {
    if (!line.trim()) continue;
    const match = /^([a-f0-9]{64})  (.+)$/.exec(line);
    if (!match) {
      failures.push(`malformed checksum line: ${line.slice(0, 80)}`);
      continue;
    }
    declaredChecksums.set(match[2], match[1]);
  }

  const present = new Set(walk(PACKAGE_ROOT));
  // The checksum manifest cannot contain its own hash.
  present.delete(CHECKSUM_NAME);

  const missing = [...declaredChecksums.keys()].filter((path) => !present.has(path));
  const unexpected = [...present].filter((path) => !declaredChecksums.has(path));
  check("no missing packaged files", missing.length === 0, missing.join(", "));
  check("no unexpected packaged files", unexpected.length === 0, unexpected.join(", "));

  let mismatched = 0;
  for (const [path, expected] of declaredChecksums) {
    if (!present.has(path)) continue;
    const actual = sha256(readFileSync(join(PACKAGE_ROOT, path)));
    if (actual !== expected) {
      mismatched += 1;
      failures.push(`checksum mismatch: ${path}`);
    }
  }
  check("every packaged file matches its recorded SHA-256", mismatched === 0);

  // ---- identities ---------------------------------------------------------
  const pkg = readJson("package.json");
  const manifest = readJson("openclaw.plugin.json");
  const provenance = readJson(PROVENANCE_NAME);
  const packageManifest = readJson(PACKAGE_MANIFEST_NAME);

  check("package name preserved", pkg.name === EXPECTED_PACKAGE, String(pkg.name));
  check("plugin id preserved", manifest.id === EXPECTED_PLUGIN_ID, String(manifest.id));
  check(
    "package.json and openclaw.plugin.json versions agree",
    pkg.version === manifest.version,
    `${pkg.version} vs ${manifest.version}`,
  );
  check(
    "provenance version matches package",
    provenance.version === pkg.version,
    `${provenance.version} vs ${pkg.version}`,
  );
  check(
    "OpenClaw compatibility floor preserved",
    pkg.openclaw?.compat?.pluginApi === EXPECTED_COMPAT,
    String(pkg.openclaw?.compat?.pluginApi),
  );
  // The build block names the preferred audited build. Re-derive it from the
  // independently declared approved target set rather than trusting the
  // package's own copy: the recorded version and short commit must belong to
  // one approved entry, and the short commit must prefix that entry's full
  // build commit.
  const declaredBuildTarget = EXPECTED_OPENCLAW_TARGET_IDENTITIES.find(
    (target) => target.semantic_version === pkg.openclaw?.build?.openclawVersion,
  );
  check(
    "build metadata names an approved OpenClaw target",
    Boolean(declaredBuildTarget),
    String(pkg.openclaw?.build?.openclawVersion),
  );
  check(
    "build metadata commit matches that target's full build commit",
    Boolean(declaredBuildTarget)
      && typeof pkg.openclaw?.build?.openclawCommit === "string"
      && pkg.openclaw.build.openclawCommit.length >= 7
      && declaredBuildTarget.full_build_commit.startsWith(
        pkg.openclaw.build.openclawCommit,
      ),
    `${pkg.openclaw?.build?.openclawCommit} vs ${declaredBuildTarget?.full_build_commit}`,
  );
  check(
    "build metadata records the POST_HOOK receipt mode",
    pkg.openclaw?.build?.receiptMode === "POST_HOOK",
    String(pkg.openclaw?.build?.receiptMode),
  );
  check(
    "config default enabled is false",
    manifest.configSchema?.properties?.enabled?.default === false,
  );
  check(
    "config schema refuses unknown keys",
    manifest.configSchema?.additionalProperties === false,
  );
  check(
    "no declared dependencies",
    !pkg.dependencies && !pkg.devDependencies
      && !pkg.peerDependencies && !pkg.bundledDependencies,
  );

  check(
    "package manifest identity matches public package",
    packageManifest.package_name === EXPECTED_PACKAGE
      && packageManifest.plugin_id === EXPECTED_PLUGIN_ID
      && packageManifest.plugin_version === pkg.version,
  );
  check(
    "package manifest source matches provenance",
    packageManifest.source_commit === provenance.source_commit
      && packageManifest.source_tree === provenance.source_tree,
  );
  let auditedTarget;
  try {
    auditedTarget = validateOpenClawTargetManifest(packageManifest);
  } catch (error) {
    failures.push(`package target binding is valid: ${error?.code ?? error?.message}`);
  }
  if (auditedTarget) {
    check(
      "package target requires an explicit local profile binding",
      auditedTarget.target_bindings[0].profile_binding_required === true,
    );
    check(
      "package target supports only explicit DEFAULT and NAMED modes",
      JSON.stringify(auditedTarget.target_bindings[0].supported_profile_modes)
        === JSON.stringify(["DEFAULT", "NAMED"]),
    );
    check(
      "package target paths are portable home-relative identities",
      auditedTarget.target_bindings[0].default_state_identity === ".openclaw"
        && auditedTarget.target_bindings[0].named_state_prefix === ".openclaw-"
        && auditedTarget.target_bindings[0].config_basename === "openclaw.json"
        && auditedTarget.target_bindings[0].runtime_identity
          === ".local/lib/node_modules/openclaw/openclaw.mjs",
    );
  }

  // ---- entrypoints resolve ------------------------------------------------
  const entrypoints = [
    pkg.main,
    ...(pkg.openclaw?.extensions ?? []),
    ...Object.values(pkg.bin ?? {}),
  ].map((value) => String(value).replace(/^\.\//, ""));
  const unresolved = entrypoints.filter((path) => !present.has(path));
  check("every declared entrypoint is present", unresolved.length === 0, unresolved.join(", "));
  const authorityEntrypoints = entrypoints.filter((path) => (
    PROHIBITED_ENTRYPOINT_BASENAMES.has(basename(path))
  ));
  check(
    "no evaluator or execution-gate entrypoint is declared",
    authorityEntrypoints.length === 0,
    authorityEntrypoints.join(", "),
  );

  const documentedCommands = [
    "init-profile-binding", "verify-profile-binding",
    "observe-live", "verify-observation", "discover",
    "propose", "govern", "render-diagnosis",
  ];
  const cliPath = "scripts/governance-diagnostics.mjs";
  if (check("diagnostics CLI is present", present.has(cliPath))) {
    const cli = readFileSync(join(PACKAGE_ROOT, cliPath), "utf8");
    const undocumented = documentedCommands.filter((command) => !cli.includes(`"${command}"`));
    check(
      "diagnostics CLI declares every documented command",
      undocumented.length === 0,
      undocumented.join(", "),
    );
    check(
      "diagnostics CLI requires an independent profile binding commitment",
      cli.includes('"profile-binding-id"'),
    );
  }

  // ---- authority ceiling --------------------------------------------------
  const constantsPath = "plugins/openclaw-connector/constants.mjs";
  if (check("connector constants are present", present.has(constantsPath))) {
    const constants = readFileSync(join(PACKAGE_ROOT, constantsPath), "utf8");
    check(
      "REMOTE_AUTHORITY is false",
      /export const REMOTE_AUTHORITY\s*=\s*false/.test(constants),
    );
    check(
      "ENFORCEABLE_REMOTE_DECISIONS is empty",
      /export const ENFORCEABLE_REMOTE_DECISIONS\s*=\s*Object\.freeze\(\[\]\)/.test(constants),
    );
    check(
      `plugin version constant is ${pkg.version}`,
      constants.includes(`export const PLUGIN_VERSION = "${pkg.version}";`),
    );
  }

  const observerPath = "packages/openclaw-live-observer/index.mjs";
  if (check("live observer is present", present.has(observerPath))) {
    const observer = readFileSync(join(PACKAGE_ROOT, observerPath), "utf8");
    check(
      "observer authority fields are NONE/off",
      /authority:\s*"NONE"/.test(observer) && /enforcement:\s*false/.test(observer),
    );
    check(
      `observer lifecycle pin is ${pkg.version}`,
      observer.includes(`export const LIVE_LIFECYCLE_PLUGIN_VERSION = "${pkg.version}";`),
    );
    check(
      "observer binds the exact profile-local receipt ledger",
      observer.includes('CONNECTOR_RECEIPT_DIRECTORY = "receipts"')
        && observer.includes('fail("live_receipt_path_binding_mismatch")'),
    );
    check(
      "observer enforces canonical binding bytes and reserved profiles",
      observer.includes('fail("live_profile_binding_noncanonical")')
        && observer.includes('fail("live_named_reserved_profile_refused")'),
    );
  }

  const installPath = "INSTALL.md";
  if (check("install guide is present", present.has(installPath))) {
    const install = readFileSync(join(PACKAGE_ROOT, installPath), "utf8");
    check(
      "install guide documents local identity bootstrap and exact ledger",
      [
        "--provider-mode singleValue",
        "--ref-source file --ref-id value",
        "gateway call health --json",
        "plugins disable",
        "plugins enable",
        'chmod 0700 "$PROFILE_STATE"',
        "LIVE_STATE_ROOT_INVALID_PERMISSIONS_INSECURE",
        "$PROFILE_STATE/mcpherson-governance-connector/receipts/connector-receipts.jsonl",
      ].every((marker) => install.includes(marker)),
    );
  }

  check(
    "provenance records AUTHORITY NONE and ENFORCEMENT OFF",
    provenance.authority?.AUTHORITY === "NONE"
      && provenance.authority?.ENFORCEMENT === "OFF",
  );

  // ---- no policy evaluator, gate, or second policy engine ----------------
  const authorityShaped = [...present].filter((path) => (
    PROHIBITED_ENTRYPOINT_BASENAMES.has(basename(path))
  ));
  check(
    "zero evaluate.mjs and zero gate.mjs files are packaged",
    authorityShaped.length === 0,
    authorityShaped.join(", "),
  );
  const diagnosticCopies = [...present].filter((path) => (
    path === DIAGNOSTIC_ASSESSMENT_MODULE
  ));
  check(
    "the diagnostic evidence-assessment module is packaged exactly once",
    diagnosticCopies.length === 1,
    String(diagnosticCopies.length),
  );
  const unexpectedGovernanceCore = [...present].filter((path) => (
    path.startsWith("packages/governance-core/")
      && !ALLOWED_GOVERNANCE_CORE_MODULES.has(path)
  ));
  check(
    "no second policy engine is packaged",
    unexpectedGovernanceCore.length === 0,
    unexpectedGovernanceCore.join(", "),
  );

  // ---- content hygiene and import discipline ------------------------------
  let contentHits = 0;
  const externalImports = new Set();
  const executionAuthorityImports = new Set();
  for (const path of present) {
    const bytes = readFileSync(join(PACKAGE_ROOT, path));
    const text = bytes.toString("utf8");
    for (const [label, pattern] of PROHIBITED_CONTENT) {
      if (pattern.test(text)) {
        contentHits += 1;
        failures.push(`${label} found in ${path}`);
      }
    }
    if (!path.endsWith(".mjs")) continue;
    const importRe = /(?:^|\s)(?:import|export)\s+(?:[\s\S]*?\sfrom\s+)?["']([^"']+)["']/g;
    let match;
    while ((match = importRe.exec(text)) !== null) {
      const specifier = match[1];
      if (specifier.startsWith(".")) {
        const target = resolve(join(PACKAGE_ROOT, path), "..", specifier);
        const packagedTarget = relative(PACKAGE_ROOT, target).split(sep).join("/");
        if (!existsSync(target)) {
          failures.push(`unresolved import ${specifier} in ${path}`);
        }
        const isExecutionRuntime = path.startsWith("plugins/openclaw-connector/")
          || path.startsWith("packages/openclaw-live-observer/");
        if (isExecutionRuntime
            && (packagedTarget === DIAGNOSTIC_ASSESSMENT_MODULE
              || PROHIBITED_ENTRYPOINT_BASENAMES.has(basename(packagedTarget)))) {
          executionAuthorityImports.add(`${packagedTarget} (${path})`);
        }
        continue;
      }
      if (!ALLOWED_BUILTINS.has(specifier)) externalImports.add(`${specifier} (${path})`);
    }
  }
  check("no private paths or credential-shaped material", contentHits === 0);
  check(
    "every import is a sibling module or an allowed Node built-in",
    externalImports.size === 0,
    [...externalImports].join(", "),
  );
  check(
    "execution runtime has no evaluator, gate, or diagnostic-assessment import path",
    executionAuthorityImports.size === 0,
    [...executionAuthorityImports].join(", "),
  );

  return report();
}

function report() {
  const ok = failures.length === 0;
  const result = {
    ok,
    package_root: PACKAGE_ROOT,
    checks_passed: checks.length,
    failures,
  };
  console.log(JSON.stringify(result, null, 2));
  return result;
}

// Entry guard resolved through realpath so an invocation via a symlinked path
// (for example macOS $TMPDIR, where /var is a symlink to /private/var) still
// runs instead of silently loading as an inert module and exiting 0.
function isDirectInvocation() {
  const argv = process.argv[1];
  if (!argv) return false;
  const self = fileURLToPath(import.meta.url);
  try {
    return realpathSync(argv) === realpathSync(self);
  } catch {
    return resolve(argv) === resolve(self);
  }
}

if (isDirectInvocation()) {
  process.exit(verifyPackage().ok ? 0 : 1);
}

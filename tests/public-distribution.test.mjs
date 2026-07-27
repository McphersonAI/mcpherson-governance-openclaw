// Public distribution structure test.
//
// WHY THIS FILE EXISTS
// ────────────────────
// The internal build's suite contains one assertion that is deliberately
// invalid for the public distribution package:
//
//     tests/connector/operator-structure.test.mjs
//     test("package is private v0.5.0 and declares only inspected supported
//           hooks at runtime")
//       -> assert.equal(pkg.private, true)
//
//   * The INTERNAL INSTALLER expects `"private": true`. That is correct for an
//     internal production-shadow artifact, which must never be publishable.
//   * The PUBLIC DISTRIBUTION deliberately expects public package metadata:
//     no `private` flag, a scoped public name, a license, and source URLs.
//     `"private": true` is npm's refuse-to-publish flag; leaving it in place
//     would block distribution and misrepresent the package.
//
// This is a PACKAGING-CONTRACT DIFFERENCE, NOT A RUNTIME CHANGE. The sealed
// connector inventory contains 28 files; the public connector matches 27/28.
// All 23 `.mjs` runtime files remain byte-identical. Only
// `connector/package.json` metadata differs.
//
// This file therefore does NOT copy the internal assertion and mark it
// skipped. It asserts the *public* contract that replaces it, and it re-checks
// every still-applicable property the internal test covered (compatibility
// grounding, receipt mode, remote authority, enforceable decisions, and the
// absence of active enforcement) against the public package.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(join(dirname(fileURLToPath(import.meta.url)), ".."));
const readJson = (p) => JSON.parse(readFileSync(join(ROOT, p), "utf8"));

const rootPkg = readJson("package.json");
const connectorPkg = readJson("connector/package.json");
const rootManifest = readJson("openclaw.plugin.json");
const connectorManifest = readJson("connector/openclaw.plugin.json");

// The sealed v0.5 candidate's compatibility contract. Provenance: the
// `openclaw` block of the sealed installer's `connector/package.json`
// (installer SHA-256 1750c1be…dc3, source candidate a5f696f064d8),
// corroborated by the sealed `connector/README.md`, which names the exact
// integration target as OpenClaw 2026.6.5 (5181e4f). These values are carried
// over unchanged; they are not derived from any local OpenClaw installation.
const SEALED = Object.freeze({
  pluginApi: ">=2026.6.5",
  openclawVersion: "2026.6.5",
  openclawCommit: "5181e4f",
  receiptMode: "POST_HOOK",
  version: "0.5.0",
});

const PUBLIC_NAME = "@mcphersonai/mcpherson-governance-openclaw";
const REPO_URL = "https://github.com/McphersonAI/mcpherson-governance-openclaw";
const ISSUES_URL = `${REPO_URL}/issues`;
const HOMEPAGE = "https://mcphersonai.com";

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

// ── Public packaging contract ───────────────────────────────────────────────

test("public package is NOT marked private (replaces the internal private assertion)", () => {
  // Internal installer expects private:true. Public distribution must not.
  assert.equal(
    Object.prototype.hasOwnProperty.call(rootPkg, "private"), false,
    "root package.json must not declare a `private` field",
  );
  assert.notEqual(rootPkg.private, true);
  assert.equal(
    Object.prototype.hasOwnProperty.call(connectorPkg, "private"), false,
    "connector/package.json must not declare a `private` field",
  );
  assert.notEqual(connectorPkg.private, true);
});

test("public package name is the approved ClawHub scope", () => {
  assert.equal(rootPkg.name, PUBLIC_NAME);
  // npm scopes are lowercase; the ClawHub owner handle (McphersonAI) is a
  // separate namespace and is supplied to the CLI, not stored here.
  assert.match(rootPkg.name, /^@mcphersonai\/[a-z0-9-]+$/);
});

test("version is 0.5.0 in every manifest", () => {
  assert.equal(rootPkg.version, SEALED.version);
  assert.equal(connectorPkg.version, SEALED.version);
  assert.equal(rootManifest.version, SEALED.version);
});

test("license is Apache-2.0 and license files are present", () => {
  assert.equal(rootPkg.license, "Apache-2.0");
  assert.equal(connectorPkg.license, "Apache-2.0");
  assert.equal(rootManifest.license, "Apache-2.0");

  const license = readFileSync(join(ROOT, "LICENSE"), "utf8");
  assert.match(license, /Apache License/);
  assert.match(license, /Version 2\.0/);
  assert.match(license, /Copyright 2026 McPherson AI LLC/);

  const notice = readFileSync(join(ROOT, "NOTICE"), "utf8");
  assert.match(notice, /McPherson AI LLC/);

  // the unresolved-license blocker must be gone
  assert.equal(existsSync(join(ROOT, "LICENSE-DECISION-REQUIRED.md")), false);
});

test("repository URL is correct in every manifest", () => {
  assert.equal(rootPkg.repository.type, "git");
  assert.equal(rootPkg.repository.url, `git+${REPO_URL}.git`);
  assert.equal(connectorPkg.repository.url, `git+${REPO_URL}.git`);
  assert.equal(rootManifest.repository, REPO_URL);
});

test("issues URL is correct", () => {
  assert.equal(rootPkg.bugs.url, ISSUES_URL);
  assert.equal(connectorPkg.bugs.url, ISSUES_URL);
});

test("homepage is correct", () => {
  assert.equal(rootPkg.homepage, HOMEPAGE);
  assert.equal(connectorPkg.homepage, HOMEPAGE);
  assert.equal(rootManifest.homepage, HOMEPAGE);
});

// ── Commands and entry points resolve ───────────────────────────────────────

test("public test command resolves inside the repository", () => {
  const command = rootPkg.scripts.test;
  assert.ok(command, "no test script declared");

  // must not escape the package root
  assert.equal(/\.\.\//.test(command), false,
    `test script escapes the package: ${command}`);

  // every script file the command references must exist inside the repository
  const targets = command.match(/[\w./-]+\.mjs/g) ?? [];
  assert.ok(targets.length > 0, `test script references no script file: ${command}`);
  for (const target of targets) {
    assert.equal(isAbsolute(target), false, `test script must use relative paths: ${target}`);
    assert.ok(existsSync(join(ROOT, target)),
      `test script target does not exist inside the repository: ${target}`);
  }

  // the release-engineering runner must also resolve
  const runner = rootPkg.scripts["test:public"].match(/[\w./-]+\.mjs/g) ?? [];
  for (const target of runner) {
    assert.ok(existsSync(join(ROOT, target)), `test:public target missing: ${target}`);
  }

  // the connector's own test script must resolve relative to connector/
  const connectorTargets = connectorPkg.scripts.test.match(/[\w./-]+\.mjs/g) ?? [];
  assert.ok(connectorTargets.length > 0, "connector test script references no file");
  for (const target of connectorTargets) {
    assert.ok(existsSync(join(ROOT, "connector", target)),
      `connector test target does not resolve: ${target}`);
  }
});

test("test files required by the public test command are packaged", () => {
  // `npm test` must work from an installed copy, so the test files it runs
  // have to be inside the published `files` list.
  const packaged = rootPkg.files;
  const referenced = (rootPkg.scripts.test.match(/[\w./-]+\.mjs/g) ?? []);
  for (const target of referenced) {
    const covered = packaged.some((entry) =>
      entry === target || (entry.endsWith("/") && target.startsWith(entry)));
    assert.ok(covered, `${target} is run by npm test but is not in package.files`);
  }
});

test("sealed provenance manifest and release artifact builder are packaged", () => {
  for (const target of [
    "SEALED-CONNECTOR-FILES.sha256",
    "scripts/build-release-artifacts.mjs",
  ]) {
    assert.ok(rootPkg.files.includes(target), `${target} is not in package.files`);
    assert.ok(existsSync(join(ROOT, target)), `${target} is missing`);
  }
});

test("CLI bin entries resolve to real executable sources", () => {
  for (const [name, target] of Object.entries(rootPkg.bin ?? {})) {
    assert.equal(target.startsWith("./"), false,
      `bin "${name}" must not use a "./" prefix (npm strips it): ${target}`);
    assert.ok(existsSync(join(ROOT, target)),
      `bin "${name}" does not resolve: ${target}`);
    assert.equal(readFileSync(join(ROOT, target), "utf8").split("\n", 1)[0],
      "#!/usr/bin/env node", `bin "${name}" has the wrong shebang`);
    assert.equal(statSync(join(ROOT, target)).mode & 0o777, 0o755,
      `bin "${name}" target is not mode 0755`);
  }
  for (const [name, target] of Object.entries(connectorPkg.bin ?? {})) {
    assert.equal(target.startsWith("./"), false,
      `connector bin "${name}" must not use a "./" prefix: ${target}`);
    assert.ok(existsSync(join(ROOT, "connector", target)),
      `connector bin "${name}" does not resolve: ${target}`);
    assert.equal(readFileSync(join(ROOT, "connector", target), "utf8").split("\n", 1)[0],
      "#!/usr/bin/env node", `connector bin "${name}" has the wrong shebang`);
    assert.equal(statSync(join(ROOT, "connector", target)).mode & 0o777, 0o755,
      `connector bin "${name}" target is not mode 0755`);
  }
});

test("declared OpenClaw extension entries resolve", () => {
  for (const entry of rootPkg.openclaw.extensions) {
    assert.ok(existsSync(join(ROOT, entry)), `extension entry missing: ${entry}`);
  }
  for (const entry of connectorPkg.openclaw.extensions) {
    assert.ok(existsSync(join(ROOT, "connector", entry)),
      `connector extension entry missing: ${entry}`);
  }
});

// ── Compatibility grounded in the sealed candidate ──────────────────────────

test("plugin API compatibility remains grounded in the sealed candidate", () => {
  assert.equal(connectorPkg.openclaw.compat.pluginApi, SEALED.pluginApi);
  assert.equal(rootPkg.openclaw.compat.pluginApi, SEALED.pluginApi);
  // root and connector must never drift apart
  assert.equal(rootPkg.openclaw.compat.pluginApi, connectorPkg.openclaw.compat.pluginApi);
});

test("OpenClaw build metadata remains grounded in the sealed candidate", () => {
  // the connector's build block must be exactly the sealed block
  assert.deepEqual(connectorPkg.openclaw.build, {
    openclawVersion: SEALED.openclawVersion,
    openclawCommit: SEALED.openclawCommit,
    receiptMode: SEALED.receiptMode,
  });
  assert.deepEqual(rootPkg.openclaw.build, connectorPkg.openclaw.build);
});

// ── Shadow-only runtime contract (still-applicable internal coverage) ───────

test("receipt mode remains POST_HOOK", async () => {
  const c = await import(pathToFileURL(join(ROOT, "connector/constants.mjs")).href);
  assert.equal(c.RECEIPT_MODE, SEALED.receiptMode);
  assert.equal(connectorPkg.openclaw.build.receiptMode, SEALED.receiptMode);
  assert.equal(rootPkg.openclaw.build.receiptMode, SEALED.receiptMode);
});

test("remote authority remains false", async () => {
  const c = await import(pathToFileURL(join(ROOT, "connector/constants.mjs")).href);
  assert.equal(c.REMOTE_AUTHORITY, false);
  assert.equal(c.DEFAULT_MODES.remote_authority, false);
  assert.equal(c.DEFAULT_MODES.remote_shadow, true);
  assert.equal(c.DEFAULT_MODES.deny_enforcement, false);
  assert.equal(c.DEFAULT_MODES.approval_enforcement, false);
  assert.equal(c.PLUGIN_VERSION, SEALED.version);
});

test("enforceable remote decisions remain empty", async () => {
  const c = await import(pathToFileURL(join(ROOT, "connector/constants.mjs")).href);
  assert.ok(Array.isArray(c.ENFORCEABLE_REMOTE_DECISIONS));
  assert.equal(c.ENFORCEABLE_REMOTE_DECISIONS.length, 0);
  assert.equal(Object.isFrozen(c.ENFORCEABLE_REMOTE_DECISIONS), true);
});

test("active enforcement remains absent from the shipped package", () => {
  // the policy evaluator and enforcement gate must not ship
  const core = join(ROOT, "connector/runtime/governance-core");
  assert.equal(existsSync(join(core, "evaluate.mjs")), false, "evaluate.mjs must not ship");
  assert.equal(existsSync(join(core, "gate.mjs")), false, "gate.mjs must not ship");

  // no remote path may construct a block; only the local canary may
  const offenders = walk(join(ROOT, "connector"))
    .filter((f) => f.endsWith(".mjs"))
    .filter((f) => /block:\s*true/.test(readFileSync(f, "utf8")))
    .filter((f) => !f.endsWith("canary.mjs"));
  assert.deepEqual(offenders, [], "blocking construction outside canary.mjs");

  // the remote observation path must not import an evaluator or approval gate
  const remote = ["allowlist.mjs", "client.mjs", "pipeline.mjs", "verify.mjs", "hook.mjs"]
    .map((n) => readFileSync(join(ROOT, "connector", n), "utf8"))
    .join("\n");
  assert.equal(remote.includes("requireApproval"), false);
  assert.equal(/return\s*\{\s*block\s*:/.test(remote), false);
  assert.equal(/event\.params\s*=/.test(remote), false);
  assert.match(remote, /return undefined;/);
});

test("configuration cannot raise authority in the public package", async () => {
  const { loadConnectorConfig } = await import(
    pathToFileURL(join(ROOT, "connector/config.mjs")).href);
  const { mkdtempSync, mkdirSync, chmodSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(join(tmpdir(), "mg-pubtest-"));
  mkdirSync(join(dir, "receipts"), { recursive: true });
  chmodSync(dir, 0o700); chmodSync(join(dir, "receipts"), 0o700);
  const base = {
    enabled: false, apiUrl: "https://governance.example.invalid:8443",
    deploymentId: "d", agentId: "a", policyVersion: 1,
    stateDir: dir, receiptDir: join(dir, "receipts"),
    toolMetadata: { t: { schemaVersion: "1.0.0", schemaHash: `sha256:${"0".repeat(64)}`, actionClass: "read_only_internal" } },
  };
  try {
    for (const key of ["remote_authority", "deny_enforcement", "approval_enforcement", "remote_shadow"]) {
      assert.throws(() => loadConnectorConfig({ ...base, [key]: true }), undefined,
        `${key} was not rejected`);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ── Manifest agreement ──────────────────────────────────────────────────────

test("public plugin manifest matches the sealed connector manifest in substance", () => {
  // The root manifest exists because ClawHub requires openclaw.plugin.json at
  // the package root. Its behavioural fields must be identical to the sealed
  // connector manifest; only presentation metadata differs.
  assert.equal(rootManifest.id, connectorManifest.id);
  assert.deepEqual(rootManifest.activation, connectorManifest.activation);
  assert.deepEqual(rootManifest.contracts, connectorManifest.contracts);
  assert.deepEqual(rootManifest.configSchema, connectorManifest.configSchema);
  assert.deepEqual(rootManifest.contracts.tools,
    ["mcpherson_connection_test", "mcpherson_governance_canary"]);
  assert.equal(rootManifest.configSchema.properties.enabled.default, false);
  assert.equal(rootManifest.configSchema.additionalProperties, false);
});

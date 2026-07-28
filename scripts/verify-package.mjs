#!/usr/bin/env node
// Self-contained public verification for the McPherson Governance Connector.
//
// This replaces the internal build's test script, whose path pointed at a test
// tree that is not shipped in the public package. It has no dependencies and
// makes no network calls. Run it from the package root:
//
//     npm test
//     node scripts/verify-package.mjs
//
// It verifies package integrity and the shadow-only invariants that this
// release's public claims rest on.

import { createHash } from "node:crypto";
import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const VERSION = "0.5.1";
const MIN_OPENCLAW = "2026.6.5";
const CONNECTOR_FILE_COUNT = 29;
const CONNECTOR_RUNTIME_COUNT = 24;
const SEALED_FILE_COUNT = 28;

// The EXACT, enumerated difference between this release's connector tree and
// the sealed v0.5.0 connector inventory. Every entry corresponds to a stated
// v0.5.1 finding in CHANGELOG.md. Anything outside this set — an unexpected
// added file, a changed runtime module, a removed sealed file — fails.
const SEALED_DELTA = Object.freeze({
  added: Object.freeze(["connector/host.mjs"]),
  changedRuntime: Object.freeze([
    "connector/config.mjs",
    "connector/constants.mjs",
    "connector/hook.mjs",
    "connector/index.mjs",
    "connector/pipeline.mjs",
  ]),
  changedMetadata: Object.freeze([
    "connector/openclaw.plugin.json",
    "connector/package.json",
  ]),
  changedDocs: Object.freeze([
    "connector/README.md",
  ]),
});

// CHANGELOG.md is a historical record: its superseded entries legitimately
// state the file counts that were true for earlier releases. Current-state
// documentation is checked against the current tree.
const HISTORICAL_DOCS = new Set(["CHANGELOG.md"]);

const results = [];
const record = (ok, name, detail) => results.push({ ok, name, detail });
const assert = (cond, msg) => { if (!cond) throw new Error(msg); };

async function check(name, fn) {
  try { record(true, name, (await fn()) ?? ""); }
  catch (e) { record(false, name, e.message); }
}

const sha256 = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");

function verifyManifest(manifestPath, base) {
  const lines = readFileSync(manifestPath, "utf8").split("\n").filter((l) => l.trim());
  let ok = 0;
  const failed = [];
  for (const line of lines) {
    const m = line.match(/^([a-f0-9]{64})\s+\*?(.+)$/);
    if (!m) { failed.push(`unparseable: ${line}`); continue; }
    const [, expected, rel] = m;
    const target = join(base, rel);
    if (!existsSync(target)) { failed.push(`missing: ${rel}`); continue; }
    if (sha256(target) !== expected) { failed.push(`MISMATCH: ${rel}`); continue; }
    ok += 1;
  }
  return { ok, failed, total: lines.length };
}

function readManifest(manifestPath) {
  const entries = new Map();
  const lines = readFileSync(manifestPath, "utf8").split("\n").filter((line) => line.trim());
  for (const line of lines) {
    const match = line.match(/^([a-f0-9]{64})\s+\*?(.+)$/);
    assert(match, `unparseable manifest line: ${line}`);
    const [, hash, path] = match;
    assert(!entries.has(path), `duplicate manifest path: ${path}`);
    entries.set(path, hash);
  }
  return entries;
}

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

// 1. connector byte manifest -------------------------------------------------
await check(`connector byte manifest verifies (${CONNECTOR_FILE_COUNT} files)`, () => {
  const { ok, failed, total } = verifyManifest(join(root, "CONNECTOR-FILES.sha256"), root);
  assert(failed.length === 0, `${failed.length} problem(s): ${failed.slice(0, 5).join("; ")}`);
  assert(total === CONNECTOR_FILE_COUNT,
    `expected ${CONNECTOR_FILE_COUNT} manifest entries, found ${total}`);
  return `${ok}/${total} match the public checksum manifest`;
});

// 2. sealed provenance identity ----------------------------------------------
await check("difference from the sealed v0.5.0 inventory is exactly the enumerated v0.5.1 set", () => {
  const sealed = readManifest(join(root, "SEALED-CONNECTOR-FILES.sha256"));
  const files = walk(join(root, "connector"))
    .map((path) => relative(root, path))
    .sort();
  assert(sealed.size === SEALED_FILE_COUNT,
    `expected ${SEALED_FILE_COUNT} sealed entries, found ${sealed.size}`);
  assert(files.length === CONNECTOR_FILE_COUNT,
    `expected ${CONNECTOR_FILE_COUNT} public connector files, found ${files.length}`);

  const expectedAdded = [...SEALED_DELTA.added].sort();
  const expectedChanged = [
    ...SEALED_DELTA.changedRuntime,
    ...SEALED_DELTA.changedMetadata,
    ...SEALED_DELTA.changedDocs,
  ].sort();

  const added = files.filter((path) => !sealed.has(path)).sort();
  assert(JSON.stringify(added) === JSON.stringify(expectedAdded),
    `unexpected added file set: ${added.join(", ") || "(none)"}`);

  const removed = [...sealed.keys()].filter((path) => !files.includes(path)).sort();
  assert(removed.length === 0, `sealed file removed: ${removed.join(", ")}`);

  const changed = files
    .filter((path) => sealed.has(path) && sha256(join(root, path)) !== sealed.get(path))
    .sort();
  assert(JSON.stringify(changed) === JSON.stringify(expectedChanged),
    `changed-file set differs from the declared v0.5.1 delta: ${changed.join(", ") || "(none)"}`);

  const unchanged = SEALED_FILE_COUNT - expectedChanged.length;
  const runtime = files.filter((path) => path.endsWith(".mjs"));
  assert(runtime.length === CONNECTOR_RUNTIME_COUNT,
    `expected ${CONNECTOR_RUNTIME_COUNT} .mjs runtime files, found ${runtime.length}`);

  // the embedded governance core must not drift in a patch release
  const coreChanged = changed.filter((path) => path.includes("runtime/governance-core"));
  assert(coreChanged.length === 0,
    `embedded governance core changed: ${coreChanged.join(", ")}`);

  return `${unchanged}/${SEALED_FILE_COUNT} sealed files byte-identical; `
    + `+${expectedAdded.length} added, ${SEALED_DELTA.changedRuntime.length} runtime, `
    + `${SEALED_DELTA.changedMetadata.length} metadata, `
    + `${SEALED_DELTA.changedDocs.length} doc file(s) changed; core unchanged`;
});

// 3. complete release checksum manifest --------------------------------------
await check("release checksum manifest covers the complete public package", () => {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const expected = new Set(["LICENSE", "README.md", "package.json"]);
  for (const entry of pkg.files) {
    const path = join(root, entry);
    if (entry.endsWith("/")) {
      for (const file of walk(path)) expected.add(relative(root, file));
    } else {
      expected.add(entry);
    }
  }
  expected.delete("RELEASE-CHECKSUMS.sha256");

  const manifest = readManifest(join(root, "RELEASE-CHECKSUMS.sha256"));
  const expectedPaths = [...expected].sort();
  const manifestPaths = [...manifest.keys()].sort();
  assert(JSON.stringify(expectedPaths) === JSON.stringify(manifestPaths),
    `release manifest inventory differs: expected ${expectedPaths.length}, found ${manifestPaths.length}`);
  const mismatches = expectedPaths.filter((path) =>
    sha256(join(root, path)) !== manifest.get(path));
  assert(mismatches.length === 0,
    `release checksum mismatch: ${mismatches.slice(0, 5).join(", ")}`);
  return `${manifest.size}/${expected.size} public package files match`;
});

// 4. documentation truth -----------------------------------------------------
await check("documentation states the exact connector identity boundary", () => {
  const runtimeCount = walk(join(root, "connector")).filter((path) => path.endsWith(".mjs")).length;
  const docs = walk(root).filter((path) => {
    const rel = relative(root, path);
    return path.endsWith(".md") && !rel.startsWith(".git/") && !HISTORICAL_DOCS.has(rel);
  });
  const documentedCounts = [];
  for (const path of docs) {
    const contents = readFileSync(path, "utf8");
    for (const match of contents.matchAll(/\b(\d+)\s+`?\.mjs`?/g)) {
      documentedCounts.push({
        path: relative(root, path),
        count: Number(match[1]),
      });
    }
  }
  assert(documentedCounts.length > 0, "no documented .mjs count found");
  const wrong = documentedCounts.filter(({ count }) => count !== runtimeCount);
  assert(wrong.length === 0,
    `documented .mjs count differs from ${runtimeCount}: ${
      wrong.map(({ path, count }) => `${path}=${count}`).join(", ")
    }`);

  // Every internal §N cross-reference must resolve to a real heading, so a
  // documentation repair cannot leave a dangling pointer behind.
  const limitations = readFileSync(join(root, "LIMITATIONS.md"), "utf8");
  const headings = new Set(
    [...limitations.matchAll(/^##\s+(\d+[a-z]?)\./gm)].map((m) => m[1]),
  );
  const dangling = [...new Set(
    [...limitations.matchAll(/§(\d+[a-z]?)/g)].map((m) => m[1]),
  )].filter((ref) => !headings.has(ref));
  assert(dangling.length === 0,
    `LIMITATIONS.md has dangling cross-reference(s): ${dangling.map((r) => `§${r}`).join(", ")}`);

  const verify = readFileSync(join(root, "VERIFY.md"), "utf8").replace(/\s+/g, " ");
  for (const required of [
    "Sealed v0.5.0 connector inventory: **28 files**",
    "Files v0.5.1 adds: **1** (`connector/host.mjs`)",
    "Sealed files carried over byte-identical: **20/28**",
    `Runtime modules (\`.mjs\`): **${CONNECTOR_RUNTIME_COUNT}**`,
    "verifies that the difference from that sealed inventory is **exactly** the enumerated set above",
  ]) {
    assert(verify.includes(required), `VERIFY.md is missing: ${required}`);
  }
  return `${documentedCounts.length} .mjs count claim(s) agree with actual count ${runtimeCount}`;
});

// 5. durable public lifecycle and claim boundaries ---------------------------
await check("public lifecycle wording is durable and makes no certification overclaim", () => {
  const docs = walk(root).filter((path) => path.endsWith(".md"));
  const joined = docs.map((path) => readFileSync(path, "utf8")).join("\n");
  const stale = joined.match(
    /\b(?:unreleased|unpublished|unaudited|pending audit|pending public release|release candidate only|public release candidate|not yet published|not been published|not been independently audited)\b/i,
  );
  assert(!stale, `stale lifecycle label remains: ${stale?.[0]}`);
  for (const overclaim of [
    /\bv0\.5\s+(?:is|provides)\s+(?:an?\s+)?active enforcement\b/i,
    /\bv0\.5\s+(?:is|provides)\s+(?:a\s+)?(?:safety|security|compliance) certification\b/i,
    /\bv0\.5\s+is\s+(?:safety|security|compliance)[ -]certified\b/i,
    /\bv0\.5\s+is guaranteed to block\b/i,
  ]) {
    assert(!overclaim.test(joined), `public documentation contains an overclaim: ${overclaim}`);
  }
  return "no stale lifecycle label or certification/enforcement overclaim";
});

// 6. no extra runtime file ---------------------------------------------------
await check(`connector tree contains exactly ${CONNECTOR_FILE_COUNT} files`, () => {
  const files = walk(join(root, "connector"));
  assert(files.length === CONNECTOR_FILE_COUNT, `found ${files.length} files in connector/`);
  return `${CONNECTOR_FILE_COUNT} files, no extras`;
});

// 7. embedded governance-core source hashes ----------------------------------
await check("embedded governance-core source hashes verify", () => {
  const base = join(root, "connector", "runtime", "governance-core");
  const { ok, failed, total } = verifyManifest(join(base, "SOURCE.sha256"), base);
  assert(failed.length === 0, failed.join("; "));
  return `${ok}/${total} match the embedded source manifest`;
});

// 8. enforcement modules absent ----------------------------------------------
await check("policy evaluator and gate are not shipped", () => {
  const base = join(root, "connector", "runtime", "governance-core");
  for (const f of ["evaluate.mjs", "gate.mjs"]) {
    assert(!existsSync(join(base, f)), `${f} is present but must not be shipped`);
  }
  return "evaluate.mjs absent, gate.mjs absent";
});

// 9. plugin manifest parses --------------------------------------------------
await check("plugin manifest parses (openclaw.plugin.json)", () => {
  const p = JSON.parse(readFileSync(join(root, "connector", "openclaw.plugin.json"), "utf8"));
  assert(p.id === "mcpherson-governance-connector", `unexpected id ${p.id}`);
  assert(p.configSchema?.additionalProperties === false, "config schema is not closed");
  return `id=${p.id}, tools=${p.contracts.tools.length}, closed schema`;
});

// 10. package metadata parses ------------------------------------------------
await check("package metadata parses and declares Apache-2.0", () => {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  assert(pkg.version === VERSION, `version is ${pkg.version}`);
  assert(pkg.license === "Apache-2.0", `license is ${pkg.license}`);
  assert(pkg.type === "module", `type is ${pkg.type}`);
  assert(pkg.private !== true, "package is marked private");
  const conn = JSON.parse(readFileSync(join(root, "connector", "package.json"), "utf8"));
  assert(conn.version === VERSION, `connector version is ${conn.version}`);
  assert(conn.license === "Apache-2.0", `connector license is ${conn.license}`);
  assert(conn.private !== true, "connector package is marked private");
  return `${pkg.name}@${pkg.version}, license=${pkg.license}`;
});

// 11. CLI source contract ----------------------------------------------------
await check("CLI bin targets have the node shebang and executable mode", () => {
  const rootPackage = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const connectorPackage = JSON.parse(readFileSync(join(root, "connector", "package.json"), "utf8"));
  const targets = [
    ...Object.values(rootPackage.bin ?? {}).map((path) => join(root, path)),
    ...Object.values(connectorPackage.bin ?? {}).map((path) => join(root, "connector", path)),
  ];
  assert(targets.length > 0, "no CLI bin target declared");
  for (const target of targets) {
    assert(existsSync(target), `CLI bin target is missing: ${relative(root, target)}`);
    const firstLine = readFileSync(target, "utf8").split("\n", 1)[0];
    assert(firstLine === "#!/usr/bin/env node",
      `CLI bin target has an incorrect shebang: ${relative(root, target)}`);
    const mode = statSync(target).mode & 0o777;
    assert(mode === 0o755,
      `CLI bin target mode is ${mode.toString(8)}, expected 755: ${relative(root, target)}`);
  }
  return `${targets.length} bin declaration(s), shebang=node, mode=755`;
});

// 12. license and notice present ---------------------------------------------
await check("LICENSE and NOTICE are present and correct", () => {
  const lic = readFileSync(join(root, "LICENSE"), "utf8");
  assert(/Apache License/.test(lic) && /Version 2\.0/.test(lic), "LICENSE is not Apache-2.0");
  assert(/Copyright 2026 McPherson AI LLC/.test(lic), "LICENSE lacks the copyright line");
  const notice = readFileSync(join(root, "NOTICE"), "utf8");
  assert(/McPherson AI LLC/.test(notice), "NOTICE lacks the copyright holder");
  assert(!existsSync(join(root, "LICENSE-DECISION-REQUIRED.md")), "license decision blocker still present");
  return "Apache-2.0 + NOTICE, no unresolved license blocker";
});

// 13. compatibility metadata is grounded -------------------------------------
await check("OpenClaw compatibility metadata matches the sealed connector", () => {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const conn = JSON.parse(readFileSync(join(root, "connector", "package.json"), "utf8"));
  assert(pkg.openclaw.compat.pluginApi === conn.openclaw.compat.pluginApi,
    "root and connector pluginApi disagree");
  assert(pkg.openclaw.build.openclawVersion === conn.openclaw.build.openclawVersion,
    "root and connector openclawVersion disagree");
  assert(pkg.openclaw.build.receiptMode === "POST_HOOK", "receipt mode is not POST_HOOK");
  return `pluginApi=${pkg.openclaw.compat.pluginApi}, openclawVersion=${pkg.openclaw.build.openclawVersion}`;
});

// 13a. release-artifact evidence root tracks the package version -------------
await check("release-artifact evidence root matches the package version", () => {
  // The release builder packages the committed HEAD and names its archive from
  // a hardcoded EVIDENCE_ROOT. If that drifts from the package version it would
  // emit an archive named for one version containing another.
  const builder = readFileSync(join(root, "scripts", "build-release-artifacts.mjs"), "utf8");
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const match = builder.match(/const EVIDENCE_ROOT = "([^"]+)";/);
  assert(match, "EVIDENCE_ROOT is not declared in the expected form");
  const expected = `mcpherson-governance-openclaw-v${pkg.version}`;
  assert(match[1] === expected,
    `EVIDENCE_ROOT is ${match[1]}, expected ${expected}`);
  return `${match[1]} == v${pkg.version}`;
});

// 13b. the primary example does not defeat profile isolation -----------------
await check("bundled example omits stateDir/receiptDir so profile isolation applies", () => {
  const raw = JSON.parse(readFileSync(join(root, "examples", "connector-config.example.json"), "utf8"));
  for (const key of ["stateDir", "receiptDir"]) {
    assert(!Object.prototype.hasOwnProperty.call(raw, key),
      `the bundled example hardcodes ${key}, which bypasses profile isolation`);
  }
  const readme = readFileSync(join(root, "examples", "README.md"), "utf8");
  assert(readme.includes("deliberately omits `stateDir` and `receiptDir`"),
    "examples/README.md does not explain the omission");
  assert(readme.includes("Optional explicit overrides"),
    "examples/README.md does not document the optional overrides separately");
  return "no explicit state paths; overrides documented separately";
});

// 14. extension entry resolves -----------------------------------------------
await check("declared OpenClaw extension entry resolves", () => {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const entries = pkg.openclaw.extensions;
  assert(Array.isArray(entries) && entries.length > 0, "no extension entry declared");
  for (const e of entries) {
    assert(existsSync(join(root, e)), `extension entry does not exist: ${e}`);
  }
  return entries.join(", ");
});

// 15. shadow-only invariants -------------------------------------------------
await check("shadow-only invariants hold in shipped source", async () => {
  const c = await import(pathToFileURL(join(root, "connector", "constants.mjs")).href);
  assert(c.PLUGIN_VERSION === VERSION, `version ${c.PLUGIN_VERSION}`);
  assert(c.REMOTE_AUTHORITY === false, "REMOTE_AUTHORITY is not false");
  assert(c.ENFORCEABLE_REMOTE_DECISIONS.length === 0, "enforceable remote decisions is not empty");
  assert(c.DEFAULT_MODES.remote_shadow === true, "remote_shadow is not true");
  assert(c.DEFAULT_MODES.remote_authority === false, "remote_authority is not false");
  assert(c.DEFAULT_MODES.deny_enforcement === false, "deny_enforcement is not false");
  assert(c.DEFAULT_MODES.approval_enforcement === false, "approval_enforcement is not false");
  assert(c.RECEIPT_MODE === "POST_HOOK", "receipt mode is not POST_HOOK");
  assert(c.MIN_SUPPORTED_OPENCLAW_VERSION === MIN_OPENCLAW,
    `minimum supported OpenClaw is ${c.MIN_SUPPORTED_OPENCLAW_VERSION}`);
  return "9/9 invariants";
});

// 16. configuration cannot raise authority -----------------------------------
await check("configuration cannot raise authority", async () => {
  const { loadConnectorConfig } = await import(pathToFileURL(join(root, "connector", "config.mjs")).href);
  const { mkdtempSync, mkdirSync, chmodSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(join(tmpdir(), "mg-verify-"));
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
      let rejected = false;
      try { loadConnectorConfig({ ...base, [key]: true }); } catch { rejected = true; }
      assert(rejected, `${key} was not rejected`);
    }
    return "4/4 authority keys rejected";
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// 17. only the local canary can construct a block ----------------------------
await check("only the local canary constructs a hook result", () => {
  const dir = join(root, "connector");
  const offenders = [];
  for (const f of walk(dir).filter((p) => p.endsWith(".mjs"))) {
    if (/block:\s*true/.test(readFileSync(f, "utf8")) && !f.endsWith("canary.mjs")) {
      offenders.push(relative(root, f));
    }
  }
  assert(offenders.length === 0, `blocking construction found in: ${offenders.join(", ")}`);
  return "block:true appears only in canary.mjs";
});

// 18. configuration example is valid ----------------------------------------
await check("bundled configuration example is valid", async () => {
  const examplePath = join(root, "examples", "connector-config.example.json");
  if (!existsSync(examplePath)) return "no example bundled (skipped)";
  const raw = JSON.parse(readFileSync(examplePath, "utf8"));
  assert(raw.enabled === false, "example does not ship disabled");
  const { loadConnectorConfig } = await import(pathToFileURL(join(root, "connector", "config.mjs")).href);
  const { mkdtempSync, mkdirSync, chmodSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(join(tmpdir(), "mg-example-"));
  mkdirSync(join(dir, "receipts"), { recursive: true });
  chmodSync(dir, 0o700); chmodSync(join(dir, "receipts"), 0o700);
  const probe = { ...raw, stateDir: dir, receiptDir: join(dir, "receipts") };
  delete probe.caFile;
  try {
    loadConnectorConfig(probe);
    return "example loads cleanly against the real config loader";
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---------------------------------------------------------------------------
const pass = results.filter((r) => r.ok).length;
const fail = results.length - pass;
const actualVerificationCount = results.length;
let documentedVerificationCount = null;
let documentationCountError = null;

try {
  const limitations = readFileSync(join(root, "LIMITATIONS.md"), "utf8").replace(/\s+/g, " ");
  const match = limitations.match(/Bundled package verification checks \| (\d+) \|/);
  assert(match, "LIMITATIONS.md is missing the bundled package verification count");
  documentedVerificationCount = Number(match[1]);
  assert(Number.isSafeInteger(documentedVerificationCount),
    "LIMITATIONS.md verification count is not an integer");
  if (documentedVerificationCount !== actualVerificationCount) {
    throw new Error("the documented verification-check count does not match the executed checks");
  }
} catch (error) {
  documentationCountError = error;
}

console.log("\nMcPherson Governance Connector - package verification\n");
for (const r of results) {
  console.log(`  ${r.ok ? "PASS" : "FAIL"}  ${r.name}`);
  if (r.detail) console.log(`        ${r.detail}`);
}
console.log(`\n  ${pass} passed, ${fail} failed\n`);
if (documentationCountError) {
  console.error("DOCUMENTATION TRUTH FAILURE: verification accounting in LIMITATIONS.md is stale.");
  console.error(`  documented verification count: ${documentedVerificationCount ?? "unparseable"}`);
  console.error(`  actual executed verification count: ${actualVerificationCount}`);
  console.error("  Update LIMITATIONS.md deliberately to match the executed verification checks.\n");
}
process.exit(fail || documentationCountError ? 1 : 0);

#!/usr/bin/env node
// Public release test runner.
//
// Runs the complete public verification for this package:
//
//   1. Every APPLICABLE upstream connector test, against this package's
//      connector bytes.
//   2. The public distribution replacement test.
//   3. The public runtime behaviour test.
//   4. The bundled public verification suite (scripts/verify-package.mjs).
//
// EXCLUSION POLICY
// ────────────────
// Exactly ONE upstream test is excluded, by exact test name:
//
//   file: tests/connector/operator-structure.test.mjs
//   test: "package is private v0.5.0 and declares only inspected supported
//          hooks at runtime"
//
// It asserts `package.json.private === true`, which is correct for the
// internal installer and deliberately invalid for the public distribution
// package. It is replaced by tests/public-distribution.test.mjs.
//
// The exclusion is by EXACT TEST NAME rather than by filename on purpose.
// That file holds 21 tests, 20 of which are safety tests (TLS never disabled,
// no hosted-service imports, no blocking construction in the remote path,
// governance-core byte matching, rotation-callback symlink rejection, unpair
// ordering). Excluding the whole file would silently drop all 20. Excluding
// the single inapplicable assertion keeps every safety test running.
//
// Node's --test-skip-pattern removes the matched test from the run entirely;
// it is NOT reported as a skipped test, and nothing else is filtered.
//
// Upstream tests are not shipped inside the published package. This runner is
// a release-engineering command: point it at the internal build repository
// with MCPHERSON_UPSTREAM_REPO. It FAILS LOUDLY if that tree is missing —
// it never silently reports success on a partial run.

import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, rmSync, mkdirSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(join(dirname(fileURLToPath(import.meta.url)), ".."));

const EXCLUDED_FILE = "tests/connector/operator-structure.test.mjs";
const EXCLUDED_TEST =
  "package is private v0.5.0 and declares only inspected supported hooks at runtime";

// Resolved from the environment, or from a path RELATIVE to this repository.
// No absolute or user-specific path is embedded - this file ships publicly.
const UPSTREAM_REPO = resolve(
  process.env.MCPHERSON_UPSTREAM_REPO
  || join(ROOT, "..", "..", "v0.5-build", "workspace", "mcpherson-governance-product"),
);

const bar = (s) => console.log(`\n${"─".repeat(72)}\n${s}\n${"─".repeat(72)}`);

function parseTotals(output) {
  const num = (label) => {
    const m = output.match(new RegExp(`^.\\s*${label}\\s+(\\d+)$`, "m"));
    return m ? Number(m[1]) : null;
  };
  return { tests: num("tests"), pass: num("pass"), fail: num("fail"), skipped: num("skipped") };
}

function runNodeTest(label, args, cwd) {
  const r = spawnSync(process.execPath, ["--test", ...args], {
    cwd, encoding: "utf8", env: process.env,
  });
  const output = `${r.stdout || ""}${r.stderr || ""}`;
  const totals = parseTotals(output);
  if (totals.tests === null) {
    console.log(output);
    throw new Error(`${label}: could not parse test totals - treating as failure`);
  }
  return { ...totals, output, status: r.status };
}

// ── 1. applicable upstream connector tests ──────────────────────────────────

bar("1/4  APPLICABLE UPSTREAM CONNECTOR TESTS");

const upstreamTests = join(UPSTREAM_REPO, "tests", "connector");
const upstreamCore = join(UPSTREAM_REPO, "packages", "governance-core");

if (!existsSync(upstreamTests) || !existsSync(upstreamCore)) {
  console.error(
    `\nERROR: upstream test tree not found.\n` +
    `  expected tests: ${upstreamTests}\n` +
    `  expected core:  ${upstreamCore}\n\n` +
    `The upstream connector suite is not shipped inside the public package.\n` +
    `Set MCPHERSON_UPSTREAM_REPO to the internal build repository root.\n` +
    `Refusing to report success on a partial run.\n`);
  process.exit(1);
}

console.log(`upstream repo: ${UPSTREAM_REPO}`);
console.log(`\nEXCLUDED (exact test name, 1 test):`);
console.log(`  file: ${EXCLUDED_FILE}`);
console.log(`  test: "${EXCLUDED_TEST}"`);
console.log(`  why:  asserts package.json.private === true, which is correct for the`);
console.log(`        internal installer and deliberately invalid for the public`);
console.log(`        distribution package. Replaced by`);
console.log(`        tests/public-distribution.test.mjs. This is a packaging-contract`);
console.log(`        difference, not a runtime change.`);
console.log(`  note: excluded by exact TEST NAME, not by filename - the same file`);
console.log(`        holds 20 safety tests which all still run.\n`);

const harness = mkdtempSync(join(tmpdir(), "mg-public-suite-"));
let upstream;
try {
  mkdirSync(join(harness, "plugins"), { recursive: true });
  mkdirSync(join(harness, "packages"), { recursive: true });
  mkdirSync(join(harness, "tests"), { recursive: true });
  // connector under test = THIS package's bytes
  cpSync(join(ROOT, "connector"), join(harness, "plugins", "openclaw-connector"), { recursive: true });
  cpSync(upstreamCore, join(harness, "packages", "governance-core"), { recursive: true });
  cpSync(upstreamTests, join(harness, "tests", "connector"), { recursive: true });

  // Enumerate the test files explicitly. Passing the directory makes Node
  // treat it as a single unit and report a bare failure, so the file list is
  // built here and every discovered *.test.mjs is run - nothing is filtered.
  const testFiles = readdirSync(join(harness, "tests", "connector"))
    .filter((n) => n.endsWith(".test.mjs"))
    .sort()
    .map((n) => join("tests", "connector", n));
  if (testFiles.length === 0) throw new Error("no upstream test files discovered");
  console.log(`discovered ${testFiles.length} upstream test files:`);
  for (const f of testFiles) console.log(`  ${f}`);
  console.log("");

  const escaped = EXCLUDED_TEST.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  upstream = runNodeTest("upstream", [
    `--test-skip-pattern=^${escaped}$`,
    ...testFiles,
  ], harness);
  console.log(`upstream: ${upstream.pass} passed, ${upstream.fail} failed, ${upstream.skipped} skipped`);
} finally {
  rmSync(harness, { recursive: true, force: true });
}

// ── 2 & 3. public replacement + runtime tests ───────────────────────────────

bar("2/4  PUBLIC DISTRIBUTION + RUNTIME TESTS");

const publicSuite = runNodeTest("public", [
  "tests/public-distribution.test.mjs",
  "tests/public-runtime.test.mjs",
], ROOT);
console.log(publicSuite.output.split("\n").filter((l) => /^.[✔✖]/.test(l)).join("\n"));
console.log(`\npublic: ${publicSuite.pass} passed, ${publicSuite.fail} failed, ${publicSuite.skipped} skipped`);

// ── 4. bundled verification suite ───────────────────────────────────────────

bar("3/4  BUNDLED PACKAGE VERIFICATION");

const bundled = spawnSync(process.execPath, [join(ROOT, "scripts", "verify-package.mjs")], {
  cwd: ROOT, encoding: "utf8", env: process.env,
});
const bundledOut = `${bundled.stdout || ""}${bundled.stderr || ""}`;
console.log(bundledOut.trim());
const bm = bundledOut.match(/(\d+)\s+passed,\s+(\d+)\s+failed/);
if (!bm) {
  console.error("ERROR: could not parse bundled verification totals");
  process.exit(1);
}
const bundledPass = Number(bm[1]);
const bundledFail = Number(bm[2]);

// ── summary ─────────────────────────────────────────────────────────────────

bar("4/4  PUBLIC RELEASE TEST SUMMARY");

const totalPass = upstream.pass + publicSuite.pass + bundledPass;
const totalFail = upstream.fail + publicSuite.fail + bundledFail;
const totalSkipped = upstream.skipped + publicSuite.skipped;

const row = (k, v) => console.log(`  ${k.padEnd(46)} ${v}`);
row("Applicable upstream connector tests", `${upstream.pass} passed / ${upstream.fail} failed`);
row("Public distribution + runtime tests", `${publicSuite.pass} passed / ${publicSuite.fail} failed`);
row("Bundled package verification", `${bundledPass} passed / ${bundledFail} failed`);
console.log(`  ${"─".repeat(66)}`);
row("COMBINED TOTAL", `${totalPass} passed / ${totalFail} failed`);
row("Skipped safety tests", totalSkipped);
row("Excluded (exact name, replaced publicly)", "1");

if (totalFail !== 0 || totalSkipped !== 0) {
  console.log(`\nRESULT: FAIL (${totalFail} failing, ${totalSkipped} skipped)\n`);
  process.exit(1);
}
console.log(`\nRESULT: PASS - ${totalPass} tests, 0 failures, 0 skipped\n`);

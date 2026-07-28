#!/usr/bin/env node
// Public release test runner.
//
// Runs the complete public verification for this package:
//
//   1. Every APPLICABLE upstream connector test, against this package's
//      connector bytes.
//   2. The public distribution, runtime, and v0.5.1 regression tests.
//   3. The bundled public verification suite (scripts/verify-package.mjs).
//
// `--package-only` runs groups 2 and 3 for the dependency-free `npm test`
// contract shipped to external auditors. The default release-engineering mode
// also runs group 1 and verifies the complete release accounting.
//
// EXCLUSION POLICY
// ────────────────
// Exactly TWO upstream tests are excluded, each by exact test name, and each
// REPLACED by a public test asserting the contract that supersedes it. No
// upstream expectation is dropped without a replacement.
//
//   1. file: tests/connector/operator-structure.test.mjs
//      test: "package is private v0.5.0 and declares only inspected supported
//             hooks at runtime"
//
//      It asserts `package.json.private === true` and version "0.5.0". The
//      private flag is correct for the internal installer and deliberately
//      invalid for the public distribution package. Replaced by
//      tests/public-distribution.test.mjs, which asserts the public packaging
//      contract, the current version in every manifest and in PLUGIN_VERSION,
//      and re-checks the compatibility, receipt-mode, remote-authority, and
//      enforceable-decision properties that test also covered.
//
//   2. file: tests/connector/scheduler-controls-adversarial.test.mjs
//      test: "disabled/kill/lock precedence beats exact canary with a
//             zero-network call-order trace"
//
//      Two of its five scenarios assert that an operationally DISABLED
//      connector still writes a NOT_ATTEMPTED attempt receipt. v0.5.1
//      deliberately changed that: disabled is now inert and writes no receipt
//      at all (see CHANGELOG.md, "disabled behavior and wording now agree").
//      The other three scenarios (kill switch, system lock, both) are
//      unchanged and still correct. Replaced by
//      tests/public-v051-regression.test.mjs, which runs ALL FIVE scenarios —
//      the three unchanged ones with their original receipt expectations, and
//      the two disabled ones under the stricter v0.5.1 contract — plus the
//      zero-network, zero-credential, and clean-shutdown assertions.
//
//      The replacement is strictly stronger for the disabled path: "writes no
//      receipt" is a tighter claim than "writes a SKIPPED receipt".
//
// Both exclusions are by EXACT TEST NAME rather than by filename on purpose.
// operator-structure.test.mjs holds 21 tests, 20 of them safety tests (TLS
// never disabled, no hosted-service imports, no blocking construction in the
// remote path, governance-core byte matching, rotation-callback symlink
// rejection, unpair ordering). scheduler-controls-adversarial.test.mjs
// likewise holds many independent adversarial control tests. Excluding either
// whole file would silently drop all of them.
//
// Node's --test-skip-pattern removes the matched test from the run entirely;
// it is NOT reported as a skipped test, and nothing else is filtered.
//
// Upstream tests are not shipped inside the published package. This runner is
// a release-engineering command: point it at the internal build repository
// with MCPHERSON_UPSTREAM_REPO. It FAILS LOUDLY if that tree is missing —
// it never silently reports success on a partial run.

import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  rmSync,
  mkdirSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(join(dirname(fileURLToPath(import.meta.url)), ".."));
const PUBLIC_TEST_FILES = Object.freeze([
  "tests/public-distribution.test.mjs",
  "tests/public-runtime.test.mjs",
  "tests/public-v051-regression.test.mjs",
]);
const PACKAGE_ONLY = process.argv.includes("--package-only");

if (process.argv.slice(2).some((arg) => arg !== "--package-only")) {
  console.error("usage: run-public-tests.mjs [--package-only]");
  process.exit(1);
}

const EXCLUSIONS = Object.freeze([
  Object.freeze({
    file: "tests/connector/operator-structure.test.mjs",
    test: "package is private v0.5.0 and declares only inspected supported hooks at runtime",
    why: "asserts package.json.private === true and version 0.5.0, which is correct for the\n"
      + "        internal installer and deliberately invalid for the public distribution\n"
      + "        package. This is a packaging-contract difference, not a runtime change.",
    replacedBy: "tests/public-distribution.test.mjs",
  }),
  Object.freeze({
    file: "tests/connector/scheduler-controls-adversarial.test.mjs",
    test: "disabled/kill/lock precedence beats exact canary with a zero-network call-order trace",
    why: "two of its five scenarios assert that a DISABLED connector still writes a\n"
      + "        NOT_ATTEMPTED attempt receipt. v0.5.1 deliberately makes disabled inert, so\n"
      + "        no receipt is written. The kill-switch and system-lock scenarios are\n"
      + "        unchanged and still asserted by the replacement.",
    replacedBy: "tests/public-v051-regression.test.mjs",
  }),
]);

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
  return {
    tests: num("tests"),
    pass: num("pass"),
    fail: num("fail"),
    cancelled: num("cancelled") ?? 0,
    skipped: num("skipped"),
    todo: num("todo") ?? 0,
  };
}

function runNodeTest(label, args, cwd) {
  const r = spawnSync(process.execPath, ["--test", ...args], {
    cwd, encoding: "utf8", env: process.env,
  });
  const output = `${r.stdout || ""}${r.stderr || ""}`;
  const totals = parseTotals(output);
  if ([totals.tests, totals.pass, totals.fail, totals.skipped].includes(null)) {
    console.log(output);
    throw new Error(`${label}: could not parse test totals - treating as failure`);
  }
  const accounted = totals.pass + totals.fail + totals.cancelled + totals.skipped + totals.todo;
  if (totals.tests !== accounted) {
    console.log(output);
    throw new Error(
      `${label}: test total ${totals.tests} does not equal `
      + `${totals.pass} pass + ${totals.fail} fail + ${totals.cancelled} cancelled + `
      + `${totals.skipped} skipped + ${totals.todo} todo`,
    );
  }
  return { ...totals, output, status: r.status };
}

function parseDocumentedAccounting() {
  const source = readFileSync(join(ROOT, "LIMITATIONS.md"), "utf8");
  const flat = source.replace(/\s+/g, " ");
  const headline = flat.match(
    /complete v0\.5\.1 public release suite reports \*\*(\d+) passed, (\d+) failed, (\d+) skipped\*\*/i,
  );
  const upstream = flat.match(
    /Applicable upstream \(sealed-reference\) connector tests \| (\d+) \|/,
  );
  const publicSuite = flat.match(
    /Public distribution, runtime, and v0\.5\.1 regression tests \| (\d+) \|/,
  );
  const verification = flat.match(/Bundled package verification checks \| (\d+) \|/);
  const tableTotal = flat.match(/\*\*Total\*\* \| \*\*(\d+)\*\* \|/);
  for (const [label, match] of [
    ["headline passed/failed/skipped accounting", headline],
    ["upstream group count", upstream],
    ["public-test group count", publicSuite],
    ["verification-check group count", verification],
    ["table total", tableTotal],
  ]) {
    if (!match) throw new Error(`LIMITATIONS.md is missing the ${label}`);
  }
  const documented = {
    passed: Number(headline[1]),
    failed: Number(headline[2]),
    skipped: Number(headline[3]),
    upstream: Number(upstream[1]),
    public: Number(publicSuite[1]),
    verification: Number(verification[1]),
    total: Number(tableTotal[1]),
  };
  const groupTotal = documented.upstream + documented.public + documented.verification;
  if (groupTotal !== documented.total || documented.passed !== documented.total) {
    throw new Error(
      "LIMITATIONS.md release accounting is internally inconsistent: "
      + `groups=${documented.upstream}+${documented.public}+${documented.verification}=${groupTotal}, `
      + `table total=${documented.total}, headline passed=${documented.passed}`,
    );
  }
  return documented;
}

function documentationTruthFailure(scope, comparisons) {
  const mismatches = comparisons.filter(({ documented, actual }) => documented !== actual);
  if (mismatches.length === 0) return false;
  console.error(`\nDOCUMENTATION TRUTH FAILURE: ${scope} accounting in LIMITATIONS.md is stale.`);
  for (const { label, documented, actual } of comparisons) {
    console.error(`  documented ${label}: ${documented}`);
    console.error(`  actual ${label}:     ${actual}`);
  }
  console.error("  Update LIMITATIONS.md deliberately to match the executed suite accounting.\n");
  return true;
}

let documented;
try {
  documented = parseDocumentedAccounting();
} catch (error) {
  console.error(`\nDOCUMENTATION TRUTH FAILURE: ${error.message}`);
  console.error("Update LIMITATIONS.md deliberately before reporting release results.\n");
  process.exit(1);
}

// ── 1. applicable upstream connector tests ──────────────────────────────────

const upstreamTests = join(UPSTREAM_REPO, "tests", "connector");
const upstreamCore = join(UPSTREAM_REPO, "packages", "governance-core");
let upstream;

if (!PACKAGE_ONLY) {
  bar("1/4  APPLICABLE UPSTREAM CONNECTOR TESTS");
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
  console.log(`\nEXCLUDED (exact test names, ${EXCLUSIONS.length} tests):`);
  for (const exclusion of EXCLUSIONS) {
    console.log(`  file: ${exclusion.file}`);
    console.log(`  test: "${exclusion.test}"`);
    console.log(`  why:  ${exclusion.why}`);
    console.log(`  repl: ${exclusion.replacedBy}`);
    console.log("");
  }
  console.log(`  note: excluded by exact TEST NAME, not by filename - every other test`);
  console.log(`        in those files still runs, and each exclusion has a replacement.\n`);

  const harness = mkdtempSync(join(tmpdir(), "mg-public-suite-"));
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

    const escaped = EXCLUSIONS
      .map((exclusion) => exclusion.test.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
      .join("|");
    upstream = runNodeTest("upstream", [
      `--test-skip-pattern=^(?:${escaped})$`,
      ...testFiles,
    ], harness);
    console.log(
      `upstream: ${upstream.pass} passed, ${upstream.fail + upstream.cancelled} failed, `
      + `${upstream.skipped + upstream.todo} skipped`,
    );
  } finally {
    rmSync(harness, { recursive: true, force: true });
  }
}

// ── 2 & 3. public replacement + runtime tests ───────────────────────────────

bar(PACKAGE_ONLY
  ? "1/3  PUBLIC DISTRIBUTION + RUNTIME + V0.5.1 REGRESSION TESTS"
  : "2/4  PUBLIC DISTRIBUTION + RUNTIME + V0.5.1 REGRESSION TESTS");

const publicSuite = runNodeTest("public", PUBLIC_TEST_FILES, ROOT);
console.log(publicSuite.output.split("\n").filter((l) => /^[✔✖]/.test(l)).join("\n"));
console.log(
  `\npublic: ${publicSuite.pass} passed, ${publicSuite.fail + publicSuite.cancelled} failed, `
  + `${publicSuite.skipped + publicSuite.todo} skipped`,
);

// ── 4. bundled verification suite ───────────────────────────────────────────

bar(PACKAGE_ONLY ? "2/3  BUNDLED PACKAGE VERIFICATION" : "3/4  BUNDLED PACKAGE VERIFICATION");

const bundled = spawnSync(process.execPath, [join(ROOT, "scripts", "verify-package.mjs")], {
  cwd: ROOT, encoding: "utf8", env: process.env,
});
const bundledOut = `${bundled.stdout || ""}${bundled.stderr || ""}`;
console.log(bundledOut.trim());
const bm = bundledOut.match(/^\s*(\d+)\s+passed,\s+(\d+)\s+failed\s*$/m);
if (!bm) {
  console.error("ERROR: could not parse bundled verification totals");
  process.exit(1);
}
const bundledPass = Number(bm[1]);
const bundledFail = Number(bm[2]);
const bundledChecks = bundledPass + bundledFail;

// ── summary ─────────────────────────────────────────────────────────────────

bar(PACKAGE_ONLY ? "3/3  PACKAGED TEST SUMMARY" : "4/4  PUBLIC RELEASE TEST SUMMARY");

const upstreamPass = upstream?.pass ?? 0;
const upstreamFail = (upstream?.fail ?? 0) + (upstream?.cancelled ?? 0);
const upstreamSkipped = (upstream?.skipped ?? 0) + (upstream?.todo ?? 0);
const publicFail = publicSuite.fail + publicSuite.cancelled;
const publicSkipped = publicSuite.skipped + publicSuite.todo;
const totalPass = upstreamPass + publicSuite.pass + bundledPass;
const totalFail = upstreamFail + publicFail + bundledFail;
const totalSkipped = upstreamSkipped + publicSkipped;
const actualExecutedTotal = (upstream?.tests ?? 0) + publicSuite.tests + bundledChecks;

const row = (k, v) => console.log(`  ${k.padEnd(46)} ${v}`);
if (!PACKAGE_ONLY) {
  row("Applicable upstream connector tests", `${upstreamPass} passed / ${upstreamFail} failed`);
}
row("Public distribution + runtime tests", `${publicSuite.pass} passed / ${publicFail} failed`);
row("Bundled package verification", `${bundledPass} passed / ${bundledFail} failed`);
console.log(`  ${"─".repeat(66)}`);
row("COMBINED TOTAL", `${totalPass} passed / ${totalFail} failed`);
row("Actually executed", actualExecutedTotal);
row("Skipped tests", totalSkipped);
if (!PACKAGE_ONLY) {
  row("Excluded (exact name, replaced publicly)", String(EXCLUSIONS.length));
}

const groupComparisons = [
  {
    label: "public-test count",
    documented: documented.public,
    actual: publicSuite.tests,
  },
  {
    label: "verification count",
    documented: documented.verification,
    actual: bundledChecks,
  },
];
let documentationMismatch = documentationTruthFailure(
  PACKAGE_ONLY ? "packaged-suite" : "public and verification group",
  groupComparisons,
);

if (!PACKAGE_ONLY) {
  documentationMismatch = documentationTruthFailure("complete release", [
    { label: "upstream passed count", documented: documented.upstream, actual: upstreamPass },
    { label: "public-test passed count", documented: documented.public, actual: publicSuite.pass },
    { label: "verification-check passed count", documented: documented.verification, actual: bundledPass },
    { label: "total passed count", documented: documented.passed, actual: totalPass },
    { label: "total executed count", documented: documented.total, actual: actualExecutedTotal },
    { label: "failure count", documented: documented.failed, actual: totalFail },
    { label: "skip count", documented: documented.skipped, actual: totalSkipped },
  ]) || documentationMismatch;
}

if (!documentationMismatch) {
  console.log(
    `\nDOCUMENTATION TRUTH PASS: actual counts match LIMITATIONS.md `
    + `(${PACKAGE_ONLY ? `${publicSuite.tests} public + ${bundledChecks} verification`
      : `${upstreamPass} upstream + ${publicSuite.tests} public + ${bundledChecks} verification; `
        + `${totalPass} passed, ${totalFail} failed, ${totalSkipped} skipped`}).`,
  );
}

const childFailure = publicSuite.status !== 0 || bundled.status !== 0
  || (!PACKAGE_ONLY && upstream.status !== 0);
if (totalFail !== 0 || totalSkipped !== 0 || documentationMismatch || childFailure) {
  console.log(`\nRESULT: FAIL (${totalFail} failing, ${totalSkipped} skipped)\n`);
  process.exit(1);
}
console.log(`\nRESULT: PASS - ${totalPass} tests, 0 failures, 0 skipped\n`);

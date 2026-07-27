#!/usr/bin/env node
// Build the two public release archives from the exact local Git HEAD.
//
// The evidence archive is derived from `git archive`, so the executable mode
// recorded in Git is preserved. Both archives are then inspected, extracted,
// and exercised before they are copied into the requested output directory.

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync, gzipSync } from "node:zlib";

const ROOT = resolve(join(dirname(fileURLToPath(import.meta.url)), ".."));
const EVIDENCE_ROOT = "mcpherson-governance-openclaw-v0.5.0";
const EVIDENCE_NAME = `${EVIDENCE_ROOT}.tar.gz`;
const CLI_RELATIVE = "connector/connector-ctl.mjs";
const FORBIDDEN_REPORT = /(?:AUDIT|CANDIDATE_REPORT|PUBLIC_SURFACE_REPAIR_REPORT)/i;

function fail(message) {
  throw new Error(message);
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? ROOT,
    encoding: options.binary ? undefined : "utf8",
    env: { ...process.env, ...options.env },
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const stdout = Buffer.isBuffer(result.stdout)
      ? result.stdout.toString("utf8")
      : result.stdout || "";
    const stderr = Buffer.isBuffer(result.stderr)
      ? result.stderr.toString("utf8")
      : result.stderr || "";
    fail(`${command} ${args.join(" ")} failed (${result.status})\n${stdout}${stderr}`);
  }
  return result;
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function tarString(buffer, start, length) {
  const end = buffer.indexOf(0, start);
  const limit = end === -1 || end > start + length ? start + length : end;
  return buffer.subarray(start, limit).toString("utf8");
}

function tarOctal(buffer, start, length) {
  const raw = tarString(buffer, start, length).trim();
  return raw ? Number.parseInt(raw, 8) : 0;
}

function tarEntries(tarBuffer) {
  const entries = [];
  let offset = 0;
  while (offset + 512 <= tarBuffer.length) {
    const header = tarBuffer.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const name = tarString(header, 0, 100);
    const prefix = tarString(header, 345, 155);
    const path = prefix ? `${prefix}/${name}` : name;
    const mode = tarOctal(header, 100, 8) & 0o7777;
    const size = tarOctal(header, 124, 12);
    const type = tarString(header, 156, 1) || "0";
    entries.push({ path, mode, size, type });
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return entries;
}

function gzipEntries(path) {
  return tarEntries(gunzipSync(readFileSync(path)));
}

function requireMode(entries, path, expected) {
  const entry = entries.find((item) => item.path === path);
  if (!entry) fail(`archive is missing ${path}`);
  if (entry.mode !== expected) {
    fail(`${path} mode is ${entry.mode.toString(8)}, expected ${expected.toString(8)}`);
  }
  return entry.mode;
}

function verifyNoInternalReports(entries, label) {
  const hits = entries
    .filter((entry) => FORBIDDEN_REPORT.test(basename(entry.path)))
    .map((entry) => entry.path);
  if (hits.length > 0) fail(`${label} contains internal report(s): ${hits.join(", ")}`);
}

function runExtractedCli(archive, cliPath, packageRoot, label, work) {
  const extractDir = join(work, `${label}-extract`);
  mkdirSync(extractDir);
  run("tar", ["-xzf", archive, "-C", extractDir]);
  const cli = join(extractDir, cliPath);
  const mode = statSync(cli).mode & 0o777;
  if (mode !== 0o755) fail(`${label} extracted CLI mode is ${mode.toString(8)}`);
  const stateDir = join(work, `${label}-state`);
  mkdirSync(stateDir, { mode: 0o700 });
  chmodSync(stateDir, 0o700);
  const result = run(realpathSync(cli), ["status", "--state-dir", stateDir], {
    cwd: join(extractDir, packageRoot),
  });
  const status = JSON.parse(result.stdout.trim());
  if (status.pluginId !== "mcpherson-governance-connector") {
    fail(`${label} CLI returned an unexpected status payload`);
  }
  return mode;
}

function parseArguments(argv) {
  const index = argv.indexOf("--output-dir");
  if (index === -1) return resolve(ROOT, "..", "dist");
  if (!argv[index + 1] || index + 2 !== argv.length) {
    fail("usage: build-release-artifacts.mjs [--output-dir <directory>]");
  }
  return resolve(argv[index + 1]);
}

const outputDir = parseArguments(process.argv.slice(2));
mkdirSync(outputDir, { recursive: true });

const cliSource = join(ROOT, CLI_RELATIVE);
if (readFileSync(cliSource, "utf8").split("\n", 1)[0] !== "#!/usr/bin/env node") {
  fail(`${CLI_RELATIVE} has an incorrect shebang`);
}

const gitMode = run("git", ["ls-files", "--stage", "--", CLI_RELATIVE]).stdout
  .trim()
  .split(/\s+/, 1)[0];
if (gitMode !== "100755") fail(`Git index mode for ${CLI_RELATIVE} is ${gitMode}`);

const work = mkdtempSync(join(tmpdir(), "mg-release-artifacts-"));
try {
  const npmCache = join(work, "npm-cache");
  mkdirSync(npmCache);
  const npmEnv = { npm_config_cache: npmCache };
  const archiveResult = run(
    "git",
    [
      "-c",
      "tar.umask=0022",
      "archive",
      "--format=tar",
      `--prefix=${EVIDENCE_ROOT}/`,
      "HEAD",
    ],
    { binary: true },
  );
  const gitTar = archiveResult.stdout;
  const gitEntries = tarEntries(gitTar);
  const gitArchiveMode = requireMode(
    gitEntries,
    `${EVIDENCE_ROOT}/${CLI_RELATIVE}`,
    0o755,
  );
  verifyNoInternalReports(gitEntries, "git archive");

  const sourceTar = join(work, "source.tar");
  writeFileSync(sourceTar, gitTar);
  const sourceDir = join(work, "source");
  mkdirSync(sourceDir);
  run("tar", ["-xf", sourceTar, "-C", sourceDir]);

  const evidenceStage = join(work, EVIDENCE_NAME);
  writeFileSync(evidenceStage, gzipSync(gitTar, { level: 9 }));
  const evidenceEntries = gzipEntries(evidenceStage);
  const evidenceMode = requireMode(
    evidenceEntries,
    `${EVIDENCE_ROOT}/${CLI_RELATIVE}`,
    0o755,
  );
  verifyNoInternalReports(evidenceEntries, "evidence archive");

  const packResult = run(
    "npm",
    ["pack", "--json", "--pack-destination", work],
    { cwd: join(sourceDir, EVIDENCE_ROOT), env: npmEnv },
  );
  const pack = JSON.parse(packResult.stdout);
  if (!Array.isArray(pack) || pack.length !== 1 || !pack[0].filename) {
    fail("npm pack returned an unexpected result");
  }
  const npmStage = join(work, pack[0].filename);
  if (!existsSync(npmStage)) fail(`npm pack did not create ${pack[0].filename}`);
  const npmEntries = gzipEntries(npmStage);
  const npmMode = requireMode(npmEntries, `package/${CLI_RELATIVE}`, 0o755);
  verifyNoInternalReports(npmEntries, "npm package");

  const evidenceExtractMode = runExtractedCli(
    evidenceStage,
    `${EVIDENCE_ROOT}/${CLI_RELATIVE}`,
    EVIDENCE_ROOT,
    "evidence",
    work,
  );
  const npmExtractMode = runExtractedCli(
    npmStage,
    `package/${CLI_RELATIVE}`,
    "package",
    "npm",
    work,
  );

  const evidencePath = join(outputDir, EVIDENCE_NAME);
  const npmPath = join(outputDir, pack[0].filename);
  copyFileSync(evidenceStage, evidencePath);
  copyFileSync(npmStage, npmPath);
  chmodSync(evidencePath, 0o644);
  chmodSync(npmPath, 0o644);

  const evidenceHash = sha256(evidencePath);
  const npmHash = sha256(npmPath);
  writeFileSync(
    `${evidencePath}.sha256`,
    `${evidenceHash}  ${basename(evidencePath)}\n`,
  );
  writeFileSync(`${npmPath}.sha256`, `${npmHash}  ${basename(npmPath)}\n`);

  console.log(JSON.stringify({
    head: run("git", ["rev-parse", "HEAD"]).stdout.trim(),
    clawPack: {
      filename: basename(npmPath),
      sha256: npmHash,
      files: npmEntries.filter((entry) => entry.type === "0").length,
      cliMode: npmMode.toString(8),
      extractedCliMode: npmExtractMode.toString(8),
      binCommand: "pass",
    },
    evidenceArchive: {
      filename: basename(evidencePath),
      sha256: evidenceHash,
      files: evidenceEntries.filter((entry) => entry.type === "0").length,
      cliMode: evidenceMode.toString(8),
      extractedCliMode: evidenceExtractMode.toString(8),
    },
    git: {
      indexMode: gitMode,
      archiveCliMode: gitArchiveMode.toString(8),
    },
  }, null, 2));
} finally {
  rmSync(work, { recursive: true, force: true });
}

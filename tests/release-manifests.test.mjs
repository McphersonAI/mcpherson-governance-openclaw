// Regression coverage for public release provenance and version
// synchronization (v0.6.2).
//
// These tests exist because of two concrete v0.6.1 defects, both of the same
// kind — a public artifact describing a private build:
//
//   * RELEASE-PROVENANCE.json named the private candidate commit as the
//     public `source_commit`, a claim no downloader could verify;
//   * V6-PACKAGE-MANIFEST.json recorded seventeen source files under private
//     `release/openclaw-public/...` paths that do not exist in the package.
//
// The assertions below fail if either recurs, and they fail if any binding
// becomes a claim the artifact cannot support.

import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, lstatSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function readJson(name) {
  return JSON.parse(readFileSync(join(PACKAGE_ROOT, name), "utf8"));
}

function readText(name) {
  return readFileSync(join(PACKAGE_ROOT, name), "utf8");
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function walk(directory, found = []) {
  for (const name of readdirSync(directory).sort()) {
    if (name === ".git" || name === "node_modules") continue;
    const absolute = join(directory, name);
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink()) continue;
    if (stat.isDirectory()) walk(absolute, found);
    else if (stat.isFile()) {
      found.push(relative(PACKAGE_ROOT, absolute).split(sep).join("/"));
    }
  }
  return found;
}

const SHA40 = /^[a-f0-9]{40}$/;
const SELF_REFERENTIAL = [
  "RELEASE-PROVENANCE.json", "V6-PACKAGE-MANIFEST.json", "PACKAGE-FILES.sha256",
];

const provenance = readJson("RELEASE-PROVENANCE.json");
const packageManifest = readJson("V6-PACKAGE-MANIFEST.json");
const pkg = readJson("package.json");
const pluginManifest = readJson("openclaw.plugin.json");

test("every current-release version declaration is synchronized", () => {
  const version = pkg.version;
  assert.match(version, /^\d+\.\d+\.\d+$/);
  assert.equal(pluginManifest.version, version, "openclaw.plugin.json");
  assert.equal(provenance.version, version, "RELEASE-PROVENANCE.json");
  assert.equal(packageManifest.plugin_version, version, "V6-PACKAGE-MANIFEST.json");
  assert.equal(
    readJson("plugins/openclaw-connector/package.json").version, version,
    "connector package.json",
  );
  assert.equal(
    readText("plugins/openclaw-connector/constants.mjs")
      .includes(`export const PLUGIN_VERSION = "${version}";`),
    true, "PLUGIN_VERSION",
  );
  assert.equal(
    readText("packages/openclaw-live-observer/index.mjs")
      .includes(`export const LIVE_LIFECYCLE_PLUGIN_VERSION = "${version}";`),
    true, "LIVE_LIFECYCLE_PLUGIN_VERSION",
  );
  assert.equal(
    provenance.archive_name,
    `mcphersonai-mcpherson-governance-openclaw-${version}.tgz`,
  );
});

test("provenance binds to the public repository, not a private build", () => {
  assert.equal(
    provenance.schema,
    "mcpherson-governance-openclaw-public-release-provenance/v2",
  );
  assert.equal(
    provenance.public_repository,
    "https://github.com/McphersonAI/mcpherson-governance-openclaw",
  );
  assert.equal(provenance.release_tag, `v${pkg.version}`);
  assert.match(provenance.source_commit, SHA40);
  assert.match(provenance.source_tree, SHA40);
  // The commit is labelled as the public base it actually is. An unlabelled
  // `source_commit` is what allowed v0.6.1 to read as a release-commit claim.
  assert.equal(provenance.source_commit_role, "PUBLIC_BASE_COMMIT");
  assert.equal(provenance.source_tree_role, "PUBLIC_BASE_TREE");
});

test("provenance declares every self-referential binding as external", () => {
  const declared = new Map(
    provenance.external_bindings.map((entry) => [entry.binding, entry]),
  );
  for (const binding of ["release_commit", "release_tree", "artifact_sha256"]) {
    const entry = declared.get(binding);
    assert.ok(entry, `missing external binding: ${binding}`);
    assert.equal(entry.resolution, "EXTERNAL", binding);
    // A binding the artifact cannot make must say how to resolve it and why
    // it could not be stated inline.
    assert.equal(typeof entry.verify === "string" && entry.verify.length > 0,
      true, `${binding} verify`);
    assert.equal(typeof entry.reason === "string" && entry.reason.length > 0,
      true, `${binding} reason`);
  }
  assert.equal(
    declared.get("release_commit").verify.includes(provenance.release_tag), true,
  );
  assert.equal(
    declared.get("artifact_sha256").verify.includes(provenance.archive_name), true,
  );
});

test("provenance documents the corrected release ordering", () => {
  const ordering = provenance.release_ordering;
  assert.equal(Array.isArray(ordering), true);
  assert.equal(ordering.length >= 8, true);
  const text = ordering.join("\n");
  // The manifests must be written in dependency order, and the tag must come
  // after the commit that it points at.
  const provenanceStep = ordering.findIndex((s) => s.includes("RELEASE-PROVENANCE.json"));
  const manifestStep = ordering.findIndex((s) => s.includes("V6-PACKAGE-MANIFEST.json"));
  const checksumStep = ordering.findIndex((s) => s.includes("PACKAGE-FILES.sha256"));
  const commitStep = ordering.findIndex((s) => s.includes("commit the release"));
  const tagStep = ordering.findIndex((s) => s.includes("tag"));
  assert.equal(provenanceStep < manifestStep, true, "provenance before manifest");
  assert.equal(manifestStep < checksumStep, true, "manifest before checksums");
  assert.equal(checksumStep < commitStep, true, "checksums before commit");
  assert.equal(commitStep < tagStep, true, "commit before tag");
  assert.equal(text.includes("npm pack"), true);
});

test("provenance records the six fixed safety values", () => {
  assert.deepEqual(provenance.authority, {
    AUTHORITY: "NONE",
    ENFORCEMENT: "OFF",
    AUTOMATIC_MAPPING_ACTIVATION: "OFF",
    OUTBOUND_ACTIONS: "OFF",
    REGISTRY_MUTATION: "OFF",
    REMOTE_DECISIONS: "SHADOW_ONLY",
  });
});

test("provenance and package manifest agree on the source identity", () => {
  assert.equal(packageManifest.source_commit, provenance.source_commit);
  assert.equal(packageManifest.source_tree, provenance.source_tree);
  for (const binding of packageManifest.target_bindings) {
    assert.equal(binding.source_commit, provenance.source_commit);
  }
});

test("the source inventory contains no private monorepo paths", () => {
  const offending = packageManifest.source_files
    .map((entry) => entry.path)
    .filter((path) => (
      path.startsWith("release/")
        || path.includes("openclaw-public/")
        || path.startsWith("/")
        || path.includes("..")
    ));
  assert.deepEqual(offending, [],
    "source_files must name public package paths only");
});

test("every recorded source file exists and matches its hash", () => {
  const present = new Set(walk(PACKAGE_ROOT));
  const missing = packageManifest.source_files
    .map((entry) => entry.path)
    .filter((path) => !present.has(path));
  assert.deepEqual(missing, [], "source_files entries absent from the package");

  const mismatched = packageManifest.source_files.filter((entry) => {
    const bytes = readFileSync(join(PACKAGE_ROOT, entry.path));
    return sha256(bytes) !== entry.sha256 || bytes.length !== entry.bytes;
  }).map((entry) => entry.path);
  assert.deepEqual(mismatched, [], "source_files hash or byte-count drift");
});

test("the source inventory covers every packaged file except the manifests", () => {
  const present = walk(PACKAGE_ROOT);
  const expected = present.filter((path) => !SELF_REFERENTIAL.includes(path)).sort();
  const recorded = packageManifest.source_files.map((entry) => entry.path).sort();
  assert.deepEqual(recorded, expected);
});

test("the checksum manifest covers every packaged file except itself", () => {
  const declared = new Map();
  for (const line of readText("PACKAGE-FILES.sha256").split("\n")) {
    if (!line.trim()) continue;
    const match = /^([a-f0-9]{64})  (.+)$/.exec(line);
    assert.ok(match, `malformed checksum line: ${line.slice(0, 80)}`);
    declared.set(match[2], match[1]);
  }
  const expected = walk(PACKAGE_ROOT)
    .filter((path) => path !== "PACKAGE-FILES.sha256").sort();
  assert.deepEqual([...declared.keys()].sort(), expected);

  const mismatched = [...declared].filter(([path, hash]) => (
    sha256(readFileSync(join(PACKAGE_ROOT, path))) !== hash
  )).map(([path]) => path);
  assert.deepEqual(mismatched, []);
});

test("declared counts match the packaged reality", () => {
  const present = walk(PACKAGE_ROOT);
  assert.equal(provenance.file_count, present.length);
  assert.equal(
    packageManifest.source_files.length,
    present.length - SELF_REFERENTIAL.length,
  );
});

test("compatibility documentation states each target's exact support", () => {
  const compatibility = readText("COMPATIBILITY.md");
  for (const marker of [
    "2026.6.33", "7af0cfc9c5488e03c4e2f528bdc7ac9f7778b35e",
    "2026.6.5", "5181e4f7c82bd373cb215a5619b0fa03c13862b7",
    "2026.7.1-2", "0790d9f593ad30c940ed93b5872a8cf6d6f3cf8c",
    "Preferred target", "Fully lifecycle-proven",
    "Exact-target binding validated", "Install and uninstall validated",
    "Live observation is not supported", "device-bound `operator.read` token",
  ]) {
    assert.equal(compatibility.includes(marker), true, `missing: ${marker}`);
  }
});

test("migration documentation covers the full v0.5.1 to v0.6.2 sequence", () => {
  const compatibility = readText("COMPATIBILITY.md");
  for (const marker of [
    "Stop v0.5.1 before rotating the ledger",
    "Archive the historical v0.5.1 ledger",
    "Create a fresh owner-only v0.6.x ledger",
    "Verify the profile binding",
    "Verify the device-bound `operator.read` token",
    "Run the lifecycle and restart proof",
    "Do not mix historical and fresh version records",
    "0600",
    "0700",
    "fails closed",
  ]) {
    assert.equal(compatibility.includes(marker), true, `missing: ${marker}`);
  }
});

#!/usr/bin/env node
// Regenerate the three release manifests in the one order that can be
// truthful, and verify that order was followed.
//
// WHY THIS EXISTS. Through v0.6.1 the public manifests were produced inside
// the private monorepo, and they described that private build rather than the
// public release:
//
//   * RELEASE-PROVENANCE.json named the private candidate commit as the
//     public `source_commit`. That commit does not exist in the public
//     repository, so the claim could not be checked by anyone who downloaded
//     the artifact.
//   * V6-PACKAGE-MANIFEST.json recorded seventeen source files under their
//     private `release/openclaw-public/...` paths, which do not resolve
//     inside the published package.
//
// Both are the same defect: a public artifact describing a private layout.
// This script removes the manual step that produced it.
//
// THE SELF-REFERENCE PROBLEM. Three bindings cannot be written into the
// artifact that they describe:
//
//   * the release commit SHA — a commit's identifier covers its own content;
//   * the release tree SHA — writing it into a tracked file changes the tree;
//   * the archive SHA-256 — the archive contains this file.
//
// The honest response is not to guess a future commit or to leave the record
// silent. Each unresolvable binding is declared explicitly, with the exact
// command that resolves it against the published repository and artifact.
// What can be stated truthfully at write time is stated as a value: the
// public base commit and its tree (both already published and verifiable),
// the release tag name, the package version, and the complete internal
// checksum coverage.
//
// ORDER (each step consumes only what the previous ones fixed):
//
//   1. RELEASE-PROVENANCE.json  — declares identity and binding method.
//   2. V6-PACKAGE-MANIFEST.json — hashes every source file; excludes the
//      three manifests, which cannot hash themselves.
//   3. PACKAGE-FILES.sha256     — hashes every packaged file except itself,
//      so it covers both manifests written above.
//
// Reversing any two steps produces a manifest that describes a file it then
// changes. `--check` re-derives all three and fails on any drift, which is
// what the packaged regression test runs.
//
// Usage:
//   node scripts/build-release-manifests.mjs --version 0.6.2 \
//     --base-commit <sha40> --base-tree <sha40> --tag v0.6.2
//   node scripts/build-release-manifests.mjs --check

import { createHash } from "node:crypto";
import { readFileSync, readdirSync, lstatSync, writeFileSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { canonicalizeJson } from "../packages/governance-core/canonical.mjs";

const PACKAGE_ROOT = resolve(
  join(fileURLToPath(new URL(".", import.meta.url)), ".."),
);

const PROVENANCE_NAME = "RELEASE-PROVENANCE.json";
const PACKAGE_MANIFEST_NAME = "V6-PACKAGE-MANIFEST.json";
const CHECKSUM_NAME = "PACKAGE-FILES.sha256";

// The three files that cannot appear in the source-file inventory: each is
// either derived from that inventory or would have to hash itself.
const SELF_REFERENTIAL = Object.freeze([
  PROVENANCE_NAME, PACKAGE_MANIFEST_NAME, CHECKSUM_NAME,
]);

const PROVENANCE_SCHEMA =
  "mcpherson-governance-openclaw-public-release-provenance/v2";
const PUBLIC_REPOSITORY =
  "https://github.com/McphersonAI/mcpherson-governance-openclaw";
const PACKAGE_NAME = "@mcphersonai/mcpherson-governance-openclaw";
const PLUGIN_ID = "mcpherson-governance-connector";

const SHA40 = /^[a-f0-9]{40}$/;

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
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

function readJson(name) {
  return JSON.parse(readFileSync(join(PACKAGE_ROOT, name), "utf8"));
}

function jsonBytes(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function archiveName(version) {
  return `mcphersonai-mcpherson-governance-openclaw-${version}.tgz`;
}

function buildProvenance({ version, baseCommit, baseTree, tag, fileCount }) {
  return {
    schema: PROVENANCE_SCHEMA,
    package_name: PACKAGE_NAME,
    plugin_id: PLUGIN_ID,
    version,
    public_repository: PUBLIC_REPOSITORY,
    release_tag: tag,
    binding_method: "PUBLIC_BASE_COMMIT_PLUS_EXTERNAL_TAG_TARGET",
    binding_statement: [
      "This record binds the published artifact to the PUBLIC release source.",
      "Bindings that a file cannot make about the object containing it are",
      "declared under external_bindings with the command that resolves them.",
      "No field states a commit that did not exist when this file was written.",
    ].join(" "),
    // Published and verifiable before this release is built. `source_commit`
    // is the public commit this release is built from, not the release commit
    // itself, and is labelled as such so it can never be read as a
    // self-reference.
    source_commit: baseCommit,
    source_commit_role: "PUBLIC_BASE_COMMIT",
    source_tree: baseTree,
    source_tree_role: "PUBLIC_BASE_TREE",
    external_bindings: [
      {
        binding: "release_commit",
        resolution: "EXTERNAL",
        reason: "a commit identifier covers the content that would state it",
        verify: `git rev-parse refs/tags/${tag}^{commit}`,
      },
      {
        binding: "release_tree",
        resolution: "EXTERNAL",
        reason: "writing the tree SHA into a tracked file changes that tree",
        verify: `git rev-parse refs/tags/${tag}^{tree}`,
      },
      {
        binding: "artifact_sha256",
        resolution: "EXTERNAL",
        reason: "the archive contains this file, so it cannot state its digest",
        verify: `shasum -a 256 ${archiveName(version)}`,
      },
    ],
    internal_bindings: {
      checksum_manifest: CHECKSUM_NAME,
      checksum_manifest_scope: "every packaged file except itself",
      package_manifest: PACKAGE_MANIFEST_NAME,
      package_manifest_scope:
        "every packaged file except the three release manifests",
    },
    release_ordering: [
      "1. freeze the release content",
      `2. write ${PROVENANCE_NAME} (identity and binding method)`,
      `3. write ${PACKAGE_MANIFEST_NAME} (hashes every source file)`,
      `4. write ${CHECKSUM_NAME} (hashes every packaged file except itself)`,
      "5. commit the release on the public repository",
      `6. create and push the annotated tag ${tag}`,
      "7. build the archive with npm pack from the tagged content",
      "8. publish the archive and record its SHA-256 externally",
      "9. resolve every external_bindings entry against the published release",
    ],
    archive_name: archiveName(version),
    archive_root: "package/",
    file_count: fileCount,
    checksum_manifest: CHECKSUM_NAME,
    package_manifest: PACKAGE_MANIFEST_NAME,
    build: {
      deterministic: true,
      builder: "npm pack",
      archive_format: "USTAR_GZIP",
      entry_order: "BYTE_SORTED_PATH",
      entry_mtime_epoch_seconds: 0,
      gzip_mtime_epoch_seconds: 0,
      uid_gid: 0,
      file_modes: "FROM_GIT_INDEX",
    },
    authority: {
      AUTHORITY: "NONE",
      ENFORCEMENT: "OFF",
      AUTOMATIC_MAPPING_ACTIVATION: "OFF",
      OUTBOUND_ACTIONS: "OFF",
      REGISTRY_MUTATION: "OFF",
      REMOTE_DECISIONS: "SHADOW_ONLY",
    },
  };
}

function buildPackageManifest({ version, baseCommit, baseTree, files }) {
  // Preserve every field the audited manifest already declares; only the
  // release identity, the source inventory, and the bindings derived from
  // the source commit are regenerated.
  const previous = readJson(PACKAGE_MANIFEST_NAME);
  const sourceFiles = files
    .filter((path) => !SELF_REFERENTIAL.includes(path))
    .map((path) => {
      const bytes = readFileSync(join(PACKAGE_ROOT, path));
      return { path, bytes: bytes.length, sha256: sha256(bytes) };
    })
    .sort((left, right) => (left.path < right.path ? -1 : 1));

  const targetBindings = previous.target_bindings.map((binding) => ({
    ...binding,
    source_commit: baseCommit,
  }));
  const targetBindingIds = targetBindings.map(
    (binding) => sha256(Buffer.from(canonicalizeJson(binding), "utf8")),
  );

  return {
    ...previous,
    plugin_version: version,
    source_commit: baseCommit,
    source_tree: baseTree,
    target_bindings: targetBindings,
    target_binding_ids: targetBindingIds,
    source_files: sourceFiles,
  };
}

function buildChecksums(files) {
  return `${files
    .filter((path) => path !== CHECKSUM_NAME)
    .map((path) => `${sha256(readFileSync(join(PACKAGE_ROOT, path)))}  ${path}`)
    .join("\n")}\n`;
}

function currentIdentity() {
  const provenance = readJson(PROVENANCE_NAME);
  const pkg = readJson("package.json");
  return {
    version: pkg.version,
    baseCommit: provenance.source_commit,
    baseTree: provenance.source_tree,
    tag: provenance.release_tag ?? `v${pkg.version}`,
  };
}

function generate(identity) {
  // Step 1: the file inventory the manifests describe.
  const files = walk(PACKAGE_ROOT);

  // Step 2: provenance.
  const provenance = buildProvenance({ ...identity, fileCount: files.length });

  // Step 3: the package manifest, which hashes files but never the manifests.
  const packageManifest = buildPackageManifest({ ...identity, files });

  return { files, provenance, packageManifest };
}

function main(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      version: { type: "string" },
      "base-commit": { type: "string" },
      "base-tree": { type: "string" },
      tag: { type: "string" },
      check: { type: "boolean", default: false },
    },
  });

  const identity = values.check
    ? currentIdentity()
    : {
      version: values.version,
      baseCommit: values["base-commit"],
      baseTree: values["base-tree"],
      tag: values.tag,
    };

  if (!identity.version) fail("missing --version");
  if (!SHA40.test(identity.baseCommit ?? "")) fail("missing or invalid --base-commit");
  if (!SHA40.test(identity.baseTree ?? "")) fail("missing or invalid --base-tree");
  if (!identity.tag) fail("missing --tag");

  const { files, provenance, packageManifest } = generate(identity);

  if (values.check) {
    const drift = [];
    if (jsonBytes(provenance) !== readFileSync(join(PACKAGE_ROOT, PROVENANCE_NAME), "utf8")) {
      drift.push(PROVENANCE_NAME);
    }
    if (jsonBytes(packageManifest)
      !== readFileSync(join(PACKAGE_ROOT, PACKAGE_MANIFEST_NAME), "utf8")) {
      drift.push(PACKAGE_MANIFEST_NAME);
    }
    if (buildChecksums(files)
      !== readFileSync(join(PACKAGE_ROOT, CHECKSUM_NAME), "utf8")) {
      drift.push(CHECKSUM_NAME);
    }
    const result = { ok: drift.length === 0, drift };
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exit(result.ok ? 0 : 1);
  }

  // Written in dependency order: each file is final before the next hashes it.
  writeFileSync(join(PACKAGE_ROOT, PROVENANCE_NAME), jsonBytes(provenance));
  writeFileSync(join(PACKAGE_ROOT, PACKAGE_MANIFEST_NAME), jsonBytes(packageManifest));
  writeFileSync(join(PACKAGE_ROOT, CHECKSUM_NAME), buildChecksums(walk(PACKAGE_ROOT)));

  process.stdout.write(`${JSON.stringify({
    ok: true,
    version: identity.version,
    file_count: files.length,
    checksum_count: files.length - 1,
    source_file_count: packageManifest.source_files.length,
  }, null, 2)}\n`);
}

main(process.argv.slice(2));

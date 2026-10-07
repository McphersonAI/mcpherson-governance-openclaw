// Release-only checks; never imported by the plugin or installed CLI.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const REQUIRED = ["LICENSE", "NOTICE", "LICENSE-CLARIFICATION-v0.7.4.md"];
const METADATA = ["package.json", "plugins/openclaw-connector/package.json"];
// Standard text from Apache's LICENSE-2.0.txt; CRLF checkout conversion is OK.
const APACHE_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30";
const normalized = (text) => text.replace(/\r\n/g, "\n");
const read = (root, path) => readFileSync(join(root, path), "utf8");
const isMetadata = (path) => path === "package.json" || path.endsWith("/package.json");

function checkLicense(readText, metadataPaths) {
  const license = normalized(readText("LICENSE"));
  assert.equal(createHash("sha256").update(license).digest("hex"), APACHE_SHA256,
    "LICENSE must contain the complete standard Apache-2.0 text");
  assert.ok(readText("NOTICE").trim(), "NOTICE must not be empty");
  assert.ok(readText("LICENSE-CLARIFICATION-v0.7.4.md").trim(), "v0.7.4 clarification must not be empty");
  for (const path of metadataPaths) {
    assert.equal(JSON.parse(readText(path)).license, "Apache-2.0", `${path}: license must be Apache-2.0`);
  }
}

export function verifySource(root = ROOT) {
  checkLicense((path) => read(root, path), METADATA);
  // Inventory only: do not rebuild an existing release or run package hooks.
  const [pack] = JSON.parse(execFileSync("npm", ["pack", "--dry-run", "--ignore-scripts", "--json"], {
    cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
  }));
  const paths = pack.files.map(({ path }) => path);
  for (const path of [...REQUIRED, ...METADATA]) assert.ok(paths.includes(path), `pack list missing ${path}`);
  checkLicense((path) => read(root, path), paths.filter(isMetadata));
  return paths;
}

export function verifyArtifact(artifact, root = ROOT) {
  const archive = resolve(artifact);
  // Read archive entries without extracting anything onto the filesystem.
  const entries = execFileSync("tar", ["-tzf", archive], { encoding: "utf8" }).trim().split("\n");
  for (const path of [...REQUIRED, ...METADATA]) {
    assert.equal(entries.filter((entry) => entry === `package/${path}`).length, 1,
      `artifact must contain exactly one package/${path}`);
  }
  const text = (path) => execFileSync("tar", ["-xOzf", archive, `package/${path}`], { encoding: "utf8" });
  const metadataPaths = entries.filter((path) => path.startsWith("package/")).map((path) => path.slice(8)).filter(isMetadata);
  checkLicense(text, metadataPaths);
  for (const path of REQUIRED) assert.equal(normalized(text(path)), normalized(read(root, path)), `${path}: artifact differs from source`);
  for (const path of metadataPaths) {
    const actual = JSON.parse(text(path));
    const expected = JSON.parse(read(root, path));
    assert.equal(actual.name, expected.name, `${path}: artifact package name differs from source`);
    assert.equal(actual.version, expected.version, `${path}: artifact version differs from source`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    assert.ok(args.length === 0 || (args.length === 2 && args[0] === "--artifact"),
      "usage: npm run verify:license [-- --artifact <new-version.tgz>]");
    verifySource();
    if (args.length) verifyArtifact(args[1]);
    process.stdout.write(`License verification PASS: source and pack list${args.length ? ", plus actual artifact" : " (artifact not checked)"}.\n`);
  } catch (error) {
    process.stderr.write(`License verification FAIL: ${error.message}\n`);
    process.exitCode = 1;
  }
}

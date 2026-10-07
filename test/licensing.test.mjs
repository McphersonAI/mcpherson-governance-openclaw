import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyArtifact, verifySource } from "../scripts/verify-license.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const temps = [];
after(() => { for (const dir of temps) rmSync(dir, { recursive: true, force: true }); });

// Metadata-only fixtures: no plugin runtime and no rebuilt v0.7.4 distribution.
function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "observa-license-fixture-"));
  temps.push(dir);
  const root = join(dir, "package");
  mkdirSync(join(root, "plugins/openclaw-connector"), { recursive: true });
  for (const file of ["LICENSE", "NOTICE", "LICENSE-CLARIFICATION-v0.7.4.md", "package.json", "plugins/openclaw-connector/package.json"]) {
    copyFileSync(join(ROOT, file), join(root, file));
  }
  for (const file of ["package.json", "plugins/openclaw-connector/package.json"]) {
    const path = join(root, file);
    const data = JSON.parse(readFileSync(path, "utf8"));
    data.version = "0.0.0-license-test";
    writeFileSync(path, JSON.stringify(data));
  }
  const archive = join(dir, "metadata-fixture.tgz");
  const pack = () => { execFileSync("tar", ["-czf", archive, "-C", dir, "package"]); return archive; };
  return { root, pack };
}

describe("public Apache-2.0 release continuity", () => {
  it("requires complete source licensing and inclusion in npm's actual pack list", () => {
    const paths = verifySource();
    assert.ok(paths.includes("LICENSE"));
    assert.ok(paths.includes("NOTICE"));
    assert.equal(paths.some((path) => path.startsWith("scripts/")), false, "release tooling must not ship as runtime");
  });

  for (const missing of ["LICENSE", "NOTICE"]) {
    it(`rejects a source tree missing ${missing}`, () => {
      const { root } = fixture();
      rmSync(join(root, missing));
      assert.throws(() => verifySource(root), /ENOENT/);
    });
  }

  for (const path of ["package.json", "plugins/openclaw-connector/package.json"]) {
    it(`rejects missing license metadata in ${path}`, () => {
      const { root } = fixture();
      const data = JSON.parse(readFileSync(join(root, path), "utf8"));
      delete data.license;
      writeFileSync(join(root, path), JSON.stringify(data));
      assert.throws(() => verifySource(root), /license must be Apache-2.0/);
    });
  }

  it("accepts the required licensing inside a synthetic metadata-only archive", () => {
    const { root, pack } = fixture();
    verifyArtifact(pack(), root);
  });

  for (const missing of ["LICENSE", "NOTICE"]) {
    it(`rejects an actual archive missing ${missing}, even with complete source`, () => {
      const { root, pack } = fixture();
      const path = join(root, missing);
      const original = readFileSync(path);
      rmSync(path);
      const archive = pack();
      writeFileSync(path, original);
      assert.throws(() => verifyArtifact(archive, root), /artifact must contain exactly one/);
    });
  }

  it("rejects truncated license text in the actual archive", () => {
    const { root, pack } = fixture();
    writeFileSync(join(root, "LICENSE"), "Apache License, Version 2.0\n");
    assert.throws(() => verifyArtifact(pack(), root), /complete standard Apache-2.0 text/);
  });

  it("rejects a bundled package that loses its license in the actual archive", () => {
    const { root, pack } = fixture();
    const path = join(root, "plugins/openclaw-connector/package.json");
    const data = JSON.parse(readFileSync(path, "utf8"));
    data.license = "UNLICENSED";
    writeFileSync(path, JSON.stringify(data));
    assert.throws(() => verifyArtifact(pack(), root), /license must be Apache-2.0/);
  });
});

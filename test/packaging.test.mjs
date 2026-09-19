// Release hygiene: one version everywhere current-facing, a valid manifest, and
// a packed artifact that contains what it should and nothing it should not.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const read = (path) => readFileSync(join(ROOT, path), "utf8");
const json = (path) => JSON.parse(read(path));

export const VERSION = "0.7.3";

describe("every current-facing version surface says 0.7.3", () => {
  const surfaces = [
    ["package.json", () => json("package.json").version],
    ["plugins/openclaw-connector/package.json", () => json("plugins/openclaw-connector/package.json").version],
    ["openclaw.plugin.json", () => json("openclaw.plugin.json").version],
    ["plugins/openclaw-connector/openclaw.plugin.json", () => json("plugins/openclaw-connector/openclaw.plugin.json").version],
    ["CANDIDATE-PROVENANCE.json", () => json("CANDIDATE-PROVENANCE.json").version],
    ["constants.mjs PLUGIN_VERSION", () => /PLUGIN_VERSION = "([^"]+)"/.exec(read("plugins/openclaw-connector/constants.mjs"))[1]],
    ["shadow-v070 SHADOW_RELEASE", () => /version: "([^"]+)"/.exec(read("plugins/openclaw-connector/shadow-v070/constants.mjs"))[1]],
    ["observa-pair CANDIDATE_VERSION", () => /CANDIDATE_VERSION = "([^"]+)"/.exec(read("observa-pair-legacy.mjs"))[1]],
    ["cli CLI_VERSION", () => /CLI_VERSION = '([^']+)'/.exec(read("cli/cli.mjs"))[1]],
    ["README heading", () => /# Observa local CLI — (\S+)/.exec(read("README.md"))[1]],
    ["plugin README heading", () => /# Observa OpenClaw plugin v(\S+)/.exec(read("plugins/openclaw-connector/README.md"))[1]],
  ];
  for (const [name, get] of surfaces) {
    it(name, () => assert.equal(get(), VERSION));
  }

  it("no current-facing surface still advertises a superseded release", () => {
    const stale = [/0\.7\.1-beta\.1/, /\b0\.7\.2\b/];
    // The provenance record's `immutable_runtime_input` is historical evidence
    // of the input this lineage was built from and keeps its own identity.
    const historical = new Set(["CANDIDATE-PROVENANCE.json"]);
    const walk = (dir, relative = "") => {
      for (const name of readdirSync(dir)) {
        if ([".git", "node_modules", "test"].includes(name)) continue;
        const path = join(dir, name);
        const rel = relative ? `${relative}/${name}` : name;
        if (statSync(path).isDirectory()) { walk(path, rel); continue; }
        if (!/\.(mjs|json|md)$/.test(name) || historical.has(rel)) continue;
        const text = readFileSync(path, "utf8");
        for (const pattern of stale) {
          // A "before v0.7.3 this happened" note is history, not a claim about
          // the current release; only a bare current-facing identity fails.
          const hit = pattern.exec(text);
          if (!hit) continue;
          const line = text.slice(0, hit.index).split("\n").length;
          const context = text.split("\n")[line - 1];
          assert.ok(
            /Before v0\.7\.3|Upgrade from|Rollback replaces|previously pinned/.test(context),
            `${rel}:${line} still presents ${hit[0]} as current: ${context.trim()}`,
          );
        }
      }
    };
    walk(ROOT);
  });
});

describe("the manifests are valid and internally consistent", () => {
  it("meets OpenClaw's required manifest fields", () => {
    const manifest = json("openclaw.plugin.json");
    assert.equal(typeof manifest.id, "string");
    assert.equal(manifest.configSchema.type, "object");
    assert.equal(manifest.configSchema.additionalProperties, false);
  });

  it("keeps the manifest id stable, and the package records the known divergence", () => {
    // OpenClaw uses the manifest id as the config key and warns that it differs
    // from the npm package name. Installed profiles key their plugin entry on
    // this id; renaming it would orphan every existing configuration.
    assert.equal(json("openclaw.plugin.json").id, "mcpherson-governance-connector");
    assert.equal(json("package.json").name, "@mcphersonai/mcpherson-governance-openclaw");
    assert.equal(json("plugins/openclaw-connector/package.json").name, "mcpherson-governance-connector");
    assert.ok(read("README.md").includes("mcpherson-governance-connector"));
  });

  it("keeps the OpenClaw compatibility floor", () => {
    const pkg = json("package.json");
    assert.equal(pkg.peerDependencies.openclaw, ">=2026.8.2");
    assert.equal(pkg.openclaw.compat.pluginApi, ">=2026.8.2");
    assert.equal(pkg.engines.node, ">=22");
    assert.deepEqual(pkg.openclaw.extensions, ["./plugins/openclaw-connector/plugin.mjs"]);
    assert.equal(pkg.openclaw.build.shadowMode, "SHADOW");
    assert.equal(pkg.openclaw.build.authority, "NONE");
    assert.equal(pkg.openclaw.build.enforcement, "OFF");
    assert.equal(pkg.openclaw.build.active, false);
    assert.ok(/MIN_SUPPORTED_OPENCLAW_VERSION = "2026\.8\.2"/.test(read("plugins/openclaw-connector/constants.mjs")));
  });

  it("records the exact authorized base this candidate was cut from", () => {
    const provenance = json("CANDIDATE-PROVENANCE.json");
    assert.equal(provenance.authorized_base.head, "d0fe213c6b0c50896645a9a7ad7cc162bd758d81");
    assert.equal(provenance.authorized_base.tree, "da91a6cdb7156a69abd0ac98bb99f0a40ebdcfe4");
    assert.deepEqual(provenance.posture, {
      mode: "SHADOW", authority: "NONE", enforcement: "OFF", active: false,
    });
  });
});

describe("the packed artifact carries exactly the release surface", () => {
  const packed = JSON.parse(
    execFileSync("npm", ["pack", "--dry-run", "--json"], { cwd: ROOT, encoding: "utf8" }),
  )[0];
  const entries = packed.files.map((file) => file.path);

  it("names the artifact for this version", () => {
    assert.equal(packed.name, "@mcphersonai/mcpherson-governance-openclaw");
    assert.equal(packed.version, VERSION);
    assert.equal(packed.filename, "mcphersonai-mcpherson-governance-openclaw-0.7.3.tgz");
  });

  it("includes every file the plugin needs at runtime", () => {
    for (const required of [
      "package.json", "README.md", "openclaw.plugin.json", "CANDIDATE-PROVENANCE.json",
      "observa.mjs", "observa-pair.mjs", "observa-pair-legacy.mjs",
      "cli/cli.mjs", "cli/providers/openclaw.mjs",
      "pairing/openclaw-profile-pairing.mjs",
      "plugins/openclaw-connector/plugin.mjs",
      "plugins/openclaw-connector/index.mjs",
      "plugins/openclaw-connector/controls.mjs",
      "plugins/openclaw-connector/runtime-publisher.mjs",
      "plugins/openclaw-connector/openclaw.plugin.json",
    ]) {
      assert.ok(entries.includes(required), `missing ${required}`);
    }
  });

  it("excludes tests, development files, and build output", () => {
    for (const entry of entries) {
      assert.equal(entry.startsWith("test/"), false, `tests must not ship: ${entry}`);
      assert.equal(/(^|\/)\.(env|git|npmrc|DS_Store)/.test(entry), false, `unexpected dotfile: ${entry}`);
      assert.equal(/\.(tgz|log|key|pem|p12|crt)$/.test(entry), false, `unexpected artifact: ${entry}`);
      assert.equal(
        /(^|\/)(deployment-credential|node_modules|coverage)(\/|$)/.test(entry),
        false,
        `state or dependency artifact: ${entry}`,
      );
    }
  });

  it("carries no credential-shaped literal anywhere in the artifact", () => {
    // The connector's own credential format. Nothing in a published package
    // may ever contain one, including in a comment, fixture, or example.
    const token = /mgd1_[a-f0-9]{32}\.[A-Za-z0-9_-]{43}/;
    for (const entry of entries) {
      if (!/\.(mjs|json|md|txt)$/.test(entry)) continue;
      assert.equal(token.test(read(entry)), false, `credential-shaped literal in ${entry}`);
    }
  });

  it("every declared bin target is packed and executable", () => {
    for (const target of Object.values(json("package.json").bin)) {
      const relative = target.replace(/^\.\//, "");
      assert.ok(entries.includes(relative), `bin target not packed: ${relative}`);
      assert.ok(read(relative).startsWith("#!/usr/bin/env node"), `bin target has no shebang: ${relative}`);
      assert.ok(statSync(join(ROOT, relative)).mode & 0o100, `bin target not executable: ${relative}`);
    }
  });
});

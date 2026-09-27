// The exact packed artifact, not the repository: pack, extract into a path with
// spaces, let the extracted plugin install its launcher beside a global-npm
// OpenClaw layout, and drive the real CLI through `observa` on PATH.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, readdirSync } from "node:fs";
import { delimiter, dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

import { ROOT, cleanupTemps, makeOpenClawLayout, makeProfileHome, tempDir } from "./cli-fixtures.mjs";
import { setControl } from "../plugins/openclaw-connector/controls.mjs";

after(cleanupTemps);

let extracted; let layout; let entrypoint; let outcome;
const NODE_DIR = dirname(process.execPath);

before(() => {
  const work = tempDir("observa packed");
  const tarball = JSON.parse(execFileSync("npm", ["pack", "--json", "--pack-destination", work], { cwd: ROOT, encoding: "utf8" }))[0].filename;
  const target = join(work, "extensions dir with spaces");
  mkdirSync(target);
  execFileSync("tar", ["-xzf", join(work, tarball), "-C", target]);
  extracted = join(target, "package");
  layout = makeOpenClawLayout();
});

function observa(args, env = {}) {
  return spawnSync("observa", args, {
    encoding: "utf8",
    env: { PATH: `${layout.bin}${delimiter}${NODE_DIR}${delimiter}/usr/bin${delimiter}/bin`, HOME: tempDir("observa packed home"), ...env },
  });
}

describe("the packed 0.7.4 artifact", () => {
  it("installs its own launcher from the extracted package", async () => {
    entrypoint = await import(pathToFileURL(join(extracted, "plugins/openclaw-connector/cli-entrypoint.mjs")).href);
    outcome = entrypoint.ensureObservaEntrypoint({ packageRoot: extracted, argv1: layout.launcher, env: { PATH: "/usr/bin" } });
    assert.equal(outcome.state, "INSTALLED");
    assert.deepEqual(readdirSync(layout.bin).sort(), ["observa", "openclaw"]);
  });

  it("observa --version / --help come from the installed package", () => {
    const version = observa(["--version"]);
    assert.equal(version.status, 0, version.stderr);
    assert.equal(version.stdout.trim(), "Observa 0.7.4");
    const help = observa(["--help"]);
    assert.equal(help.status, 0);
    assert.match(help.stdout, /request-access[\s\S]*request-status[\s\S]*pair[\s\S]*hosted-health[\s\S]*identify/);
  });

  it("runs every local view and the funnel/Hosted commands through the launcher", () => {
    const { home } = makeProfileHome({ journal: {} });
    const p = ["--profile-home", home];
    for (const [args, code, pattern] of [
      [["status", ...p], 0, /Paired\s+YES[\s\S]*Posture\s+SHADOW ONLY/],
      [["agents", ...p], 0, /aegis[\s\S]*main[\s\S]*sterling/],
      [["agent", "main", ...p], 0, /COMPLETED[\s\S]*WOULD_/],
      [["activity", "--limit", "5", ...p], 0, /COMPLETED/],
      [["decisions", "--limit", "5", ...p], 0, /WOULD_REQUIRE_APPROVAL/],
      [["request-status", "--api-url", "https://observa.example", ...p], 1, /^$/],
    ]) {
      const result = observa(args);
      assert.equal(result.status, code, `${args[0]}: ${result.stderr}`);
      assert.match(result.stdout, pattern, args[0]);
    }
    assert.match(observa(["request-status", "--api-url", "https://observa.example", ...p]).stderr, /^ACCESS_NO_REQUEST/);
    // Stop controls hold for the Hosted checks run through the launcher: no network.
    const { stateDir } = makeProfileHome({ journal: {} });
    setControl(stateDir, "killswitch", true);
    const home2 = dirname(dirname(stateDir));
    const health = observa(["hosted-health", "--json", "--profile-home", home2]);
    assert.equal(health.status, 2);
    assert.equal(JSON.parse(health.stdout).hosted_health.state, "REFUSED_BY_CONTROL");
    const identify = observa(["identify", "--profile-home", home2]);
    assert.equal(identify.status, 2);
    assert.match(identify.stdout, /aegis\n  main\n  sterling[\s\S]*REFUSED_BY_CONTROL/);
  });

  it("unpaired hosted-health and identify are deterministic through the launcher", () => {
    const { home } = makeProfileHome({ paired: false, enabled: false });
    const health = observa(["hosted-health", "--profile-home", home]);
    assert.equal(health.status, 2);
    assert.match(health.stdout, /^Observa hosted health: NOT_PAIRED/);
    const identify = observa(["identify", "--profile-home", home]);
    assert.equal(identify.status, 0);
    assert.match(identify.stdout, /Hosted roster\s+NOT_PAIRED/);
  });

  it("uninstall removes the packed plugin's launcher only", () => {
    const removal = entrypoint.removeObservaEntrypoint({ pluginRoot: outcome.pluginRoot, argv1: join(layout.bin, "observa") });
    assert.equal(removal.removed.length, 1);
    assert.deepEqual(readdirSync(layout.bin), ["openclaw"]);
  });
});

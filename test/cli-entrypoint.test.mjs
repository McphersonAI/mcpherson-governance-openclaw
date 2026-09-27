// The managed `observa` launcher: automatic install beside the `openclaw`
// launcher, safe argument forwarding, update/reinstall/uninstall ownership,
// and every collision and hostile-path case the plugin must refuse.
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync, linkSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, statSync,
  symlinkSync, writeFileSync,
} from "node:fs";
import { delimiter, dirname, join } from "node:path";

import {
  ENTRYPOINT_RECORD_FILE, classifyEntrypoint, ensureObservaEntrypoint, readEntrypointRecord,
  removeObservaEntrypoint, renderEntrypoint, resolveLauncherDirs, resolveObservaOnPath,
} from "../plugins/openclaw-connector/cli-entrypoint.mjs";
import { createGovernanceConnector } from "../plugins/openclaw-connector/index.mjs";
import {
  ROOT, cleanupTemps, makeFakePlugin, makeLocalNode, makeOpenClawLayout, tempDir,
} from "./cli-fixtures.mjs";
import { makeClientSpy, makeProfile, cleanupProfiles } from "./helpers.mjs";

after(() => { cleanupTemps(); cleanupProfiles(); });

const NODE_DIR = dirname(process.execPath);
function run(bin, args, extraEnv = {}) {
  const result = spawnSync(join(bin, "observa"), args, {
    encoding: "utf8",
    env: { PATH: `${bin}${delimiter}${NODE_DIR}${delimiter}/usr/bin${delimiter}/bin`, HOME: tempDir("observa run home"), ...extraEnv },
  });
  return result;
}
function runOnPath(pathValue, args) {
  return spawnSync("observa", args, { encoding: "utf8", env: { PATH: pathValue, HOME: tempDir("observa run home") } });
}
function setup({ version = "fake-1" } = {}) {
  const layout = makeOpenClawLayout();
  const plugin = makeFakePlugin(version);
  const stateDir = join(tempDir("observa state"), "state");
  mkdirSync(stateDir, { mode: 0o700 });
  const ensure = (overrides = {}) => ensureObservaEntrypoint({
    packageRoot: plugin, stateDir, argv1: layout.launcher, env: { PATH: "/usr/bin:/bin" }, ...overrides,
  });
  return { layout, plugin, stateDir, ensure };
}

describe("a normal install exposes `observa` automatically", () => {
  it("installs beside the openclaw launcher the gateway runs from, and it runs", () => {
    const { layout, plugin, stateDir, ensure } = setup();
    const outcome = ensure();
    assert.equal(outcome.state, "INSTALLED");
    assert.equal(outcome.path, join(layout.bin, "observa"));
    const st = lstatSync(outcome.path);
    assert.equal(st.isFile(), true);
    assert.equal(st.mode & 0o777, 0o755);
    const result = runOnPath(`${layout.bin}${delimiter}${NODE_DIR}${delimiter}/usr/bin${delimiter}/bin`, ["status"]);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { version: "fake-1", argv: ["status"] });
    const record = readEntrypointRecord(stateDir);
    assert.equal(record.state, "INSTALLED");
    assert.equal(record.plugin_root, outcome.pluginRoot);
    assert.equal(statSync(join(stateDir, ENTRYPOINT_RECORD_FILE)).mode & 0o777, 0o600);
    assert.ok(outcome.pluginRoot.endsWith(plugin.split("/").slice(-1)[0]));
  });

  it("uses the npm global-prefix bin directory when the gateway was started from the package path", () => {
    const layout = makeOpenClawLayout();
    const plugin = makeFakePlugin();
    const outcome = ensureObservaEntrypoint({ packageRoot: plugin, argv1: join(layout.pkg, "openclaw.mjs"), env: { PATH: "/usr/bin" } });
    assert.equal(outcome.state, "INSTALLED");
    assert.equal(realpathSync(outcome.path), realpathSync(join(layout.bin, "observa")));
  });

  it("finds the launcher directory through PATH when argv does not name it", () => {
    const layout = makeOpenClawLayout();
    const plugin = makeFakePlugin();
    const outcome = ensureObservaEntrypoint({ packageRoot: plugin, argv1: join(layout.pkg, "openclaw.mjs"), env: { PATH: `/usr/bin${delimiter}${layout.bin}` } });
    assert.equal(outcome.path, join(layout.bin, "observa"));
  });

  it("ignores PATH directories whose openclaw is a different OpenClaw package", () => {
    const running = makeOpenClawLayout();
    const other = makeOpenClawLayout();
    const dirs = resolveLauncherDirs({ argv1: running.launcher, env: { PATH: `${other.bin}${delimiter}${running.bin}` } });
    assert.deepEqual(dirs, [running.bin]);
  });

  it("the launcher holds no product code and no environment values", () => {
    const { plugin } = setup();
    const text = renderEntrypoint(plugin);
    assert.ok(text.length < 4096);
    assert.equal(/cli\.mjs|runObserva|withCredential|deployment-credential/.test(text), false);
    process.env.OBSERVA_TEST_SENTINEL = "sentinel-value-that-must-not-leak";
    const fresh = renderEntrypoint(plugin);
    assert.equal(fresh.includes("sentinel-value-that-must-not-leak"), false);
    delete process.env.OBSERVA_TEST_SENTINEL;
    for (const [key, value] of Object.entries(process.env)) {
      if (key.startsWith("npm_")) continue;
      if (typeof value === "string" && value.length > 12 && !plugin.includes(value)) {
        assert.equal(text.includes(value), false, `environment value of ${key} leaked into the launcher`);
      }
    }
  });
});

describe("the launcher runs the currently installed plugin, faithfully", () => {
  it("forwards shell metacharacters, spaces, quotes and option-like arguments verbatim", () => {
    const { layout, ensure } = setup();
    ensure();
    const args = ["status", "--profile", "a b", "'; rm -rf / #", "$(touch /tmp/pwned)", "`id`", "\"q\"", "--", "-h", "*", "\\x", "ü"];
    const result = run(layout.bin, args);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).argv, args);
  });

  it("an in-place plugin update is picked up without rewriting the launcher", () => {
    const { layout, plugin, ensure } = setup();
    ensure();
    const before = readFileSync(join(layout.bin, "observa"), "utf8");
    writeFileSync(join(plugin, "observa.mjs"), "process.stdout.write(JSON.stringify({ version: 'fake-2', argv: process.argv.slice(2) }));\n", { mode: 0o755 });
    writeFileSync(join(plugin, "package.json"), JSON.stringify({ name: "@mcphersonai/mcpherson-governance-openclaw", version: "fake-2" }));
    assert.equal(JSON.parse(run(layout.bin, ["--version"]).stdout).version, "fake-2");
    assert.equal(ensure().state, "CURRENT");
    assert.equal(readFileSync(join(layout.bin, "observa"), "utf8"), before);
  });

  it("an update to a new install path re-points the launcher (no stale copy)", () => {
    const { layout, stateDir, ensure } = setup();
    ensure();
    const moved = makeFakePlugin("fake-new-path");
    const outcome = ensure({ packageRoot: moved });
    assert.equal(outcome.state, "UPDATED");
    assert.equal(JSON.parse(run(layout.bin, []).stdout).version, "fake-new-path");
    assert.equal(readEntrypointRecord(stateDir).state, "UPDATED");
  });

  it("reinstall is idempotent: one launcher, no temporaries, no rewrite", () => {
    const { layout, ensure } = setup();
    assert.equal(ensure().state, "INSTALLED");
    const ino = lstatSync(join(layout.bin, "observa")).ino;
    for (let i = 0; i < 3; i += 1) assert.equal(ensure().state, "CURRENT");
    assert.equal(lstatSync(join(layout.bin, "observa")).ino, ino);
    assert.deepEqual(readdirSync(layout.bin).sort(), ["observa", "openclaw"]);
  });

  it("a stale launcher whose plugin is gone is refreshed on the next gateway start", () => {
    const { layout, plugin, ensure } = setup();
    ensure();
    rmSync(plugin, { recursive: true, force: true });
    const replacement = makeFakePlugin("fake-reinstalled");
    assert.equal(ensure({ packageRoot: replacement }).state, "UPDATED");
    assert.equal(JSON.parse(run(layout.bin, []).stdout).version, "fake-reinstalled");
  });
});

describe("a missing, broken or foreign plugin never runs anything else", () => {
  it("missing plugin: deterministic diagnostic, exit 1, no fallback", () => {
    const { layout, plugin, ensure } = setup();
    ensure();
    rmSync(plugin, { recursive: true, force: true });
    const result = run(layout.bin, ["status"]);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /^OBSERVA_PLUGIN_NOT_INSTALLED: /);
    assert.match(result.stderr, /openclaw plugins install clawhub:@mcphersonai\/mcpherson-governance-openclaw/);
    assert.match(result.stderr, /rm '.*observa'/);
  });

  it("corrupt entrypoint: reported, not executed around", () => {
    const { layout, plugin, ensure } = setup();
    ensure();
    writeFileSync(join(plugin, "observa.mjs"), "this is ( not javascript", { mode: 0o755 });
    const result = run(layout.bin, ["status"]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /^OBSERVA_PLUGIN_ENTRYPOINT_INVALID: /);
  });

  it("wrong package at the recorded path: refused", () => {
    const { layout, plugin, ensure } = setup();
    ensure();
    writeFileSync(join(plugin, "package.json"), JSON.stringify({ name: "evil-package" }));
    const result = run(layout.bin, ["status"]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /^OBSERVA_PLUGIN_IDENTITY_MISMATCH: /);
  });

  it("world-writable plugin CLI or a symlinked entry file: refused", () => {
    const { layout, plugin, ensure } = setup();
    ensure();
    chmodSync(join(plugin, "observa.mjs"), 0o777);
    assert.match(run(layout.bin, []).stderr, /^OBSERVA_PLUGIN_UNTRUSTED: /);
    chmodSync(join(plugin, "observa.mjs"), 0o755);
    const elsewhere = join(tempDir("observa elsewhere"), "observa.mjs");
    writeFileSync(elsewhere, "process.stdout.write('HIJACKED')", { mode: 0o755 });
    rmSync(join(plugin, "observa.mjs"));
    symlinkSync(elsewhere, join(plugin, "observa.mjs"));
    const result = run(layout.bin, []);
    assert.equal(result.stdout.includes("HIJACKED"), false);
    assert.match(result.stderr, /^OBSERVA_PLUGIN_UNTRUSTED: /);
  });

  it("refuses to install for a directory that is not this package", () => {
    const layout = makeOpenClawLayout();
    const bogus = tempDir("observa bogus");
    writeFileSync(join(bogus, "package.json"), JSON.stringify({ name: "something-else" }));
    const outcome = ensureObservaEntrypoint({ packageRoot: bogus, argv1: layout.launcher, env: {} });
    assert.equal(outcome.state, "FAILED");
    assert.deepEqual(readdirSync(layout.bin), ["openclaw"]);
  });
});

describe("another product's `observa` is never overwritten or removed", () => {
  it("Local Node: detected, left byte-identical, remediation recorded", () => {
    const { layout, stateDir, ensure } = setup();
    const link = makeLocalNode(layout.prefix, layout.bin);
    const target = readFileSync(link, "utf8");
    const outcome = ensure();
    assert.equal(outcome.state, "COLLISION_LOCAL_NODE");
    assert.equal(lstatSync(link).isSymbolicLink(), true);
    assert.equal(readFileSync(link, "utf8"), target);
    assert.equal(run(layout.bin, []).stdout, "LOCAL_NODE_OBSERVA");
    assert.match(outcome.remediation, /npm uninstall -g @mcpherson-ai\/observa-local-node/);
    assert.match(outcome.remediation, /Until then run: node '.*observa\.mjs' <command>/);
    assert.equal(readEntrypointRecord(stateDir).state, "COLLISION_LOCAL_NODE");
    // Uninstall does not touch it either.
    const removal = removeObservaEntrypoint({ pluginRoot: outcome.pluginRoot, stateDir });
    assert.deepEqual(removal.removed, []);
    assert.deepEqual(removal.kept.map((k) => k.kind), ["LOCAL_NODE"]);
    assert.equal(lstatSync(link).isSymbolicLink(), true);
  });

  it("unknown binary: detected, left byte-identical", () => {
    const { layout, ensure } = setup();
    writeFileSync(join(layout.bin, "observa"), "#!/bin/sh\necho SOMEONE_ELSE\n", { mode: 0o755 });
    assert.equal(ensure().state, "COLLISION_UNKNOWN");
    assert.equal(readFileSync(join(layout.bin, "observa"), "utf8"), "#!/bin/sh\necho SOMEONE_ELSE\n");
  });

  it("a forged marker in a file owned elsewhere, a hard link, or a dangling link is not ours", () => {
    const { layout, plugin, ensure } = setup();
    // Hard link to a marked launcher elsewhere: nlink 2 => not owned.
    const outside = join(tempDir("observa outside"), "observa");
    writeFileSync(outside, renderEntrypoint(plugin), { mode: 0o755 });
    linkSync(outside, join(layout.bin, "observa"));
    assert.equal(classifyEntrypoint(join(layout.bin, "observa")).kind, "UNKNOWN");
    assert.equal(ensure().state, "COLLISION_UNKNOWN");
    rmSync(join(layout.bin, "observa"));
    // Symlink replacement pointing at a marked launcher: links are never ours.
    symlinkSync(outside, join(layout.bin, "observa"));
    assert.equal(ensure().state, "COLLISION_UNKNOWN");
    rmSync(join(layout.bin, "observa"));
    symlinkSync(join(layout.bin, "missing-target"), join(layout.bin, "observa"));
    assert.equal(ensure().state, "COLLISION_UNKNOWN");
  });

  it("a package-manager link to this package is left to the package manager", () => {
    const { layout, ensure } = setup();
    const pkg = join(layout.prefix, "lib", "node_modules", "@mcphersonai", "mcpherson-governance-openclaw");
    mkdirSync(pkg, { recursive: true });
    writeFileSync(join(pkg, "package.json"), JSON.stringify({ name: "@mcphersonai/mcpherson-governance-openclaw" }));
    writeFileSync(join(pkg, "observa.mjs"), "", { mode: 0o755 });
    symlinkSync("../lib/node_modules/@mcphersonai/mcpherson-governance-openclaw/observa.mjs", join(layout.bin, "observa"));
    assert.equal(ensure().state, "PROVIDED_BY_PACKAGE_MANAGER");
  });

  it("a foreign file that replaced our launcher is never clobbered by a refresh", () => {
    const { layout, ensure } = setup();
    ensure();
    const path = join(layout.bin, "observa");
    rmSync(path);
    writeFileSync(path, "#!/bin/sh\necho FOREIGN\n", { mode: 0o755 });
    assert.equal(ensure({ packageRoot: makeFakePlugin("fake-other") }).state, "COLLISION_UNKNOWN");
    assert.equal(readFileSync(path, "utf8"), "#!/bin/sh\necho FOREIGN\n");
  });
});

describe("uninstall removes only this plugin's own launcher", () => {
  it("removes our launcher for this install and nothing else", () => {
    const { layout, stateDir, ensure } = setup();
    const outcome = ensure();
    const removal = removeObservaEntrypoint({ pluginRoot: outcome.pluginRoot, stateDir });
    assert.deepEqual(removal.removed, [join(layout.bin, "observa")]);
    assert.deepEqual(readdirSync(layout.bin), ["openclaw"]);
  });

  it("keeps a launcher that belongs to another install of the plugin", () => {
    const { stateDir, ensure } = setup();
    const outcome = ensure();
    const other = makeFakePlugin("fake-other-profile");
    const removal = removeObservaEntrypoint({ pluginRoot: other, stateDir });
    assert.deepEqual(removal.removed, []);
    assert.equal(classifyEntrypoint(outcome.path).kind, "OWNED");
  });
});

describe("hostile launcher directories and platforms", () => {
  it("a world-writable launcher directory is refused", () => {
    const { layout, ensure } = setup();
    chmodSync(layout.bin, 0o777);
    const outcome = ensure();
    assert.equal(outcome.state, "UNSAFE_BIN_DIR");
    assert.deepEqual(readdirSync(layout.bin), ["openclaw"]);
    chmodSync(layout.bin, 0o755);
  });

  it("a world-writable ancestor (without sticky bit) is refused", () => {
    const { layout, ensure } = setup();
    chmodSync(layout.prefix, 0o777);
    assert.equal(ensure().state, "UNSAFE_BIN_DIR");
    chmodSync(layout.prefix, 0o755);
  });

  it("a sticky world-writable ancestor such as /tmp is accepted, but never as the launcher directory", () => {
    const sticky = tempDir("observa sticky");
    chmodSync(sticky, 0o1777);
    const layout = makeOpenClawLayout(sticky);
    const plugin = makeFakePlugin();
    assert.equal(ensureObservaEntrypoint({ packageRoot: plugin, argv1: layout.launcher, env: {} }).state, "INSTALLED");
    const direct = makeOpenClawLayout();
    chmodSync(direct.bin, 0o1777);
    assert.equal(ensureObservaEntrypoint({ packageRoot: plugin, argv1: direct.launcher, env: {} }).state, "UNSAFE_BIN_DIR");
    chmodSync(direct.bin, 0o755);
    chmodSync(sticky, 0o700);
  });

  it("a group-writable launcher directory is refused unless the group is private", () => {
    const { layout, ensure } = setup();
    chmodSync(layout.bin, 0o775);
    // macOS primary groups are shared; Linux UPG groups qualify only when the
    // group carries the user's name and has no other members.
    const outcome = ensure();
    if (process.platform !== "linux") assert.equal(outcome.state, "UNSAFE_BIN_DIR");
    chmodSync(layout.bin, 0o755);
  });

  it("no qualifying launcher directory and non-POSIX platforms install nothing", () => {
    const plugin = makeFakePlugin();
    assert.equal(ensureObservaEntrypoint({ packageRoot: plugin, argv1: "/nonexistent/openclaw", env: {} }).state, "NO_LAUNCHER_DIR");
    const layout = makeOpenClawLayout();
    assert.equal(ensureObservaEntrypoint({ packageRoot: plugin, argv1: layout.launcher, env: {}, platform: "win32" }).state, "UNSUPPORTED_PLATFORM");
    assert.deepEqual(readdirSync(layout.bin), ["openclaw"]);
  });

  it("PATH shadowing is reported by what actually resolves first", () => {
    const { layout, ensure } = setup();
    ensure();
    const early = tempDir("observa early");
    writeFileSync(join(early, "observa"), "#!/bin/sh\necho EARLY\n", { mode: 0o755 });
    const found = resolveObservaOnPath(`${early}${delimiter}${layout.bin}`);
    assert.equal(found.kind, "UNKNOWN");
    assert.equal(found.path, join(early, "observa"));
    assert.equal(resolveObservaOnPath(`${layout.bin}${delimiter}${early}`).kind, "OWNED");
  });

  it("renders only absolute, single-line plugin roots", () => {
    for (const bad of ["relative/path", "/a\nb", "/a b", 42, null]) {
      assert.throws(() => renderEntrypoint(bad), /ENTRYPOINT_ROOT_INVALID/);
    }
    const text = renderEntrypoint("/odd \"root\" with 'quotes' and \\ backslash");
    assert.equal(classifyEntrypoint.length, 1);
    assert.ok(text.includes("const PLUGIN_ROOT = \"/odd \\\"root\\\" with 'quotes' and \\\\ backslash\";"));
  });
});

describe("the plugin lifecycle installs the launcher on gateway start", () => {
  function connector(cliEntrypoint) {
    const { config } = makeProfile({ enabled: true });
    const hooks = new Map();
    const api = {
      pluginConfig: { enabled: true, apiUrl: "https://hosted.invalid", stateDir: config.stateDir, receiptDir: config.receiptDir },
      config: { agents: { entries: { main: {} } } },
      runtime: { openclawVersion: "2026.8.2" },
      logger: { info() {}, warn() {}, error() {} },
      registerTool() {},
      on(name, handler) { hooks.set(name, [...(hooks.get(name) ?? []), handler]); },
    };
    const plugin = createGovernanceConnector({
      client: makeClientSpy(),
      transport: async () => { throw new Error("no transport in tests"); },
      shadowTransport: { evaluate: async () => { throw Object.assign(new Error("UNAVAILABLE"), { code: "UNAVAILABLE" }); }, close() {} },
      credentialProvider: async (callback) => callback("mgd1_x"),
      shadowCredentialProvider: async (_stateDir, callback) => callback("mgd1_x"),
      statusJournal: null,
      ...(cliEntrypoint ? { cliEntrypoint } : {}),
    });
    const handle = plugin.register(api);
    const emit = async (name) => { for (const handler of hooks.get(name) ?? []) await handler(); };
    return { emit, handle, config: handle.config };
  }

  it("calls the launcher installer once per gateway start, with the connector config", async () => {
    const calls = [];
    const { emit, handle, config } = connector((cfg) => { calls.push(cfg.stateDir); return { state: "INSTALLED", path: "/x/observa" }; });
    await emit("gateway_start");
    assert.deepEqual(calls, [config.stateDir]);
    await handle.shutdown();
  });

  it("a failing installer never breaks gateway start", async () => {
    const { emit, handle } = connector(() => { throw new Error("EACCES"); });
    await emit("gateway_start");
    await handle.shutdown();
  });

  it("without the shipped entry's installer (tests, harnesses) nothing is installed", async () => {
    const { emit, handle } = connector(null);
    await emit("gateway_start");
    await handle.shutdown();
  });

  it("the shipped plugin entry wires the installer to its own package root", () => {
    const text = readFileSync(join(ROOT, "plugins/openclaw-connector/plugin.mjs"), "utf8");
    assert.ok(text.includes('new URL("../..", import.meta.url)'));
    assert.ok(text.includes("ensureObservaEntrypoint({ packageRoot: PACKAGE_ROOT, stateDir: config.stateDir })"));
  });
});

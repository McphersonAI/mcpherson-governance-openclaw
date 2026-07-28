// v0.5.1 patch regression suite.
//
// One section per v0.5.1 finding. Every assertion is written against a
// non-vacuous baseline: the isolation tests first prove that state IS written
// under the active profile, the inertness tests first prove that receipts ARE
// written while enabled, and the compatibility tests first prove that a
// supported version DOES activate. A permanently-inert or permanently-refusing
// build cannot make these pass trivially.
//
// No network calls, no OpenClaw process, no real profile, no credential.

import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync,
  statSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(join(dirname(fileURLToPath(import.meta.url)), ".."));
const mod = (p) => import(pathToFileURL(join(ROOT, p)).href);

const SUPPORTED_HOST = "2026.6.5";
const UNSUPPORTED_HOST = "2026.3.2";
const COUNT_GUARD_INNER = process.env.MCPHERSON_COUNT_GUARD_INNER === "1";

// Never reached by any assertion about credential CONTENT — these tests only
// count whether the credential provider was invoked at all.
const SYNTHETIC_CREDENTIAL = "SYNTHETIC-TEST-CREDENTIAL-NOT-A-REAL-VALUE";

function sandbox() {
  const dir = mkdtempSync(join(tmpdir(), "mg-v051-"));
  return {
    dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function countGuardScratch(label) {
  const dir = mkdtempSync(join(tmpdir(), `mg-v051-count-guard-${label}-`));
  const root = join(dir, "repo");
  const gitDir = join(ROOT, ".git");
  cpSync(ROOT, root, {
    recursive: true,
    filter: (source) => source !== gitDir && !source.startsWith(`${gitDir}/`),
  });
  return {
    root,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function updateReleaseChecksum(root, relativePath) {
  const manifestPath = join(root, "RELEASE-CHECKSUMS.sha256");
  const manifest = readFileSync(manifestPath, "utf8");
  const escaped = relativePath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(`^[a-f0-9]{64}  ${escaped}$`, "m");
  assert.match(manifest, pattern, `release checksum manifest does not contain ${relativePath}`);
  const next = manifest.replace(
    pattern,
    `${sha256(join(root, relativePath))}  ${relativePath}`,
  );
  writeFileSync(manifestPath, next);
}

function updateScratchAccounting(root, { publicCount, verificationCount }) {
  const path = join(root, "LIMITATIONS.md");
  const source = readFileSync(path, "utf8");
  const upstream = Number(
    source.replace(/\s+/g, " ")
      .match(/Applicable upstream \(sealed-reference\) connector tests \| (\d+) \|/)?.[1],
  );
  assert.ok(Number.isSafeInteger(upstream), "scratch LIMITATIONS.md lacks the upstream count");
  const total = upstream + publicCount + verificationCount;
  const shipped = publicCount + verificationCount;
  let next = source
    .replace(
      /\*\*\d+ passed, \d+ failed, \d+\s*skipped\*\*/,
      `**${total} passed, 0 failed, 0\nskipped**`,
    )
    .replace(
      /(\| Public distribution, runtime, and v0\.5\.1 regression tests \| )\d+( \|)/,
      `$1${publicCount}$2`,
    )
    .replace(
      /(\| Bundled package verification checks \| )\d+( \|)/,
      `$1${verificationCount}$2`,
    )
    .replace(/(\| \*\*Total\*\* \| \*\*)\d+(\*\* \|)/, `$1${total}$2`)
    .replace(/Those \d+ are not all upstream tests/, `Those ${total} are not all upstream tests`)
    .replace(
      /together they are the\s+\d+ checks/,
      `together they are the\n${shipped} checks`,
    );
  assert.notEqual(next, source, "scratch LIMITATIONS.md accounting did not change");
  writeFileSync(path, next);
  updateReleaseChecksum(root, "LIMITATIONS.md");
}

function runScratch(root, args) {
  const env = { ...process.env, MCPHERSON_COUNT_GUARD_INNER: "1" };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, args, {
    cwd: root,
    encoding: "utf8",
    env,
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  return {
    status: result.status,
    output: `${result.stdout || ""}${result.stderr || ""}`,
  };
}

// A profile root shaped like `openclaw --profile <name>`: ~/.openclaw-<name>.
function profileRoot(home, name) {
  const root = join(home, name === "default" ? ".openclaw" : `.openclaw-${name}`);
  mkdirSync(root, { recursive: true });
  return root;
}

// Minimal stand-in for the OpenClaw plugin API surface the connector uses.
function hostApi({ pluginConfig = {}, version = SUPPORTED_HOST, stateDir = null } = {}) {
  const hooks = new Map();
  const tools = new Map();
  const logged = { error: [], warn: [], info: [] };
  return {
    hooks,
    tools,
    logged,
    pluginConfig,
    logger: {
      error: (m) => logged.error.push(m),
      warn: (m) => logged.warn.push(m),
      info: (m) => logged.info.push(m),
    },
    runtime: {
      ...(version === null ? {} : { version }),
      ...(stateDir === null ? {} : { state: { resolveStateDir: () => stateDir } }),
    },
    registerTool(tool, options = {}) { tools.set(options.name || tool.name, tool); },
    on(name, handler) {
      const list = hooks.get(name) || [];
      list.push(handler);
      hooks.set(name, list);
      return () => {
        const current = hooks.get(name) || [];
        const index = current.indexOf(handler);
        if (index >= 0) current.splice(index, 1);
        if (current.length === 0) hooks.delete(name);
      };
    },
  };
}

async function callHook(api, name, event = {}, ctx = {}) {
  let result;
  for (const handler of api.hooks.get(name) || []) result = await handler(event, ctx);
  return result;
}

function pluginConfigFor(stateDir, overrides = {}) {
  return {
    enabled: true,
    apiUrl: "https://governance.example.invalid:8443",
    deploymentId: "dep-v051",
    agentId: "agent-v051",
    policyVersion: 1,
    observationBudgetMs: 0,
    stateDir,
    receiptDir: join(stateDir, "receipts"),
    toolMetadata: {
      probe: {
        schemaVersion: "1.0.0",
        schemaHash: `sha256:${"0".repeat(64)}`,
        actionClass: "read_only_internal",
      },
    },
    ...overrides,
  };
}

// Register the shipped connector with a transport that records, but never
// answers usefully. Nothing leaves the loopback-free fake.
async function registerConnector(api, extra = {}) {
  const { createGovernanceConnector } = await mod("connector/index.mjs");
  const attempts = { transport: 0, credential: 0 };
  const runtime = createGovernanceConnector({
    transport: async () => {
      attempts.transport += 1;
      return { statusCode: 500, body: Buffer.from("{}") };
    },
    credentialProvider: async (callback) => {
      attempts.credential += 1;
      // Opaque synthetic label. The transport is faked, so nothing parses it;
      // it deliberately does not carry the real credential prefix.
      return callback(SYNTHETIC_CREDENTIAL);
    },
    ...extra,
  }).register(api);
  return { runtime, attempts };
}

function receiptLines(receiptDir) {
  const path = join(receiptDir, "connector-receipts.jsonl");
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8").split("\n").filter((line) => line.trim()).map((l) => JSON.parse(l));
}

// Ordinary OBSERVATION receipts only. `connector_lifecycle` records are a
// separate schema recording that the connector was loaded; they are not
// observation receipts and are deliberately unaffected by the disable.
function observationReceipts(receiptDir) {
  return receiptLines(receiptDir)
    .filter((r) => r.receipt_type === "attempt_receipt" || r.receipt_type === "completion_receipt");
}

// ── Finding 3 — named-profile state isolation ───────────────────────────────

test("v0.5.1 F3: connector state resolves inside the ACTIVE named profile", async () => {
  const { dir, cleanup } = sandbox();
  try {
    const { loadConnectorConfig } = await mod("connector/config.mjs");
    const named = profileRoot(dir, "governance-named");
    const config = loadConnectorConfig({}, { openclawStateDir: named });
    assert.equal(config.stateDir, join(named, "mcpherson-governance-connector"));
    assert.equal(config.receiptDir, join(config.stateDir, "receipts"));
    assert.equal(config.stateDir.startsWith(named), true);
  } finally { cleanup(); }
});

test("v0.5.1 F3: a named profile never resolves into the default profile root", async () => {
  const { dir, cleanup } = sandbox();
  try {
    const { loadConnectorConfig } = await mod("connector/config.mjs");
    const defaultRoot = profileRoot(dir, "default");
    const named = profileRoot(dir, "governance-named");

    // Non-vacuous baseline: the default profile really does resolve to the
    // default root, so the named-profile assertion below is meaningful.
    const defaultConfig = loadConnectorConfig({}, { openclawStateDir: defaultRoot });
    assert.equal(defaultConfig.stateDir, join(defaultRoot, "mcpherson-governance-connector"));

    const namedConfig = loadConnectorConfig({}, { openclawStateDir: named });
    assert.equal(namedConfig.stateDir.startsWith(defaultRoot + "/"), false,
      `named profile resolved inside the default profile: ${namedConfig.stateDir}`);
    assert.notEqual(namedConfig.stateDir, defaultConfig.stateDir);
  } finally { cleanup(); }
});

test("v0.5.1 F3: the host profile resolver and OPENCLAW_STATE_DIR both win over the home default", async () => {
  const { dir, cleanup } = sandbox();
  try {
    const { resolveOpenClawStateDir, connectorStateRoot } = await mod("connector/host.mjs");
    const named = profileRoot(dir, "governance-named");
    const fakeHome = join(dir, "home");
    mkdirSync(fakeHome, { recursive: true });

    // 1. host resolver wins
    assert.equal(
      resolveOpenClawStateDir({
        runtime: { state: { resolveStateDir: () => named } },
        env: {},
        home: () => fakeHome,
      }),
      named,
    );
    // 2. OPENCLAW_STATE_DIR wins when the host exposes no resolver
    assert.equal(
      resolveOpenClawStateDir({ runtime: null, env: { OPENCLAW_STATE_DIR: named }, home: () => fakeHome }),
      named,
    );
    // 3. only with neither does the default profile root apply
    assert.equal(
      resolveOpenClawStateDir({ runtime: null, env: {}, home: () => fakeHome }),
      join(fakeHome, ".openclaw"),
    );
    assert.equal(
      connectorStateRoot(named),
      join(named, "mcpherson-governance-connector"),
    );
  } finally { cleanup(); }
});

test("v0.5.1 F3: registering under a named profile writes state there and leaves the default profile untouched", async () => {
  const { dir, cleanup } = sandbox();
  try {
    const defaultRoot = profileRoot(dir, "default");
    const named = profileRoot(dir, "governance-named");
    const defaultBefore = readdirSync(defaultRoot);

    const api = hostApi({ pluginConfig: { enabled: true }, stateDir: named });
    const { runtime } = await registerConnector(api);
    try {
      const stateDir = runtime.config.stateDir;
      assert.equal(stateDir, join(named, "mcpherson-governance-connector"));
      assert.equal(existsSync(stateDir), true, "named-profile state directory was not created");
      assert.equal(statSync(stateDir).mode & 0o777, 0o700);

      // default profile untouched: no connector directory, no new entries
      assert.equal(existsSync(join(defaultRoot, "mcpherson-governance-connector")), false,
        "the default profile received connector state");
      assert.deepEqual(readdirSync(defaultRoot), defaultBefore);
    } finally { await runtime.shutdown(); }
  } finally { cleanup(); }
});

test("v0.5.1 F3: two named profiles share no connector state", async () => {
  const { dir, cleanup } = sandbox();
  try {
    const alphaRoot = profileRoot(dir, "alpha");
    const betaRoot = profileRoot(dir, "beta");

    const alphaApi = hostApi({ pluginConfig: { enabled: true }, stateDir: alphaRoot });
    const betaApi = hostApi({ pluginConfig: { enabled: true }, stateDir: betaRoot });
    const { runtime: alpha } = await registerConnector(alphaApi);
    const { runtime: beta } = await registerConnector(betaApi);
    try {
      assert.notEqual(alpha.config.stateDir, beta.config.stateDir);
      assert.equal(alpha.config.stateDir.startsWith(alphaRoot), true);
      assert.equal(beta.config.stateDir.startsWith(betaRoot), true);

      const { setControl, inspectControl } = await mod("connector/controls.mjs");
      // A control written in alpha must not be visible in beta.
      setControl(alpha.config.stateDir, "killswitch", true);
      assert.equal(inspectControl(alpha.config.stateDir, "killswitch").active, true);
      assert.equal(inspectControl(beta.config.stateDir, "killswitch").active, false,
        "profiles share connector control state");

      // Receipts written in beta must not appear in alpha.
      await callHook(betaApi, "before_tool_call",
        { toolName: "probe", params: {}, toolCallId: "beta-1" },
        { toolName: "probe", agentId: "agent-v051", toolCallId: "beta-1" });
      assert.ok(observationReceipts(beta.config.receiptDir).length > 0, "beta wrote no receipt");
      assert.equal(observationReceipts(alpha.config.receiptDir).length, 0,
        "a receipt written under beta appeared under alpha");
    } finally {
      await alpha.shutdown();
      await beta.shutdown();
    }
  } finally { cleanup(); }
});

test("v0.5.1 F3: removing one profile's state leaves the other profile's state intact", async () => {
  const { dir, cleanup } = sandbox();
  try {
    const alphaRoot = profileRoot(dir, "alpha");
    const betaRoot = profileRoot(dir, "beta");
    const alphaApi = hostApi({ pluginConfig: { enabled: true }, stateDir: alphaRoot });
    const betaApi = hostApi({ pluginConfig: { enabled: true }, stateDir: betaRoot });
    const { runtime: alpha } = await registerConnector(alphaApi);
    const { runtime: beta } = await registerConnector(betaApi);
    await alpha.shutdown();
    await beta.shutdown();

    await callHook(betaApi, "before_tool_call", {}, {});
    const betaState = beta.config.stateDir;
    const alphaState = alpha.config.stateDir;
    assert.equal(existsSync(alphaState), true);
    assert.equal(existsSync(betaState), true);

    // Uninstalling / purging one profile is a directory removal under that
    // profile root. It must not reach the other profile.
    rmSync(alphaRoot, { recursive: true, force: true });
    assert.equal(existsSync(alphaState), false);
    assert.equal(existsSync(betaState), true,
      "removing one profile's state removed another profile's state");
  } finally { cleanup(); }
});

test("v0.5.1 F3: no automatic legacy-state migration occurs", async () => {
  const { dir, cleanup } = sandbox();
  try {
    const defaultRoot = profileRoot(dir, "default");
    const legacy = join(defaultRoot, "mcpherson-governance-connector");
    mkdirSync(join(legacy, "receipts"), { recursive: true });
    chmodSync(legacy, 0o700);
    chmodSync(join(legacy, "receipts"), 0o700);
    const { setControl } = await mod("connector/controls.mjs");
    setControl(legacy, "killswitch", true);
    const legacyBefore = readdirSync(legacy).sort();
    const legacyMtime = statSync(legacy).mtimeMs;

    const named = profileRoot(dir, "governance-named");
    const api = hostApi({ pluginConfig: { enabled: true }, stateDir: named });
    const { runtime } = await registerConnector(api);
    try {
      const stateDir = runtime.config.stateDir;
      // Nothing was copied forward: the named profile starts with no control,
      // no credential, and no receipt inherited from the legacy location.
      const { inspectControl } = await mod("connector/controls.mjs");
      assert.equal(inspectControl(stateDir, "killswitch").active, false,
        "a legacy control was migrated into the named profile");
      assert.equal(existsSync(join(stateDir, "deployment-credential")), false);
      assert.equal(receiptLines(join(stateDir, "receipts")).length, 0);

      // And nothing was taken away: the legacy location is byte-for-byte as
      // it was, with no new files and no removal.
      assert.deepEqual(readdirSync(legacy).sort(), legacyBefore);
      assert.equal(statSync(legacy).mtimeMs, legacyMtime);
    } finally { await runtime.shutdown(); }
  } finally { cleanup(); }
});

// ── Finding 4 — OpenClaw compatibility activation gate ──────────────────────

test("v0.5.1 F4: version comparison orders OpenClaw versions and pre-releases correctly", async () => {
  const { compareOpenClawVersions, evaluateHostCompatibility } = await mod("connector/host.mjs");
  assert.equal(compareOpenClawVersions("2026.6.5", "2026.6.5"), 0);
  assert.equal(compareOpenClawVersions("2026.3.2", "2026.6.5") < 0, true);
  assert.equal(compareOpenClawVersions("2026.6.4", "2026.6.5") < 0, true);
  assert.equal(compareOpenClawVersions("2025.9.9", "2026.6.5") < 0, true);
  assert.equal(compareOpenClawVersions("2026.6.6", "2026.6.5") > 0, true);
  assert.equal(compareOpenClawVersions("2026.7.0", "2026.6.5") > 0, true);
  assert.equal(compareOpenClawVersions("2027.1.0", "2026.6.5") > 0, true);
  // a pre-release of the minimum ranks below the minimum
  assert.equal(compareOpenClawVersions("2026.6.5-rc.1", "2026.6.5") < 0, true);
  assert.equal(evaluateHostCompatibility("2026.6.5-rc.1").status, "UNSUPPORTED");
  // build metadata does not
  assert.equal(compareOpenClawVersions("2026.6.5+build.9", "2026.6.5"), 0);
  // unparseable input is not silently ordered
  assert.equal(compareOpenClawVersions("not-a-version", "2026.6.5"), null);

  // A host that DECLARES a version it cannot determine is not treated as
  // satisfying the support contract. OpenClaw's own fallback for that case is
  // the literal string "unknown".
  for (const undetermined of ["not-a-version", "unknown", ""]) {
    const gate = evaluateHostCompatibility({ declared: true, version: undetermined });
    assert.equal(gate.status, "UNSUPPORTED", `"${undetermined}" was treated as supported`);
    assert.equal(gate.activate, false);
  }
  // A host that does not implement the field at all is a harness, not a claim.
  assert.equal(evaluateHostCompatibility(null).status, "UNKNOWN");
  assert.equal(evaluateHostCompatibility(null).activate, true);
  assert.equal(evaluateHostCompatibility({ declared: false }).activate, true);
});

test("v0.5.1 F4: an unresolvable runtime version falls back to the host's own package manifest", async () => {
  const { dir, cleanup } = sandbox();
  try {
    const {
      resolveHostOpenClawVersion, readHostManifestVersion, evaluateHostCompatibility,
    } = await mod("connector/host.mjs");
    const { writeFileSync, mkdirSync: mk } = await import("node:fs");

    // A host tree shaped like a real OpenClaw install: entry script beside the
    // package manifest that names the true version.
    const hostRoot = join(dir, "lib", "node_modules", "openclaw");
    mk(hostRoot, { recursive: true });
    writeFileSync(join(hostRoot, "package.json"),
      JSON.stringify({ name: "openclaw", version: "2026.3.2" }));
    const entry = join(hostRoot, "openclaw.mjs");
    writeFileSync(entry, "export default {};\n");

    assert.equal(readHostManifestVersion({ entry }), "2026.3.2");

    // runtime.version resolves fine -> the manifest is never consulted
    const direct = resolveHostOpenClawVersion({ runtime: { version: "2026.7.0" } }, { entry });
    assert.equal(direct.version, "2026.7.0");
    assert.equal(direct.source, "runtime");

    // runtime.version is the host's own "unknown" fallback -> manifest wins,
    // and the gate then refuses on the TRUE version with it named in the error
    const fallback = resolveHostOpenClawVersion({ runtime: { version: "unknown" } }, { entry });
    assert.equal(fallback.declared, true);
    assert.equal(fallback.version, "2026.3.2");
    assert.equal(fallback.source, "host_manifest");
    const gate = evaluateHostCompatibility(fallback);
    assert.equal(gate.status, "UNSUPPORTED");
    assert.equal(gate.versionSource, "host_manifest");
    assert.match(gate.message, /2026\.3\.2/);

    // a supported host whose runtime field is equally unresolvable still runs
    writeFileSync(join(hostRoot, "package.json"),
      JSON.stringify({ name: "openclaw", version: "2026.6.5" }));
    const supported = resolveHostOpenClawVersion({ runtime: { version: "unknown" } }, { entry });
    assert.equal(evaluateHostCompatibility(supported).status, "SUPPORTED");

    // neither source available -> declared but undetermined -> refuse
    const none = resolveHostOpenClawVersion({ runtime: { version: "unknown" } },
      { entry: join(dir, "no-such-entry") });
    assert.equal(none.declared, true);
    assert.equal(none.version, null);
    assert.equal(evaluateHostCompatibility(none).activate, false);
  } finally { cleanup(); }
});

test("v0.5.1 F4: a supported host activates and a host below the minimum refuses", async () => {
  const { dir, cleanup } = sandbox();
  try {
    // Non-vacuous baseline: the SUPPORTED host must genuinely activate.
    const okDir = join(dir, "supported");
    mkdirSync(okDir, { recursive: true });
    const okApi = hostApi({
      pluginConfig: pluginConfigFor(okDir), version: SUPPORTED_HOST,
    });
    const { runtime: ok } = await registerConnector(okApi);
    try {
      assert.equal(ok.activated, true);
      assert.equal(ok.compatibility.status, "SUPPORTED");
      assert.equal(ok.compatibility.hostVersion, SUPPORTED_HOST);
      assert.notEqual(ok.pipeline, null);
    } finally { await ok.shutdown(); }

    const badDir = join(dir, "unsupported");
    mkdirSync(badDir, { recursive: true });
    const badApi = hostApi({
      pluginConfig: pluginConfigFor(badDir), version: UNSUPPORTED_HOST,
    });
    const { runtime: bad, attempts } = await registerConnector(badApi);
    try {
      assert.equal(bad.activated, false);
      assert.equal(bad.compatibility.status, "UNSUPPORTED");
      assert.equal(bad.compatibility.hostVersion, UNSUPPORTED_HOST);
      assert.equal(bad.compatibility.minimumVersion, "2026.6.5");

      // a clear compatibility error is surfaced exactly once
      assert.equal(badApi.logged.error.length, 1);
      assert.match(badApi.logged.error[0], /requires OpenClaw >=2026\.6\.5/);
      assert.match(badApi.logged.error[0], new RegExp(UNSUPPORTED_HOST.replace(/\./g, "\\.")));

      // no connector-owned runtime was constructed at all
      assert.equal(bad.pipeline, null);
      assert.equal(bad.client, null);
      assert.equal(bad.receiptWriter, null);
      assert.equal(bad.config, null);

      // unrelated OpenClaw execution is preserved and non-blocking
      for (const hook of ["before_tool_call", "after_tool_call", "gateway_start", "gateway_stop"]) {
        assert.ok(badApi.hooks.has(hook), `hook not registered on refusal: ${hook}`);
        assert.equal(
          await callHook(badApi, hook,
            { toolName: "probe", params: { secret: "x" }, toolCallId: "c1" },
            { toolName: "probe", agentId: "agent-v051", toolCallId: "c1" }),
          undefined,
          `${hook} produced a hook result on an unsupported host`,
        );
      }

      // no governance request and no receipt of any kind
      assert.equal(attempts.transport, 0);
      assert.equal(attempts.credential, 0);
      assert.equal(existsSync(join(badDir, "receipts", "connector-receipts.jsonl")), false);
      assert.equal(existsSync(join(badDir, "mcpherson-governance-connector")), false);
      assert.equal(bad.status().activated, false);
    } finally { await bad.shutdown(); }
  } finally { cleanup(); }
});

test("v0.5.1 F4: the version source is the host runtime object, never a subprocess", async () => {
  const { readHostOpenClawVersion } = await mod("connector/host.mjs");
  assert.equal(readHostOpenClawVersion({ runtime: { version: "2026.6.5" } }), "2026.6.5");
  assert.equal(readHostOpenClawVersion({ runtime: {} }), null);
  assert.equal(readHostOpenClawVersion({}), null);
  assert.equal(readHostOpenClawVersion(null), null);

  const source = readFileSync(join(ROOT, "connector/host.mjs"), "utf8");
  for (const forbidden of ["child_process", "spawnSync", "execSync", "execFile"]) {
    assert.equal(source.includes(forbidden), false,
      `the compatibility gate must not shell out: ${forbidden}`);
  }
});

// ── Finding 5 — disabled means inert, registered hooks are not activation ───

test("v0.5.1 F5: operationally disabled hook handlers no-op and write no receipts", async () => {
  const { dir, cleanup } = sandbox();
  try {
    const stateDir = join(dir, "state");
    mkdirSync(stateDir, { recursive: true });

    // Non-vacuous baseline: while ENABLED, the same calls DO produce receipts.
    const enabledApi = hostApi({ pluginConfig: pluginConfigFor(stateDir, { enabled: true }) });
    const { runtime: enabled } = await registerConnector(enabledApi);
    const ctx = { toolName: "probe", agentId: "agent-v051", toolCallId: "call-1" };
    await callHook(enabledApi, "gateway_start", { port: 0 }, {});
    await callHook(enabledApi, "before_tool_call", { ...ctx, params: {} }, ctx);
    await callHook(enabledApi, "after_tool_call", { ...ctx, params: {} }, ctx);
    await new Promise((r) => setTimeout(r, 50));
    const enabledCount = observationReceipts(enabled.config.receiptDir).length;
    assert.ok(enabledCount > 0, "baseline wrote no receipts - the inertness check would be vacuous");
    await enabled.shutdown();

    // Now the disabled case, from a clean receipt log.
    const disabledDir = join(dir, "disabled-state");
    mkdirSync(disabledDir, { recursive: true });
    const api = hostApi({ pluginConfig: pluginConfigFor(disabledDir, { enabled: false }) });
    const { runtime, attempts } = await registerConnector(api);
    try {
      assert.equal(runtime.activated, true, "the plugin still loads and registers");
      // hook entrypoints ARE registered - that is acceptable and expected
      for (const hook of ["before_tool_call", "after_tool_call", "gateway_start", "gateway_stop"]) {
        assert.ok(api.hooks.has(hook), `hook entrypoint missing: ${hook}`);
      }
      assert.deepEqual([...api.tools.keys()].sort(),
        ["mcpherson_connection_test", "mcpherson_governance_canary"]);

      // ...and every tool-observation handler immediately no-ops
      assert.equal(await callHook(api, "before_tool_call", { ...ctx, params: {} }, ctx), undefined);
      assert.equal(await callHook(api, "after_tool_call", { ...ctx, params: {} }, ctx), undefined);
      await new Promise((r) => setTimeout(r, 50));

      assert.equal(attempts.transport, 0, "a governance request was sent while disabled");
      assert.equal(attempts.credential, 0, "the credential was read while disabled");
      assert.deepEqual(observationReceipts(runtime.config.receiptDir), [],
        "an ordinary observation receipt was written while disabled");
      assert.equal(runtime.pipeline.status().totals.admitted, 0,
        "shadow observation was admitted while disabled");
      assert.equal(runtime.status().enabled, false);
    } finally { await runtime.shutdown(); }
  } finally { cleanup(); }
});

test("v0.5.1 F5: explicit enablement activates shadow observation and disabling returns it to inert", async () => {
  const { dir, cleanup } = sandbox();
  try {
    const stateDir = join(dir, "state");
    mkdirSync(stateDir, { recursive: true });
    const api = hostApi({ pluginConfig: pluginConfigFor(stateDir, { enabled: true }) });
    const { runtime, attempts } = await registerConnector(api);
    const { disableConnector, enableConnector } = await mod("connector/operator.mjs");
    const ctx = { toolName: "probe", agentId: "agent-v051", toolCallId: "call-a" };
    try {
      // enabled: shadow observation runs
      enableConnector(runtime.config);
      await callHook(api, "before_tool_call", { ...ctx, params: {} }, ctx);
      await new Promise((r) => setTimeout(r, 50));
      const afterEnabled = observationReceipts(runtime.config.receiptDir).length;
      assert.ok(afterEnabled > 0, "enablement did not activate shadow observation");
      const transportsWhileEnabled = attempts.transport;
      assert.ok(transportsWhileEnabled > 0, "no governance request was attempted while enabled");

      // disabled: immediately inert
      disableConnector(runtime.config);
      for (const call of ["call-b", "call-c"]) {
        const c = { ...ctx, toolCallId: call };
        assert.equal(await callHook(api, "before_tool_call", { ...c, params: {} }, c), undefined);
        assert.equal(await callHook(api, "after_tool_call", { ...c, params: {} }, c), undefined);
      }
      await new Promise((r) => setTimeout(r, 50));
      assert.equal(observationReceipts(runtime.config.receiptDir).length, afterEnabled,
        "an observation receipt was written after disabling");
      assert.equal(attempts.transport, transportsWhileEnabled,
        "a governance request was attempted after disabling");
    } finally { await runtime.shutdown(); }
  } finally { cleanup(); }
});

test("v0.5.1 F5: kill switch and system lock keep their documented local-receipt behaviour", async () => {
  const { dir, cleanup } = sandbox();
  try {
    const { setControl } = await mod("connector/controls.mjs");
    for (const [control, expected] of [
      ["killswitch", "KILL_SWITCH_ACTIVE"],
      ["lock", "SYSTEM_LOCK_ACTIVE"],
    ]) {
      const stateDir = join(dir, `state-${control}`);
      mkdirSync(stateDir, { recursive: true });
      const api = hostApi({ pluginConfig: pluginConfigFor(stateDir, { enabled: true }) });
      const { runtime, attempts } = await registerConnector(api);
      try {
        setControl(runtime.config.stateDir, control, true);
        const ctx = { toolName: "probe", agentId: "agent-v051", toolCallId: `ctl-${control}` };
        assert.equal(await callHook(api, "before_tool_call", { ...ctx, params: {} }, ctx), undefined);
        await new Promise((r) => setTimeout(r, 50));
        const records = observationReceipts(runtime.config.receiptDir);
        assert.ok(records.length > 0, `${control} suppressed the local receipt`);
        assert.equal(records.at(-1).remote_status, expected);
        assert.equal(records.at(-1).local_disposition, "SKIPPED");
        assert.equal(attempts.transport, 0, `${control} did not stop remote contact`);
      } finally { await runtime.shutdown(); }
    }
  } finally { cleanup(); }
});

// ── Replacement for the excluded upstream control-precedence test ───────────
//
// Replaces, by exact name:
//   tests/connector/scheduler-controls-adversarial.test.mjs
//   "disabled/kill/lock precedence beats exact canary with a zero-network
//    call-order trace"
//
// All five upstream scenarios run here. The three kill-switch/system-lock
// scenarios keep their original receipt expectations. The two disabled
// scenarios assert the stricter v0.5.1 contract: no receipt at all, and the
// tool summary is never even derived. Every scenario still proves the control
// gate beats an armed exact-match canary with zero network, zero credential
// access, zero outbound construction, and a clean shutdown.

test("v0.5.1 replacement: disabled/kill/lock precedence beats exact canary with a zero-network call-order trace", async () => {
  const [
    { createGovernanceConnector },
    { inspectObservationControls, setControl },
    { deriveSafeToolSummary, buildObservationRequest, serializeAllowlistedRequest },
    { evaluateLocalCanary },
    { CANARY_TOKEN },
    { loadConnectorConfig },
  ] = await Promise.all([
    mod("connector/index.mjs"), mod("connector/controls.mjs"), mod("connector/allowlist.mjs"),
    mod("connector/canary.mjs"), mod("connector/constants.mjs"), mod("connector/config.mjs"),
  ]);

  const scenarios = [
    { controls: [], configEnabled: false, expected: null, trace: ["control_gate"] },
    { controls: ["killswitch"], expected: "KILL_SWITCH_ACTIVE", trace: ["control_gate", "local_summary"] },
    { controls: ["lock"], expected: "SYSTEM_LOCK_ACTIVE", trace: ["control_gate", "local_summary"] },
    { controls: ["killswitch", "lock"], expected: "KILL_SWITCH_ACTIVE", trace: ["control_gate", "local_summary"] },
    { controls: ["disabled", "killswitch", "lock"], expected: null, trace: ["control_gate"] },
  ];

  for (const [index, scenario] of scenarios.entries()) {
    const { dir, cleanup } = sandbox();
    try {
      const stateDir = join(dir, "state");
      mkdirSync(join(stateDir, "receipts"), { recursive: true });
      const config = loadConnectorConfig(pluginConfigFor(stateDir, {
        enabled: scenario.configEnabled !== false,
        observationBudgetMs: 0,
      }));

      // The canary is ARMED and the exact token is supplied, so a scenario that
      // reached canary evaluation would visibly block.
      setControl(config.stateDir, "canary", true);
      for (const control of scenario.controls) setControl(config.stateDir, control, true);

      const trace = [];
      const records = [];
      const api = hostApi({ pluginConfig: pluginConfigFor(stateDir) });
      const runtime = createGovernanceConnector({
        receiptWriter: { write: (r) => { records.push(r); return r; }, status: () => ({}), close: () => {} },
        controlInspector: () => { trace.push("control_gate"); return inspectObservationControls(config); },
        summaryBuilder: (...args) => { trace.push("local_summary"); return deriveSafeToolSummary(...args); },
        canaryEvaluator: (...args) => { trace.push("canary"); return evaluateLocalCanary(...args); },
        requestBuilder: (...args) => { trace.push("outbound_builder"); return buildObservationRequest(...args); },
        requestSerializer: (...args) => { trace.push("canonical_serializer"); return serializeAllowlistedRequest(...args); },
        credentialProvider: (callback) => { trace.push("credential"); return callback(SYNTHETIC_CREDENTIAL); },
        transport: async () => { trace.push("https_transport"); return { statusCode: 500, body: Buffer.from("{}") }; },
      }).register(api);

      const ctx = {
        toolName: "mcpherson_governance_canary",
        agentId: config.agentId,
        toolCallId: `combined-control-${index}`,
      };
      const result = await callHook(api, "before_tool_call",
        { ...ctx, params: { token: CANARY_TOKEN } }, ctx);

      const label = `scenario ${index} [${scenario.controls.join("+") || "config-disabled"}]`;
      assert.equal(result, undefined, `${label} produced a hook result`);
      assert.deepEqual(trace, scenario.trace, `${label} call order`);

      if (scenario.expected === null) {
        assert.deepEqual(records, [], `${label} wrote a receipt while disabled`);
      } else {
        assert.equal(records.length, 1, `${label} receipt count`);
        assert.equal(records.at(-1).remote_status, scenario.expected, label);
        assert.equal(records.at(-1).local_disposition, "SKIPPED", label);
      }

      // zero network, zero credential, zero outbound construction, in every case
      for (const forbidden of [
        "https_transport", "credential", "outbound_builder", "canonical_serializer", "canary",
      ]) {
        assert.equal(trace.includes(forbidden), false, `${label} reached ${forbidden}`);
      }
      assert.deepEqual({
        activeTransports: runtime.client.status().activeTransports,
        requests: runtime.client.status().requests,
        sockets: runtime.client.status().sockets,
        queued: runtime.pipeline.status().queued,
      }, { activeTransports: 0, requests: 0, sockets: 0, queued: 0 }, label);

      await runtime.shutdown();
      assert.equal(runtime.controller.status().hookCount, 0, `${label} residual hook count`);
      assert.equal(runtime.terminalStatus().registeredHooks, 0, label);
      assert.equal(api.hooks.size, 0, `${label} hooks not unregistered`);
    } finally { cleanup(); }
  }
});

// ── Findings 1 & 2 — public installation and lifecycle documentation ────────

test("v0.5.1 F1/F2: docs describe the real ClawHub artifact and no unavailable command", () => {
  const install = readFileSync(join(ROOT, "INSTALL.md"), "utf8");
  const lifecycle = readFileSync(join(ROOT, "LIFECYCLE.md"), "utf8");
  const verify = readFileSync(join(ROOT, "VERIFY.md"), "utf8");
  const readme = readFileSync(join(ROOT, "README.md"), "utf8");
  const all = [install, lifecycle, verify, readme].join("\n");

  // the real ClawHub artifact name, not a GitHub release tarball
  assert.match(all, /mcphersonai-mcpherson-governance-openclaw-0\.5\.1\.tgz/);
  assert.equal(/mcpherson-governance-openclaw-v0\.5\.\d+\.tar\.gz/.test(all), false,
    "docs still reference a release tarball that ClawHub does not publish");

  // the exact acquisition, install, and lifecycle commands
  for (const required of [
    "clawhub package download",
    "clawhub package verify",
    "openclaw --profile",
    "plugins install",
    "plugins info",
    "plugins disable",
    "plugins uninstall",
  ]) {
    assert.ok(all.includes(required), `documentation is missing the command: ${required}`);
  }

  // connector-ctl must never be presented as a PATH command: the ClawHub +
  // OpenClaw archive install does not put it on PATH.
  const bareCtl = all.match(/^[^\S\n]*(?:\$ )?(?:mcpherson-)?connector-ctl\s/gm) ?? [];
  assert.deepEqual(bareCtl, [],
    `documentation invokes connector-ctl as a PATH command: ${bareCtl.join(", ")}`);
  // where the connector's own control CLI is documented, it is by explicit path
  assert.match(all, /node\s+"?\$\{?[A-Z_]+\}?"?\/connector\/connector-ctl\.mjs|node .*connector\/connector-ctl\.mjs/);
});

// ── Audit-repair regression: documentation and example truth ────────────────
//
// These lock the three items the independent audit required. Each asserts the
// documented fact, not merely the presence of a keyword, so stale v0.5.0
// wording cannot survive a future edit.

test("v0.5.1 audit-repair: LIMITATIONS.md states the correct suite accounting and both exclusions", () => {
  const limitations = readFileSync(join(ROOT, "LIMITATIONS.md"), "utf8");
  const flat = limitations.replace(/\s+/g, " ");

  // The stated total must be internally consistent with the stated groups, so
  // a drift in any group cannot leave the headline number silently wrong.
  const total = Number(flat.match(/\*\*(\d+) passed, 0 failed, 0\s*skipped\*\*/)?.[1]);
  assert.ok(Number.isInteger(total), "no complete suite total is stated");
  const upstream = Number(flat.match(/Applicable upstream \(sealed-reference\) connector tests \| (\d+)/)?.[1]);
  const publicGroup = Number(flat.match(/Public distribution, runtime, and v0\.5\.1 regression tests \| (\d+)/)?.[1]);
  const verifyGroup = Number(flat.match(/Bundled package verification checks \| (\d+)/)?.[1]);
  for (const [label, value] of [["upstream", upstream], ["public", publicGroup], ["verification", verifyGroup]]) {
    assert.ok(Number.isInteger(value), `no ${label} group count is stated`);
  }
  assert.equal(upstream + publicGroup + verifyGroup, total,
    `stated groups ${upstream}+${publicGroup}+${verifyGroup} do not sum to the stated total ${total}`);
  assert.match(flat, new RegExp(`\\*\\*Total\\*\\* \\| \\*\\*${total}\\*\\*`),
    "the table total disagrees with the headline total");
  assert.match(flat, new RegExp(`Those ${total} are not all upstream tests`));

  // the upstream figures are the audit-relevant ones and are pinned exactly
  assert.equal(upstream, 179, `LIMITATIONS.md claims ${upstream} applicable upstream tests`);
  assert.match(flat, /sealed reference suite contains \*\*181\*\* connector tests/);
  assert.equal(181 - upstream, 2, "the stated upstream figures do not imply exactly two exclusions");

  // the stale v0.5.0 accounting must be gone
  assert.equal(/The applicable 180\s+tests pass/.test(limitations), false,
    "stale '180 applicable tests' wording is still present");
  assert.equal(/its one internal-only packaging\s+assertion is replaced/.test(limitations), false,
    "stale 'one exclusion' wording is still present");
  assert.equal(/\b180\b/.test(flat), false, "LIMITATIONS.md still claims 180 upstream tests");

  // both exclusions named, with a reason and a replacement each
  assert.match(flat, /\*\*Two\*\* are\s*excluded, each by exact test name/);
  assert.match(flat, /package is private v0\.5\.0 and declares only inspected supported hooks at\s*runtime/);
  assert.match(flat, /disabled\/kill\/lock precedence beats exact canary/);
  assert.match(flat, /tests\/public-distribution\.test\.mjs/);
  assert.match(flat, /tests\/public-v051-regression\.test\.mjs/);
  assert.match(flat, /stricter/i);
  assert.match(flat, /runs \*\*all five\*\* of the original/);

  // and the no-broad-pattern guarantee
  assert.match(flat, /No broad exclusion pattern is used/);
  assert.match(flat, /never by filename, prefix, or wildcard/);
});

test("v0.5.1 audit-repair: the documented suite accounting matches the real runner", () => {
  // The numbers in LIMITATIONS.md §9 must agree with the runner's own
  // exclusion set and with the test files the package actually ships.
  const limitations = readFileSync(join(ROOT, "LIMITATIONS.md"), "utf8").replace(/\s+/g, " ");
  const runner = readFileSync(join(ROOT, "scripts/run-public-tests.mjs"), "utf8");

  const excluded = [...runner.matchAll(/^\s*test:\s*"([^"]+)"/gm)].map((m) => m[1]);
  assert.equal(excluded.length, 2, `runner declares ${excluded.length} exclusions, expected 2`);
  for (const name of excluded) {
    assert.ok(limitations.includes(name.replace(/\s+/g, " ")),
      `LIMITATIONS.md does not name the excluded test: ${name}`);
  }

  // Every shipped public test file is run by the one count-aware package
  // coordinator used by npm test.
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  assert.match(pkg.scripts.test, /scripts\/run-public-tests\.mjs --package-only/);
  for (const file of ["tests/public-distribution.test.mjs", "tests/public-runtime.test.mjs",
    "tests/public-v051-regression.test.mjs"]) {
    assert.ok(runner.includes(file), `the public runner does not run ${file}`);
  }

  // Nested scratch runs execute this same test. The environment marker keeps
  // those inner runs from recursively creating more scratch suites; the outer
  // official test is still the one that performs and proves both probes.
  if (COUNT_GUARD_INNER) return;

  const publicProbe = countGuardScratch("public");
  try {
    const regressionPath = join(publicProbe.root, "tests", "public-v051-regression.test.mjs");
    writeFileSync(
      regressionPath,
      `${readFileSync(regressionPath, "utf8")}\n`
      + `test("synthetic passing public count probe", () => {});\n`,
    );
    updateReleaseChecksum(publicProbe.root, "tests/public-v051-regression.test.mjs");

    let result = runScratch(publicProbe.root, [
      join(publicProbe.root, "scripts", "run-public-tests.mjs"),
      "--package-only",
    ]);
    assert.notEqual(result.status, 0, "a synthetic 52nd public test did not fail documentation truth");
    assert.match(result.output, /DOCUMENTATION TRUTH FAILURE/);
    assert.match(result.output, /documented public-test count:\s*51/);
    assert.match(result.output, /actual public-test count:\s*52/);
    assert.match(result.output, /Update LIMITATIONS\.md deliberately/);

    updateScratchAccounting(publicProbe.root, { publicCount: 52, verificationCount: 20 });
    result = runScratch(publicProbe.root, [
      join(publicProbe.root, "scripts", "run-public-tests.mjs"),
      "--package-only",
    ]);
    assert.equal(
      result.status,
      0,
      `the scratch public suite did not pass after deliberate documentation update:\n${result.output}`,
    );
    assert.match(result.output, /RESULT: PASS - 72 tests, 0 failures, 0 skipped/);
  } finally {
    publicProbe.cleanup();
  }

  const verificationProbe = countGuardScratch("verification");
  try {
    const verifierPath = join(verificationProbe.root, "scripts", "verify-package.mjs");
    const verifier = readFileSync(verifierPath, "utf8");
    const marker = "// ---------------------------------------------------------------------------";
    assert.ok(verifier.includes(marker), "verification insertion marker is missing");
    writeFileSync(
      verifierPath,
      verifier.replace(
        marker,
        `await check("synthetic passing verification count probe", () => "synthetic");\n\n${marker}`,
      ),
    );
    updateReleaseChecksum(verificationProbe.root, "scripts/verify-package.mjs");

    let result = runScratch(verificationProbe.root, [verifierPath]);
    assert.notEqual(result.status, 0,
      "a synthetic 21st verification check did not fail documentation truth");
    assert.match(result.output, /DOCUMENTATION TRUTH FAILURE/);
    assert.match(result.output, /documented verification count:\s*20/);
    assert.match(result.output, /actual executed verification count:\s*21/);
    assert.match(result.output, /Update LIMITATIONS\.md deliberately/);

    updateScratchAccounting(verificationProbe.root, {
      publicCount: 51,
      verificationCount: 21,
    });
    result = runScratch(verificationProbe.root, [verifierPath]);
    assert.equal(
      result.status,
      0,
      `the scratch verifier did not pass after deliberate documentation update:\n${result.output}`,
    );
    assert.match(result.output, /21 passed, 0 failed/);
  } finally {
    verificationProbe.cleanup();
  }
});

test("v0.5.1 audit-repair: the UNKNOWN compatibility case is publicly documented", async () => {
  const { MIN_SUPPORTED_OPENCLAW_VERSION } = await mod("connector/constants.mjs");
  const limitations = readFileSync(join(ROOT, "LIMITATIONS.md"), "utf8");
  const flat = limitations.replace(/\s+/g, " ");

  assert.ok(flat.includes(`minimum supported OpenClaw version is \`${MIN_SUPPORTED_OPENCLAW_VERSION}\``),
    "the minimum supported version is not stated");
  // each required disclosure element
  assert.match(flat, /A version below `2026\.6\.5` \| `UNSUPPORTED` \| \*\*No\*\*/);
  assert.match(flat, /supplied but not parseable[^|]*\| `UNSUPPORTED` \| \*\*No\*\*/);
  assert.match(flat, /No detectable version at all[^|]*\| `UNKNOWN` \| \*\*Yes\*\*/);
  assert.match(flat, /`UNKNOWN` does not mean verified compatible/);
  assert.match(flat, /not officially supported/);
  assert.match(flat, /shadow-only and non-blocking/i);
  assert.match(flat, /run OpenClaw `2026\.6\.5` or newer/);
  // and it must not be overclaimed anywhere public
  const publicDocs = ["README.md", "INSTALL.md", "LIFECYCLE.md", "VERIFY.md", "LIMITATIONS.md"]
    .map((f) => readFileSync(join(ROOT, f), "utf8")).join("\n");
  assert.equal(/UNKNOWN hosts are (?:officially )?supported/i.test(publicDocs), false,
    "a public document claims UNKNOWN hosts are supported");
  // README and INSTALL must point at the full disclosure
  for (const file of ["README.md", "INSTALL.md"]) {
    const text = readFileSync(join(ROOT, file), "utf8");
    assert.match(text, /UNKNOWN/, `${file} does not mention the UNKNOWN case`);
    assert.match(text, /LIMITATIONS\.md\) §9a/, `${file} does not link the §9a disclosure`);
  }
});

test("v0.5.1 audit-repair: the primary example is profile-safe", () => {
  const raw = JSON.parse(readFileSync(join(ROOT, "examples/connector-config.example.json"), "utf8"));

  // the two keys that would defeat profile isolation must be absent
  assert.equal(Object.prototype.hasOwnProperty.call(raw, "stateDir"), false,
    "the example hardcodes stateDir, which bypasses profile isolation");
  assert.equal(Object.prototype.hasOwnProperty.call(raw, "receiptDir"), false,
    "the example hardcodes receiptDir, which bypasses profile isolation");

  // it must still ship disabled and carry no real endpoint, credential, or user path
  assert.equal(raw.enabled, false, "the example must ship disabled");
  const text = readFileSync(join(ROOT, "examples/connector-config.example.json"), "utf8");
  assert.match(raw.apiUrl, /^https:\/\//);
  assert.match(raw.apiUrl, /\.invalid|\.example|127\.0\.0\.1/,
    "the example names a non-synthetic endpoint");
  assert.equal(/\/Users\/|\/home\/|\/root\/|bmcpherson/.test(text), false,
    "the example contains a user-specific path");
  assert.equal(/mgd1_|BEGIN [A-Z ]*PRIVATE KEY|Bearer\s+[A-Za-z0-9]/.test(text), false,
    "the example contains a credential-shaped value");
  assert.equal(Object.prototype.hasOwnProperty.call(raw, "deployment-credential"), false);

  // the overrides must be documented separately, with the isolation caveat
  const examplesReadme = readFileSync(join(ROOT, "examples/README.md"), "utf8").replace(/\s+/g, " ");
  assert.match(examplesReadme, /deliberately omits `stateDir` and `receiptDir`/);
  assert.match(examplesReadme, /\*\*active OpenClaw profile\*\*/);
  assert.match(examplesReadme, /Optional explicit overrides/);
  assert.match(examplesReadme, /opts out of profile-based isolation/);
  assert.match(examplesReadme, /OPENCLAW_STATE_DIR/);

  // and the example must still load against the real loader with no path keys
  assert.ok(Object.keys(raw).length > 0);
});

test("v0.5.1 audit-repair: the example loads with profile-resolved paths and no explicit dirs", async () => {
  const { dir, cleanup } = sandbox();
  try {
    const { loadConnectorConfig } = await mod("connector/config.mjs");
    const raw = JSON.parse(readFileSync(join(ROOT, "examples/connector-config.example.json"), "utf8"));
    const probe = { ...raw };
    delete probe.caFile; // the placeholder CA path does not exist on this machine

    // With no stateDir/receiptDir in the example, the loader must derive both
    // from the active profile rather than failing or reaching the home default.
    const named = profileRoot(dir, "example-profile");
    const cfg = loadConnectorConfig(probe, { openclawStateDir: named });
    assert.equal(cfg.enabled, false);
    assert.equal(cfg.stateDir, join(named, "mcpherson-governance-connector"));
    assert.equal(cfg.receiptDir, join(cfg.stateDir, "receipts"));
  } finally { cleanup(); }
});

test("v0.5.1 audit-repair: the release-artifact evidence root tracks package.json", () => {
  // scripts/build-release-artifacts.mjs packages the committed HEAD, and names
  // its archive from a hardcoded EVIDENCE_ROOT. If that string drifts from the
  // package version, the builder emits an archive named for one version holding
  // another. This pins them together.
  const builder = readFileSync(join(ROOT, "scripts/build-release-artifacts.mjs"), "utf8");
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  const match = builder.match(/const EVIDENCE_ROOT = "([^"]+)";/);
  assert.ok(match, "EVIDENCE_ROOT is not declared as expected");
  assert.equal(match[1], `mcpherson-governance-openclaw-v${pkg.version}`,
    `EVIDENCE_ROOT (${match[1]}) disagrees with package.json version ${pkg.version}`);
});

test("v0.5.1 F1: documented compatibility and profile behaviour match the implementation", async () => {
  const { MIN_SUPPORTED_OPENCLAW_VERSION, PLUGIN_VERSION } = await mod("connector/constants.mjs");
  assert.equal(PLUGIN_VERSION, "0.5.1");
  assert.equal(MIN_SUPPORTED_OPENCLAW_VERSION, "2026.6.5");

  const docs = ["README.md", "INSTALL.md", "LIFECYCLE.md", "VERIFY.md", "LIMITATIONS.md", "CHANGELOG.md"]
    .map((name) => readFileSync(join(ROOT, name), "utf8")).join("\n");
  assert.ok(docs.includes(MIN_SUPPORTED_OPENCLAW_VERSION),
    "documentation does not state the minimum supported OpenClaw version");
  // the profile-isolation contract must be stated, not implied
  assert.match(docs, /\.openclaw-<profile>|--profile/);
  assert.match(docs, /mcpherson-governance-connector/);
});

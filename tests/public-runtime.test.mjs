// Public runtime behaviour test.
//
// Verifies, against the shipped package, the runtime properties the public
// claims rest on: the plugin registers on the supported hook surface, a failed
// or hostile remote observation cannot block execution, receipts stay
// metadata-only, the outbound guard rejects content, local controls win, and
// the bundled configuration example still loads.
//
// No network calls. A fake OpenClaw host is supplied. Nothing here touches a
// live deployment.
//
// Every assertion below is written against a genuine non-vacuous baseline —
// e.g. the control tests first prove the connector is UNBLOCKED before
// asserting that a control blocks it, so a permanently-blocked configuration
// cannot make them pass trivially.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, mkdirSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(join(dirname(fileURLToPath(import.meta.url)), ".."));
const mod = (p) => import(pathToFileURL(join(ROOT, p)).href);

function tempState() {
  const dir = mkdtempSync(join(tmpdir(), "mg-runtime-"));
  mkdirSync(join(dir, "receipts"), { recursive: true });
  chmodSync(dir, 0o700);
  chmodSync(join(dir, "receipts"), 0o700);
  return dir;
}

function baseConfigInput(dir, overrides = {}) {
  return {
    enabled: false,
    apiUrl: "https://governance.example.invalid:8443",
    deploymentId: "dep-test",
    agentId: "agent-test",
    policyVersion: 1,
    stateDir: dir,
    receiptDir: join(dir, "receipts"),
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

// ── manifest / metadata parsing ─────────────────────────────────────────────

test("plugin and package manifests parse", () => {
  const plugin = JSON.parse(readFileSync(join(ROOT, "connector/openclaw.plugin.json"), "utf8"));
  assert.equal(plugin.id, "mcpherson-governance-connector");
  assert.equal(plugin.configSchema.additionalProperties, false);
  assert.deepEqual(plugin.contracts.tools,
    ["mcpherson_connection_test", "mcpherson_governance_canary"]);

  const pkg = JSON.parse(readFileSync(join(ROOT, "connector/package.json"), "utf8"));
  assert.equal(pkg.version, "0.5.1");
  assert.equal(pkg.type, "module");

  const rootPkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  assert.equal(rootPkg.type, "module");
  JSON.parse(readFileSync(join(ROOT, "openclaw.plugin.json"), "utf8"));
});

// ── config example ──────────────────────────────────────────────────────────

test("bundled configuration example loads against the real config loader", async () => {
  const { loadConnectorConfig } = await mod("connector/config.mjs");
  const raw = JSON.parse(readFileSync(join(ROOT, "examples/connector-config.example.json"), "utf8"));
  assert.equal(raw.enabled, false, "example must ship disabled");
  const dir = tempState();
  try {
    const probe = { ...raw, stateDir: dir, receiptDir: join(dir, "receipts") };
    delete probe.caFile;
    const cfg = loadConnectorConfig(probe);
    assert.equal(cfg.enabled, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ── hook registration ───────────────────────────────────────────────────────

test("plugin registers on the supported OpenClaw hook surface", async () => {
  const { default: connector } = await mod("connector/plugin.mjs");
  const dir = tempState();
  const seen = { hooks: [], tools: [] };
  const api = {
    pluginConfig: baseConfigInput(dir),
    logger: { error() {}, warn() {}, info() {} },
    on(name) { seen.hooks.push(name); return () => {}; },
    registerTool(_impl, meta) { seen.tools.push(meta?.name); },
  };
  let handle;
  try {
    handle = connector.register(api);
    for (const hook of ["before_tool_call", "after_tool_call", "gateway_start", "gateway_stop"]) {
      assert.ok(seen.hooks.includes(hook), `hook not registered: ${hook}`);
    }
    assert.deepEqual(seen.tools.sort(),
      ["mcpherson_connection_test", "mcpherson_governance_canary"]);
  } finally {
    try { await handle?.shutdown?.(500); } catch { /* best effort */ }
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── non-blocking remote failure ─────────────────────────────────────────────

test("failed or hostile remote observation cannot block execution", async () => {
  const { ConnectorHookController } = await mod("connector/hook.mjs");
  const { loadConnectorConfig } = await mod("connector/config.mjs");
  const dir = tempState();
  try {
    const cfg = loadConnectorConfig(baseConfigInput(dir));
    const scenarios = ["network_error", "timeout", "DENY", "REQUIRE_APPROVAL", "HOLD", "malformed"];
    for (const scenario of scenarios) {
      const pipeline = {
        submit() {
          const promise = ["network_error", "timeout"].includes(scenario)
            ? Promise.reject(new Error(scenario))
            : Promise.resolve({ decision_id: "d1", decision: scenario });
          promise.catch(() => {});
          return {
            request: {
              request_hash: `sha256:${"0".repeat(64)}`,
              correlation_ref: `sha256:${"1".repeat(64)}`,
              agent_id: "agent-test",
              tool_id: "probe",
            },
            promise,
          };
        },
        recordLocal() {
          const promise = Promise.resolve({});
          return { request: { request_hash: "h", correlation_ref: "r", agent_id: "a", tool_id: "t" }, promise };
        },
        async waitForeground() {},
        status() { return { shutdown: { clean: true } }; },
        async shutdown() {},
      };
      const controller = new ConnectorHookController({
        config: cfg,
        pipeline,
        receiptWriter: { write: () => ({ ok: true }), status: () => ({}) },
        controlInspector: () => ({ blocked: false }),
      });
      const result = await controller.beforeToolCall(
        { toolName: "probe" },
        { toolName: "probe", agentId: "agent-test", toolCallId: "call-1" },
      );
      assert.equal(result, undefined,
        `scenario ${scenario} produced a hook result: ${JSON.stringify(result)}`);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ── metadata-only receipts ──────────────────────────────────────────────────

test("receipts are metadata-only", async () => {
  const { makeAttemptReceipt, makeCompletionReceipt } = await mod("connector/receipts.mjs");
  const attempt = makeAttemptReceipt({
    requestHash: `sha256:${"0".repeat(64)}`,
    deploymentId: "dep-test", agentId: "agent-test", toolId: "probe",
    outcome: "NOT_OBSERVED", remoteStatus: "NOT_ATTEMPTED",
    correlationRef: `sha256:${"1".repeat(64)}`,
  });
  const completion = makeCompletionReceipt({
    decisionId: null, requestHash: `sha256:${"0".repeat(64)}`,
    deploymentId: "dep-test", agentId: "agent-test", toolId: "probe",
    outcome: "COMPLETED", correlationRef: `sha256:${"1".repeat(64)}`,
  });

  const forbidden = ["prompt", "message", "content", "param", "argument",
    "body", "text", "credential", "token", "input", "output", "payload"];
  for (const receipt of [attempt, completion]) {
    for (const key of Object.keys(receipt)) {
      assert.ok(!forbidden.some((f) => key.toLowerCase().includes(f)),
        `receipt exposes a content-bearing field: ${key}`);
      const value = receipt[key];
      assert.ok(value === null || ["string", "number", "boolean"].includes(typeof value),
        `receipt field ${key} is not a scalar`);
    }
  }
  assert.equal(completion.observation_basis, "DIRECT_SUPPORTED_POST_HOOK");
});

test("outbound guard rejects content injection against a valid baseline", async () => {
  const { serializeAllowlistedRequest, buildObservationRequest, deriveSafeToolSummary } =
    await mod("connector/allowlist.mjs");
  const { loadConnectorConfig } = await mod("connector/config.mjs");
  const dir = tempState();
  try {
    const cfg = loadConnectorConfig(baseConfigInput(dir));
    const summary = deriveSafeToolSummary(
      { toolName: "probe", agentId: "agent-test", toolCallId: "call-1", runId: null }, cfg);
    const valid = buildObservationRequest(summary, cfg);

    // the baseline MUST serialize, or every rejection below is vacuous
    const bytes = serializeAllowlistedRequest({ ...valid });
    assert.ok(bytes.length > 0, "valid baseline failed to serialize");

    const attacks = {
      extra_prompt_field: { ...valid, prompt: "secret user text" },
      extra_params_field: { ...valid, params: { path: "/etc/shadow" } },
      // Synthetic, obviously-fake fixture. It still matches the guard's
      // bearer pattern (which permits hyphens), so the rejection is real,
      // but it does not read as a credential to a secret scanner.
      bearer_in_label: { ...valid, action_class: "Bearer EXAMPLE-NOT-A-REAL-TOKEN-0000" },
      url_in_label: { ...valid, agent_id: "https://evil.example/leak" },
      pem_in_label: { ...valid, agent_id: "-----BEGIN PRIVATE KEY-----" },
      newline_injection: { ...valid, tool_id: "probe\nX-Inject: 1" },
      oversize_label: { ...valid, agent_id: "a".repeat(300) },
    };
    for (const [name, payload] of Object.entries(attacks)) {
      assert.throws(() => serializeAllowlistedRequest(payload), undefined,
        `${name} was not rejected`);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ── local controls win ──────────────────────────────────────────────────────

test("disable, kill switch, and lock block observation before any network use", async () => {
  const { setControl, inspectObservationControls } = await mod("connector/controls.mjs");
  const { loadConnectorConfig } = await mod("connector/config.mjs");
  const dir = tempState();
  try {
    // enabled:true so the baseline is genuinely unblocked - otherwise these
    // assertions would pass trivially
    const cfg = loadConnectorConfig(baseConfigInput(dir, { enabled: true }));
    assert.equal(inspectObservationControls(cfg).blocked, false,
      "baseline already blocked - this check would be vacuous");

    for (const [control, expected] of [
      ["disabled", "NOT_ATTEMPTED"],
      ["killswitch", "KILL_SWITCH_ACTIVE"],
      ["lock", "SYSTEM_LOCK_ACTIVE"],
    ]) {
      setControl(cfg.stateDir, control, true);
      const active = inspectObservationControls(cfg);
      assert.equal(active.blocked, true, `${control} did not block`);
      assert.equal(active.remoteStatus, expected, `${control} reported ${active.remoteStatus}`);
      setControl(cfg.stateDir, control, false);
      assert.equal(inspectObservationControls(cfg).blocked, false, `${control} did not clear`);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

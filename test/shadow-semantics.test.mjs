// SHADOW ONLY / AUTHORITY NONE / ENFORCEMENT OFF / ACTIVE OFF.
//
// These tests pin the properties that make the connector observational, so the
// outbound repair cannot quietly become an execution path. They drive the real
// plugin through a fake OpenClaw host API.
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { createGovernanceConnector } from "../plugins/openclaw-connector/index.mjs";
import {
  DEFAULT_MODES, ENFORCEABLE_REMOTE_DECISIONS, PLUGIN_VERSION, REMOTE_AUTHORITY,
} from "../plugins/openclaw-connector/constants.mjs";
import { SHADOW_RELEASE } from "../plugins/openclaw-connector/shadow-v070/constants.mjs";
import { cleanupProfiles, flush, makeClientSpy, makeProfile } from "./helpers.mjs";

after(cleanupProfiles);

const ROOT = fileURLToPath(new URL("..", import.meta.url));

/** Minimal stand-in for the OpenClaw plugin host API. */
function makeHost({ stateDir, receiptDir, enabled = true, apiUrl = "https://hosted.invalid" }) {
  const hooks = new Map();
  const tools = new Map();
  const errors = [];
  return {
    api: {
      pluginConfig: { enabled, apiUrl, stateDir, receiptDir },
      config: { agents: { entries: { main: {} } } },
      runtime: { openclawVersion: "2026.8.2" },
      logger: { error: (message) => errors.push(message), warn() {}, info() {} },
      registerTool: (tool, options) => tools.set(options.name, tool),
      on(name, handler) {
        const list = hooks.get(name) ?? [];
        list.push(handler);
        hooks.set(name, list);
        return () => hooks.set(name, hooks.get(name).filter((entry) => entry !== handler));
      },
    },
    hooks, tools, errors,
    async emit(name, ...args) {
      const results = [];
      for (const handler of hooks.get(name) ?? []) results.push(await handler(...args));
      return results;
    },
  };
}

async function register(overrides = {}) {
  const { config } = makeProfile({ enabled: true });
  const host = makeHost({ stateDir: config.stateDir, receiptDir: config.receiptDir });
  const client = makeClientSpy();
  const plugin = createGovernanceConnector({
    client,
    transport: async () => { throw new Error("no transport in tests"); },
    shadowTransport: { evaluate: async () => { throw Object.assign(new Error("UNAVAILABLE"), { code: "UNAVAILABLE" }); }, close() {} },
    credentialProvider: async (callback) => callback("mgd1_x"),
    shadowCredentialProvider: async (_stateDir, callback) => callback("mgd1_x"),
    ...overrides,
  });
  const registered = plugin.register(host.api);
  return { config, host, client, registered };
}

describe("the posture is fixed in source and cannot be configured", () => {
  it("declares SHADOW / NONE / OFF / OFF everywhere", () => {
    assert.equal(DEFAULT_MODES.mode, "SHADOW");
    assert.equal(DEFAULT_MODES.authority, "NONE");
    assert.equal(DEFAULT_MODES.enforcement, "OFF");
    assert.equal(DEFAULT_MODES.active, false);
    assert.equal(REMOTE_AUTHORITY, false);
    assert.deepEqual(ENFORCEABLE_REMOTE_DECISIONS, []);
    assert.equal(SHADOW_RELEASE.mode, "SHADOW");
    assert.equal(SHADOW_RELEASE.authority, "NONE");
    assert.equal(SHADOW_RELEASE.enforcement, "OFF");
    assert.equal(SHADOW_RELEASE.active, false);
    assert.equal(SHADOW_RELEASE.active_capable, false);
  });

  it("refuses configuration that would claim authority", async () => {
    const { loadConnectorConfig } = await import("../plugins/openclaw-connector/config.mjs");
    for (const key of ["mode", "authority", "enforcement", "active", "remoteAuthority"]) {
      assert.throws(() => loadConnectorConfig({ [key]: "ANYTHING" }), (error) => (
        error.code === "FORBIDDEN_AUTHORITY_CONFIG" || error.code === "CONFIG_UNKNOWN_KEY"
      ), key);
    }
  });

  it("ships no enforceable decision vocabulary and no blocking result shape", () => {
    for (const file of [
      "plugins/openclaw-connector/hook.mjs",
      "plugins/openclaw-connector/index.mjs",
      "plugins/openclaw-connector/shadow-v070/runtime.mjs",
      "plugins/openclaw-connector/runtime-observer.mjs",
    ]) {
      const text = readFileSync(join(ROOT, file), "utf8");
      for (const token of ["requireApproval", "allowedDecisions", "allow-once", "allow-always"]) {
        assert.equal(text.includes(token), false, `${file} must not use ${token}`);
      }
    }
  });
});

describe("tool execution is never altered", () => {
  it("before_tool_call resolves undefined, so OpenClaw keeps execution authority", async () => {
    const { host } = await register();
    const event = { toolName: "exec", params: { command: "ls" }, toolCallId: "call-1", runId: "run-1" };
    const results = await host.emit("before_tool_call", event, { agentId: "main", runId: "run-1", toolCallId: "call-1" });
    assert.ok(results.length > 0, "the hook is registered");
    for (const result of results) {
      assert.equal(result, undefined, "a non-undefined result could alter the call");
    }
  });

  it("neither hook mutates the event or its parameters", async () => {
    const { host } = await register();
    const params = { command: "ls", cwd: "/tmp" };
    const event = { toolName: "exec", params, toolCallId: "call-2", runId: "run-2" };
    const before = JSON.stringify(event);
    const ctx = { agentId: "main", runId: "run-2", toolCallId: "call-2" };
    await host.emit("before_tool_call", event, ctx);
    await host.emit("after_tool_call", { ...event, result: { stdout: "a" } }, ctx);
    assert.equal(JSON.stringify(event), before, "the tool event must come back unchanged");
    assert.equal(params.command, "ls");
  });

  it("an unreachable endpoint still lets the tool proceed", async () => {
    const { host } = await register({ client: makeClientSpy({ fail: true }) });
    const event = { toolName: "exec", params: {}, toolCallId: "call-3", runId: "run-3" };
    const results = await host.emit("before_tool_call", event, { agentId: "main", runId: "run-3", toolCallId: "call-3" });
    for (const result of results) assert.equal(result, undefined);
  });

  it("reports SHADOW status with no authority after registration", async () => {
    const { registered } = await register();
    const status = registered.status();
    assert.equal(status.mode, "SHADOW");
    assert.equal(status.authority, "NONE");
    assert.equal(status.enforcement, "OFF");
    assert.equal(status.active, false);
    assert.equal(status.remoteAuthority, false);
    assert.equal(status.pluginVersion, PLUGIN_VERSION);
    assert.equal(status.runtimePublication.outboundGoverned, true, "roster/heartbeat is gated");
    await registered.shutdown();
  });
});

describe("WOULD_* projections stay counterfactual", () => {
  it("maps shadow actions to WOULD_* labels and nothing executable", async () => {
    const source = readFileSync(join(ROOT, "cli/providers/openclaw.mjs"), "utf8");
    const actions = /const ACTIONS = Object\.freeze\((\{[^}]*\})\)/.exec(source);
    assert.ok(actions, "the projection table is present");
    for (const [key, value] of [
      ["SHADOW_WOULD_ALLOW", "WOULD_ALLOW"],
      ["SHADOW_WOULD_DENY", "WOULD_DENY"],
      ["SHADOW_WOULD_REQUIRE_APPROVAL", "WOULD_REQUIRE_APPROVAL"],
    ]) {
      assert.ok(actions[1].includes(`${key}: '${value}'`), `${key} must project to ${value}`);
    }
    for (const forbidden of ["ALLOWED", "DENIED", "BLOCKED", "APPROVED", "ENFORCED"]) {
      assert.equal(actions[1].includes(`: '${forbidden}'`), false, `must not project ${forbidden}`);
    }
  });

  it("records REQUIRE_APPROVAL as shadow_mode_no_approval, creating no approval", () => {
    const runtime = readFileSync(join(ROOT, "plugins/openclaw-connector/shadow-v070/runtime.mjs"), "utf8");
    assert.ok(runtime.includes('"shadow_mode_no_approval"'));
    assert.ok(runtime.includes('execution_effect: "NONE"'));
  });

  it("keeps runtime identities UNMAPPED unless the operator maps them", () => {
    const manifest = JSON.parse(readFileSync(join(ROOT, "openclaw.plugin.json"), "utf8"));
    const bootstrap = manifest.configSchema.properties.runtimeObservation.properties;
    assert.equal(bootstrap.mappingStatus.const, "UNMAPPED");
    assert.equal(bootstrap.authority.const, "NONE");
    assert.equal(bootstrap.enforcement.const, "OFF");
    assert.equal(bootstrap.automaticMappingActivation.const, false);
    assert.equal(bootstrap.mode.const, "SHADOW_METADATA_ONLY");
  });
});

describe("the whole plugin, end to end, obeys the outbound controls", () => {
  it("an enabled gateway_start publishes roster and heartbeat", async () => {
    const { registered, host, client } = await register();
    await host.emit("gateway_start");
    await flush();
    assert.deepEqual(
      client.calls.map((call) => call.path),
      ["/v1/runtime/inventory", "/v1/runtime/heartbeat"],
    );
    await registered.shutdown();
  });

  for (const name of ["disabled", "killswitch", "lock"]) {
    it(`a ${name} gateway_start publishes nothing at all`, async () => {
      const { registered, host, client, config } = await register();
      const { setControl } = await import("../plugins/openclaw-connector/controls.mjs");
      setControl(config.stateDir, name, true);
      await host.emit("gateway_start");
      await flush();
      assert.deepEqual(client.calls, [], `${name}: zero Hosted requests from startup`);
      await registered.shutdown();
    });
  }

  it("operator disable stops publication for the life of the process", async () => {
    const { registered, host, client } = await register();
    await host.emit("gateway_start");
    await flush();
    const afterStart = client.calls.length;
    assert.ok(afterStart > 0, "publication happened while enabled");
    await registered.disable();
    await flush();
    assert.equal(client.calls.length, afterStart, "disable stops all further Hosted traffic");
  });
});

describe("shutdown stays terminal and silent", () => {
  it("gateway_stop terminates every owned lane and publishes nothing further", async () => {
    const { registered, host, client } = await register();
    await host.emit("gateway_start");
    await flush();
    const afterStart = client.calls.length;
    assert.ok(afterStart > 0, "the enabled lane really did publish before shutdown");
    await host.emit("gateway_stop");
    await flush();
    assert.equal(client.calls.length, afterStart, "shutdown must not publish");
    const terminal = registered.terminalStatus();
    assert.equal(terminal.terminal, true);
    assert.equal(terminal.reason, "gateway_stop");
    assert.equal(registered.status().runtimePublication.stopped, true);
  });
});

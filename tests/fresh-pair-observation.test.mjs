import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createGovernanceConnector } from "../plugins/openclaw-connector/index.mjs";
import { validateReceipt } from "../plugins/openclaw-connector/receipts.mjs";
import {
  buildShadowObservationAck,
  createRuntimeObservationBootstrap,
  validateShadowObservationRequest,
} from "../plugins/openclaw-connector/runtime-observation-contract.mjs";

async function settle(predicate) {
  for (let turn = 0; turn < 100; turn += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.fail("runtime observation did not settle");
}

function harness(t, { profileName = "default" } = {}) {
  const home = mkdtempSync(join(tmpdir(), `observa-package-${profileName}-`));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const profileState = join(home, profileName === "default" ? ".openclaw" : `.openclaw-${profileName}`);
  const handlers = new Map();
  const receipts = [];
  const requests = [];
  let connector;
  const transport = async ({ url, body }) => {
    assert.equal(url.pathname, "/v1/observations");
    const request = JSON.parse(Buffer.from(body).toString("utf8"));
    assert.deepEqual(validateShadowObservationRequest(request), { ok: true });
    requests.push(request);
    const ack = buildShadowObservationAck(request, `obs_${requests.length}`);
    return { statusCode: 200, body: Buffer.from(JSON.stringify(ack)) };
  };
  const api = {
    pluginConfig: {
      enabled: true,
      apiUrl: "https://dashboard.example.test",
      deploymentId: "installation_test",
      agentId: "main",
      runtimeObservation: createRuntimeObservationBootstrap(profileState),
    },
    runtime: {
      version: "2026.6.33",
      state: { resolveStateDir: () => profileState },
    },
    logger: { error() {} },
    registerTool() {},
    on(name, handler) { handlers.set(name, handler); },
  };
  connector = createGovernanceConnector({
    transport,
    credentialProvider: async (callback) => callback("test-credential-never-recorded"),
    controlInspector: () => Object.freeze({ blocked: false, priority: null }),
    receiptWriter: {
      write(value) { validateReceipt(value); receipts.push(value); return { ok: true }; },
      status: () => ({ closed: false }),
      close() {},
    },
  }).register(api);
  return { connector, handlers, receipts, requests, profileState };
}

function callShape({ toolName = "session_status", toolKind, correlation = "call_dynamic_1",
  params = {}, error, result } = {}) {
  const event = {
    toolName, params, runId: "run_supported_1", toolCallId: correlation,
    ...(toolKind ? { toolKind } : {}),
    ...(error === undefined ? {} : { error }),
    ...(result === undefined ? {} : { result }),
  };
  const context = {
    toolName, agentId: "main", runId: "run_supported_1", toolCallId: correlation,
    ...(toolKind ? { toolKind } : {}),
  };
  return { event, context };
}

async function observe(h, before, after = before) {
  const hookResult = await h.handlers.get("before_tool_call")(before.event, before.context);
  assert.equal(hookResult, undefined, "shadow observation cannot alter tool execution");
  assert.equal(h.requests.length, 0, "pre-hook cannot claim execution completed");
  const postResult = await h.handlers.get("after_tool_call")(after.event, after.context);
  assert.equal(postResult, undefined, "post-hook cannot alter tool execution");
  await settle(() => h.connector.runtimeObserver.status().active === 0);
}

test("fresh-pair dynamic tool produces attempt, completion, and neutral remote evidence", async (t) => {
  const h = harness(t);
  const secret = `${["mgd1", "_"].join("")}${"a".repeat(32)}.${"A".repeat(43)}`;
  const before = callShape({ params: { prompt: secret, workspaceBody: "private customer text" } });
  const after = callShape({
    params: before.event.params,
    result: { raw: "private result body" },
  });
  await observe(h, before, after);

  assert.equal(h.receipts.length, 2);
  assert.equal(h.receipts[0].receipt_type, "attempt_receipt");
  assert.equal(h.receipts[0].remote_status, "NOT_ATTEMPTED");
  assert.equal(h.receipts[1].receipt_type, "completion_receipt");
  assert.equal(h.receipts[1].outcome, "COMPLETED");
  assert.equal(h.requests.length, 1);
  const [request] = h.requests;
  assert.equal(request.agent_id, "main");
  assert.equal(request.tool_id, "session_status");
  assert.equal(request.runtime_tool_kind, "OPENCLAW_DYNAMIC");
  assert.equal(request.mapping_status, "UNMAPPED");
  assert.equal(request.authority, "NONE");
  assert.equal(request.enforcement, "OFF");
  const wire = JSON.stringify(request);
  for (const prohibited of [secret, "prompt", "workspaceBody", "private customer text",
    "result", "private result body", "actionClass", "resourceClass", "schemaHash",
    "approved", "active"]) assert.equal(wire.includes(prohibited), false, prohibited);
  await h.connector.shutdown();
});

test("embedded-run success shape (own error key, undefined value) stays COMPLETED", async (t) => {
  // The supported OpenClaw embedded-run host emits its after-hook event as an
  // object literal with `error: isToolError ? <message> : undefined`, so a
  // SUCCESSFUL call carries an OWN nullish `error` key. The 2026-08-24 live
  // beta proved the old own-key test classified that success FAILED/TOOL_ERROR.
  const h = harness(t);
  const before = callShape({ correlation: "call_embedded_ok_1" });
  const after = callShape({
    correlation: "call_embedded_ok_1", params: before.event.params,
    result: { ok: true },
  });
  after.event.error = undefined;
  assert.equal(Object.prototype.hasOwnProperty.call(after.event, "error"), true);
  await observe(h, before, after);
  assert.equal(h.receipts.length, 2);
  assert.equal(h.receipts[1].receipt_type, "completion_receipt");
  assert.equal(h.receipts[1].outcome, "COMPLETED");
  assert.equal("error_category" in h.receipts[1], false);
  assert.equal(h.requests.length, 1);
  assert.equal(h.requests[0].tool_outcome, "COMPLETED");
  await h.connector.shutdown();
});

test("success shape with error: null stays COMPLETED", async (t) => {
  const h = harness(t);
  const before = callShape({ correlation: "call_null_ok_1" });
  const after = callShape({
    correlation: "call_null_ok_1", params: before.event.params,
    result: { ok: true }, error: null,
  });
  await observe(h, before, after);
  assert.equal(h.receipts[1].outcome, "COMPLETED");
  assert.equal("error_category" in h.receipts[1], false);
  assert.equal(h.requests.length, 1);
  assert.equal(h.requests[0].tool_outcome, "COMPLETED");
  await h.connector.shutdown();
});

test("Codex-native hook kind is separately identified without semantic promotion", async (t) => {
  const h = harness(t);
  const shape = callShape({
    toolName: "exec", toolKind: "code_mode_exec", correlation: "call_native_1",
  });
  await observe(h, shape);
  assert.equal(h.requests.length, 1);
  assert.equal(h.requests[0].runtime_tool_kind, "CODEX_NATIVE");
  assert.equal(h.requests[0].mapping_status, "UNMAPPED");
  assert.equal(h.connector.runtimeObserver.status().authority, "NONE");
  assert.equal(h.connector.runtimeObserver.status().enforcement, "OFF");
  await h.connector.shutdown();
});

test("profile binding and malformed identity fail closed", async (t) => {
  const a = harness(t, { profileName: "default" });
  const otherProfile = join(a.profileState, "..", ".openclaw-other");
  assert.throws(() => createGovernanceConnector({
    config: {
      ...a.connector.config,
      runtimeObservation: createRuntimeObservationBootstrap(a.profileState),
    },
    pathOverrides: { openclawStateDir: otherProfile },
  }).register({
    runtime: { version: "2026.6.33", state: { resolveStateDir: () => otherProfile } },
    registerTool() {}, on() {},
  }), (error) => error.code === "CONFIG_RUNTIME_OBSERVATION_PROFILE_MISMATCH");

  const unsupported = callShape({ toolName: "session_status", correlation: undefined });
  delete unsupported.event.runId;
  delete unsupported.event.toolCallId;
  delete unsupported.context.runId;
  delete unsupported.context.toolCallId;
  await a.handlers.get("before_tool_call")(unsupported.event, unsupported.context);
  await a.handlers.get("after_tool_call")(unsupported.event, unsupported.context);
  assert.equal(a.requests.length, 0);

  const b = harness(t, { profileName: "reuse" });
  const original = callShape({ toolName: "session_status", correlation: "call_reused" });
  await observe(b, original);
  const reusedAlias = callShape({
    toolName: "openclawsession_status", correlation: "call_reused",
  });
  await b.handlers.get("before_tool_call")(reusedAlias.event, reusedAlias.context);
  await b.handlers.get("after_tool_call")(reusedAlias.event, reusedAlias.context);
  await settle(() => b.connector.runtimeObserver.status().active === 0);
  assert.equal(b.requests.length, 1, "completed correlation reuse cannot double count");
  await b.connector.shutdown();
});

test("supported alias pair collapses to ONE canonical observation in both orders", async (t) => {
  for (const [profileName, firstName, secondName] of [
    ["alias-fwd", "openclawsession_status", "session_status"],
    ["alias-rev", "session_status", "openclawsession_status"],
  ]) {
    const h = harness(t, { profileName });
    const first = callShape({ toolName: firstName, correlation: "call_alias_pair" });
    const second = callShape({ toolName: secondName, correlation: "call_alias_pair" });
    await h.handlers.get("before_tool_call")(first.event, first.context);
    await h.handlers.get("before_tool_call")(second.event, second.context);
    await h.handlers.get("after_tool_call")(first.event, first.context);
    await h.handlers.get("after_tool_call")(second.event, second.context);
    await settle(() => h.connector.runtimeObserver.status().active === 0
      && h.connector.runtimeObserver.status().pendingHooks === 0);
    assert.equal(h.requests.length, 1, `${profileName}: exactly one remote observation`);
    assert.equal(h.requests[0].tool_id, "session_status", `${profileName}: canonical identity`);
    const totals = h.connector.runtimeObserver.status().totals;
    assert.equal(totals.aliasCanonicalized, 1);
    assert.equal(totals.ambiguous, 0, `${profileName}: no ambiguity refusal`);
    assert.equal(h.receipts.filter((r) => r.receipt_type === "completion_receipt").length, 1);
    await h.connector.shutdown();
  }
});

test("exact duplicate dispatch is idempotent: one logical observation", async (t) => {
  const h = harness(t, { profileName: "duplicate" });
  const claim = callShape({ toolName: "session_status", correlation: "call_dup" });
  await h.handlers.get("before_tool_call")(claim.event, claim.context);
  await h.handlers.get("before_tool_call")(claim.event, claim.context);
  await h.handlers.get("after_tool_call")(claim.event, claim.context);
  await h.handlers.get("after_tool_call")(claim.event, claim.context);
  await settle(() => h.connector.runtimeObserver.status().active === 0);
  assert.equal(h.requests.length, 1, "exactly one remote observation");
  const totals = h.connector.runtimeObserver.status().totals;
  assert.equal(totals.duplicateClaims, 1);
  assert.equal(totals.ambiguous, 0);
  assert.equal(h.receipts.filter((r) => r.receipt_type === "attempt_receipt").length, 1);
  assert.equal(h.receipts.filter((r) => r.receipt_type === "completion_receipt").length, 1);
  await h.connector.shutdown();
});

test("genuine identity conflict fails closed with durable refusal evidence", async (t) => {
  const h = harness(t, { profileName: "conflict" });
  const first = callShape({ toolName: "session_status", correlation: "call_conflict" });
  const second = callShape({ toolName: "exec", correlation: "call_conflict" });
  await h.handlers.get("before_tool_call")(first.event, first.context);
  await h.handlers.get("before_tool_call")(second.event, second.context);
  await h.handlers.get("after_tool_call")(first.event, first.context);
  await h.handlers.get("after_tool_call")(second.event, second.context);
  await settle(() => h.connector.runtimeObserver.status().pendingHooks === 0);
  assert.equal(h.requests.length, 0, "conflicting identities cannot enter the remote lane");
  const status = h.connector.runtimeObserver.status();
  assert.equal(status.totals.ambiguous, 1);
  assert.equal(status.ambiguity.disposition, "AMBIGUOUS_FAIL_CLOSED");
  const refused = h.receipts.filter((r) => r.receipt_type === "attempt_receipt"
    && r.local_disposition === "BLOCKED_LOCAL");
  assert.equal(refused.length, 2, "every refused claim leaves durable evidence");
  await h.connector.shutdown();
});

test("alias pair plus a third conflicting claim fails closed entirely", async (t) => {
  const h = harness(t, { profileName: "alias-conflict" });
  const prefixed = callShape({ toolName: "openclawsession_status", correlation: "call_mixed" });
  const canonical = callShape({ toolName: "session_status", correlation: "call_mixed" });
  const conflict = callShape({ toolName: "exec", correlation: "call_mixed" });
  await h.handlers.get("before_tool_call")(prefixed.event, prefixed.context);
  await h.handlers.get("before_tool_call")(canonical.event, canonical.context);
  await h.handlers.get("before_tool_call")(conflict.event, conflict.context);
  await h.handlers.get("after_tool_call")(prefixed.event, prefixed.context);
  await h.handlers.get("after_tool_call")(canonical.event, canonical.context);
  await h.handlers.get("after_tool_call")(conflict.event, conflict.context);
  await settle(() => h.connector.runtimeObserver.status().pendingHooks === 0);
  assert.equal(h.requests.length, 0, "a poisoned correlation delivers nothing");
  assert.equal(h.connector.runtimeObserver.status().totals.ambiguous >= 1, true);
  await h.connector.shutdown();
});

test("runtime-controlled exception text and invalid identities never cross the boundary", async (t) => {
  const h = harness(t);
  const hostile = "password=do-not-copy\nBearer secret";
  const before = callShape({ correlation: "call_error_1", params: { raw: hostile } });
  const after = callShape({ correlation: "call_error_1", params: before.event.params, error: hostile });
  await observe(h, before, after);
  assert.equal(h.requests[0].tool_outcome, "FAILED");
  assert.equal(JSON.stringify(h.requests[0]).includes(hostile), false);

  const malformed = callShape({ toolName: "plugin/../../credential", correlation: "call_bad_1" });
  await h.handlers.get("before_tool_call")(malformed.event, malformed.context);
  await h.handlers.get("after_tool_call")(malformed.event, malformed.context);
  assert.equal(h.requests.length, 1);
  await h.connector.shutdown();
});

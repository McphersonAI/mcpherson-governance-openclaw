import assert from "node:assert/strict";
import test from "node:test";

import {
  buildObservationRequest,
  deriveSafeToolSummary,
} from "../plugins/openclaw-connector/allowlist.mjs";
import { ConnectorHookController } from "../plugins/openclaw-connector/hook.mjs";
import {
  buildCodeOwnedToolCatalog,
  normalizeOpenClawToolHook,
  OPENCLAW_HOOK_PROVENANCE,
} from "../plugins/openclaw-connector/hook-adapter.mjs";
import {
  makeConnectionToolRegistration,
} from "../plugins/openclaw-connector/tools.mjs";
import {
  correlationRef,
  requestHash,
} from "../plugins/openclaw-connector/runtime/governance-core/index.mjs";

const TOOL_NAME = "mcpherson_connection_test";
const RUN_ID = "d4beea56-38c1-4d53-80fe-aaaaeb917946";
const TOOL_CALL_ID = "call_Lo2kwpm68j21wxHhFkDa8IP9|fc_00cc435b529efd3c016a77a8d2ec44819aa24d2bc7450b7a4e";
const EXPECTED_SCHEMA_HASH =
  "sha256:99334726611ccf58a148b0814696bfa6fe08c1b2d027e946beccf5a74331c9aa";

function emptyMetadata() {
  return Object.freeze(Object.create(null));
}

function makeConfig(toolMetadata = emptyMetadata()) {
  return Object.freeze({
    agentId: "main",
    deploymentId: "inst_1f120bcddcba32ea",
    observationBudgetMs: 150,
    policyVersion: 3,
    toolMetadata,
  });
}

function capturedBeforeEvent(overrides = {}) {
  return {
    toolName: TOOL_NAME,
    params: {},
    runId: RUN_ID,
    toolCallId: TOOL_CALL_ID,
    ...overrides,
  };
}

function capturedContext(overrides = {}) {
  return {
    toolName: TOOL_NAME,
    agentId: "main",
    sessionKey: "agent:main:explicit:v06-final-hook-proof",
    sessionId: "7f31c2f5-e4c5-417c-a29f-4440ac9a7fd1",
    runId: RUN_ID,
    toolCallId: TOOL_CALL_ID,
    ...overrides,
  };
}

function makeHarness({ config = makeConfig() } = {}) {
  const submissions = [];
  const local = [];
  const pipeline = {
    submit(summary, options) {
      const request = buildObservationRequest(summary, config, {
        randomUUID: () => "123e4567-e89b-42d3-a456-426614174000",
        randomBytes: () => Buffer.from("00112233445566778899aabbccddeeff", "hex"),
        now: () => new Date("2026-08-08T12:00:00.000Z"),
      });
      submissions.push({ summary, options, request });
      return Object.freeze({
        request,
        promise: Promise.resolve(Object.freeze({
          decision_id: "01KZTESTDECISION00000000000",
          request_hash: request.request_hash,
        })),
      });
    },
    recordLocal(summary, remoteStatus, localDisposition) {
      const ref = correlationRef(summary.rawCorrelation || `${summary.agentId}:${summary.toolId}`);
      const request = Object.freeze({
        request_hash: `sha256:${"0".repeat(64)}`,
        correlation_ref: ref,
        agent_id: summary.agentId,
        tool_id: summary.toolId,
      });
      local.push({ summary, remoteStatus, localDisposition });
      return Object.freeze({
        request,
        promise: Promise.resolve(Object.freeze({ decision_id: null })),
      });
    },
    waitForeground: async () => undefined,
  };
  const controller = new ConnectorHookController({
    config,
    pipeline,
    receiptWriter: { write() {} },
    controlInspector: () => Object.freeze({ blocked: false, priority: "CLEAR" }),
    canaryEvaluator: () => Object.freeze({ blocked: false, inScope: false }),
    summaryBuilder: deriveSafeToolSummary,
    codeOwnedTools: buildCodeOwnedToolCatalog([makeConnectionToolRegistration()]),
  });
  return { controller, submissions, local };
}

test("captured normal OpenClaw hook shape normalizes and constructs one mgp/1 request", async () => {
  const event = capturedBeforeEvent();
  const context = capturedContext();
  const normalized = normalizeOpenClawToolHook(event, context, "before_tool_call");
  assert.equal(normalized.accepted, true);
  assert.equal(normalized.provenance, OPENCLAW_HOOK_PROVENANCE);
  assert.equal(normalized.toolName, TOOL_NAME);
  assert.equal(normalized.agentId, "main");
  assert.equal(normalized.runId, RUN_ID);
  assert.equal(normalized.toolCallId, TOOL_CALL_ID);

  const { controller, submissions, local } = makeHarness();
  const hookResult = await controller.beforeToolCall(event, context);
  assert.equal(hookResult, undefined);
  assert.equal(local.length, 0);
  assert.equal(submissions.length, 1);
  const [{ summary, options, request }] = submissions;
  assert.deepEqual(options, { healthFirst: true });
  assert.equal(summary.toolId, TOOL_NAME);
  assert.equal(summary.agentId, "main");
  assert.equal(summary.toolSchemaVersion, "1.0.0");
  assert.equal(summary.toolSchemaHash, EXPECTED_SCHEMA_HASH);
  assert.equal(summary.actionClass, "read_only_internal");
  assert.equal(request.api_version, "mgp/1");
  assert.equal(request.tool_id, TOOL_NAME);
  assert.equal(request.tool_schema_hash, EXPECTED_SCHEMA_HASH);
  assert.equal(request.deployment_id, undefined);
  assert.equal(request.correlation_ref, correlationRef(TOOL_CALL_ID));
  assert.equal(request.request_hash, requestHash(request));
});

test("missing or conflicting host tool identity stays local", async () => {
  for (const [event, context] of [
    [{ params: {}, runId: RUN_ID, toolCallId: TOOL_CALL_ID }, capturedContext()],
    [capturedBeforeEvent(), capturedContext({ toolName: "other_tool" })],
  ]) {
    const { controller, submissions, local } = makeHarness();
    await controller.beforeToolCall(event, context);
    assert.equal(submissions.length, 0);
    assert.equal(local.length, 1);
    assert.equal(local[0].remoteStatus, "NOT_ATTEMPTED");
    assert.equal(local[0].localDisposition, "SKIPPED");
  }
});

test("malformed params and metadata spoof attempts stay local without invoking accessors", async () => {
  let getterCalls = 0;
  const accessorParams = {};
  Object.defineProperty(accessorParams, "token", {
    enumerable: true,
    get() { getterCalls += 1; return "spoof"; },
  });
  const cases = [
    capturedBeforeEvent({ params: null }),
    capturedBeforeEvent({ params: accessorParams }),
    capturedBeforeEvent({ params: { toolName: "other_tool" } }),
    capturedBeforeEvent({ toolMetadata: { schemaHash: EXPECTED_SCHEMA_HASH } }),
    capturedBeforeEvent({ schemaHash: EXPECTED_SCHEMA_HASH }),
  ];
  for (const event of cases) {
    const { controller, submissions, local } = makeHarness();
    await controller.beforeToolCall(event, capturedContext());
    assert.equal(submissions.length, 0);
    assert.equal(local.length, 1);
  }
  assert.equal(getterCalls, 0);
});

test("unknown tool and conflicting configured metadata remain fail-closed", async () => {
  {
    const { controller, submissions, local } = makeHarness();
    await controller.beforeToolCall(
      capturedBeforeEvent({ toolName: "unknown_tool" }),
      capturedContext({ toolName: "unknown_tool" }),
    );
    assert.equal(submissions.length, 0);
    assert.equal(local.length, 1);
  }

  const metadata = Object.freeze(Object.assign(Object.create(null), {
    [TOOL_NAME]: Object.freeze({
      schemaVersion: "1.0.0",
      schemaHash: `sha256:${"f".repeat(64)}`,
      actionClass: "read_only_internal",
    }),
  }));
  const { controller, submissions, local } = makeHarness({ config: makeConfig(metadata) });
  await controller.beforeToolCall(capturedBeforeEvent(), capturedContext());
  assert.equal(submissions.length, 0);
  assert.equal(local.length, 1);
});

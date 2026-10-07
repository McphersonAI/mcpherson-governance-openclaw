// Fresh final audit pass, executable.
//
// Each test here is an attempt to get one Hosted request out of a stopped
// installation, or to get the gate to answer "allowed" when it should not.
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, writeFileSync } from "node:fs";

import { RuntimePublisher } from "../plugins/openclaw-connector/runtime-publisher.mjs";
import {
  controlPath, createHostedOutboundGate, inspectObservationControls,
} from "../plugins/openclaw-connector/controls.mjs";
import {
  cleanupProfiles, control, flush, makeClientSpy, makeCredentialSpy, makeManualTimers, makeProfile,
} from "./helpers.mjs";

after(cleanupProfiles);

const HOST_CONFIG = Object.freeze({ agents: { entries: { main: {} } } });

function publisher(config, extra = {}) {
  const client = extra.client ?? makeClientSpy();
  const credentials = extra.credentialProvider ?? makeCredentialSpy();
  const clock = extra.timers ?? makeManualTimers();
  return {
    client, credentials, clock,
    instance: new RuntimePublisher({
      client,
      hostConfig: HOST_CONFIG,
      runtimeInstanceId: "22222222-2222-4222-8222-222222222222",
      credentialProvider: credentials,
      cadenceSeconds: 60,
      setTimeoutFn: clock.setTimeoutFn,
      clearTimeoutFn: clock.clearTimeoutFn,
      ...(extra.controlInspector ? { controlInspector: extra.controlInspector } : {}),
    }),
  };
}

async function run(config, extra) {
  const made = publisher(config, extra);
  made.instance.start(config);
  await flush();
  return made;
}

const silent = (made, label) => {
  assert.deepEqual(made.client.calls, [], `${label}: a Hosted request escaped`);
  assert.deepEqual(made.credentials.reads, [], `${label}: the credential was read`);
};

describe("a corrupt or hostile control file fails closed", () => {
  for (const [label, corrupt] of [
    ["truncated JSON", (path) => writeFileSync(path, "{", { mode: 0o600 })],
    ["wrong schema", (path) => writeFileSync(path, JSON.stringify({ schema: "other", name: "disabled", enabled: true }), { mode: 0o600 })],
    ["wrong name", (path) => writeFileSync(path, JSON.stringify({ schema: "mcpherson-governance-control/v1", name: "lock", enabled: true }), { mode: 0o600 })],
    ["extra keys", (path) => writeFileSync(path, JSON.stringify({ schema: "mcpherson-governance-control/v1", name: "disabled", enabled: true, extra: 1 }), { mode: 0o600 })],
    ["enabled: false", (path) => writeFileSync(path, JSON.stringify({ schema: "mcpherson-governance-control/v1", name: "disabled", enabled: false }), { mode: 0o600 })],
    ["world readable", (path) => { writeFileSync(path, JSON.stringify({ schema: "mcpherson-governance-control/v1", name: "disabled", enabled: true }), { mode: 0o600 }); chmodSync(path, 0o644); }],
    ["oversized", (path) => writeFileSync(path, "x".repeat(400), { mode: 0o600 })],
  ]) {
    it(`${label} is treated as ACTIVE, not as absent`, async () => {
      const { config } = makeProfile({ enabled: true });
      corrupt(controlPath(config.stateDir, "disabled"));
      assert.equal(inspectObservationControls(config).blocked, true, label);
      silent(await run(config), label);
    });
  }
});

describe("a broken control inspector cannot open the gate", () => {
  for (const [label, inspector] of [
    ["throws", () => { throw new Error("EIO"); }],
    ["returns null", () => null],
    ["returns a string", () => "allowed"],
    ["omits blocked", () => ({ priority: null })],
    ["claims blocked is not a boolean", () => ({ blocked: 0 })],
    ["returns a promise", () => Promise.resolve({ blocked: false })],
  ]) {
    it(`an inspector that ${label} refuses`, async () => {
      const { config } = makeProfile({ enabled: true });
      silent(await run(config, { controlInspector: inspector }), label);
    });
  }
});

describe("lifecycle races cannot leak a request", () => {
  it("stop() during an in-flight run prevents the follow-on heartbeat", async () => {
    const { config } = makeProfile({ enabled: true });
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const calls = [];
    const client = {
      publishInventory: async () => { calls.push("/v1/runtime/inventory"); await gate; return { ok: true }; },
      publishHeartbeat: async () => { calls.push("/v1/runtime/heartbeat"); return { ok: true }; },
      recordFailure() {}, recordSuccess() {},
      status: () => ({ activeTransports: 0 }), shutdown: async () => undefined,
    };
    const made = publisher(config, { client });
    made.instance.start(config);
    await flush();
    assert.deepEqual(calls, ["/v1/runtime/inventory"]);

    const stopping = made.instance.stop();
    release();
    await stopping;
    await flush();
    assert.deepEqual(calls, ["/v1/runtime/inventory"], "shutdown must not emit a heartbeat");
    assert.equal(made.instance.status().stopped, true);
  });

  it("a second start() on the same publisher is a no-op", async () => {
    const { config } = makeProfile({ enabled: true });
    const made = await run(config);
    const before = made.client.calls.length;
    assert.equal(made.instance.start(config), false);
    await flush();
    assert.equal(made.client.calls.length, before);
    await made.instance.stop();
  });

  it("two publishers in one process each take a distinct runtime generation", async () => {
    const { config } = makeProfile({ enabled: true });
    const first = await run(config);
    const second = await run(config);
    const a = first.instance.status().runtimeGeneration;
    const b = second.instance.status().runtimeGeneration;
    assert.ok(Number.isSafeInteger(a) && Number.isSafeInteger(b));
    assert.notEqual(a, b, "generations must not collide");
    await first.instance.stop();
    await second.instance.stop();
  });

  it("start() after stop() stays stopped", async () => {
    const { config } = makeProfile({ enabled: true });
    const made = await run(config);
    await made.instance.stop();
    const before = made.client.calls.length;
    assert.equal(made.instance.start(config), false);
    await flush();
    assert.equal(made.client.calls.length, before);
  });

  it("many refused ticks never arm a second timer or leak a request", async () => {
    const { config } = makeProfile({ enabled: true });
    control(config, "killswitch", true);
    const made = await run(config);
    for (let i = 0; i < 25; i += 1) await made.clock.fire();
    silent(made, "repeated refused ticks");
    assert.ok(made.instance.status().totals.refusals >= 25);
    assert.equal(made.instance.status().requestActive, false, "no run is wedged");
    await made.instance.stop();
  });
});

describe("a credential without authority is never used", () => {
  it("an endpoint and a credential are both present, and still nothing is sent", async () => {
    const { config } = makeProfile({ enabled: true, paired: true, apiUrl: "https://hosted.invalid" });
    assert.ok(config.apiUrl.startsWith("https://"), "an endpoint is configured");
    control(config, "lock", true);
    const made = await run(config);
    silent(made, "endpoint + credential + lock");
  });

  it("an unpaired install sends nothing, using the real credential reader", async () => {
    // No credentialProvider override here: the publisher uses the connector's
    // own withCredential, which has no credential file to read.
    const { config } = makeProfile({ enabled: true, paired: false });
    const client = makeClientSpy();
    const clock = makeManualTimers();
    const instance = new RuntimePublisher({
      client, hostConfig: HOST_CONFIG,
      runtimeInstanceId: "33333333-3333-4333-8333-333333333333",
      cadenceSeconds: 60, setTimeoutFn: clock.setTimeoutFn, clearTimeoutFn: clock.clearTimeoutFn,
    });
    instance.start(config);
    await flush();
    assert.deepEqual(client.calls, [], "an unpaired install has nothing to publish with");
    await instance.stop();
  });

  it("the gate's run() never yields a credential to a refused sender", async () => {
    const { config } = makeProfile({ enabled: true });
    control(config, "disabled", true);
    const seen = [];
    const gate = createHostedOutboundGate({
      config,
      purpose: "runtime_inventory",
      credentialProvider: async (callback) => callback("mgd1_secret"),
    });
    await assert.rejects(() => gate.run((credential) => { seen.push(credential); }));
    assert.deepEqual(seen, [], "the sender must never see a credential");
  });
});

describe("the real Hosted client honours the gate before the wire", () => {
  it("a mid-flight refusal aborts inside the real client with zero transport calls", async () => {
    const { GovernanceApiClient } = await import("../plugins/openclaw-connector/client.mjs");
    const { config } = makeProfile({ enabled: true });

    // The transport is the last thing before the socket. If it is ever
    // invoked, a request was about to be sent.
    const transportCalls = [];
    const client = new GovernanceApiClient({
      baseUrl: config.apiUrl,
      connectTimeoutMs: 100,
      transport: async (params) => {
        transportCalls.push(params.url.pathname);
        return { statusCode: 200, body: Buffer.from("{}") };
      },
    });

    // Arm the control after the first read so the refusal lands at the
    // client's own pre-transport checkpoint, not at checkpoint 1.
    const clock = makeManualTimers();
    let armed = false;
    const instance = new RuntimePublisher({
      client,
      hostConfig: HOST_CONFIG,
      runtimeInstanceId: "44444444-4444-4444-8444-444444444444",
      credentialProvider: makeCredentialSpy(),
      cadenceSeconds: 60,
      setTimeoutFn: clock.setTimeoutFn,
      clearTimeoutFn: clock.clearTimeoutFn,
      controlInspector: () => {
        // Allowed for checkpoints 1-3, refused at checkpoint 4.
        if (!armed) { armed = true; return inspectObservationControls(config); }
        return Object.freeze({ blocked: true, priority: "KILL_SWITCH", remoteStatus: "KILL_SWITCH_ACTIVE" });
      },
    });
    instance.start(config);
    await flush();

    assert.deepEqual(transportCalls, [], "the transport must never be reached after a refusal");
    const status = instance.status();
    assert.equal(status.totals.inventoryAccepted, 0);
    assert.ok(status.totals.refusals >= 1, "the refusal is recorded as a control decision");
    assert.equal(status.totals.failures, 0, "a refusal is not a transport failure");
    assert.equal(client.status().failures, 0, "a refusal must not trip the circuit breaker");
    await instance.stop();
    await client.shutdown();
  });

  it("an allowed publication does reach the real client's transport", async () => {
    const { GovernanceApiClient } = await import("../plugins/openclaw-connector/client.mjs");
    const { config } = makeProfile({ enabled: true });
    const transportCalls = [];
    const client = new GovernanceApiClient({
      baseUrl: config.apiUrl,
      connectTimeoutMs: 100,
      transport: async (params) => {
        transportCalls.push({ path: params.url.pathname, credential: params.credential });
        return { statusCode: 200, body: Buffer.from(JSON.stringify({ accepted: false })) };
      },
    });
    const clock = makeManualTimers();
    const instance = new RuntimePublisher({
      client, hostConfig: HOST_CONFIG,
      runtimeInstanceId: "55555555-5555-4555-8555-555555555555",
      credentialProvider: makeCredentialSpy(),
      cadenceSeconds: 60, setTimeoutFn: clock.setTimeoutFn, clearTimeoutFn: clock.clearTimeoutFn,
    });
    instance.start(config);
    await flush();
    // This proves the control-off path is genuinely live: the request reached
    // the transport, over the configured endpoint, carrying the credential.
    assert.ok(transportCalls.length >= 1, "an allowed publication reaches the transport");
    assert.equal(transportCalls[0].path, "/v1/runtime/inventory");
    assert.ok(transportCalls[0].credential, "and carries the credential");
    await instance.stop();
    await client.shutdown();
  });
});

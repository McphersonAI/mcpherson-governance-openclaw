// The ClawHub finding, as tests.
//
// "a paired installation can publish runtime roster and liveness metadata to
//  the configured Observa endpoint on startup"
//
// Every test here uses a paired profile with a real credential file on disk and
// a network spy that records any Hosted call and the credential handed to it.
// A refused path must produce zero calls and zero credential reads.
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join } from "node:path";

import { RuntimePublisher } from "../plugins/openclaw-connector/runtime-publisher.mjs";
import {
  HOSTED_OUTBOUND_PURPOSES,
  HostedOutboundRefused,
  createHostedOutboundGate,
  inspectHostedOutboundControls,
  inspectObservationControls,
} from "../plugins/openclaw-connector/controls.mjs";
import { RUNTIME_GENERATION_CLAIMS_DIR } from "../plugins/openclaw-connector/runtime-generation.mjs";
import {
  cleanupProfiles, control, flush, makeClientSpy, makeCredentialSpy, makeManualTimers, makeProfile,
} from "./helpers.mjs";

after(cleanupProfiles);

const HOST_CONFIG = Object.freeze({ agents: { entries: { main: {} } } });

function makePublisher(config, { client, credentialProvider, timers, cadenceSeconds = 60 } = {}) {
  const spyClient = client ?? makeClientSpy();
  const credentials = credentialProvider ?? makeCredentialSpy();
  const clock = timers ?? makeManualTimers();
  const publisher = new RuntimePublisher({
    client: spyClient,
    hostConfig: HOST_CONFIG,
    runtimeInstanceId: "11111111-1111-4111-8111-111111111111",
    credentialProvider: credentials,
    cadenceSeconds,
    setTimeoutFn: clock.setTimeoutFn,
    clearTimeoutFn: clock.clearTimeoutFn,
  });
  return { publisher, client: spyClient, credentials, clock };
}

const settle = flush;

async function startAndSettle(config, options) {
  const made = makePublisher(config, options);
  made.publisher.start(config);
  await settle();
  return made;
}

function assertSilent(made, label) {
  assert.deepEqual(made.client.calls, [], `${label}: expected zero Hosted requests`);
  assert.deepEqual(made.credentials.reads, [], `${label}: expected zero credential reads`);
  assert.deepEqual(made.client.credentialsSeen(), [], `${label}: no credential may be transmitted`);
}

describe("enabled startup publishes bounded roster and liveness", () => {
  it("publishes inventory then heartbeat, credential-bearing, metadata only", async () => {
    const { config } = makeProfile({ enabled: true });
    const made = await startAndSettle(config);

    assert.deepEqual(
      made.client.calls.map((call) => call.path),
      ["/v1/runtime/inventory", "/v1/runtime/heartbeat"],
    );
    assert.equal(made.credentials.reads.length, 2, "credential read once per publication");
    for (const call of made.client.calls) {
      assert.ok(call.credential, "an allowed publication carries the paired credential");
      assert.ok(call.bytes > 0 && call.bytes < 8 * 1024, "publication body stays bounded");
    }
    const status = made.publisher.status();
    assert.equal(status.totals.inventoryAccepted, 1);
    assert.equal(status.totals.heartbeatsAccepted, 1);
    assert.equal(status.totals.refusals, 0);
    assert.equal(status.authority, "NONE");
    assert.equal(status.enforcement, "OFF");
    assert.equal(status.active, false);
    assert.equal(status.meaningfulActivity, false);
    assert.equal(status.capabilitiesClaimed, false);
    await made.publisher.stop();
  });

  it("keeps publishing on each cadence tick while allowed", async () => {
    const { config } = makeProfile({ enabled: true });
    const made = await startAndSettle(config);
    assert.equal(made.client.calls.length, 2);
    await made.clock.fire();
    assert.equal(made.client.calls.length, 3, "a later tick sends one more heartbeat");
    assert.equal(made.client.calls.at(-1).path, "/v1/runtime/heartbeat");
    await made.publisher.stop();
  });
});

describe("startup in a stopped state makes zero Hosted requests", () => {
  it("config-disabled paired install is silent on startup", async () => {
    const { config } = makeProfile({ enabled: false });
    const made = await startAndSettle(config);
    assertSilent(made, "config disabled");
    assert.equal(made.publisher.status().lastRefusal, "DISABLED");
    await made.publisher.stop();
  });

  for (const name of ["disabled", "killswitch", "lock"]) {
    it(`durable ${name} control is silent on startup`, async () => {
      const { config } = makeProfile({ enabled: true });
      control(config, name, true);
      const made = await startAndSettle(config);
      assertSilent(made, name);
      await made.publisher.stop();
    });
  }

  it("a refused startup allocates no runtime generation claim", async () => {
    const { config } = makeProfile({ enabled: true });
    control(config, "killswitch", true);
    const made = await startAndSettle(config);
    assertSilent(made, "killswitch");
    assert.equal(
      existsSync(join(config.stateDir, RUNTIME_GENERATION_CLAIMS_DIR)),
      false,
      "a refused install must leave no generation claim behind",
    );
    assert.equal(made.publisher.status().runtimeGeneration, null);
    await made.publisher.stop();
  });

  it("restarting a fresh process while stopped still publishes nothing", async () => {
    const { config } = makeProfile({ enabled: true });
    control(config, "lock", true);
    for (const attempt of [1, 2, 3]) {
      const made = await startAndSettle(config);
      assertSilent(made, `restart ${attempt}`);
      await made.publisher.stop();
    }
  });
});

describe("runtime transitions and background retries cannot bypass the control", () => {
  it("a control set after startup stops all further publication", async () => {
    const { config } = makeProfile({ enabled: true });
    const made = await startAndSettle(config);
    assert.equal(made.client.calls.length, 2);

    control(config, "killswitch", true);
    const before = made.client.calls.length;
    const readsBefore = made.credentials.reads.length;
    await made.clock.fire();
    await made.clock.fire();

    assert.equal(made.client.calls.length, before, "no Hosted request after the kill switch");
    assert.equal(made.credentials.reads.length, readsBefore, "no credential read after the kill switch");
    assert.ok(made.publisher.status().totals.refusals >= 1);
    await made.publisher.stop();
  });

  it("a retry armed before the control fires after it and still refuses", async () => {
    const { config } = makeProfile({ enabled: true });
    // The first run fails at transport, which arms the ordinary cadence retry.
    const made = await startAndSettle(config, { client: makeClientSpy({ fail: true }) });
    assert.equal(made.client.calls.length, 1, "one failed inventory attempt");
    assert.ok(made.clock.armed(), "a retry is armed");

    control(config, "disabled", true);
    await made.clock.fire();

    assert.equal(made.client.calls.length, 1, "the armed retry must not reach Hosted");
    assert.equal(made.credentials.reads.length, 1, "the armed retry must not read the credential");
    await made.publisher.stop();
  });

  it("re-enabling resumes publication without a restart", async () => {
    const { config } = makeProfile({ enabled: true });
    control(config, "disabled", true);
    const made = await startAndSettle(config);
    assertSilent(made, "disabled");

    control(config, "disabled", false);
    await made.clock.fire();

    assert.deepEqual(
      made.client.calls.map((call) => call.path),
      ["/v1/runtime/inventory", "/v1/runtime/heartbeat"],
    );
    await made.publisher.stop();
  });

  it("a control that activates between the gate and the socket still refuses", async () => {
    const { config } = makeProfile({ enabled: true });
    // The spy invokes beforeAttempt exactly where the real client does. Setting
    // the control from inside it reproduces the mid-flight race.
    const calls = [];
    const racingClient = {
      publishInventory: async (body, credential, options) => {
        control(config, "killswitch", true);
        options.beforeAttempt?.({ attempt: 0, phase: "before_transport" });
        calls.push({ path: "/v1/runtime/inventory", credential });
        return { ok: true };
      },
      publishHeartbeat: async () => { calls.push({ path: "/v1/runtime/heartbeat" }); return { ok: true }; },
      recordFailure() {}, recordSuccess() {},
      status: () => ({ activeTransports: 0 }), shutdown: async () => undefined,
    };
    const made = await startAndSettle(config, { client: racingClient });
    assert.deepEqual(calls, [], "beforeAttempt must abort the attempt before it is sent");
    assert.ok(made.publisher.status().totals.refusals >= 1);
    await made.publisher.stop();
  });

  it("stop() ends the cadence loop permanently", async () => {
    const { config } = makeProfile({ enabled: true });
    const made = await startAndSettle(config);
    await made.publisher.stop();
    const before = made.client.calls.length;
    await made.clock.fire();
    assert.equal(made.client.calls.length, before);
    assert.equal(made.publisher.status().stopped, true);
  });
});

describe("the gate itself fails closed", () => {
  it("refuses an unknown outbound purpose", () => {
    assert.throws(
      () => createHostedOutboundGate({ config: {}, purpose: "exfiltrate" }),
      /HOSTED_OUTBOUND_PURPOSE_UNKNOWN/,
    );
    assert.deepEqual([...HOSTED_OUTBOUND_PURPOSES].sort(), [
      "observation", "runtime_heartbeat", "runtime_inventory", "shadow_evaluation",
    ]);
  });

  it("treats a throwing control read as blocked", () => {
    const controls = inspectHostedOutboundControls(() => { throw new Error("EIO"); });
    assert.equal(controls.blocked, true);
    assert.equal(controls.priority, "CONTROL_READ_FAILED");
  });

  it("treats a malformed control answer as blocked", () => {
    for (const answer of [null, undefined, "allowed", 42, {}, { blocked: "no" }, []]) {
      assert.equal(inspectHostedOutboundControls(() => answer).blocked, true, String(answer));
    }
  });

  it("never reaches the credential provider on a refused run", async () => {
    const { config } = makeProfile({ enabled: true });
    control(config, "lock", true);
    let credentialTouched = false;
    const gate = createHostedOutboundGate({
      config,
      purpose: "runtime_heartbeat",
      credentialProvider: async (run) => { credentialTouched = true; return run("secret"); },
    });
    await assert.rejects(() => gate.run(() => { throw new Error("must not send"); }), HostedOutboundRefused);
    assert.equal(credentialTouched, false, "the credential provider must never be invoked");
    assert.equal(gate.allowed(), false);
  });

  it("missing control state on an enabled profile is allowed, and present state is not", () => {
    const { config } = makeProfile({ enabled: true });
    assert.equal(inspectObservationControls(config).blocked, false);
    control(config, "disabled", true);
    assert.equal(inspectObservationControls(config).blocked, true);
  });

  it("applies disabled > killswitch > lock precedence", () => {
    const { config } = makeProfile({ enabled: true });
    control(config, "lock", true);
    assert.equal(inspectObservationControls(config).priority, "SYSTEM_LOCK");
    control(config, "killswitch", true);
    assert.equal(inspectObservationControls(config).priority, "KILL_SWITCH");
    control(config, "disabled", true);
    assert.equal(inspectObservationControls(config).priority, "DISABLED");
  });
});

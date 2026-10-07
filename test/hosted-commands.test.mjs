// `observa hosted-health` and `observa identify`, driven through the real CLI,
// the real GovernanceApiClient and the real gateway RuntimePublisher against an
// in-process Hosted simulator. The simulator mirrors the Hosted runtime
// publication rules (generation ownership, idempotent roster replay, heartbeat
// roster binding, 410 for a superseded runtime) so the tests can prove that
// identify never supersedes the running gateway.
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { readFileSync, writeFileSync } from "node:fs";

import { runObserva } from "../cli/cli.mjs";
import { GovernanceApiClient } from "../plugins/openclaw-connector/client.mjs";
import { loadConnectorConfig } from "../plugins/openclaw-connector/config.mjs";
import { parseCredential } from "../plugins/openclaw-connector/credentials.mjs";
import { setControl } from "../plugins/openclaw-connector/controls.mjs";
import { RuntimePublisher } from "../plugins/openclaw-connector/runtime-publisher.mjs";
import {
  buildRuntimeInventoryRequest, buildRuntimePublicationAck, rosterRevision, serializeRuntimePublication,
  validateRuntimeHeartbeatRequest, validateRuntimeInventoryRequest,
} from "../plugins/openclaw-connector/runtime-publication-contract.mjs";
import {
  PUBLICATION_STATUS_FILE, parsePublicationStatus, writePublicationStatus,
} from "../plugins/openclaw-connector/runtime-publication-status.mjs";
import {
  AGENTS, DEPLOYMENT, PLUGIN, cleanupTemps, makeProfileHome, snapshotTree, writeJournal,
} from "./cli-fixtures.mjs";
import { TEST_CREDENTIAL, flush, makeManualTimers } from "./helpers.mjs";

after(cleanupTemps);

const ENV = Object.freeze({ PATH: "/usr/bin:/bin" });
const IDENTITY = parseCredential(TEST_CREDENTIAL);

function hostedSimulator({ revoked = false, unreachable = false, identityDeployment = DEPLOYMENT, controlPlaneDown = false } = {}) {
  const state = { owner: null, snapshots: [], heartbeats: [], bindings: new Map(), nonces: new Set(), requests: [], replays: 0 };
  const reply = (statusCode, value) => ({ statusCode, body: Buffer.from(JSON.stringify(value)) });
  const refused = (statusCode, reason) => reply(statusCode, { accepted: false, reason, authority: "NONE", enforcement: "OFF", active: false });
  const transport = async ({ url, method, body, credential }) => {
    state.requests.push({ path: url.pathname, method, credentialMatches: credential === TEST_CREDENTIAL, bytes: body?.length ?? 0 });
    if (unreachable) throw Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" });
    if (controlPlaneDown) return refused(503, "control_plane_unavailable");
    if (credential !== TEST_CREDENTIAL || revoked) return refused(403, "credential_not_accepted");
    if (url.pathname === "/v1/health" && method === "GET") return reply(200, { ok: true, api_version: "mgp/1", authority: "NONE", enforcement: "OFF" });
    if (url.pathname === "/v1/credentials/identity" && method === "GET") {
      return reply(200, { credential_id: IDENTITY.credentialId, deployment_id: identityDeployment, fingerprint: IDENTITY.fingerprint });
    }
    const request = JSON.parse(Buffer.from(body).toString("utf8"));
    if (state.nonces.has(request.nonce)) return refused(409, "replay_rejected");
    state.nonces.add(request.nonce);
    const generation = request.runtime_generation;
    const bound = state.bindings.get(request.runtime_instance_id);
    const current = state.snapshots.at(-1);
    if (url.pathname === "/v1/runtime/inventory") {
      assert.equal(validateRuntimeInventoryRequest(request).ok, true);
      if (bound !== undefined && bound !== generation) return refused(409, "runtime_generation_collision");
      if (state.owner && generation < state.owner.generation) return refused(410, "stale_runtime");
      if (state.owner && generation === state.owner.generation && state.owner.instance !== request.runtime_instance_id) return refused(409, "runtime_generation_collision");
      if (state.owner && generation === state.owner.generation && current?.instance === request.runtime_instance_id && current.revision === request.roster_revision) {
        state.replays += 1;
        return reply(200, buildRuntimePublicationAck("INVENTORY", request, current.id));
      }
      if (!state.owner || generation > state.owner.generation) {
        state.owner = { generation, instance: request.runtime_instance_id };
        state.bindings.set(request.runtime_instance_id, generation);
      }
      const snapshot = { id: `oris_${state.snapshots.length + 1}`, instance: request.runtime_instance_id, revision: request.roster_revision, agents: request.agents.map((a) => a.agent_id) };
      state.snapshots.push(snapshot);
      return reply(200, buildRuntimePublicationAck("INVENTORY", request, snapshot.id));
    }
    if (url.pathname === "/v1/runtime/heartbeat") {
      assert.equal(validateRuntimeHeartbeatRequest(request).ok, true);
      if (!state.owner) return refused(409, "inventory_required");
      if (generation < state.owner.generation || (bound !== undefined && bound < state.owner.generation)) return refused(410, "stale_runtime");
      if (current?.instance !== request.runtime_instance_id || current.revision !== request.roster_revision) return refused(409, "inventory_required");
      state.heartbeats.push({ instance: request.runtime_instance_id, sequence: request.sequence });
      return reply(200, buildRuntimePublicationAck("HEARTBEAT", request, `orhb_${state.heartbeats.length}`));
    }
    return refused(404, "not_found");
  };
  const client = () => new GovernanceApiClient({ baseUrl: "https://hosted.invalid", connectTimeoutMs: 100, transport, random: () => 0 });
  return { state, transport, client };
}

const cli = (argv, { home, hosted, credentialProvider, now } = {}) => runObserva(
  [...argv, "--profile-home", home],
  { env: ENV, now, dependencies: { ...(hosted ? { hostedClient: hosted.client() } : {}), ...(credentialProvider ? { hostedCredentialProvider: credentialProvider } : {}) } },
);
const json = (result) => JSON.parse(result.stdout);
function credentialReads() {
  const reads = [];
  const provider = async (stateDir, callback) => {
    reads.push(stateDir);
    const { withCredential } = await import("../plugins/openclaw-connector/credentials.mjs");
    return withCredential(stateDir, callback);
  };
  return { reads, provider };
}

/** A real gateway publisher on the fixture profile, publishing to the simulator. */
async function startGateway(profile, hosted, { instance = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" } = {}) {
  const host = JSON.parse(readFileSync(join(profile.root, "openclaw.json"), "utf8"));
  const config = loadConnectorConfig(host.plugins.entries[PLUGIN].config, { openclawStateDir: profile.root });
  const timers = makeManualTimers();
  const publisher = new RuntimePublisher({
    client: hosted.client(), hostConfig: host, runtimeInstanceId: instance,
    setTimeoutFn: timers.setTimeoutFn, clearTimeoutFn: timers.clearTimeoutFn,
    statusJournal: writePublicationStatus,
  });
  publisher.start(config);
  await flush();
  return { publisher, timers, config };
}

describe("hosted-health", () => {
  it("paired and healthy: probes health + identity, reports binding and fresh heartbeat", async () => {
    const profile = makeProfileHome();
    const hosted = hostedSimulator();
    const gateway = await startGateway(profile, hosted);
    const result = await cli(["hosted-health"], { home: profile.home, hosted });
    assert.equal(result.code, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /^Observa hosted health: HEALTHY/);
    assert.match(result.stdout, /Hosted reachable\s+YES/);
    assert.match(result.stdout, /Installation binding\s+VALID \(deployment founder-dep\)/);
    assert.match(result.stdout, /Runtime heartbeat\s+FRESH/);
    assert.match(result.stdout, /Roster\s+CURRENT \(3 agents/);
    assert.equal(result.stdout.includes(TEST_CREDENTIAL), false);
    assert.equal(result.stdout.includes(TEST_CREDENTIAL.split(".")[1]), false);
    const report = json(await cli(["hosted-health", "--json"], { home: profile.home, hosted })).hosted_health;
    assert.equal(report.state, "HEALTHY");
    assert.equal(report.binding, "VALID");
    assert.equal(report.credential_fingerprint, IDENTITY.fingerprint);
    // Exactly the two existing read contracts, with the paired credential.
    const probes = hosted.state.requests.filter((r) => r.path.startsWith("/v1/health") || r.path.startsWith("/v1/credentials"));
    assert.deepEqual(probes.map((r) => `${r.method} ${r.path}`), ["GET /v1/health", "GET /v1/credentials/identity", "GET /v1/health", "GET /v1/credentials/identity"]);
    assert.ok(probes.every((r) => r.credentialMatches));
    await gateway.publisher.stop();
  });

  it("unpaired: NOT_PAIRED with the access funnel, zero requests, zero credential reads", async () => {
    const profile = makeProfileHome({ paired: false, enabled: false });
    const hosted = hostedSimulator();
    const spy = credentialReads();
    const result = await cli(["hosted-health"], { home: profile.home, hosted, credentialProvider: spy.provider });
    assert.equal(result.code, 2);
    assert.match(result.stdout, /^Observa hosted health: NOT_PAIRED/);
    assert.match(result.stdout, /observa request-access[\s\S]*observa request-status[\s\S]*observa pair/);
    assert.deepEqual(hosted.state.requests, []);
    assert.deepEqual(spy.reads, []);
  });

  it("Hosted unreachable: reachable NO, deterministic state, no crash", async () => {
    const profile = makeProfileHome({ journal: {} });
    const result = await cli(["hosted-health", "--json"], { home: profile.home, hosted: hostedSimulator({ unreachable: true }) });
    assert.equal(result.code, 2);
    const report = json(result).hosted_health;
    assert.equal(report.state, "UNREACHABLE");
    assert.equal(report.reachable, "NO");
    assert.ok(report.last_success_at, "last success comes from the gateway journal");
  });

  it("revoked or invalid credential: CREDENTIAL_REFUSED, binding INVALID, re-pair guidance", async () => {
    const profile = makeProfileHome({ journal: {} });
    const report = json(await cli(["hosted-health", "--json"], { home: profile.home, hosted: hostedSimulator({ revoked: true }) })).hosted_health;
    assert.equal(report.state, "CREDENTIAL_REFUSED");
    assert.equal(report.reachable, "YES");
    assert.equal(report.binding, "INVALID");
    assert.match(report.next.join(" "), /--replace-existing/);
  });

  it("foreign installation binding: BINDING_MISMATCH", async () => {
    const profile = makeProfileHome({ journal: {} });
    const report = json(await cli(["hosted-health", "--json"], { home: profile.home, hosted: hostedSimulator({ identityDeployment: "someone-elses-deployment" }) })).hosted_health;
    assert.equal(report.state, "BINDING_MISMATCH");
    assert.equal(report.binding, "INVALID");
  });

  it("Hosted control plane unavailable: HOSTED_UNAVAILABLE, binding UNKNOWN", async () => {
    const profile = makeProfileHome({ journal: {} });
    const report = json(await cli(["hosted-health", "--json"], { home: profile.home, hosted: hostedSimulator({ controlPlaneDown: true }) })).hosted_health;
    assert.equal(report.state, "HOSTED_UNAVAILABLE");
    assert.equal(report.binding, "UNKNOWN");
  });

  it("stale heartbeat: connection fine, heartbeat STALE, not HEALTHY", async () => {
    const profile = makeProfileHome({ journal: { heartbeatAgeSeconds: 900 } });
    const result = await cli(["hosted-health"], { home: profile.home, hosted: hostedSimulator() });
    assert.equal(result.code, 2);
    assert.match(result.stdout, /^Observa hosted health: CONNECTED_HEARTBEAT_STALE/);
    assert.match(result.stdout, /Runtime heartbeat\s+STALE \(accepted 15m ago/);
  });

  it("no gateway journal (gateway not yet restarted on this version): heartbeat unknown", async () => {
    const profile = makeProfileHome();
    const report = json(await cli(["hosted-health", "--json"], { home: profile.home, hosted: hostedSimulator() })).hosted_health;
    assert.equal(report.state, "CONNECTED_HEARTBEAT_UNKNOWN");
    assert.equal(report.publication.heartbeat, "NOT_AVAILABLE");
  });

  for (const control of ["disabled", "killswitch", "lock"]) {
    it(`${control}: refused before any credential read or request`, async () => {
      const profile = makeProfileHome({ journal: {} });
      setControl(profile.stateDir, control, true);
      const hosted = hostedSimulator();
      const spy = credentialReads();
      const report = json(await cli(["hosted-health", "--json"], { home: profile.home, hosted, credentialProvider: spy.provider })).hosted_health;
      assert.equal(report.state, "REFUSED_BY_CONTROL");
      assert.equal(report.refusal, { disabled: "DISABLED", killswitch: "KILL_SWITCH", lock: "SYSTEM_LOCK" }[control]);
      assert.deepEqual(hosted.state.requests, []);
      assert.deepEqual(spy.reads, []);
    });
  }

  it("a disabled connector configuration is also a stop", async () => {
    const profile = makeProfileHome({ enabled: false, journal: {} });
    const hosted = hostedSimulator();
    const report = json(await cli(["hosted-health", "--json"], { home: profile.home, hosted })).hosted_health;
    assert.equal(report.state, "REFUSED_BY_CONTROL");
    assert.deepEqual(hosted.state.requests, []);
  });

  it("creates zero meaningful activity, decisions, heartbeats or file changes", async () => {
    const profile = makeProfileHome({ journal: {} });
    const hosted = hostedSimulator();
    const before = snapshotTree(profile.root);
    const activityBefore = (await cli(["activity", "--json"], { home: profile.home })).stdout;
    const agentsBefore = json(await cli(["agents", "--json"], { home: profile.home })).agents;
    for (let i = 0; i < 3; i += 1) await cli(["hosted-health"], { home: profile.home, hosted });
    assert.deepEqual(snapshotTree(profile.root), before);
    assert.equal((await cli(["activity", "--json"], { home: profile.home })).stdout, activityBefore);
    const agentsAfter = json(await cli(["agents", "--json"], { home: profile.home })).agents;
    assert.deepEqual(agentsAfter, agentsBefore);
    assert.ok(agentsAfter.every((a) => a.state !== "ACTIVE"));
    assert.ok(hosted.state.requests.every((r) => r.method === "GET"), "health never publishes a heartbeat or anything else");
    assert.equal(hosted.state.heartbeats.length, 0);
    assert.equal(hosted.state.snapshots.length, 0);
  });
});

describe("identify", () => {
  it("unpaired: identifies the configured agents locally and points to the funnel", async () => {
    const profile = makeProfileHome({ paired: false, enabled: false });
    const hosted = hostedSimulator();
    const result = await cli(["identify"], { home: profile.home, hosted });
    assert.equal(result.code, 0);
    assert.match(result.stdout, /Configured agents \(3, OpenClaw configured roster\):\n  aegis\n  main\n  sterling/);
    assert.match(result.stdout, /Hosted roster\s+NOT_PAIRED/);
    assert.match(result.stdout, /observa request-access/);
    assert.deepEqual(hosted.state.requests, []);
  });

  it("paired: confirms the roster on Hosted under the running gateway's own runtime identity", async () => {
    const profile = makeProfileHome();
    const hosted = hostedSimulator();
    const gateway = await startGateway(profile, hosted);
    const journal = parsePublicationStatus(readFileSync(join(profile.stateDir, PUBLICATION_STATUS_FILE), "utf8"));
    assert.equal(journal.last_outcome, "HEARTBEAT_ACCEPTED");
    const snapshotsBefore = hosted.state.snapshots.length;
    const result = await cli(["identify", "--json"], { home: profile.home, hosted });
    assert.equal(result.code, 0, result.stdout);
    const report = json(result).identify;
    assert.equal(report.hosted.state, "ROSTER_CONFIRMED");
    assert.deepEqual(report.local.agents, [...AGENTS]);
    assert.equal(report.hosted.runtime_instance_id, journal.runtime_instance_id);
    assert.equal(report.hosted.runtime_generation, journal.runtime_generation);
    // The existing inventory contract, idempotent on Hosted: no new owner, no new snapshot.
    const last = hosted.state.requests.at(-1);
    assert.equal(last.path, "/v1/runtime/inventory");
    assert.equal(hosted.state.replays, 1);
    assert.equal(hosted.state.snapshots.length, snapshotsBefore);
    assert.equal(hosted.state.owner.instance, journal.runtime_instance_id);
    // The running gateway keeps heartbeating afterwards: not superseded.
    const beats = hosted.state.heartbeats.length;
    await gateway.timers.fire();
    assert.equal(hosted.state.heartbeats.length, beats + 1);
    assert.equal(gateway.publisher.status().superseded, false);
    await gateway.publisher.stop();
  });

  it("why identify never claims a generation: a CLI-owned generation would supersede the gateway", async () => {
    const profile = makeProfileHome();
    const hosted = hostedSimulator();
    const gateway = await startGateway(profile, hosted);
    const journal = parsePublicationStatus(readFileSync(join(profile.stateDir, PUBLICATION_STATUS_FILE), "utf8"));
    const naive = buildRuntimeInventoryRequest({
      runtimeInstanceId: "99999999-9999-4999-8999-999999999999", runtimeGeneration: journal.runtime_generation + 1,
      rosterRevision: journal.roster_revision, agents: journal.agents.map((agent_id) => ({ agent_id })),
    });
    await hosted.client().publishInventory(serializeRuntimePublication(naive), TEST_CREDENTIAL, { expectedRequestHash: naive.request_hash });
    await gateway.timers.fire();
    assert.equal(gateway.publisher.status().superseded, true, "this is the failure identify is designed to avoid");
  });

  it("a changed roster is left for the gateway restart (no publication, no supersession)", async () => {
    const profile = makeProfileHome();
    const hosted = hostedSimulator();
    const gateway = await startGateway(profile, hosted);
    const host = JSON.parse(readFileSync(join(profile.root, "openclaw.json"), "utf8"));
    host.agents.entries.newcomer = {};
    writeFileSync(join(profile.root, "openclaw.json"), JSON.stringify(host));
    const requests = hosted.state.requests.length;
    const result = await cli(["identify", "--json"], { home: profile.home, hosted });
    assert.equal(result.code, 2);
    const report = json(result).identify;
    assert.equal(report.hosted.state, "ROSTER_CHANGED_RESTART_REQUIRED");
    assert.ok(report.local.agents.includes("newcomer"));
    assert.equal(hosted.state.requests.length, requests);
    await gateway.timers.fire();
    assert.equal(gateway.publisher.status().superseded, false);
    await gateway.publisher.stop();
  });

  it("no journal or a stale/stopped gateway: nothing is published", async () => {
    for (const [journal, expected] of [[null, "GATEWAY_PUBLICATION_UNAVAILABLE"], [{ heartbeatAgeSeconds: 900 }, "GATEWAY_PUBLICATION_STALE"], [{ outcome: "STOPPED" }, "GATEWAY_PUBLICATION_STALE"]]) {
      const profile = makeProfileHome(journal ? { journal } : {});
      const hosted = hostedSimulator();
      const report = json(await cli(["identify", "--json"], { home: profile.home, hosted })).identify;
      assert.equal(report.hosted.state, expected);
      assert.deepEqual(hosted.state.requests, []);
    }
  });

  it("a superseded journal identity is reported, not retried with a new generation", async () => {
    const profile = makeProfileHome();
    const hosted = hostedSimulator();
    await startGateway(profile, hosted);
    // Another runtime has since taken a higher generation on this credential.
    const other = buildRuntimeInventoryRequest({ runtimeInstanceId: "77777777-7777-4777-8777-777777777777", runtimeGeneration: 50, rosterRevision: rosterRevision(AGENTS.map((agent_id) => ({ agent_id }))), agents: AGENTS.map((agent_id) => ({ agent_id })) });
    await hosted.client().publishInventory(serializeRuntimePublication(other), TEST_CREDENTIAL, { expectedRequestHash: other.request_hash });
    const report = json(await cli(["identify", "--json"], { home: profile.home, hosted })).identify;
    assert.equal(report.hosted.state, "RUNTIME_SUPERSEDED");
    assert.equal(hosted.state.owner.generation, 50);
  });

  for (const control of ["disabled", "killswitch", "lock"]) {
    it(`${control}: local identity still reported; Hosted untouched, credential unread`, async () => {
      const profile = makeProfileHome({ journal: {} });
      setControl(profile.stateDir, control, true);
      const hosted = hostedSimulator();
      const spy = credentialReads();
      const result = await cli(["identify", "--json"], { home: profile.home, hosted, credentialProvider: spy.provider });
      const report = json(result).identify;
      assert.equal(report.local.state, "IDENTIFIED");
      assert.equal(report.hosted.state, "REFUSED_BY_CONTROL");
      assert.deepEqual(hosted.state.requests, []);
      assert.deepEqual(spy.reads, []);
    });
  }

  it("creates zero activity, zero decisions, no heartbeat, and no governance-state change", async () => {
    const profile = makeProfileHome();
    const hosted = hostedSimulator();
    const gateway = await startGateway(profile, hosted);
    await gateway.publisher.stop();
    // Keep the journal fresh without the gateway so only identify talks to Hosted.
    writeJournal(profile.stateDir, {
      instance: gateway.publisher.status().runtimeInstanceId, generation: gateway.publisher.status().runtimeGeneration,
    });
    const before = snapshotTree(profile.root);
    const decisionsBefore = (await cli(["decisions", "--json"], { home: profile.home })).stdout;
    const activityBefore = (await cli(["activity", "--json"], { home: profile.home })).stdout;
    const beats = hosted.state.heartbeats.length;
    const report = json(await cli(["identify", "--json"], { home: profile.home, hosted })).identify;
    assert.equal(report.hosted.state, "ROSTER_CONFIRMED");
    assert.equal(report.meaningful_activity_written, false);
    assert.equal(report.governance_decisions_written, false);
    assert.equal(report.heartbeat_sent, false);
    assert.deepEqual(snapshotTree(profile.root), before, "no receipt, control, config or journal change");
    assert.equal((await cli(["decisions", "--json"], { home: profile.home })).stdout, decisionsBefore);
    assert.equal((await cli(["activity", "--json"], { home: profile.home })).stdout, activityBefore);
    assert.equal(hosted.state.heartbeats.length, beats);
    const agents = json(await cli(["agents", "--json"], { home: profile.home })).agents;
    assert.ok(agents.every((a) => a.state !== "ACTIVE"));
  });
});

describe("the gateway publication journal", () => {
  it("records accepted inventory and heartbeat, never a credential, owner-only", async () => {
    const profile = makeProfileHome();
    const hosted = hostedSimulator();
    const gateway = await startGateway(profile, hosted);
    const path = join(profile.stateDir, PUBLICATION_STATUS_FILE);
    const text = readFileSync(path, "utf8");
    assert.equal(text.includes(TEST_CREDENTIAL), false);
    const journal = parsePublicationStatus(text);
    assert.deepEqual([...journal.agents], [...AGENTS]);
    assert.ok(journal.inventory_accepted_at && journal.heartbeat_accepted_at);
    assert.equal((await import("node:fs")).statSync(path).mode & 0o777, 0o600);
    await gateway.publisher.stop();
    assert.equal(parsePublicationStatus(readFileSync(path, "utf8")).last_outcome, "STOPPED");
  });

  it("a refused gateway start writes no journal (refusal stays side-effect free)", async () => {
    const profile = makeProfileHome();
    setControl(profile.stateDir, "killswitch", true);
    const hosted = hostedSimulator();
    const gateway = await startGateway(profile, hosted);
    assert.throws(() => readFileSync(join(profile.stateDir, PUBLICATION_STATUS_FILE)), /ENOENT/);
    assert.deepEqual(hosted.state.requests, []);
    await gateway.publisher.stop();
  });

  it("rejects malformed or authority-claiming journals", () => {
    const good = { schema: "observa-openclaw-runtime-publication-status/v1", runtime_instance_id: "x", runtime_generation: 1, roster_revision: `sha256:${"a".repeat(64)}`, agents: ["main"], cadence_seconds: 60, inventory_accepted_at: null, heartbeat_accepted_at: null, heartbeats_accepted: 0, last_outcome: "FAILED", last_outcome_at: new Date().toISOString(), last_failure: "UNREACHABLE", authority: "NONE", enforcement: "OFF", active: false };
    assert.ok(parsePublicationStatus(JSON.stringify(good)));
    for (const patch of [{ authority: "FULL" }, { active: true }, { agents: ["../x"] }, { extra: 1 }, { runtime_generation: 0 }, { last_failure: "x\ny" }]) {
      assert.equal(parsePublicationStatus(JSON.stringify({ ...good, ...patch })), null, JSON.stringify(patch));
    }
    assert.equal(parsePublicationStatus("not json"), null);
  });
});

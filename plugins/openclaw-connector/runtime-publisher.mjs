import { withCredential } from "./credentials.mjs";
import { createHostedOutboundGate } from "./controls.mjs";
import { allocateRuntimeGeneration } from "./runtime-generation.mjs";
import {
  buildRuntimeHeartbeatRequest, buildRuntimeInventoryRequest,
  canonicalRuntimePublicationJson, rosterRevision, serializeRuntimePublication,
} from "./runtime-publication-contract.mjs";
import { publicationFailureCode } from "./runtime-publication-status.mjs";

export const RUNTIME_HEARTBEAT_CADENCE_SECONDS = 60;
const AGENT_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/i;

function normalizeAgentId(value) {
  const trimmed = typeof value === "string" ? value.trim() : "";
  if (!AGENT_ID.test(trimmed)) throw new TypeError("OPENCLAW_AGENT_ID_INVALID");
  return trimmed.toLowerCase();
}

// Mirrors OpenClaw's supported configured roster semantics without importing
// private core modules or executing its CLI.  2026.8 uses agents.entries;
// compatible hosts may expose agents.list.  Both non-empty is ambiguous and
// fails closed.  With neither, OpenClaw's documented implicit roster is main.
export function configuredAgentRoster(hostConfig) {
  if (!hostConfig || typeof hostConfig !== "object" || Array.isArray(hostConfig)) {
    throw new TypeError("OPENCLAW_CONFIG_INVALID");
  }
  const agents = hostConfig.agents;
  if (agents !== undefined && (!agents || typeof agents !== "object" || Array.isArray(agents))) {
    throw new TypeError("OPENCLAW_AGENT_ROSTER_INVALID");
  }
  const entries = agents?.entries;
  const list = agents?.list;
  const entryKeys = entries && typeof entries === "object" && !Array.isArray(entries)
    ? Object.keys(entries) : [];
  const listValues = Array.isArray(list) ? list : [];
  if (entryKeys.length > 0 && listValues.length > 0) {
    throw new TypeError("OPENCLAW_AGENT_ROSTER_CONFLICT");
  }
  let ids;
  if (entryKeys.length > 0) {
    ids = entryKeys.map((key) => {
      const value = entries[key];
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new TypeError("OPENCLAW_AGENT_ROSTER_INVALID");
      }
      const fromKey = normalizeAgentId(key);
      if (value.id !== undefined && normalizeAgentId(value.id) !== fromKey) {
        throw new TypeError("OPENCLAW_AGENT_ROSTER_CONFLICT");
      }
      return fromKey;
    });
  } else if (listValues.length > 0) {
    ids = listValues.map((value) => {
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new TypeError("OPENCLAW_AGENT_ROSTER_INVALID");
      }
      return normalizeAgentId(value.id);
    });
  } else {
    ids = ["main"];
  }
  if (new Set(ids).size !== ids.length) throw new TypeError("OPENCLAW_AGENT_ROSTER_CONFLICT");
  return Object.freeze(ids.sort().map((agent_id) => Object.freeze({ agent_id })));
}

/**
 * Runtime roster + liveness publisher.
 *
 * Every publication it performs is credential-bearing Hosted traffic, so it is
 * governed by exactly the same durable controls as observation: the source
 * `enabled` flag, then disabled > kill switch > system lock. Before v0.7.3 it
 * consulted none of them and published on `gateway_start` from any paired
 * installation; that is the defect this class now closes.
 *
 * The gate is consulted at four points per cycle, so no scheduling window can
 * be used to slip past a control that became active after the timer was armed:
 *
 *   1. at the top of every run (startup run and every cadence tick)
 *   2. before the runtime generation is allocated, so a refused install
 *      leaves no generation claim behind
 *   3. before the credential is read, by the gate's own `run` helper
 *   4. before every transport attempt and every retry, via `beforeAttempt`
 *
 * The cadence timer keeps running while refused. It makes no network attempt
 * and reads no credential; it exists so that clearing the control resumes
 * publication without a gateway restart, matching how the observation lane
 * already behaves when the operator re-enables the connector.
 */
export class RuntimePublisher {
  #client;
  #credentialProvider;
  #gateFactory;
  #gates = new Map();
  #runtimeInstanceId;
  #agents;
  #rosterRevision;
  #cadenceSeconds;
  #setTimeout;
  #clearTimeout;
  #timer = null;
  #now;
  #active = null;
  // Re-entrancy is tracked by this synchronous flag rather than by `#active`.
  // A refused run returns without ever awaiting, so its `finally` executes
  // before the outer `#active = (async ...)()` assignment does; clearing
  // `#active` there would be undone a moment later and wedge the loop.
  #running = false;
  #started = false;
  #stopped = false;
  #superseded = false;
  #generationAllocator;
  #runtimeGeneration = null;
  #reason = null;
  #inventoryAccepted = false;
  #sequence = 0;
  #lastRefusal = null;
  #totals = { inventoryAccepted: 0, heartbeatsAccepted: 0, failures: 0, refusals: 0 };
  // Local journal of accepted publications (see runtime-publication-status.mjs).
  // Written only after a run the controls allowed, so a refused install stays
  // free of new local state exactly as before.
  #statusJournal;
  #journalConfig = null;
  #inventoryAcceptedAt = null;
  #heartbeatAcceptedAt = null;

  constructor({
    client, hostConfig, runtimeInstanceId,
    credentialProvider = null,
    controlInspector = null,
    gateFactory = createHostedOutboundGate,
    cadenceSeconds = RUNTIME_HEARTBEAT_CADENCE_SECONDS,
    setTimeoutFn = setTimeout, clearTimeoutFn = clearTimeout,
    generationAllocator = (config) => allocateRuntimeGeneration(config?.stateDir),
    statusJournal = null, now = () => new Date(),
  }) {
    this.#generationAllocator = generationAllocator;
    this.#statusJournal = typeof statusJournal === "function" ? statusJournal : null;
    this.#now = now;
    if (!Number.isSafeInteger(cadenceSeconds) || cadenceSeconds < 10 || cadenceSeconds > 300) {
      throw new TypeError("RUNTIME_HEARTBEAT_CADENCE_INVALID");
    }
    this.#client = client;
    this.#runtimeInstanceId = runtimeInstanceId;
    this.#agents = configuredAgentRoster(hostConfig);
    this.#rosterRevision = rosterRevision(this.#agents);
    this.#credentialProvider = credentialProvider || withCredential;
    this.#cadenceSeconds = cadenceSeconds;
    this.#setTimeout = setTimeoutFn;
    this.#clearTimeout = clearTimeoutFn;
    // The package uses two inspector shapes: a zero-argument closure already
    // bound to a config (pipeline, runtime observer) and a one-argument
    // function taking the config (shadow runtime). Calling with the config
    // satisfies both, since the bound form ignores the extra argument.
    this.#gateFactory = (config, purpose) => gateFactory({
      config,
      purpose,
      ...(controlInspector ? { controlInspector: () => controlInspector(config) } : {}),
      credentialProvider: (run) => this.#credential(config, run),
    });
  }

  // One gate per (config, purpose). It is built lazily so a publisher that is
  // never started never constructs one, and cached so the decision seam is the
  // same object for the life of the process.
  #gate(config, purpose) {
    const existing = this.#gates.get(purpose);
    if (existing !== undefined) return existing;
    const gate = this.#gateFactory(config, purpose);
    this.#gates.set(purpose, gate);
    return gate;
  }

  async #credential(config, run) {
    // Production uses the standard connector credential reader.  Tests can
    // inject the simpler callback form used elsewhere in the package.
    if (this.#credentialProvider.length >= 2) {
      return this.#credentialProvider(config.stateDir, run);
    }
    return this.#credentialProvider(run);
  }

  async #publishInventory(config) {
    const request = buildRuntimeInventoryRequest({
      runtimeInstanceId: this.#runtimeInstanceId,
      runtimeGeneration: this.#runtimeGeneration,
      rosterRevision: this.#rosterRevision,
      agents: this.#agents,
    });
    const body = serializeRuntimePublication(request);
    try {
      await this.#gate(config, "runtime_inventory").run(
        (credential, { beforeAttempt }) => this.#client.publishInventory(
          body, credential, { expectedRequestHash: request.request_hash, beforeAttempt },
        ),
      );
      this.#inventoryAccepted = true;
      this.#totals.inventoryAccepted += 1;
      this.#inventoryAcceptedAt = this.#now().toISOString();
      this.#journal("INVENTORY_ACCEPTED");
    } finally { body.fill(0); }
  }

  async #publishHeartbeat(config) {
    const request = buildRuntimeHeartbeatRequest({
      runtimeInstanceId: this.#runtimeInstanceId,
      runtimeGeneration: this.#runtimeGeneration,
      rosterRevision: this.#rosterRevision,
      sequence: ++this.#sequence,
      cadenceSeconds: this.#cadenceSeconds,
    });
    const body = serializeRuntimePublication(request);
    try {
      await this.#gate(config, "runtime_heartbeat").run(
        (credential, { beforeAttempt }) => this.#client.publishHeartbeat(
          body, credential, { expectedRequestHash: request.request_hash, beforeAttempt },
        ),
      );
      this.#totals.heartbeatsAccepted += 1;
      this.#heartbeatAcceptedAt = this.#now().toISOString();
      this.#journal("HEARTBEAT_ACCEPTED");
    } finally { body.fill(0); }
  }

  // Best effort and never able to affect publication: a journal failure only
  // means hosted-health reports the heartbeat as unavailable.
  #journal(outcome, failure = null) {
    if (this.#statusJournal === null || this.#journalConfig === null || this.#runtimeGeneration === null) return;
    try {
      this.#statusJournal(this.#journalConfig.stateDir, {
        runtime_instance_id: this.#runtimeInstanceId,
        runtime_generation: this.#runtimeGeneration,
        roster_revision: this.#rosterRevision,
        agents: this.#agents.map((agent) => agent.agent_id),
        cadence_seconds: this.#cadenceSeconds,
        inventory_accepted_at: this.#inventoryAcceptedAt,
        heartbeat_accepted_at: this.#heartbeatAcceptedAt,
        heartbeats_accepted: this.#totals.heartbeatsAccepted,
        last_outcome: outcome,
        last_outcome_at: this.#now().toISOString(),
        last_failure: failure,
      });
    } catch { /* journal is advisory */ }
  }

  #schedule(config) {
    if (this.#stopped || this.#timer !== null) return;
    this.#timer = this.#setTimeout(() => {
      this.#timer = null;
      this.#run(config);
    }, this.#cadenceSeconds * 1000);
    this.#timer?.unref?.();
  }

  // Checkpoint 1. Consulted at the top of the startup run and of every cadence
  // tick, before ANY publication work: no generation claim, no request build,
  // no credential read, no socket.
  #refusedThisRun(config) {
    const controls = this.#gate(config, "runtime_inventory").inspect();
    if (!controls.blocked) return false;
    this.#totals.refusals += 1;
    this.#lastRefusal = String(controls.priority ?? controls.remoteStatus ?? "NOT_ATTEMPTED");
    return true;
  }

  // Checkpoint 2. One generation per process, allocated lazily on the first
  // run the controls actually authorize, so a disabled, killed, or locked
  // install leaves no generation claim on disk. Without a valid generation
  // this runtime never publishes (fail closed; tool execution is unaffected).
  #ensureGeneration(config) {
    if (this.#runtimeGeneration !== null) return true;
    try {
      const generation = this.#generationAllocator(config);
      if (!Number.isSafeInteger(generation) || generation < 1) {
        throw Object.assign(new Error("RUNTIME_GENERATION_INVALID"), { code: "RUNTIME_GENERATION_INVALID" });
      }
      this.#runtimeGeneration = generation;
      return true;
    } catch (error) {
      this.#stopped = true;
      this.#reason = String(error?.code ?? "RUNTIME_GENERATION_UNAVAILABLE");
      return false;
    }
  }

  #run(config) {
    if (this.#stopped || this.#running) return this.#active;
    this.#running = true;
    this.#active = (async () => {
      try {
        if (this.#refusedThisRun(config)) return;
        if (!this.#ensureGeneration(config)) return;
        this.#journalConfig = config;
        if (!this.#inventoryAccepted) await this.#publishInventory(config);
        if (this.#inventoryAccepted && !this.#stopped) await this.#publishHeartbeat(config);
      } catch (error) {
        // A refusal raised by the gate at checkpoint 3 or 4 is a control
        // decision, not a transport failure, and never counts against the
        // client's circuit or this publisher's failure total.
        if (error?.name === "HostedOutboundRefused") {
          this.#totals.refusals += 1;
          this.#lastRefusal = String(error.priority ?? error.remoteStatus ?? "NOT_ATTEMPTED");
          return;
        }
        this.#totals.failures += 1;
        // 410 is the server's terminal answer for a runtime instance another
        // process on this credential has superseded. Stop publishing for the
        // life of this process instead of emitting refused heartbeats forever;
        // tool execution is unaffected either way.
        if (error?.remoteStatus === "HTTP_ERROR:410") {
          this.#superseded = true;
          this.#stopped = true;
        }
        this.#journal(this.#superseded ? "SUPERSEDED" : "FAILED", publicationFailureCode(error));
      } finally {
        this.#running = false;
        this.#schedule(config);
      }
    })();
    this.#active.catch(() => {});
    return this.#active;
  }

  // `start` arms the cadence loop; it does not itself authorize publication.
  // A refused install still "starts" in the sense that the loop is live and
  // will resume if the operator clears the control, but it performs no Hosted
  // network activity and reads no credential while the control is active.
  start(config) {
    if (this.#started || this.#stopped) return false;
    this.#started = true;
    this.#run(config);
    return true;
  }

  async stop() {
    if (this.#stopped) return this.status();
    this.#stopped = true;
    if (this.#timer !== null) {
      this.#clearTimeout(this.#timer);
      this.#timer = null;
    }
    if (this.#active !== null) await Promise.allSettled([this.#active]);
    this.#journal("STOPPED");
    return this.status();
  }

  status() {
    return Object.freeze({
      started: this.#started, stopped: this.#stopped, superseded: this.#superseded,
      timerActive: this.#timer !== null, requestActive: this.#running,
      runtimeInstanceId: this.#runtimeInstanceId,
      runtimeGeneration: this.#runtimeGeneration,
      reason: this.#reason,
      // Publication is governed by the same durable controls as observation.
      // `lastRefusal` names the control that most recently refused a run; it
      // is evidence of a refusal, never a live control read (status must stay
      // free of side effects and of filesystem dependence).
      outboundGoverned: true,
      lastRefusal: this.#lastRefusal,
      rosterRevision: this.#rosterRevision,
      rosterSize: this.#agents.length,
      cadenceSeconds: this.#cadenceSeconds,
      sequence: this.#sequence,
      totals: Object.freeze({ ...this.#totals }),
      messageShape: canonicalRuntimePublicationJson(this.#agents),
      meaningfulActivity: false, capabilitiesClaimed: false,
      authority: "NONE", enforcement: "OFF", active: false,
    });
  }
}

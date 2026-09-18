import { withCredential } from "./credentials.mjs";
import { allocateRuntimeGeneration } from "./runtime-generation.mjs";
import {
  buildRuntimeHeartbeatRequest, buildRuntimeInventoryRequest,
  canonicalRuntimePublicationJson, rosterRevision, serializeRuntimePublication,
} from "./runtime-publication-contract.mjs";

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

export class RuntimePublisher {
  #client;
  #credentialProvider;
  #runtimeInstanceId;
  #agents;
  #rosterRevision;
  #cadenceSeconds;
  #setTimeout;
  #clearTimeout;
  #timer = null;
  #active = null;
  #started = false;
  #stopped = false;
  #superseded = false;
  #generationAllocator;
  #runtimeGeneration = null;
  #reason = null;
  #inventoryAccepted = false;
  #sequence = 0;
  #totals = { inventoryAccepted: 0, heartbeatsAccepted: 0, failures: 0 };

  constructor({
    client, hostConfig, runtimeInstanceId,
    credentialProvider = null,
    cadenceSeconds = RUNTIME_HEARTBEAT_CADENCE_SECONDS,
    setTimeoutFn = setTimeout, clearTimeoutFn = clearTimeout,
    generationAllocator = (config) => allocateRuntimeGeneration(config?.stateDir),
  }) {
    this.#generationAllocator = generationAllocator;
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
      await this.#credential(config, (credential) => this.#client.publishInventory(
        body, credential, { expectedRequestHash: request.request_hash },
      ));
      this.#inventoryAccepted = true;
      this.#totals.inventoryAccepted += 1;
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
      await this.#credential(config, (credential) => this.#client.publishHeartbeat(
        body, credential, { expectedRequestHash: request.request_hash },
      ));
      this.#totals.heartbeatsAccepted += 1;
    } finally { body.fill(0); }
  }

  #schedule(config) {
    if (this.#stopped || this.#timer !== null) return;
    this.#timer = this.#setTimeout(() => {
      this.#timer = null;
      this.#run(config);
    }, this.#cadenceSeconds * 1000);
    this.#timer?.unref?.();
  }

  #run(config) {
    if (this.#stopped || this.#active !== null) return this.#active;
    this.#active = (async () => {
      try {
        if (!this.#inventoryAccepted) await this.#publishInventory(config);
        if (this.#inventoryAccepted && !this.#stopped) await this.#publishHeartbeat(config);
      } catch (error) {
        this.#totals.failures += 1;
        // 410 is the server's terminal answer for a runtime instance another
        // process on this credential has superseded. Stop publishing for the
        // life of this process instead of emitting refused heartbeats forever;
        // tool execution is unaffected either way.
        if (error?.remoteStatus === "HTTP_ERROR:410") {
          this.#superseded = true;
          this.#stopped = true;
        }
      } finally {
        this.#active = null;
        this.#schedule(config);
      }
    })();
    this.#active.catch(() => {});
    return this.#active;
  }

  start(config) {
    if (this.#started || this.#stopped) return false;
    this.#started = true;
    // One generation per process, taken at start. Without a valid one this
    // runtime never publishes (fail closed; tool execution is unaffected).
    try {
      const generation = this.#generationAllocator(config);
      if (!Number.isSafeInteger(generation) || generation < 1) {
        throw Object.assign(new Error("RUNTIME_GENERATION_INVALID"), { code: "RUNTIME_GENERATION_INVALID" });
      }
      this.#runtimeGeneration = generation;
    } catch (error) {
      this.#stopped = true;
      this.#reason = String(error?.code ?? "RUNTIME_GENERATION_UNAVAILABLE");
      return false;
    }
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
    return this.status();
  }

  status() {
    return Object.freeze({
      started: this.#started, stopped: this.#stopped, superseded: this.#superseded,
      timerActive: this.#timer !== null, requestActive: this.#active !== null,
      runtimeInstanceId: this.#runtimeInstanceId,
      runtimeGeneration: this.#runtimeGeneration,
      reason: this.#reason,
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

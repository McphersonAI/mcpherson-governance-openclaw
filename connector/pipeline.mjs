import { correlationRef, requestHash } from "./runtime/governance-core/index.mjs";
import { buildObservationRequest, serializeAllowlistedRequest } from "./allowlist.mjs";
import { withCredential } from "./credentials.mjs";
import { makeAttemptReceipt } from "./receipts.mjs";
import { ConnectorClientError } from "./client.mjs";
import { inspectObservationControls } from "./controls.mjs";
import { DecisionIdWindow, ResponseValidationError, verifyDecision } from "./verify.mjs";

const CONTROL_STATUSES = new Set([
  "NOT_ATTEMPTED", "KILL_SWITCH_ACTIVE", "SYSTEM_LOCK_ACTIVE", "ABORTED_SHUTDOWN",
]);
const ALLOWED_TRANSITIONS = Object.freeze({
  QUEUED: new Set(["RUNNING", "SETTLING"]),
  RUNNING: new Set(["SETTLING"]),
  SETTLING: new Set(["DONE"]),
  DONE: new Set(),
});

function statusFrom(error) {
  if (error instanceof ConnectorClientError || error instanceof ResponseValidationError) return error.remoteStatus;
  if (error && typeof error === "object" && error.code === "CREDENTIAL_FORMAT_INVALID") return "NOT_ATTEMPTED";
  if (error && typeof error === "object" && ["ENOENT", "INSECURE_PERMISSIONS", "WRONG_OWNER", "INVALID_SIZE"].includes(String(error.code))) return "NOT_ATTEMPTED";
  return "NOT_ATTEMPTED";
}

function fallbackIdentity(summary, config) {
  const seed = {
    api_version: "mgp/1",
    agent_id: summary.agentId,
    tool_id: summary.toolId,
    timestamp: new Date(0).toISOString(),
  };
  return Object.freeze({
    request_hash: requestHash(seed),
    correlation_ref: correlationRef(summary.rawCorrelation || `${summary.agentId}:${summary.toolId}`),
    timestamp: new Date().toISOString(),
    agent_id: summary.agentId,
    tool_id: summary.toolId,
    deployment_id: config.deploymentId,
  });
}

function boundedDeadline(value) {
  return Math.max(1, Math.min(Number.isFinite(value) ? Math.floor(value) : 5_000, 5_000));
}

export class ObservationPipeline {
  #config;
  #client;
  #writer;
  #credentialProvider;
  #decisionIds;
  #controlInspector;
  #requestBuilder;
  #requestSerializer;
  #queue = [];
  #active = new Set();
  #entries = new Set();
  #pendingCompletions = new Set();
  #foregroundTimers = new Set();
  #accepting = true;
  #pumping = false;
  #shutdownPromise = null;
  #shutdownState = "OPEN";
  #shutdownDeadlineExceeded = false;
  #nextEntryId = 1;
  #lastContactAt = null;
  #lastRemoteStatus = null;
  #lastShutdownElapsedMs = null;
  #transitionFailures = 0;
  #recentTransitions = [];
  #totals = {
    submitted: 0,
    admitted: 0,
    droppedSaturated: 0,
    completed: 0,
    credentialAccesses: 0,
  };
  #peaks = { inFlight: 0, queued: 0, pendingCompletions: 0 };

  constructor({
    config,
    client,
    receiptWriter,
    credentialProvider = null,
    decisionIds = null,
    controlInspector = null,
    requestBuilder = buildObservationRequest,
    requestSerializer = serializeAllowlistedRequest,
  }) {
    this.#config = config;
    this.#client = client;
    this.#writer = receiptWriter;
    this.#credentialProvider = credentialProvider || ((callback) => withCredential(config.stateDir, callback));
    this.#decisionIds = decisionIds || new DecisionIdWindow();
    this.#controlInspector = controlInspector || (() => inspectObservationControls(config));
    this.#requestBuilder = requestBuilder;
    this.#requestSerializer = requestSerializer;
  }

  #inspectControls() {
    const value = this.#controlInspector();
    if (!value || typeof value.blocked !== "boolean") {
      return Object.freeze({ blocked: true, priority: "INVALID_CONTROL_STATE", remoteStatus: "NOT_ATTEMPTED" });
    }
    return value;
  }

  #assertRemoteAllowed() {
    const controls = this.#inspectControls();
    if (controls.blocked) throw new ConnectorClientError(controls.remoteStatus || "NOT_ATTEMPTED");
  }

  #makeReceipt(request, remoteStatus, localDisposition, decision = null) {
    return makeAttemptReceipt({
      decisionId: decision?.decision_id ?? null,
      requestHash: request.request_hash,
      deploymentId: this.#config.deploymentId,
      agentId: request.agent_id,
      toolId: request.tool_id,
      attemptAt: request.timestamp,
      outcome: "NOT_OBSERVED",
      remoteStatus,
      localDisposition,
      correlationRef: request.correlation_ref,
    });
  }

  #writeReceipt(receipt) {
    try { this.#writer.write(receipt); } catch {}
    this.#lastRemoteStatus = receipt.remote_status;
    return receipt;
  }

  #writeImmediate(summary, remoteStatus, localDisposition) {
    const request = fallbackIdentity(summary, this.#config);
    const receipt = this.#writeReceipt(this.#makeReceipt(request, remoteStatus, localDisposition));
    return Object.freeze({
      request,
      receipt,
      immediate: true,
      promise: Promise.resolve(receipt),
    });
  }

  recordLocal(summary, remoteStatus, localDisposition = "SKIPPED") {
    return this.#writeImmediate(summary, remoteStatus, localDisposition);
  }

  #updatePeaks() {
    this.#peaks.inFlight = Math.max(this.#peaks.inFlight, this.#active.size);
    this.#peaks.queued = Math.max(this.#peaks.queued, this.#queue.length);
    this.#peaks.pendingCompletions = Math.max(
      this.#peaks.pendingCompletions,
      this.#pendingCompletions.size,
    );
  }

  #invariantFailure(code) {
    this.#transitionFailures += 1;
    const error = new Error(code);
    error.code = code;
    throw error;
  }

  #assertInvariants() {
    if (this.#active.size > this.#config.maxInFlight) this.#invariantFailure("PIPELINE_IN_FLIGHT_BOUND_BROKEN");
    if (this.#queue.length > this.#config.maxQueue) this.#invariantFailure("PIPELINE_QUEUE_BOUND_BROKEN");
    const queued = new Set(this.#queue);
    if (queued.size !== this.#queue.length) this.#invariantFailure("PIPELINE_DUPLICATE_QUEUE_OWNERSHIP");
    for (const entry of this.#active) {
      if (!this.#entries.has(entry) || entry.permit !== true
        || !["RUNNING", "SETTLING"].includes(entry.state)) {
        this.#invariantFailure("PIPELINE_ACTIVE_OWNERSHIP_BROKEN");
      }
      if (queued.has(entry)) this.#invariantFailure("PIPELINE_DOUBLE_ACCOUNTING");
    }
    for (const entry of queued) {
      if (!this.#entries.has(entry) || entry.permit !== false || entry.state !== "QUEUED") {
        this.#invariantFailure("PIPELINE_QUEUE_OWNERSHIP_BROKEN");
      }
    }
    if (this.#entries.size !== this.#active.size + this.#queue.length) {
      this.#invariantFailure("PIPELINE_UNACCOUNTED_TASK");
    }
    const clientStatus = this.#client.status?.();
    if (Number.isInteger(clientStatus?.activeTransports)
      && clientStatus.activeTransports > this.#config.maxInFlight) {
      this.#invariantFailure("PIPELINE_TRANSPORT_BOUND_BROKEN");
    }
    this.#updatePeaks();
  }

  #transition(entry, next) {
    if (!ALLOWED_TRANSITIONS[entry.state]?.has(next)) this.#invariantFailure("PIPELINE_TRANSITION_INVALID");
    const previous = entry.state;
    entry.state = next;
    this.#recentTransitions.push(Object.freeze({ entryId: entry.id, from: previous, to: next }));
    if (this.#recentTransitions.length > 64) this.#recentTransitions.shift();
  }

  #makeEntry(fields) {
    let resolve;
    const promise = new Promise((done) => { resolve = done; });
    promise.catch(() => {});
    return {
      ...fields,
      id: this.#nextEntryId++,
      state: "QUEUED",
      permit: false,
      cleaned: false,
      execution: null,
      resolve,
      promise,
    };
  }

  submit(summary, { healthFirst = false } = {}) {
    this.#totals.submitted += 1;
    if (!this.#accepting) return this.recordLocal(summary, "ABORTED_SHUTDOWN", "SKIPPED");

    // Control precedence is rechecked here even when the caller is the hook.
    // This occurs before outbound identity construction or queue admission.
    const controls = this.#inspectControls();
    if (controls.blocked) return this.recordLocal(summary, controls.remoteStatus || "NOT_ATTEMPTED", "SKIPPED");

    // Capacity admission is synchronous. A saturated submission never invokes
    // the outbound builder, credential provider, client, or transport.
    if (this.#active.size >= this.#config.maxInFlight
      && this.#queue.length >= this.#config.maxQueue) {
      this.#totals.droppedSaturated += 1;
      return this.recordLocal(summary, "DROPPED_SATURATED", "NONE");
    }

    let request;
    let body;
    try {
      request = this.#requestBuilder(summary, this.#config);
      body = this.#requestSerializer(request);
    } catch {
      return this.#writeImmediate(summary, "PRIVACY_GUARD_TRIPPED", "SKIPPED");
    }
    const entry = this.#makeEntry({ summary, request, body, healthFirst });
    this.#entries.add(entry);
    this.#totals.admitted += 1;
    if (this.#active.size < this.#config.maxInFlight) this.#start(entry);
    else {
      this.#queue.push(entry);
      this.#assertInvariants();
    }
    return Object.freeze({ request, promise: entry.promise, immediate: false, entryId: entry.id });
  }

  #start(entry) {
    if (entry.cleaned || entry.state !== "QUEUED") return;
    if (!this.#accepting) {
      this.#finishEntry(entry, this.#makeReceipt(entry.request, "ABORTED_SHUTDOWN", "SKIPPED"));
      return;
    }
    const controls = this.#inspectControls();
    if (controls.blocked) {
      this.#finishEntry(entry, this.#makeReceipt(
        entry.request,
        controls.remoteStatus || "NOT_ATTEMPTED",
        "SKIPPED",
      ));
      return;
    }
    entry.permit = true;
    this.#active.add(entry);
    this.#transition(entry, "RUNNING");
    this.#pendingCompletions.add(entry);
    this.#assertInvariants();
    const execution = this.#runEntry(entry);
    entry.execution = execution;
    execution.catch(() => {});
  }

  async #observe(entry) {
    this.#assertRemoteAllowed();
    const response = await this.#credentialProvider(async (credential) => {
      this.#totals.credentialAccesses += 1;
      const beforeAttempt = () => this.#assertRemoteAllowed();
      this.#assertRemoteAllowed();
      if (entry.healthFirst) {
        // Sequential by construction: a failed or hanging health request can
        // never leave a detached sibling decision transport behind.
        await this.#client.health(credential, { beforeAttempt });
        this.#assertRemoteAllowed();
      }
      this.#assertRemoteAllowed();
      return this.#client.decide(entry.body, credential, { beforeAttempt });
    });
    const decision = verifyDecision(response, {
      requestHash: entry.request.request_hash,
      deploymentId: this.#config.deploymentId,
      agentId: entry.request.agent_id,
      toolId: entry.request.tool_id,
    }, { decisionIds: this.#decisionIds });
    this.#lastContactAt = new Date().toISOString();
    return this.#makeReceipt(entry.request, "OK", "NONE", decision);
  }

  async #runEntry(entry) {
    let receipt;
    try {
      receipt = await this.#observe(entry);
    } catch (error) {
      const remoteStatus = statusFrom(error);
      if (error instanceof ResponseValidationError) this.#client.recordFailure();
      receipt = this.#makeReceipt(
        entry.request,
        remoteStatus,
        CONTROL_STATUSES.has(remoteStatus) ? "SKIPPED" : "NONE",
      );
    }
    this.#finishEntry(entry, receipt);
  }

  #finishEntry(entry, receipt) {
    if (entry.cleaned) return receipt;
    if (entry.state === "QUEUED" || entry.state === "RUNNING") this.#transition(entry, "SETTLING");
    let finalReceipt = receipt;
    try { finalReceipt = this.#writeReceipt(receipt); }
    finally { this.#cleanupEntry(entry, finalReceipt); }
    return finalReceipt;
  }

  #cleanupEntry(entry, receipt) {
    if (entry.cleaned) return;
    entry.cleaned = true;
    const queueIndex = this.#queue.indexOf(entry);
    if (queueIndex >= 0) this.#queue.splice(queueIndex, 1);
    if (Buffer.isBuffer(entry.body)) entry.body.fill(0);
    this.#active.delete(entry);
    this.#pendingCompletions.delete(entry);
    entry.permit = false;
    if (entry.state !== "SETTLING") this.#invariantFailure("PIPELINE_CLEANUP_OUTSIDE_SETTLING");
    this.#transition(entry, "DONE");
    this.#entries.delete(entry);
    this.#totals.completed += 1;
    entry.resolve(receipt);
    entry.body = null;
    entry.summary = null;
    entry.request = null;
    entry.execution = null;
    this.#assertInvariants();
    this.#pump();
    this.#refreshShutdownState();
  }

  #refreshShutdownState() {
    if (this.#shutdownState === "OPEN") return;
    const client = this.#client.status?.() || null;
    const clientClean = client === null || (
      client.admission === false
      && client.activeOperations === 0
      && client.activeTransports === 0
      && client.controllers === 0
      && client.timers === 0
      && client.requests === 0
      && client.responses === 0
      && client.sockets === 0
    );
    const clean = this.#active.size === 0
      && this.#queue.length === 0
      && this.#entries.size === 0
      && this.#pendingCompletions.size === 0
      && this.#foregroundTimers.size === 0
      && clientClean;
    if (clean) {
      this.#shutdownState = this.#shutdownDeadlineExceeded
        ? "CLEAN_AFTER_DEADLINE"
        : "CLEAN";
    }
  }

  #pump() {
    if (this.#pumping) return;
    this.#pumping = true;
    try {
      while (this.#accepting && this.#active.size < this.#config.maxInFlight
        && this.#queue.length > 0) {
        const next = this.#queue.shift();
        this.#start(next);
      }
    } finally {
      this.#pumping = false;
      this.#assertInvariants();
    }
  }

  async waitForeground(handle, budgetMs = this.#config.observationBudgetMs) {
    if (budgetMs === 0 || handle.immediate) return undefined;
    let timer = null;
    let release = null;
    const deadline = new Promise((resolve) => {
      release = resolve;
      timer = setTimeout(resolve, budgetMs);
      const waiter = { timer, resolve };
      release.waiter = waiter;
      this.#foregroundTimers.add(waiter);
    });
    try { await Promise.race([handle.promise, deadline]); }
    finally {
      const waiter = release?.waiter;
      if (waiter) this.#foregroundTimers.delete(waiter);
      if (timer !== null) clearTimeout(timer);
    }
    return undefined;
  }

  status() {
    const states = { QUEUED: 0, RUNNING: 0, SETTLING: 0, DONE: 0 };
    for (const entry of this.#entries) states[entry.state] += 1;
    const client = this.#client.status?.() || null;
    return Object.freeze({
      admission: this.#accepting,
      accepting: this.#accepting,
      inFlight: this.#active.size,
      permits: this.#active.size,
      queued: this.#queue.length,
      entries: this.#entries.size,
      activeOperations: this.#active.size,
      pendingCompletions: this.#pendingCompletions.size,
      timers: this.#foregroundTimers.size,
      bodyBytes: [...this.#entries].reduce((total, entry) => total + (entry.body?.length || 0), 0),
      transitionFailures: this.#transitionFailures,
      states: Object.freeze(states),
      peaks: Object.freeze({ ...this.#peaks }),
      totals: Object.freeze({ ...this.#totals }),
      recentTransitions: Object.freeze([...this.#recentTransitions]),
      lastContactAt: this.#lastContactAt,
      lastRemoteStatus: this.#lastRemoteStatus,
      lastShutdownElapsedMs: this.#lastShutdownElapsedMs,
      shutdown: Object.freeze({
        state: this.#shutdownState,
        clean: this.#shutdownState === "CLEAN"
          || this.#shutdownState === "CLEAN_AFTER_DEADLINE",
        deadlineExceeded: this.#shutdownDeadlineExceeded,
      }),
      decisionWindowSize: this.#decisionIds.size,
      client,
    });
  }

  stopAdmission() { this.#accepting = false; }

  shutdown(deadlineMs = 5_000) {
    if (this.#shutdownPromise !== null) return this.#shutdownPromise;
    const started = Date.now();
    const deadline = boundedDeadline(deadlineMs);
    this.#accepting = false;
    this.#shutdownState = "DRAINING";
    for (const waiter of this.#foregroundTimers) {
      clearTimeout(waiter.timer);
      waiter.resolve();
    }
    this.#foregroundTimers.clear();
    while (this.#queue.length > 0) {
      const entry = this.#queue.shift();
      this.#finishEntry(entry, this.#makeReceipt(entry.request, "ABORTED_SHUTDOWN", "SKIPPED"));
    }
    const clientShutdown = Promise.resolve(this.#client.shutdown(deadline));
    clientShutdown.catch(() => {});
    const executions = [...this.#pendingCompletions]
      .map((entry) => entry.execution)
      .filter(Boolean);
    const drained = Promise.allSettled([clientShutdown, ...executions]);
    drained.then(() => this.#refreshShutdownState()).catch(() => {});

    this.#shutdownPromise = (async () => {
      let timer = null;
      const outcome = await Promise.race([
        drained.then(() => "DRAINED"),
        new Promise((resolve) => {
          timer = setTimeout(() => resolve("DEADLINE"), deadline);
        }),
      ]);
      if (timer !== null) clearTimeout(timer);
      if (outcome === "DEADLINE") {
        this.#shutdownDeadlineExceeded = true;
        this.#shutdownState = "NON_CLEAN_DEADLINE";
      }
      this.#decisionIds.clear();
      this.#lastShutdownElapsedMs = Date.now() - started;
      this.#assertInvariants();
      this.#refreshShutdownState();
      return this.status();
    })();
    this.#shutdownPromise.catch(() => {});
    return this.#shutdownPromise;
  }
}

import { correlationRef } from "./runtime/governance-core/index.mjs";
import {
  CONNECTION_TOOL_NAME,
  RECEIPT_MODE,
} from "./constants.mjs";
import { deriveSafeToolSummary } from "./allowlist.mjs";
import { inspectObservationControls } from "./controls.mjs";
import { makeCompletionReceipt } from "./receipts.mjs";
import {
  buildCodeOwnedToolCatalog,
  normalizeOpenClawToolHook,
  resolveHookAttribution,
  resolveRuntimeObservationEligibility,
} from "./hook-adapter.mjs";

function observedOutcome(event) {
  if (event && Object.prototype.hasOwnProperty.call(event, "error") && typeof event.error !== "string") {
    return Object.freeze({ outcome: "FAILED", errorCategory: "TOOL_ERROR" });
  }
  if (typeof event?.error !== "string" || event.error.length === 0) return Object.freeze({ outcome: "COMPLETED", errorCategory: null });
  const exact = event.error.trim().toUpperCase();
  if (exact === "TIMEOUT" || exact === "TIMED_OUT") return Object.freeze({ outcome: "TIMED_OUT", errorCategory: "TOOL_TIMEOUT" });
  return Object.freeze({ outcome: "FAILED", errorCategory: "TOOL_ERROR" });
}

function boundedDeadline(value) {
  return Math.max(1, Math.min(Number.isFinite(value) ? Math.floor(value) : 5_000, 5_000));
}

export class ConnectorHookController {
  #config;
  #pipeline;
  #writer;
  #receiptMode;
  #pending = new Map();
  #completionTasks = new Set();
  #stopped = false;
  #shutdownPromise = null;
  #shutdownState = "OPEN";
  #shutdownDeadlineExceeded = false;
  #controlInspector;
  #summaryBuilder;
  #normalizer;
  #attributionResolver;
  #runtimeEligibilityResolver;
  #runtimeObserver;
  #codeOwnedTools;

  constructor({
    config,
    pipeline,
    receiptWriter,
    receiptMode = RECEIPT_MODE,
    controlInspector = null,
    summaryBuilder = deriveSafeToolSummary,
    normalizer = normalizeOpenClawToolHook,
    attributionResolver = resolveHookAttribution,
    runtimeEligibilityResolver = resolveRuntimeObservationEligibility,
    runtimeObserver = null,
    codeOwnedTools = buildCodeOwnedToolCatalog([]),
  }) {
    if (!["POST_HOOK", "ATTEMPT_ONLY"].includes(receiptMode)) {
      throw new TypeError("invalid_receipt_mode");
    }
    this.#config = config;
    this.#pipeline = pipeline;
    this.#writer = receiptWriter;
    this.#receiptMode = receiptMode;
    this.#controlInspector = controlInspector || (() => inspectObservationControls(config));
    this.#summaryBuilder = summaryBuilder;
    this.#normalizer = normalizer;
    this.#attributionResolver = attributionResolver;
    this.#runtimeEligibilityResolver = runtimeEligibilityResolver;
    this.#runtimeObserver = runtimeObserver;
    this.#codeOwnedTools = codeOwnedTools;
  }

  #summary(normalized, metadata = null) {
    return this.#summaryBuilder({
      toolName: normalized?.toolName || "unknown",
      agentId: normalized?.agentId || this.#config.agentId,
      toolCallId: normalized?.toolCallId || null,
      runId: normalized?.runId || null,
    }, this.#config, metadata);
  }

  #normalize(event, ctx, phase) {
    const normalized = this.#normalizer(event, ctx, phase);
    return normalized?.accepted === true ? normalized : null;
  }

  #attribution(normalized) {
    const attribution = this.#attributionResolver(
      normalized,
      this.#config,
      this.#codeOwnedTools,
    );
    return attribution?.accepted === true ? attribution : null;
  }

  #runtimeEligibility(normalized) {
    const eligibility = this.#runtimeEligibilityResolver(
      normalized,
      this.#config,
      this.#codeOwnedTools,
    );
    return eligibility?.accepted === true ? eligibility : null;
  }

  #remember(handle) {
    const request = handle.request;
    const entry = {
      requestHash: request.request_hash,
      correlationRef: request.correlation_ref,
      deploymentId: this.#config.deploymentId,
      agentId: request.agent_id,
      toolId: request.tool_id,
      decisionId: null,
      attemptPromise: handle.promise,
    };
    const values = this.#pending.get(request.correlation_ref) || [];
    values.push(entry);
    this.#pending.set(request.correlation_ref, values);
    handle.promise.then((receipt) => { entry.decisionId = receipt.decision_id ?? null; }, () => {}).catch(() => {});
    while ([...this.#pending.values()].reduce((sum, queue) => sum + queue.length, 0) > 1024) {
      const firstKey = this.#pending.keys().next().value;
      const queue = this.#pending.get(firstKey);
      queue.shift();
      if (queue.length === 0) this.#pending.delete(firstKey);
    }
  }

  async beforeToolCall(event, ctx) {
    if (this.#stopped) return undefined;

    // The ordinary observation gate is structurally first. Only the permitted
    // local receipt metadata summary is derived after a blocked result; no
      // outbound builder, credential, queue, client, or transport exists
    // on this path.
    const controls = this.#controlInspector();
    if (controls.blocked) {
      // Operationally disabled is INERT: the handler returns here without
      // deriving a summary, writing an ordinary observation receipt, or
      // retaining correlation state. Kill switch and system lock keep their
      // documented behaviour of stopping remote contact while still recording
      // a local receipt.
      if (controls.priority === "DISABLED") return undefined;
      const normalized = this.#normalize(event, ctx, "before_tool_call");
      const summary = this.#summary(normalized);
      const handle = this.#pipeline.recordLocal(summary, controls.remoteStatus || "NOT_ATTEMPTED", "SKIPPED");
      this.#remember(handle);
      return undefined;
    }

    const normalized = this.#normalize(event, ctx, "before_tool_call");
    if (normalized === null) {
      const handle = this.#pipeline.recordLocal(this.#summary(null), "NOT_ATTEMPTED", "SKIPPED");
      this.#remember(handle);
      return undefined;
    }
    // A real hook supplies identity and arguments, never governance metadata.
    // Metadata must resolve from the connector's own registered tool contract
    // or from operator-validated configuration. Missing, conflicting, or
    // schema-invalid attribution stays local and cannot reach the network.
    const attribution = this.#attribution(normalized);
    const summary = this.#summary(normalized, attribution?.metadata ?? null);
    if (attribution === null) {
      const eligibility = this.#runtimeEligibility(normalized);
      if (eligibility !== null
          && this.#runtimeObserver?.before(normalized, eligibility) === true) {
        return undefined;
      }
      const handle = this.#pipeline.recordLocal(summary, "NOT_ATTEMPTED", "SKIPPED");
      this.#remember(handle);
      return undefined;
    }

    const handle = this.#pipeline.submit(summary, { healthFirst: summary.toolId === CONNECTION_TOOL_NAME });
    this.#remember(handle);
    await this.#pipeline.waitForeground(handle, this.#config.observationBudgetMs);

    // The remote observation path always rejoins here. No remote decision or
    // failure can create a hook result, mutate the event, or alter execution.
    return undefined;
  }

  async afterToolCall(event, ctx) {
    if (this.#stopped || this.#receiptMode !== "POST_HOOK") return undefined;
    // Disabling takes effect immediately, including for a call whose pre-hook
    // ran while the connector was still enabled. No completion receipt is
    // written while operationally disabled.
    if (this.#controlInspector().priority === "DISABLED") return undefined;
    const normalized = this.#normalize(event, ctx, "after_tool_call");
    if (normalized === null) return undefined;
    const attribution = this.#attribution(normalized);
    if (attribution === null) {
      const eligibility = this.#runtimeEligibility(normalized);
      this.#runtimeObserver?.after(normalized, eligibility);
      return undefined;
    }
    const summary = this.#summary(normalized, attribution.metadata);
    const ref = correlationRef(summary.rawCorrelation || "");
    const queue = ref ? this.#pending.get(ref) : null;
    const pending = queue?.shift();
    if (queue && queue.length === 0) this.#pending.delete(ref);
    if (!pending) return undefined;
    const observed = observedOutcome(normalized.event);
    const task = pending.attemptPromise.then((attempt) => {
      const receipt = makeCompletionReceipt({
        decisionId: attempt.decision_id ?? pending.decisionId,
        requestHash: pending.requestHash,
        deploymentId: pending.deploymentId,
        agentId: pending.agentId,
        toolId: pending.toolId,
        outcome: observed.outcome,
        correlationRef: pending.correlationRef,
        errorCategory: observed.errorCategory,
      });
      this.#writer.write(receipt);
    });
    this.#completionTasks.add(task);
    task.finally(() => {
      this.#completionTasks.delete(task);
      this.#refreshShutdownState();
    }).catch(() => {});
    return undefined;
  }

  #refreshShutdownState() {
    if (this.#shutdownState === "OPEN") return;
    const pipeline = this.#pipeline.status();
    const runtime = this.#runtimeObserver?.status?.() ?? null;
    const runtimeClean = runtime === null
      || runtime.active === 0 && runtime.queued === 0 && runtime.pendingHooks === 0;
    const clean = pipeline.shutdown?.clean === true
      && runtimeClean
      && this.#pending.size === 0
      && this.#completionTasks.size === 0;
    if (clean) {
      this.#shutdownState = this.#shutdownDeadlineExceeded
        ? "CLEAN_AFTER_DEADLINE"
        : "CLEAN";
    }
  }

  status() {
    return Object.freeze({
      receiptMode: this.#receiptMode,
      stopped: this.#stopped,
      pendingAttempts: [...this.#pending.values()].reduce((sum, queue) => sum + queue.length, 0),
      completionTasks: this.#completionTasks.size,
      pendingCompletions: [...this.#pending.values()].reduce((sum, queue) => sum + queue.length, 0) + this.#completionTasks.size,
      hookCount: [...this.#pending.values()].reduce((sum, queue) => sum + queue.length, 0) + this.#completionTasks.size,
      runtimeObservation: this.#runtimeObserver?.status?.() ?? null,
      shutdown: Object.freeze({
        state: this.#shutdownState,
        clean: this.#shutdownState === "CLEAN"
          || this.#shutdownState === "CLEAN_AFTER_DEADLINE",
        deadlineExceeded: this.#shutdownDeadlineExceeded,
      }),
      pipeline: this.#pipeline.status(),
    });
  }

  shutdown(deadlineMs = 5_000) {
    if (this.#shutdownPromise !== null) return this.#shutdownPromise;
    const started = Date.now();
    const deadline = boundedDeadline(deadlineMs);
    this.#stopped = true;
    this.#shutdownState = "DRAINING";
    this.#shutdownPromise = (async () => {
      await Promise.allSettled([
        this.#runtimeObserver?.shutdown?.(deadline),
        this.#pipeline.shutdown(deadline),
      ]);
      const pendingAttempts = [...this.#pending.values()]
        .flat()
        .map((entry) => entry.attemptPromise);
      const drained = Promise.allSettled([
        ...pendingAttempts,
        ...this.#completionTasks,
      ]).then(() => {
        this.#pending.clear();
        this.#completionTasks.clear();
        this.#refreshShutdownState();
      });
      drained.catch(() => {});
      const remaining = Math.max(0, deadline - (Date.now() - started));
      let timer = null;
      const outcome = await Promise.race([
        drained.then(() => "DRAINED"),
        new Promise((resolve) => {
          timer = setTimeout(() => resolve("DEADLINE"), remaining);
        }),
      ]);
      if (timer !== null) clearTimeout(timer);
      if (outcome === "DEADLINE") {
        this.#shutdownDeadlineExceeded = true;
        this.#shutdownState = "NON_CLEAN_DEADLINE";
      }
      this.#refreshShutdownState();
      return this.status();
    })();
    this.#shutdownPromise.catch(() => {});
    return this.#shutdownPromise;
  }
}

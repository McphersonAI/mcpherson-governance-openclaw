import { correlationRef } from "./runtime/governance-core/index.mjs";
import {
  CONNECTION_TOOL_NAME,
  RECEIPT_MODE,
} from "./constants.mjs";
import { deriveSafeToolSummary } from "./allowlist.mjs";
import { evaluateLocalCanary } from "./canary.mjs";
import { inspectObservationControls } from "./controls.mjs";
import { makeCompletionReceipt } from "./receipts.mjs";

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
  #canaryEvaluator;

  constructor({
    config,
    pipeline,
    receiptWriter,
    receiptMode = RECEIPT_MODE,
    controlInspector = null,
    summaryBuilder = deriveSafeToolSummary,
    canaryEvaluator = evaluateLocalCanary,
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
    this.#canaryEvaluator = canaryEvaluator;
  }

  #summary(event, ctx) {
    const toolName = ctx?.toolName || event?.toolName || "unknown";
    const agentId = ctx?.agentId || this.#config.agentId;
    const toolCallId = ctx?.toolCallId || event?.toolCallId || null;
    const runId = ctx?.runId || event?.runId || null;
    return this.#summaryBuilder({ toolName, agentId, toolCallId, runId }, this.#config);
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
    // canary, outbound builder, credential, queue, client, or transport exists
    // on this path.
    const controls = this.#controlInspector();
    if (controls.blocked) {
      // Operationally disabled is INERT: the handler returns here without
      // deriving a summary, writing an ordinary observation receipt, or
      // retaining correlation state. Kill switch and system lock keep their
      // documented behaviour of stopping remote contact while still recording
      // a local receipt.
      if (controls.priority === "DISABLED") return undefined;
      const summary = this.#summary(event, ctx);
      const handle = this.#pipeline.recordLocal(summary, controls.remoteStatus || "NOT_ATTEMPTED", "SKIPPED");
      this.#remember(handle);
      return undefined;
    }

    const summary = this.#summary(event, ctx);
    const canary = this.#canaryEvaluator(event, ctx, this.#config);
    if (canary.blocked) {
      this.#pipeline.recordLocal(summary, "NOT_ATTEMPTED", "BLOCKED_LOCAL");
      return canary.hookResult;
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
    const summary = this.#summary(event, ctx);
    const ref = correlationRef(summary.rawCorrelation || "");
    const queue = ref ? this.#pending.get(ref) : null;
    const pending = queue?.shift();
    if (queue && queue.length === 0) this.#pending.delete(ref);
    if (!pending) return undefined;
    const observed = observedOutcome(event);
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
    const clean = pipeline.shutdown?.clean === true
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
      await this.#pipeline.shutdown(deadline);
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

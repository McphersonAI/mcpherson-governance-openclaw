import { randomUUID } from "node:crypto";

import { correlationRef, requestHash } from "./runtime/governance-core/index.mjs";
import { ConnectorClientError } from "./client.mjs";
import { canonicalObservationToolId } from "./hook-adapter.mjs";
import { inspectObservationControls } from "./controls.mjs";
import { withCredential } from "./credentials.mjs";
import { makeAttemptReceipt, makeCompletionReceipt } from "./receipts.mjs";
import {
  buildLinkedShadowObservationRequest,
  buildShadowObservationRequest,
  executionCorrelationReference,
  serializeShadowObservationRequest,
} from "./runtime-observation-contract.mjs";

// The supported OpenClaw host can dispatch the SAME logical tool invocation
// twice under one host correlation: either as an exact duplicate (`message` +
// `message`) or as a flattened-alias pair (`openclawmemory_search` +
// `memory_search`). The 2026-08-29/30 live trace proved the previous guard
// treated every such second claim as conflicting runtime identity and barred
// the whole correlation from the remote lane, silently suppressing valid
// capture for every dual-dispatch tool class.
//
// The alias rule is intentionally exact and closed: two names are an alias
// pair only when one is the literal concatenation "openclaw" + the other,
// under the same agent identity, runtime tool kind, and raw host correlation.
// There is no substring, prefix-only, fuzzy, or semantic matching. Anything
// else sharing a correlation remains a genuine identity conflict and fails
// closed exactly as before — now with durable refusal evidence instead of a
// silent counter.
const ALIAS_PREFIX = "openclaw";

function canonicalAliasOf(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a === b) return null;
  if (b.length > 0 && a === ALIAS_PREFIX + b) return b;
  if (a.length > 0 && b === ALIAS_PREFIX + a) return a;
  return null;
}

function observedOutcome(event) {
  // The supported OpenClaw embedded-run host builds the after-hook event as
  // an object literal with `error: isToolError ? <message> : undefined`, so a
  // SUCCESSFUL tool call carries an OWN `error` key whose value is nullish
  // (other host paths spread the key in conditionally, or send null). Key
  // presence is therefore not a failure signal — only a non-nullish value is.
  // The 2026-08-24 live beta proved the old own-key test classified every
  // successful real built-in action FAILED / TOOL_ERROR.
  const error = event?.error;
  if (error === undefined || error === null) return "COMPLETED";
  if (typeof error !== "string") return "FAILED";
  if (error.length === 0) return "COMPLETED";
  const exact = error.trim().toUpperCase();
  return exact === "TIMEOUT" || exact === "TIMED_OUT" ? "TIMED_OUT" : "FAILED";
}

// Exact execution identity needs BOTH host ids; only then can a result carry
// a decision proof (V2). With exactly one id the 0.7.0 behaviour is kept: the
// result is still observed, over the legacy V1 contract, and can never link.
function hostCorrelation(normalized, runtimeInstanceId) {
  const present = (value) => (typeof value === "string" && value.length > 0 ? value : null);
  const runId = present(normalized?.runId);
  const toolCallId = present(normalized?.toolCallId);
  if (runId !== null && toolCallId !== null) {
    return Object.freeze({
      raw: `${runId}\n${toolCallId}`, exact: true,
      ref: executionCorrelationReference({ runtimeInstanceId, runId, toolCallId }),
    });
  }
  const raw = toolCallId ?? runId;
  if (raw === null) return null;
  const ref = correlationRef(raw);
  return typeof ref === "string" ? Object.freeze({ raw, exact: false, ref }) : null;
}

function localRequestHash(entry) {
  return requestHash({
    api_version: "observa-shadow-local/1",
    agent_id: entry.agentId,
    tool_id: entry.toolId,
    runtime_tool_kind: entry.runtimeToolKind,
    correlation_ref: entry.correlationRef,
  });
}

function boundedDeadline(value) {
  return Math.max(1, Math.min(Number.isFinite(value) ? Math.floor(value) : 5_000, 5_000));
}

/**
 * Post-hook-only remote observer for runtime identities that have no semantic
 * toolMetadata. It has no hook-result API and therefore cannot block, approve,
 * alter, retry, or execute the observed tool.
 */
export class RuntimeShadowObserver {
  #config;
  #client;
  #writer;
  #credentialProvider;
  #controlInspector;
  #runtimeInstanceId;
  #pending = new Map();
  // One record per host correlation this process has accepted a claim for:
  // { agentId, runtimeToolKind, names:Set, poisoned }. Used to keep completed
  // correlations single-use while still recognizing a benign late duplicate
  // or supported-alias re-dispatch of the identity that already delivered.
  #seen = new Map();
  #seenOrder = [];
  #active = new Set();
  #queue = [];
  #accepting = true;
  #shutdownPromise = null;
  #totals = {
    attempts: 0,
    completions: 0,
    submitted: 0,
    observed: 0,
    ambiguous: 0,
    aliasCanonicalized: 0,
    duplicateClaims: 0,
    dropped: 0,
  };

  constructor({
    config,
    client,
    receiptWriter,
    runtimeInstanceId,
    credentialProvider = null,
    controlInspector = null,
  }) {
    this.#config = config;
    this.#client = client;
    this.#writer = receiptWriter;
    this.#runtimeInstanceId = runtimeInstanceId;
    this.#credentialProvider = credentialProvider
      || ((callback) => withCredential(config.stateDir, callback));
    this.#controlInspector = controlInspector || (() => inspectObservationControls(config));
  }

  #controlsAllowRemote() {
    const controls = this.#controlInspector();
    return controls && controls.blocked === false;
  }

  #writeAttempt(entry, localDisposition) {
    this.#writer.write(makeAttemptReceipt({
      decisionId: null,
      requestHash: entry.requestHash,
      deploymentId: this.#config.deploymentId,
      agentId: entry.agentId,
      toolId: entry.toolId,
      outcome: "NOT_OBSERVED",
      remoteStatus: "NOT_ATTEMPTED",
      localDisposition,
      correlationRef: entry.correlationRef,
    }));
  }

  // Durable AMBIGUOUS_FAIL_CLOSED evidence. BLOCKED_LOCAL is the canonical
  // receipt vocabulary for "this connector locally barred the claim from the
  // remote lane"; the runtime observer writes it for exactly one reason —
  // genuine correlation-identity ambiguity — so a BLOCKED_LOCAL attempt
  // receipt from this observer IS the ambiguity refusal record. No secret,
  // parameter, result, or message content is ever carried by these receipts.
  #refuse(entry) {
    entry.ambiguous = true;
    this.#writeAttempt(entry, "BLOCKED_LOCAL");
  }

  #poisonGroup(group, record) {
    if (record) record.poisoned = true;
    for (const prior of group) {
      if (!prior.ambiguous) this.#refuse(prior);
    }
  }

  #writeCompletion(entry, outcome) {
    this.#writer.write(makeCompletionReceipt({
      decisionId: null,
      requestHash: entry.requestHash,
      deploymentId: this.#config.deploymentId,
      agentId: entry.agentId,
      toolId: entry.toolId,
      outcome,
      correlationRef: entry.correlationRef,
      errorCategory: outcome === "TIMED_OUT" ? "TOOL_TIMEOUT"
        : outcome === "FAILED" ? "TOOL_ERROR" : null,
    }));
    this.#totals.completions += 1;
  }

  #entryFor(normalized, eligibility, corr) {
    const entry = {
      id: randomUUID(),
      agentId: normalized.agentId,
      toolId: eligibility.toolId,
      runtimeToolKind: eligibility.runtimeToolKind,
      runId: normalized.runId,
      toolCallId: normalized.toolCallId,
      exact: corr.exact,
      rawCorrelation: corr.raw,
      correlationRef: corr.ref,
      requestHash: null,
      ambiguous: false,
      claimedNames: new Set([normalized.toolName]),
      duplicateClaims: 0,
    };
    entry.requestHash = localRequestHash(entry);
    return entry;
  }

  before(normalized, eligibility) {
    if (!this.#accepting || !eligibility?.accepted || !this.#controlsAllowRemote()) return false;
    // Without a host call/run identity there is no safe before/after binding
    // and no way to distinguish two same-name executions. Keep that local-only.
    const corr = hostCorrelation(normalized, this.#runtimeInstanceId);
    if (corr === null) return false;
    const { raw, ref } = corr;
    const group = this.#pending.get(ref) || [];
    if (group.length === 0) {
      const record = this.#seen.get(ref);
      if (record !== undefined) {
        // A completed host correlation is single-use for this connector
        // process. A late exact-duplicate or supported-alias re-dispatch of
        // the identity that already delivered is benign idempotent repetition
        // and cannot produce a second remote observation. Anything else is a
        // conflicting reuse and fails closed with durable evidence. The
        // server independently enforces the same single-use rule per
        // credential, so a restart cannot turn reuse into double counting.
        const sameIdentity = record.agentId === normalized.agentId
          && record.runtimeToolKind === eligibility.runtimeToolKind;
        const knownName = record.names.has(normalized.toolName)
          || [...record.names].some(
            (name) => canonicalAliasOf(name, normalized.toolName) !== null,
          );
        if (!record.poisoned && sameIdentity && knownName) {
          record.names.add(normalized.toolName);
          this.#totals.duplicateClaims += 1;
          return true;
        }
        record.poisoned = true;
        this.#totals.ambiguous += 1;
        this.#refuse(this.#entryFor(normalized, eligibility, corr));
        return false;
      }
      this.#seen.set(ref, {
        agentId: normalized.agentId,
        runtimeToolKind: eligibility.runtimeToolKind,
        names: new Set([normalized.toolName]),
        poisoned: false,
      });
      this.#seenOrder.push(ref);
      while (this.#seenOrder.length > 4096) {
        this.#seen.delete(this.#seenOrder.shift());
      }
      const entry = this.#entryFor(normalized, eligibility, corr);
      this.#pending.set(ref, [entry]);
      this.#writeAttempt(entry, "NONE");
      this.#totals.attempts += 1;
      return true;
    }
    const record = this.#seen.get(ref);
    if (group.length === 1 && !group[0].ambiguous) {
      const entry = group[0];
      const sameIdentity = entry.agentId === normalized.agentId
        && entry.runtimeToolKind === eligibility.runtimeToolKind
        && entry.rawCorrelation === raw;
      if (sameIdentity && entry.claimedNames.has(normalized.toolName)) {
        // Exact duplicate dispatch of one logical invocation: idempotent.
        // No new logical record, no second attempt receipt, no poisoning.
        entry.duplicateClaims += 1;
        this.#totals.duplicateClaims += 1;
        record?.names.add(normalized.toolName);
        return true;
      }
      if (sameIdentity && entry.claimedNames.size === 1) {
        // Compare HOST names: entry.toolId is already the canonical governed
        // identity (exec -> openclaw:exec) and is not itself a host name.
        const [firstName] = entry.claimedNames;
        const alias = canonicalAliasOf(firstName, normalized.toolName);
        const canonical = alias === null ? null : canonicalObservationToolId(alias);
        if (canonical !== null) {
          // Supported exact alias pair — exactly two claims, literal
          // "openclaw" + canonical relationship, all protected identity
          // fields equal. Collapse to ONE logical invocation under the
          // canonical (unprefixed) tool identity, regardless of which form
          // arrived first.
          entry.claimedNames.add(normalized.toolName);
          record?.names.add(normalized.toolName);
          if (entry.toolId !== canonical) {
            entry.toolId = canonical;
            entry.requestHash = localRequestHash(entry);
            this.#writeAttempt(entry, "NONE");
            this.#totals.attempts += 1;
          }
          this.#totals.aliasCanonicalized += 1;
          return true;
        }
      }
    }
    // Genuine identity conflict: non-equivalent claims share one host
    // correlation. Every member of the group fails closed away from the
    // remote lane, and each refused claim leaves a durable BLOCKED_LOCAL
    // attempt receipt so the refusal is never silent.
    this.#poisonGroup(group, record);
    const entry = this.#entryFor(normalized, eligibility, corr);
    this.#refuse(entry);
    group.push(entry);
    this.#pending.set(ref, group);
    record?.names.add(normalized.toolName);
    this.#totals.attempts += 1;
    this.#totals.ambiguous += 1;
    return true;
  }

  after(normalized, eligibility, decisionLinkage = null) {
    if (!eligibility?.accepted) return false;
    const corr = hostCorrelation(normalized, this.#runtimeInstanceId);
    if (corr === null) return false;
    const { ref } = corr;
    const pending = this.#pending.get(ref);
    if (!pending || pending.length === 0) return false;
    const index = pending.findIndex((entry) => (
      entry.agentId === normalized.agentId
      && entry.runtimeToolKind === eligibility.runtimeToolKind
      && (entry.toolId === normalized.toolName
        || entry.claimedNames.has(normalized.toolName))
    ));
    if (index < 0) {
      const record = this.#seen.get(ref);
      if (record !== undefined
          && record.agentId === normalized.agentId
          && record.runtimeToolKind === eligibility.runtimeToolKind
          && record.names.has(normalized.toolName)) {
        // Second post-hook for a claim of this correlation that already
        // reached its terminal disposition: benign duplicate completion.
        return false;
      }
      this.#poisonGroup(pending, record);
      this.#totals.ambiguous += 1;
      return false;
    }
    const [entry] = pending.splice(index, 1);
    if (pending.length === 0) this.#pending.delete(ref);
    const record = this.#seen.get(ref);
    if (record !== undefined) {
      for (const name of entry.claimedNames) record.names.add(name);
      record.names.add(entry.toolId);
      if (entry.ambiguous) record.poisoned = true;
    }
    const outcome = observedOutcome(normalized.event);
    if (entry.ambiguous || !this.#accepting || !this.#controlsAllowRemote()) {
      this.#writeCompletion(entry, outcome);
      return true;
    }
    const exactLink = entry.exact && decisionLinkage
      && decisionLinkage.runtimeInstanceId === this.#runtimeInstanceId
      && decisionLinkage.runId === entry.runId
      && decisionLinkage.toolCallId === entry.toolCallId
      && decisionLinkage.agentId === entry.agentId
      && decisionLinkage.toolId === entry.toolId
      && decisionLinkage.correlationRef === entry.correlationRef
      ? decisionLinkage : null;
    const job = { entry, outcome, decisionLinkage: exactLink, body: null, promise: null };
    this.#totals.submitted += 1;
    if (this.#active.size < this.#config.maxInFlight) this.#start(job);
    else if (this.#queue.length < this.#config.maxQueue) this.#queue.push(job);
    else {
      this.#totals.dropped += 1;
      this.#writeCompletion(entry, outcome);
    }
    return true;
  }

  #start(job) {
    if (!this.#accepting || !this.#controlsAllowRemote()) {
      this.#writeCompletion(job.entry, job.outcome);
      return;
    }
    this.#active.add(job);
    job.promise = this.#run(job).finally(() => {
      if (job.body) job.body.fill(0);
      job.body = null;
      this.#active.delete(job);
      this.#writeCompletion(job.entry, job.outcome);
      this.#pump();
    });
    job.promise.catch(() => {});
  }

  async #run(job) {
    let request;
    try {
      request = job.entry.exact
        ? buildLinkedShadowObservationRequest({
          agentId: job.entry.agentId,
          toolId: job.entry.toolId,
          runtimeToolKind: job.entry.runtimeToolKind,
          runtimeInstanceId: this.#runtimeInstanceId,
          runId: job.entry.runId,
          toolCallId: job.entry.toolCallId,
          decisionId: job.decisionLinkage?.decisionId ?? null,
          decisionRequestHash: job.decisionLinkage?.decisionRequestHash ?? null,
          toolOutcome: job.outcome,
        })
        : buildShadowObservationRequest({
          agentId: job.entry.agentId,
          toolId: job.entry.toolId,
          runtimeToolKind: job.entry.runtimeToolKind,
          rawCorrelation: job.entry.rawCorrelation,
          toolOutcome: job.outcome,
        });
      job.body = serializeShadowObservationRequest(request);
    } catch {
      return Object.freeze({ remoteStatus: "PRIVACY_GUARD_TRIPPED" });
    }
    try {
      const ack = await this.#credentialProvider(async (credential) => {
        const beforeAttempt = () => {
          if (!this.#accepting || !this.#controlsAllowRemote()) {
            throw new ConnectorClientError("NOT_ATTEMPTED");
          }
        };
        return this.#client.observeShadow(job.body, credential, {
          beforeAttempt,
          expectedRequestHash: request.request_hash,
        });
      });
      this.#totals.observed += 1;
      return Object.freeze({
        remoteStatus: "OK",
        observationId: ack.observation_id,
      });
    } catch (error) {
      return Object.freeze({
        remoteStatus: error?.remoteStatus ?? error?.code ?? "NOT_ATTEMPTED",
      });
    }
  }

  #pump() {
    while (this.#accepting && this.#active.size < this.#config.maxInFlight
        && this.#queue.length > 0) this.#start(this.#queue.shift());
  }

  status() {
    return Object.freeze({
      mode: "SHADOW_METADATA_ONLY",
      accepting: this.#accepting,
      pendingHooks: [...this.#pending.values()].reduce((sum, list) => sum + list.length, 0),
      active: this.#active.size,
      queued: this.#queue.length,
      totals: Object.freeze({ ...this.#totals }),
      ambiguity: Object.freeze({
        disposition: "AMBIGUOUS_FAIL_CLOSED",
        receiptDisposition: "BLOCKED_LOCAL",
        refusals: this.#totals.ambiguous,
      }),
      authority: "NONE",
      enforcement: "OFF",
      automaticMappingActivation: false,
    });
  }

  shutdown(deadlineMs = 5_000) {
    if (this.#shutdownPromise !== null) return this.#shutdownPromise;
    this.#accepting = false;
    // A pre-hook without a delivered post-hook has no truthful terminal
    // outcome. Preserve its attempt receipt and do not fabricate completion.
    this.#pending.clear();
    while (this.#queue.length > 0) {
      const job = this.#queue.shift();
      this.#writeCompletion(job.entry, job.outcome);
    }
    const active = [...this.#active].map((job) => job.promise).filter(Boolean);
    const deadline = boundedDeadline(deadlineMs);
    this.#shutdownPromise = (async () => {
      let timer = null;
      await Promise.race([
        Promise.allSettled(active),
        new Promise((resolvePromise) => {
          timer = setTimeout(resolvePromise, deadline);
        }),
      ]);
      if (timer !== null) clearTimeout(timer);
      return this.status();
    })();
    this.#shutdownPromise.catch(() => {});
    return this.#shutdownPromise;
  }
}

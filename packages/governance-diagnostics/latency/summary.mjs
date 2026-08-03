// Deterministic latency summaries over recorded or imported latency events.
//
// Percentiles use the documented nearest-rank method: for quantile q over n
// ascending samples, the value at index ceil(q/100 * n) - 1. Tail
// percentiles (p95, p99) are only reported when the sample count reaches the
// documented floor; below it they are marked insufficient instead of
// inventing precision. Summaries separate local and remote paths, cache
// states, success/timeout/unavailable statuses, explicit FIXTURE or
// LIVE_SHADOW provenance, and each duration metric (governance phases and
// tool execution are never merged). No summary is an SLA; fixture latency is
// never a production benchmark, and live receipt pairs measure tool execution
// only, not complete governance overhead.

import {
  ALLOWED_DURATION_KEYS,
  LATENCY_EVENT_SCHEMA,
  RECORDER_MEASUREMENT_KINDS,
  SUPPORTED_LATENCY_INSTRUMENTATION_VERSIONS,
} from "./recorder.mjs";
import { validateArtifact, validateEnvelope } from "../contracts.mjs";
import { sensitiveValueReason } from "../sensitive-values.mjs";
import { canonicalizeJson } from "../../governance-core/canonical.mjs";
import {
  LIVE_OUTPUT_FILES,
  readVerifiedOpenClawLiveArtifact,
} from "../../openclaw-live-observer/index.mjs";

export const LATENCY_SUMMARY_SCHEMA = "mcpherson-governance-latency-summary/v1";
export const LIVE_LATENCY_SUMMARY_SCHEMA =
  "mcpherson-governance-live-latency-summary/v1";
export const LATENCY_EVENT_SET_SCHEMA =
  "mcpherson-governance-latency-event-set/v1";
export const LIVE_LATENCY_EVENT_SCHEMA =
  "mcpherson-governance-live-latency-event/v1";
export const LIVE_LATENCY_EVENT_SET_SCHEMA =
  "mcpherson-governance-live-latency-event-set/v1";
export const LIVE_LATENCY_INSTRUMENTATION_VERSIONS = Object.freeze([
  "0.6-live.2",
]);

// Identifier tags carry free-form values; the enum tags cannot. Imported
// events are held to the same semantic sensitive-value policy the recorder
// applies to these keys at record time.
const SCREENED_IDENTIFIER_TAGS = Object.freeze([
  "agent_id", "capability_id", "normalized_capability",
]);

/**
 * Return a deterministic `key:reason` string when any identifier tag value
 * trips the semantic sensitive-value policy, or null when all are acceptable.
 * Recorded events already pass this screen; imported events are screened here
 * so recorded and imported events are held to one privacy contract.
 */
export function latencyTagSensitiveReason(tags) {
  if (!tags || typeof tags !== "object") return null;
  for (const key of SCREENED_IDENTIFIER_TAGS) {
    const value = tags[key];
    if (typeof value === "string") {
      const reason = sensitiveValueReason(value);
      if (reason !== null) return `${key}:${reason}`;
    }
  }
  return null;
}
export const MIN_SAMPLES_FOR_TAIL_PERCENTILES = 20;
export const EMPTY_SUMMARY_CAVEAT =
  "No usable latency events were supplied; this summary is empty by contract "
  + "and supports no timing claim of any kind.";
export const FIXTURE_CAVEAT =
  "This summary accepts only FIXTURE inputs from deterministic local test "
  + "harnesses. Its inputs are not production measurements, not a benchmark, "
  + "not an SLA, and support no claim about live overhead. A real live "
  + "baseline still requires a separately approved shadow test.";
export const LIVE_SHADOW_CAVEAT =
  "This LIVE_SHADOW summary contains local tool-execution durations paired "
  + "from connector attempt and supported post-hook completion receipts. It "
  + "does not measure total governance overhead, is not an SLA, and does not "
  + "establish safety, coverage completeness, or enforcement.";

function invalidSummary(reason, detail = null) {
  return Object.freeze({
    ok: false,
    reason,
    ...(detail === null ? {} : { detail }),
  });
}

/**
 * Validate the composition of an ordered event sequence. The caller must
 * supply its measurement context explicitly; omission never defaults to
 * FIXTURE. Per-event schemas can reject duplicate/reordered sequence
 * identifiers and mixed supported versions. Because v0.6 event files are
 * unsigned local artifacts, coherent payload copies with freshly renumbered
 * sequence values remain indistinguishable from distinct fixture
 * observations; this validator does not claim source authentication or
 * observation uniqueness.
 */
export function validateLatencyEventSequence(
  events, options,
) {
  if (!Array.isArray(events)) {
    return invalidSummary("latency_events_invalid");
  }
  if (options === null
      || typeof options !== "object"
      || Array.isArray(options)
      || !Object.prototype.hasOwnProperty.call(options, "measurementKind")
      || options.measurementKind === undefined
      || options.measurementKind === null) {
    return invalidSummary("latency_measurement_kind_required");
  }
  const { measurementKind } = options;
  const live = measurementKind === "LIVE_SHADOW";
  if (!live && !RECORDER_MEASUREMENT_KINDS.includes(measurementKind)) {
    return invalidSummary("latency_measurement_kind_not_accepted_in_v0_6");
  }
  if (live) {
    if (typeof options.observationDirectory !== "string") {
      return invalidSummary("live_observation_directory_required");
    }
    const verified = readVerifiedOpenClawLiveArtifact({
      outDir: options.observationDirectory,
      filename: LIVE_OUTPUT_FILES.latency,
      packageManifestPath: options.packageManifestPath,
      profileBindingPath: options.profileBindingPath,
      profileBindingId: options.profileBindingId,
    });
    if (canonicalizeJson(events) !== canonicalizeJson(verified.value.events)) {
      return invalidSummary("live_latency_observation_binding_mismatch");
    }
  }
  const eventSchema = live ? LIVE_LATENCY_EVENT_SCHEMA : LATENCY_EVENT_SCHEMA;
  const supportedVersions = live
    ? LIVE_LATENCY_INSTRUMENTATION_VERSIONS
    : SUPPORTED_LATENCY_INSTRUMENTATION_VERSIONS;
  let instrumentationVersion = null;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    const contract = validateArtifact(eventSchema, event);
    if (!contract.ok) {
      return invalidSummary("latency_event_invalid", contract.errors);
    }
    if (event.measurement_kind !== measurementKind) {
      return invalidSummary("latency_event_measurement_context_mismatch");
    }
    if (!supportedVersions.includes(
      event.instrumentation_version,
    )) {
      return invalidSummary("latency_event_instrumentation_version_unsupported");
    }
    if (instrumentationVersion === null) {
      instrumentationVersion = event.instrumentation_version;
    } else if (event.instrumentation_version !== instrumentationVersion) {
      return invalidSummary("latency_event_instrumentation_context_mismatch");
    }
    // Recorder-produced sets are canonical streams: one member per sequence
    // position, ordered and contiguous from 1. This rejects duplicate or
    // reordered identifiers, but cannot authenticate coherently renumbered
    // copies in an unsigned imported fixture.
    if (event.sequence !== index + 1) {
      return invalidSummary("latency_event_sequence_not_canonical");
    }
    const sensitive = latencyTagSensitiveReason(event.tags);
    if (sensitive !== null) {
      return invalidSummary(
        "latency_event_sensitive_value", sensitive,
      );
    }
  }
  return Object.freeze({
    ok: true,
    measurement_kind: measurementKind,
    instrumentation_version: instrumentationVersion,
  });
}

/** Validate an event-set envelope and its cross-member semantics. */
export function validateLatencyEventSet(eventSet, {
  observationDirectory = null,
  packageManifestPath = null,
  profileBindingPath = null,
  profileBindingId = null,
} = {}) {
  const schema = eventSet?.schema === LIVE_LATENCY_EVENT_SET_SCHEMA
    ? LIVE_LATENCY_EVENT_SET_SCHEMA
    : eventSet?.schema === LATENCY_EVENT_SET_SCHEMA
      ? LATENCY_EVENT_SET_SCHEMA
      : null;
  if (schema === null) {
    return invalidSummary("latency_event_set_schema_invalid");
  }
  const contract = validateEnvelope(schema, eventSet);
  if (!contract.ok) {
    return invalidSummary("latency_event_set_contract_invalid", contract.errors);
  }
  return validateLatencyEventSequence(eventSet.events, {
    measurementKind: eventSet.measurement_kind,
    observationDirectory,
    packageManifestPath,
    profileBindingPath,
    profileBindingId,
  });
}

function insufficientTailNote(sampleCount) {
  return `p95 and p99 withheld: ${sampleCount} sample(s) is below the `
    + `documented floor of ${MIN_SAMPLES_FOR_TAIL_PERCENTILES}`;
}

/** Nearest-rank percentile over an ascending-sorted array. */
export function nearestRankPercentile(sortedValues, quantile) {
  if (!Array.isArray(sortedValues) || sortedValues.length === 0) return null;
  if (typeof quantile !== "number" || quantile <= 0 || quantile > 100) {
    return null;
  }
  const rank = Math.ceil((quantile / 100) * sortedValues.length);
  return sortedValues[rank - 1];
}

function remoteStatusClass(status) {
  if (status === "OK") return "OK";
  if (status === "TIMEOUT") return "TIMEOUT";
  if (status === "NOT_ATTEMPTED" || status === "UNKNOWN") return status;
  return "UNAVAILABLE";
}

function groupKey(event, metric) {
  return [
    event.measurement_kind,
    event.tags.path_kind,
    event.tags.cache_state,
    remoteStatusClass(event.tags.remote_status),
    metric,
  ].join("|");
}

function summaryGroupKey(group) {
  return [
    group.measurement_kind,
    group.path_kind,
    group.cache_state,
    group.remote_status_class,
    group.metric,
  ].join("|");
}

/**
 * Validate a latency summary at a direct consumer boundary. JSON Schema
 * establishes shape; this function establishes cross-field facts that remain
 * forgeable in a shape-valid document.
 */
export function validateLatencySummary(summary) {
  const schema = summary?.schema === LIVE_LATENCY_SUMMARY_SCHEMA
    ? LIVE_LATENCY_SUMMARY_SCHEMA
    : summary?.schema === LATENCY_SUMMARY_SCHEMA
      ? LATENCY_SUMMARY_SCHEMA
      : null;
  if (schema === null) {
    return invalidSummary("latency_summary_schema_invalid");
  }
  const contract = validateArtifact(schema, summary);
  if (!contract.ok) {
    return invalidSummary("latency_summary_contract_invalid", contract.errors);
  }
  if (summary.events_skipped > summary.events_considered) {
    return invalidSummary("latency_summary_event_counts_inconsistent");
  }

  const usableEvents = summary.events_considered - summary.events_skipped;
  const hasGroups = summary.groups.length > 0;
  // The declared FIXTURE context remains a summary fact even when the event
  // sequence is empty or every schema-valid event has no usable duration.
  const expectedKind = schema === LIVE_LATENCY_SUMMARY_SCHEMA
    ? "LIVE_SHADOW"
    : "FIXTURE";
  const expectedKinds = [expectedKind];
  const provenanceCaveat = expectedKind === "LIVE_SHADOW"
    ? LIVE_SHADOW_CAVEAT
    : FIXTURE_CAVEAT;
  const expectedCaveats = hasGroups
    ? [provenanceCaveat]
    : [EMPTY_SUMMARY_CAVEAT, provenanceCaveat];
  if (JSON.stringify(summary.measurement_kinds)
        !== JSON.stringify(expectedKinds)
      || JSON.stringify(summary.caveats) !== JSON.stringify(expectedCaveats)) {
    return invalidSummary("latency_summary_provenance_inconsistent");
  }
  if ((hasGroups && usableEvents === 0)
      || (!hasGroups && usableEvents !== 0)) {
    return invalidSummary("latency_summary_event_partition_inconsistent");
  }

  const groupKeys = new Set();
  const samplesByMetric = new Map();
  let previousKey = null;
  let totalSamples = 0;
  for (const group of summary.groups) {
    const key = summaryGroupKey(group);
    if (groupKeys.has(key)) {
      return invalidSummary("latency_summary_duplicate_group");
    }
    if (previousKey !== null && key <= previousKey) {
      return invalidSummary("latency_summary_groups_not_normalized");
    }
    groupKeys.add(key);
    previousKey = key;

    if (group.sample_count > usableEvents) {
      return invalidSummary("latency_summary_group_sample_count_inconsistent");
    }
    totalSamples += group.sample_count;
    samplesByMetric.set(
      group.metric,
      (samplesByMetric.get(group.metric) ?? 0) + group.sample_count,
    );

    if (!(group.min_ms <= group.p50_ms
        && group.p50_ms <= group.max_ms)) {
      return invalidSummary("latency_summary_percentile_order_invalid");
    }
    const tailsExpected = group.sample_count
      >= MIN_SAMPLES_FOR_TAIL_PERCENTILES;
    if (group.tail_percentiles_sufficient !== tailsExpected) {
      return invalidSummary("latency_summary_tail_state_inconsistent");
    }
    if (tailsExpected) {
      if (group.p95_ms === null
          || group.p99_ms === null
          || group.tail_note !== null) {
        return invalidSummary("latency_summary_tail_state_inconsistent");
      }
      if (!(group.p50_ms <= group.p95_ms
          && group.p95_ms <= group.p99_ms
          && group.p99_ms <= group.max_ms)) {
        return invalidSummary("latency_summary_percentile_order_invalid");
      }
    } else {
      if (group.p95_ms !== null || group.p99_ms !== null) {
        return invalidSummary("latency_summary_tail_state_inconsistent");
      }
      if (group.tail_note !== insufficientTailNote(group.sample_count)) {
        return invalidSummary("latency_summary_tail_note_inconsistent");
      }
    }
  }

  for (const samples of samplesByMetric.values()) {
    if (samples > usableEvents) {
      return invalidSummary("latency_summary_metric_partition_inconsistent");
    }
  }
  if (hasGroups && totalSamples < usableEvents) {
    return invalidSummary("latency_summary_event_partition_inconsistent");
  }
  return Object.freeze({ ok: true });
}

/**
 * Summarize latency events. Returns one summary group per distinct
 * (measurement kind, path, cache state, status class, metric) combination —
 * nothing is ever averaged across those boundaries.
 *
 * Every event is validated fail-closed against the shared latency-event
 * contract before it can contribute to a group, and identifier tag values are
 * screened by the semantic sensitive-value policy. A schema-invalid event
 * (for example an out-of-enum path_kind, a non-FIXTURE measurement kind, a
 * calendar-invalid ts, or an out-of-range duration) or an event whose tag
 * value trips the privacy policy is rejected — never summarized into a group
 * that would then fail the summary's own contract. The produced summary is
 * validated against its own contract before it is returned. `measurementKind`
 * is required even for an empty sequence; the direct API never manufactures
 * FIXTURE provenance from omission.
 */
export function summarizeLatency(events, options) {
  let liveVerification = null;
  if (options?.measurementKind === "LIVE_SHADOW") {
    if (typeof options.observationDirectory !== "string") {
      const error = new TypeError("live_observation_directory_required");
      error.code = "live_observation_directory_required";
      throw error;
    }
    const verified = readVerifiedOpenClawLiveArtifact({
      outDir: options.observationDirectory,
      filename: LIVE_OUTPUT_FILES.latency,
      packageManifestPath: options.packageManifestPath,
      profileBindingPath: options.profileBindingPath,
      profileBindingId: options.profileBindingId,
    });
    liveVerification = verified.verification;
    if (canonicalizeJson(events) !== canonicalizeJson(verified.value.events)) {
      const error = new TypeError("live_latency_observation_binding_mismatch");
      error.code = "live_latency_observation_binding_mismatch";
      throw error;
    }
  }
  const eventSetValidation = validateLatencyEventSequence(events, options);
  if (!eventSetValidation.ok) {
    const error = new TypeError(eventSetValidation.reason);
    error.code = eventSetValidation.reason;
    if (eventSetValidation.detail !== undefined) {
      error.detail = eventSetValidation.detail;
    }
    throw error;
  }
  const measurementKind = eventSetValidation.measurement_kind;
  const buckets = new Map();
  let skipped = 0;
  for (const event of events) {
    let contributed = false;
    for (const metric of ALLOWED_DURATION_KEYS) {
      const value = event.durations_ms[metric];
      if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
        continue;
      }
      contributed = true;
      const key = groupKey(event, metric);
      if (!buckets.has(key)) {
        buckets.set(key, {
          measurement_kind: event.measurement_kind,
          path_kind: event.tags.path_kind,
          cache_state: event.tags.cache_state,
          remote_status_class: remoteStatusClass(event.tags.remote_status),
          metric,
          values: [],
        });
      }
      buckets.get(key).values.push(value);
    }
    // A schema-valid event with no usable duration metric is counted, not
    // silently ignored: it is honestly reported in events_skipped.
    if (!contributed) skipped += 1;
  }
  const groups = [...buckets.entries()]
    .sort(([left], [right]) => (left < right ? -1 : 1))
    .map(([, bucket]) => {
      const sorted = [...bucket.values].sort((a, b) => a - b);
      const count = sorted.length;
      const tailSufficient = count >= MIN_SAMPLES_FOR_TAIL_PERCENTILES;
      return Object.freeze({
        measurement_kind: bucket.measurement_kind,
        path_kind: bucket.path_kind,
        cache_state: bucket.cache_state,
        remote_status_class: bucket.remote_status_class,
        metric: bucket.metric,
        sample_count: count,
        min_ms: sorted[0],
        p50_ms: nearestRankPercentile(sorted, 50),
        p95_ms: tailSufficient ? nearestRankPercentile(sorted, 95) : null,
        p99_ms: tailSufficient ? nearestRankPercentile(sorted, 99) : null,
        max_ms: sorted[count - 1],
        tail_percentiles_sufficient: tailSufficient,
        tail_note: tailSufficient
          ? null
          : insufficientTailNote(count),
      });
    });
  // The validated envelope context is retained independently of member
  // presence. This prevents an empty FIXTURE event set from becoming an
  // unprovenanced summary.
  const kinds = [measurementKind];
  const caveats = groups.length === 0
    ? [
      EMPTY_SUMMARY_CAVEAT,
      measurementKind === "LIVE_SHADOW" ? LIVE_SHADOW_CAVEAT : FIXTURE_CAVEAT,
    ]
    : [
      measurementKind === "LIVE_SHADOW" ? LIVE_SHADOW_CAVEAT : FIXTURE_CAVEAT,
    ];
  const summary = Object.freeze({
    schema: measurementKind === "LIVE_SHADOW"
      ? LIVE_LATENCY_SUMMARY_SCHEMA
      : LATENCY_SUMMARY_SCHEMA,
    percentile_method: "nearest_rank",
    tail_percentile_floor: MIN_SAMPLES_FOR_TAIL_PERCENTILES,
    measurement_kinds: kinds,
    ...(measurementKind === "LIVE_SHADOW" ? {
      observation_id: liveVerification.observation_id,
      source_id: liveVerification.source_id,
      authority: "NONE",
      enforcement: false,
      automatic_mapping_activation: false,
      outbound_actions: false,
    } : {}),
    events_considered: events.length,
    events_skipped: skipped,
    groups,
    caveats,
  });
  // Producer output guard: schema and semantic invariants are both validated
  // before a summary leaves this function.
  const validation = validateLatencySummary(summary);
  if (!validation.ok) {
    const error = new TypeError(validation.reason);
    error.code = validation.reason;
    if (validation.detail !== undefined) error.detail = validation.detail;
    throw error;
  }
  return summary;
}

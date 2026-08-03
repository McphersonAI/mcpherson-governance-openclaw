// Offline, prototype-only governance-path latency instrumentation.
//
// Scope (Sol repair): this recorder is NOT integrated into the live
// governance runtime. It is an offline prototype validated with
// deterministic fixtures and fake clocks. Its inertness claim is exactly
// this: for supported result types (synchronous values, thrown errors, and
// native promises) under the tested fixture conditions, the wrapped
// operation's return value or error passes through with identity preserved,
// and recorder failures are counted and swallowed. Custom thenables are an
// unsupported result type: they are returned untouched as synchronous
// values and never introspected. Integration with a real recorder,
// serializer, and sink is a separate, later approved phase.
//
// Durations use a monotonic high-resolution clock (integer nanoseconds
// internally, explicit millisecond conversion at serialization). Wall-clock
// UTC timestamps are chronology only and are calendar-validated (an
// impossible date is nulled, never recorded as an invalid value). Event
// metadata is
// strictly validated: enum tags admit only their enum values, identifier
// tags are wire-safe and pass the semantic sensitive-value policy, and
// durations must be finite, non-negative, and bounded. An event failing any
// check is rejected and counted — never coerced, never recorded with
// defaults.

import {
  ACTION_CLASS_VALUES,
  CLASSIFICATION_STATUS_VALUES,
  MAPPING_STATUS_VALUES,
} from "../vocabulary.mjs";
import { DECISION_VALUES } from "../../governance-core/policy-validate.mjs";
import { REMOTE_STATUSES } from "../../governance-core/contracts.mjs";
import { isCalendarUtcTimestamp } from "../schema-validate.mjs";
import { validateArtifact } from "../contracts.mjs";
import { sensitiveValueReason } from "../sensitive-values.mjs";

export const LATENCY_EVENT_SCHEMA = "mcpherson-governance-latency-event/v1";
export const LATENCY_INSTRUMENTATION_VERSION = "0.6.1";
export const SUPPORTED_LATENCY_INSTRUMENTATION_VERSIONS = Object.freeze([
  "0.6.0", LATENCY_INSTRUMENTATION_VERSION,
]);

// FIXTURE is the complete v0.6 measurement vocabulary. LIVE_SHADOW appears
// only as an explicitly rejected input below so callers receive a precise
// later-phase error; no v0.6 schema, producer, or consumer accepts it.
export const RECORDER_MEASUREMENT_KINDS = Object.freeze(["FIXTURE"]);
export const CACHE_STATE_VALUES = Object.freeze(["HIT", "MISS", "NONE", "UNKNOWN"]);
export const PATH_KIND_VALUES = Object.freeze(["LOCAL", "REMOTE", "UNKNOWN"]);
export const MAX_EVENTS_CEILING = 1_000_000;
export const MAX_DURATION_MS = 1_000_000_000;

export const ALLOWED_TAG_KEYS = Object.freeze([
  "agent_id", "capability_id", "normalized_capability", "risk_tier",
  "policy_outcome", "cache_state", "path_kind", "remote_status",
  "mapping_status", "classification_status",
]);

export const ALLOWED_DURATION_KEYS = Object.freeze([
  "intercept_ms", "normalization_ms", "automap_lookup_ms", "local_policy_ms",
  "remote_policy_roundtrip_ms", "decision_processing_ms", "receipt_write_ms",
  "total_governance_ms", "tool_execution_ms", "total_end_to_end_ms",
]);

const TAG_VALUE_RE = /^[A-Za-z0-9._:-]{1,96}$/;
const TAG_ENUMS = Object.freeze({
  cache_state: new Set(CACHE_STATE_VALUES),
  path_kind: new Set(PATH_KIND_VALUES),
  risk_tier: new Set([...ACTION_CLASS_VALUES, "UNKNOWN"]),
  policy_outcome: new Set([...DECISION_VALUES, "UNAVAILABLE", "UNKNOWN"]),
  remote_status: new Set([...REMOTE_STATUSES, "UNKNOWN"]),
  mapping_status: new Set([...MAPPING_STATUS_VALUES, "UNKNOWN"]),
  classification_status: new Set([...CLASSIFICATION_STATUS_VALUES, "UNKNOWN"]),
});

export function defaultClock() {
  return Object.freeze({
    monotonicNs: () => process.hrtime.bigint(),
    wallClockIso: () => new Date().toISOString(),
  });
}

/** Explicit nanosecond-to-millisecond conversion (microsecond precision). */
export function nanosecondsToMilliseconds(deltaNs) {
  if (typeof deltaNs !== "bigint" || deltaNs < 0n) return null;
  const milliseconds = Number(deltaNs / 1000n) / 1000;
  return Number.isFinite(milliseconds) && milliseconds <= MAX_DURATION_MS
    ? milliseconds
    : null;
}

function validateTags(tags) {
  // A non-object tags argument (e.g. a literal string) is rejected outright,
  // never coerced into a full set of UNKNOWN tags.
  if (tags !== undefined
      && (tags === null || typeof tags !== "object" || Array.isArray(tags))) {
    return { ok: false, reason: "tags_not_object" };
  }
  const clean = Object.create(null);
  for (const key of ALLOWED_TAG_KEYS) {
    const value = tags?.[key];
    if (value === undefined) {
      // Absent means honestly unknown; a supplied value is never coerced.
      clean[key] = "UNKNOWN";
      continue;
    }
    if (typeof value !== "string" || !TAG_VALUE_RE.test(value)) {
      return { ok: false, reason: `tag_invalid:${key}` };
    }
    const enumValues = TAG_ENUMS[key];
    if (enumValues) {
      if (!enumValues.has(value)) return { ok: false, reason: `tag_enum:${key}` };
    } else if (sensitiveValueReason(value) !== null) {
      return { ok: false, reason: `tag_sensitive_value:${key}` };
    }
    clean[key] = value;
  }
  if (tags && typeof tags === "object") {
    for (const key of Object.keys(tags)) {
      if (!ALLOWED_TAG_KEYS.includes(key)) {
        return { ok: false, reason: `tag_unknown_key:${key}` };
      }
    }
  }
  return { ok: true, tags: clean };
}

function validateDurations(durations) {
  const clean = Object.create(null);
  if (!durations || typeof durations !== "object" || Array.isArray(durations)) {
    return { ok: false, reason: "durations_invalid" };
  }
  for (const key of Object.keys(durations)) {
    if (!ALLOWED_DURATION_KEYS.includes(key)) {
      return { ok: false, reason: `duration_unknown_key:${key}` };
    }
    const value = durations[key];
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0
        || value > MAX_DURATION_MS) {
      return { ok: false, reason: `duration_invalid:${key}` };
    }
    const rounded = Math.round(value * 1000) / 1000;
    if (!Number.isFinite(rounded) || rounded > MAX_DURATION_MS) {
      return { ok: false, reason: `duration_rounding_invalid:${key}` };
    }
    clean[key] = rounded;
  }
  if (Object.keys(clean).length === 0) {
    return { ok: false, reason: "durations_empty" };
  }
  return { ok: true, durations: clean };
}

/**
 * Create an offline prototype latency recorder. Only FIXTURE measurements
 * can be produced; a LIVE_SHADOW recorder requires a later, separately
 * approved phase and is rejected here with a distinct reason.
 */
export function makeLatencyRecorder({
  clock = defaultClock(),
  measurementKind = "FIXTURE",
  maxEvents = 10_000,
} = {}) {
  if (measurementKind === "LIVE_SHADOW") {
    throw new TypeError("live_shadow_requires_separately_approved_phase");
  }
  if (!RECORDER_MEASUREMENT_KINDS.includes(measurementKind)) {
    throw new TypeError("measurement_kind_invalid");
  }
  if (!Number.isSafeInteger(maxEvents) || maxEvents < 1
      || maxEvents > MAX_EVENTS_CEILING) {
    throw new TypeError("max_events_invalid");
  }
  const events = [];
  let sequence = 0;
  let dropped = 0;
  let rejected = 0;
  let instrumentationFailures = 0;

  function safeWallClock() {
    try {
      const value = clock.wallClockIso();
      // Real calendar validation (not a digit-shape pattern): an impossible
      // date such as 2026-02-31T00:00:00Z is rejected here, so a bad wall
      // clock never stamps an event with a calendar-invalid ts_utc. A rejected
      // timestamp records as null (chronology unknown, schema-valid), never as
      // the invalid value. Length is bounded to the schema's 32-char maximum.
      if (typeof value !== "string" || value.length > 32
          || !isCalendarUtcTimestamp(value)) {
        instrumentationFailures += 1;
        return null;
      }
      return value;
    } catch {
      instrumentationFailures += 1;
      return null;
    }
  }

  function record(tags, durations) {
    try {
      if (events.length >= maxEvents) {
        dropped += 1;
        return null;
      }
      const tagResult = validateTags(tags);
      if (!tagResult.ok) {
        rejected += 1;
        return null;
      }
      const durationResult = validateDurations(durations);
      if (!durationResult.ok) {
        rejected += 1;
        return null;
      }
      const event = Object.freeze({
        schema: LATENCY_EVENT_SCHEMA,
        instrumentation_version: LATENCY_INSTRUMENTATION_VERSION,
        measurement_kind: measurementKind,
        sequence: sequence + 1,
        ts_utc: safeWallClock(),
        tags: Object.freeze({ ...tagResult.tags }),
        durations_ms: Object.freeze({ ...durationResult.durations }),
      });
      // Producer output guard: a recorded event is validated against its own
      // contract before it is retained, so events() only ever yields
      // schema-valid latency events. A rejected event consumes no sequence
      // number and is counted as an instrumentation failure, never emitted.
      if (!validateArtifact(LATENCY_EVENT_SCHEMA, event).ok) {
        instrumentationFailures += 1;
        return null;
      }
      sequence += 1;
      events.push(event);
      return event;
    } catch {
      instrumentationFailures += 1;
      return null;
    }
  }

  function startTimer() {
    try {
      const value = clock.monotonicNs();
      if (typeof value !== "bigint" || value < 0n) {
        instrumentationFailures += 1;
        return null;
      }
      return value;
    } catch {
      instrumentationFailures += 1;
      return null;
    }
  }

  function elapsedMs(startToken) {
    try {
      if (typeof startToken !== "bigint") return null;
      const now = clock.monotonicNs();
      if (typeof now !== "bigint" || now < startToken) {
        instrumentationFailures += 1;
        return null;
      }
      return nanosecondsToMilliseconds(now - startToken);
    } catch {
      instrumentationFailures += 1;
      return null;
    }
  }

  /**
   * Run `operation` and best-effort record the SYNCHRONOUS governance-path
   * duration under `durationKey` — the time up to the operation returning.
   *
   * Sol re-audit repair for native-Promise observability: the recorder does
   * NOT attach any handler to a returned native promise. Attaching
   * `promise.then(onF, onR)` registers a rejection handler and suppresses the
   * runtime's `unhandledRejection` signal for that promise; that is
   * observable control-flow interference. Instead, the timing is taken
   * synchronously and the ORIGINAL promise object is returned untouched, so
   * its identity, resolution value, rejection reason, and unhandled-rejection
   * behavior are all exactly as if the operation had not been wrapped. The
   * async settlement duration is deliberately not measured — the governance
   * decision is synchronous, and tool-execution latency is a separate metric.
   *
   * Supported result types: synchronous values, thrown errors, and native
   * promises (all returned untouched with the synchronous duration recorded).
   * A custom thenable is an unsupported result type: it is returned untouched
   * as a synchronous value and never introspected, so a hostile `then` getter
   * cannot convert success into an error. Instrumentation failures are
   * swallowed and counted, never surfaced into the wrapped path.
   */
  function withTiming(tags, durationKey, operation) {
    const start = startTimer();
    const finish = () => {
      try {
        if (!ALLOWED_DURATION_KEYS.includes(durationKey)) {
          rejected += 1;
          return;
        }
        const elapsed = start === null ? null : elapsedMs(start);
        // Nothing measured means nothing recorded: a broken clock produces
        // a counted failure, never an empty telemetry event.
        if (elapsed !== null) record(tags, { [durationKey]: elapsed });
      } catch {
        instrumentationFailures += 1;
      }
    };
    let outcome;
    try {
      outcome = operation();
    } catch (error) {
      finish();
      throw error;
    }
    // Record the synchronous governance-path duration now, and return the
    // operation's result (sync value, native promise, or thenable) untouched.
    finish();
    return outcome;
  }

  return Object.freeze({
    record,
    startTimer,
    elapsedMs,
    withTiming,
    events: () => Object.freeze([...events]),
    status: () => Object.freeze({
      measurement_kind: measurementKind,
      recorded: events.length,
      dropped,
      rejected_events: rejected,
      instrumentation_failures: instrumentationFailures,
    }),
  });
}

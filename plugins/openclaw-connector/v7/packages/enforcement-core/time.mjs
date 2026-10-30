// Pure, clock-free RFC3339 UTC timestamp arithmetic.
//
// Every timestamp used by the evaluator is a SUPPLIED input (envelope
// observed_at, approval issued_at/expires_at, evaluation-context evaluated_at).
// This module converts a validated RFC3339 UTC string to epoch seconds by
// explicit field parsing + Date.UTC — it NEVER reads the ambient clock, and it
// is a deterministic pure function of its string argument.

const RFC3339_UTC_RE =
  /^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(?:\.(\d{1,9}))?Z$/;

/** Epoch seconds (float) for a validated RFC3339 UTC string, or null. */
export function toEpochSeconds(value) {
  if (typeof value !== "string") return null;
  const m = RFC3339_UTC_RE.exec(value);
  if (!m) return null;
  const [, y, mo, d, h, mi, s, frac] = m;
  const ms = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s));
  const fraction = frac ? Number(`0.${frac}`) : 0;
  return ms / 1000 + fraction;
}

/** -1 / 0 / 1 comparing two RFC3339 UTC strings, or null if either is invalid. */
export function compareTimestamps(a, b) {
  const ea = toEpochSeconds(a);
  const eb = toEpochSeconds(b);
  if (ea === null || eb === null) return null;
  if (ea < eb) return -1;
  if (ea > eb) return 1;
  return 0;
}

// Semantic sensitive-value policy for diagnostic artifact strings.
//
// Key allowlists alone do not prevent sensitive content: a credential-shaped,
// host-shaped, customer-record-shaped, or business-value-shaped string can
// hide under an allowed key (Sol audit, latency finding 2). This module
// rejects values by shape, not by key name. It is deliberately conservative:
// a rejected label costs only a diagnostic record; an accepted secret would
// cost much more.
//
// PROTECTED CLASSES (exact, and the limit of the claim): secret/token
// prefixes, long mixed token shapes, URLs, IP addresses, hostnames, emails,
// long digit runs, and a fixed set of sensitive keyword markers (credential,
// customer/patient/account records, and monetary/business values). This is
// NOT universal secret detection: a novel secret shape outside these classes
// can pass. The policy is conservative and may over-reject a legitimate
// value that happens to contain a protected keyword.

const SECRET_PREFIX_RE =
  /(mgd1_|AKIA[0-9A-Z]{2}|gh[pousr]_|github_pat_|sk[-_](?:live|proj)[-_]|xox[baprs]-|eyJ[A-Za-z0-9_-]{8})/;
const BARE_FQDN_RE =
  /(?:^|[^A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:com|org|net|io|dev|gov|edu|cloud|app|co|ai|internal|local)(?:[^A-Za-z0-9_-]|$)/i;
const EMAIL_RE = /@/;
const URL_MARKER_RE = /:\/\/|^www\./i;
const LONG_DIGIT_RUN_RE = /\d{6,}/;
const IPV4_RE = /(?:^|\D)(?:\d{1,3}\.){3}\d{1,3}(?:\D|$)/;
// Mixed-case-plus-digit runs of 20 or more characters look like tokens or
// key material. Lowercase hex hashes are allowed only in fields declared as
// hash-bearing by their schema, which never pass through this guard.
const TOKEN_SHAPE_RE = /(?=[A-Za-z0-9+/=_-]{20,})(?=[^\s]*[a-z])(?=[^\s]*[A-Z])(?=[^\s]*\d)[A-Za-z0-9+/=_-]{20,}/;
// Sensitive keyword markers as whole tokens (bounded by start/end or a
// separator). Catches credential labels, customer/record identifiers, and
// monetary/business values (the exact synthetic probes the re-audit left).
const SENSITIVE_KEYWORD_RE =
  /(?:^|[_:.\- ])(password|passwd|secret|token|apikey|api_key|credential|credentials|cookie|session|bearer|customer|patient|account|ssn|deal|salary|revenue|amount|payment|invoice|wire_transfer|wire|iban|message|msg|contact)(?:[_:.\- ]|\d|$)/i;

export const SENSITIVE_VALUE_REASONS = Object.freeze([
  "secret_prefix_shape",
  "token_shape",
  "url_marker",
  "host_name_shape",
  "ip_address_shape",
  "email_shape",
  "long_digit_run",
  "sensitive_keyword_shape",
]);

/**
 * Inspect one free-form label or identifier value. Returns null when the
 * value is acceptable, or a deterministic reason string when it must be
 * rejected. Values are expected to be short single-line labels; anything
 * else should already have been rejected by pattern/length validation.
 */
export function sensitiveValueReason(value) {
  if (typeof value !== "string") return null;
  if (SECRET_PREFIX_RE.test(value)) return "secret_prefix_shape";
  if (TOKEN_SHAPE_RE.test(value)) return "token_shape";
  if (URL_MARKER_RE.test(value)) return "url_marker";
  if (IPV4_RE.test(value)) return "ip_address_shape";
  if (BARE_FQDN_RE.test(value)) return "host_name_shape";
  if (EMAIL_RE.test(value)) return "email_shape";
  if (SENSITIVE_KEYWORD_RE.test(value)) return "sensitive_keyword_shape";
  if (LONG_DIGIT_RUN_RE.test(value)) return "long_digit_run";
  return null;
}

export function isSensitiveValue(value) {
  return sensitiveValueReason(value) !== null;
}

// Note: the Governor establishes evidence truth with TYPED POSITIVE values
// (`packages/governance-diagnostics/typed-values.mjs` — strict identifiers and
// per-field positive-assertion enums, plus an explicit `asserts` boolean), not
// with a negative-phrase blacklist. The earlier finite negative-marker filter
// was removed because a blacklist can never enumerate every semantically
// negative phrase (Sol re-audit, Governor finding); a value now PASSes only by
// being a typed positive assertion, never merely by avoiding blacklisted words.

// Recursive secret redaction for diagnostic and evidence output.
//
// `sensitive-values.mjs` rejects a *label* by its shape before it is ever
// admitted into an artifact. This module solves the complementary problem:
// a structured document that is about to leave the process — written to an
// evidence file, printed by the CLI, or embedded in a transcript record —
// must carry no credential material anywhere in its tree, including under
// nested objects, arrays of objects, and hyphenated or mixed-case keys.
//
// TWO INDEPENDENT LAYERS (both required; neither is sufficient alone):
//
//   1. KEY LAYER. A normalized key name (case-folded, separators stripped)
//      that names credential material redacts its value. `access-token`,
//      `Access_Token`, and `accessToken` all normalize to `accesstoken`.
//
//   2. VALUE LAYER. Every string is scrubbed for known credential shapes
//      regardless of the key above it, because a token pasted into a free
//      text transcript field is not announced by its key name.
//
// DELIBERATE NON-GOALS (the limit of the claim): this is not universal
// secret detection. A novel credential shape stored under a key that does
// not name it can still pass the value layer. The design accepts that in
// exchange for keeping evidence usable.
//
// EVIDENCE USABILITY IS A REQUIREMENT, NOT A COURTESY. Over-redaction
// destroys the diagnostic value this package exists to produce, so:
//
//   * Booleans, null, and undefined are NEVER redacted. They cannot carry
//     credential material, so `has_token: true` and `session: null` survive
//     intact and still describe the shape of what was observed.
//   * Only whole normalized key names, or key names *ending* in a credential
//     term, match. Descriptive neighbours keep their values: `credential_id`,
//     `credential_material`, `token_shape`, `private_key_shape`,
//     `known_weak_credential_shape`, `session_identifiers`, and — critically
//     for this package's safety posture — `authority`.
//   * The value layer replaces only the matched credential substring, so the
//     surrounding sentence in a transcript remains readable.
//
// HOSTILE INPUT: recursion is depth-limited and cycle-safe, so a deeply
// nested or self-referential document degrades to a placeholder instead of
// exhausting the stack.

export const REDACTION_PLACEHOLDER = "[REDACTED]";
export const DEPTH_LIMIT_PLACEHOLDER = "[REDACTED:DEPTH_LIMIT]";
export const CYCLE_PLACEHOLDER = "[REDACTED:CYCLE]";

// Matches the bounded input reader's schema depth budget so a document that
// was accepted by `input-safety.mjs` can always be fully redacted.
export const MAX_REDACTION_DEPTH = 32;

// Whole normalized key names that name credential material directly.
const SECRET_KEYS = new Set([
  "token", "tokens",
  "accesstoken", "refreshtoken", "devicetoken", "idtoken",
  "sessiontoken", "bearertoken", "authtoken",
  "authorization", "proxyauthorization", "wwwauthenticate", "bearer",
  "apikey", "apikeys", "apisecret", "appsecret", "clientsecret",
  "secret", "secrets", "secretkey", "accesskey",
  "password", "passwd", "pwd", "passphrase",
  "credential", "credentials",
  "cookie", "cookies", "setcookie",
  "session", "sessionid", "sessionkey",
  "privatekey", "signingkey", "encryptionkey",
  "totpseed", "totpsecret", "otpseed",
  "recoverycode", "recoverycodes", "backupcode", "backupcodes",
  "statekey", "refreshkey",
]);

// Normalized key *endings* that name credential material. An ending match is
// safe where a substring match would not be: `client_secret` ends in
// `secret`, while `credential_secret_access` and `secret_prefix_shape` end in
// `access` and `shape` and therefore keep their descriptive values.
const SECRET_KEY_SUFFIXES = Object.freeze([
  "token", "secret", "password", "passphrase",
  "apikey", "privatekey", "credential", "credentials",
  "authorization", "cookie", "totpseed", "otpseed",
  "recoverycode", "recoverycodes", "statekey", "sessionkey", "bearer",
]);

// Credential shapes recognised inside any string value. Each entry replaces
// only its own match, so surrounding transcript text survives.
const VALUE_PATTERNS = Object.freeze([
  ["pem_private_key",
    /-----BEGIN (?:[A-Z ]*)PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]*)PRIVATE KEY-----/g],
  ["bearer_credential", /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi],
  ["jwt_shape", /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]+)?/g],
  ["mcpherson_credential", /\bmgd1_[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*/g],
  ["aws_access_key_id", /\bAKIA[0-9A-Z]{12,}/g],
  ["github_credential", /\bgh[pousr]_[A-Za-z0-9]{16,}|\bgithub_pat_[A-Za-z0-9_]{20,}/g],
  ["openai_style_credential", /\bsk-(?:live|proj|test)-[A-Za-z0-9_-]{12,}/gi],
  ["slack_credential", /\bxox[baprs]-[A-Za-z0-9-]{8,}/gi],
  // `key: value` and `key=value` pairs embedded in prose or log lines.
  ["inline_credential_assignment",
    /\b(?:pass(?:word|wd|phrase)?|secret|token|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|device[_ -]?token|authorization|bearer|cookie|session[_ -]?(?:id|key|token)?|private[_ -]?key|client[_ -]?secret|totp[_ -]?seed|recovery[_ -]?code|state[_ -]?key)\s*[:=]\s*(?:"[^"\n]{1,}"|'[^'\n]{1,}'|[^\s,;&"'}\]]{1,})/gi],
]);

/**
 * Case-fold a key and strip every non-alphanumeric separator so that
 * `Access-Token`, `access_token`, `accessToken`, and `ACCESS TOKEN` all
 * compare equal.
 */
export function normalizeSecretKey(key) {
  return String(key).toLowerCase().replace(/[^a-z0-9]+/g, "");
}

/**
 * True when `key` names credential material by whole name or by credential
 * ending. Descriptive neighbours such as `credential_id`, `token_shape`, and
 * `authority` are deliberately false.
 */
export function isSecretKey(key) {
  const normalized = normalizeSecretKey(key);
  if (normalized.length === 0) return false;
  if (SECRET_KEYS.has(normalized)) return true;
  return SECRET_KEY_SUFFIXES.some(
    (suffix) => normalized.length > suffix.length && normalized.endsWith(suffix),
  );
}

/**
 * Report every credential shape found in one string. Returns an ordered,
 * de-duplicated list of reason identifiers.
 */
export function scanTextForSecrets(text) {
  if (typeof text !== "string" || text.length === 0) return [];
  const reasons = [];
  for (const [reason, pattern] of VALUE_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) reasons.push(reason);
    pattern.lastIndex = 0;
  }
  return reasons;
}

function scrubText(text) {
  if (typeof text !== "string" || text.length === 0) {
    return { value: text, reasons: [] };
  }
  let output = text;
  const reasons = [];
  for (const [reason, pattern] of VALUE_PATTERNS) {
    pattern.lastIndex = 0;
    if (!pattern.test(output)) continue;
    pattern.lastIndex = 0;
    output = output.replace(pattern, REDACTION_PLACEHOLDER);
    reasons.push(reason);
  }
  return { value: output, reasons };
}

// Values that can never carry credential material. Preserving them is what
// keeps a redacted artifact diagnostically useful.
function isNonSecretBearing(value) {
  return value === null || value === undefined || typeof value === "boolean";
}

// A value already reduced to a placeholder, or an empty string, carries no
// credential material. Distinguishing these keeps `assertNoSecrets` usable as
// a gate on *redacted* output: redaction must be a fixed point, otherwise the
// gate would reject its own clean result.
function carriesMaterial(value) {
  if (value === "" ) return false;
  return value !== REDACTION_PLACEHOLDER
    && value !== DEPTH_LIMIT_PLACEHOLDER
    && value !== CYCLE_PLACEHOLDER;
}

function joinPath(path, segment) {
  if (path === "") return String(segment);
  return typeof segment === "number" ? `${path}[${segment}]` : `${path}.${segment}`;
}

function walk(value, context) {
  const { path, depth, sealed, seen, findings, redact } = context;

  if (isNonSecretBearing(value)) return value;

  if (typeof value === "string") {
    if (sealed) {
      if (!carriesMaterial(value)) return value;
      findings.push({ path, reason: "secret_key" });
      return redact ? REDACTION_PLACEHOLDER : value;
    }
    const scrubbed = scrubText(value);
    for (const reason of scrubbed.reasons) findings.push({ path, reason });
    return redact ? scrubbed.value : value;
  }

  if (typeof value === "number" || typeof value === "bigint") {
    if (sealed) {
      findings.push({ path, reason: "secret_key" });
      return redact ? REDACTION_PLACEHOLDER : value;
    }
    return value;
  }

  if (typeof value !== "object") {
    // Functions and symbols are not evidence data; never emit them.
    return redact ? REDACTION_PLACEHOLDER : value;
  }

  if (seen.has(value)) {
    findings.push({ path, reason: "cycle" });
    return redact ? CYCLE_PLACEHOLDER : value;
  }
  if (depth >= MAX_REDACTION_DEPTH) {
    findings.push({ path, reason: "depth_limit" });
    return redact ? DEPTH_LIMIT_PLACEHOLDER : value;
  }

  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((entry, index) => walk(entry, {
        ...context,
        path: joinPath(path, index),
        depth: depth + 1,
        // An array under a credential key seals every element: a list of
        // device tokens is still a list of device tokens.
        sealed,
      }));
    }

    const output = {};
    for (const [key, child] of Object.entries(value)) {
      const childSealed = sealed || isSecretKey(key);
      output[key] = walk(child, {
        ...context,
        path: joinPath(path, key),
        depth: depth + 1,
        sealed: childSealed,
      });
    }
    return output;
  } finally {
    seen.delete(value);
  }
}

function run(value, options, redact) {
  const findings = [];
  const result = walk(value, {
    path: options.path ?? "",
    depth: 0,
    sealed: false,
    seen: new WeakSet(),
    findings,
    redact,
  });
  return { value: result, findings };
}

/**
 * Return a deep copy of `value` with credential material removed from every
 * nested object and array. Booleans, null, and undefined are preserved.
 */
export function redactSecrets(value, options = {}) {
  return run(value, options, true).value;
}

/**
 * As `redactSecrets`, but also reports where redaction occurred. `redactions`
 * is empty exactly when the input carried no detectable credential material.
 */
export function redactSecretsWithReport(value, options = {}) {
  const { value: redacted, findings } = run(value, options, true);
  return Object.freeze({ value: redacted, redactions: Object.freeze(findings) });
}

/**
 * Detect, without modifying, every credential shape reachable in `value`.
 * Intended as a final-output gate immediately before bytes are written or
 * printed: an empty result is the assertion that the output is clean.
 */
export function scanForSecrets(value, options = {}) {
  return run(value, options, false).findings
    .filter((finding) => finding.reason !== "cycle" && finding.reason !== "depth_limit");
}

/**
 * Final-output gate. Throws when `value` still carries credential material
 * after redaction, so a leak fails closed instead of reaching disk.
 */
export function assertNoSecrets(value, options = {}) {
  const findings = scanForSecrets(value, options);
  if (findings.length === 0) return;
  const where = findings
    .map((finding) => `${finding.path || "<root>"}:${finding.reason}`)
    .sort()
    .join(",");
  const error = new Error(`secret_material_detected(${where})`);
  error.code = "SECRET_MATERIAL_DETECTED";
  error.findings = Object.freeze(findings);
  throw error;
}

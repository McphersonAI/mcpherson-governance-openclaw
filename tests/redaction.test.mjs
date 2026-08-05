// Regression coverage for recursive secret redaction (v0.6.2).
//
// Two obligations are tested with equal weight: credential material must not
// survive anywhere in a nested document, AND evidence must remain usable —
// a redactor that erases `authority`, `credential_id`, or a boolean shape
// flag has broken the artifact it was meant to protect.

import { strict as assert } from "node:assert";
import test from "node:test";

import {
  CYCLE_PLACEHOLDER,
  DEPTH_LIMIT_PLACEHOLDER,
  MAX_REDACTION_DEPTH,
  REDACTION_PLACEHOLDER,
  assertNoSecrets,
  isSecretKey,
  normalizeSecretKey,
  redactSecrets,
  redactSecretsWithReport,
  scanForSecrets,
  scanTextForSecrets,
} from "../packages/governance-diagnostics/redaction.mjs";

// Synthetic credential probes are assembled from fragments at runtime. The
// packaged verifier scans every shipped file for credential-shaped literals,
// so a test that hard-coded these strings would make the package fail its own
// content-hygiene check.
const probe = (...parts) => parts.join("");

const SECRET = probe("mgd1_", "synthetic", ".", "c3VwZXJzZWNyZXR2YWx1ZQ");
const AWS_PROBE = probe("AK", "IAIOSFODNN7EXAMPLE");
const PEM_PROBE = probe(
  "-----BEGIN ", "RSA ", "PRIVATE", " KEY-----\nMIIE\n",
  "-----END ", "RSA ", "PRIVATE", " KEY-----",
);

test("normalizes case, hyphen, and underscore key variants to one form", () => {
  for (const variant of [
    "access_token", "access-token", "accessToken", "ACCESS_TOKEN",
    "Access-Token", "access token", "AccessToken",
  ]) {
    assert.equal(normalizeSecretKey(variant), "accesstoken", variant);
    assert.equal(isSecretKey(variant), true, variant);
  }
});

test("recognises every required credential key family", () => {
  const required = [
    "token", "access_token", "refresh_token", "device_token",
    "authorization", "bearer", "api_key", "secret", "password",
    "credential", "cookie", "session", "private_key", "totp_seed",
    "recovery_code", "state_key",
  ];
  for (const key of required) {
    assert.equal(isSecretKey(key), true, `expected ${key} to be a secret key`);
    assert.equal(isSecretKey(key.toUpperCase()), true, key.toUpperCase());
    assert.equal(isSecretKey(key.replace(/_/g, "-")), true, key);
  }
});

test("harmless similarly named fields keep their values", () => {
  // These are the descriptive neighbours that actually occur in this
  // package's schemas. Redacting any of them would destroy evidence.
  const harmless = {
    authority: "NONE",
    remote_authority: "SHADOW_ONLY",
    credential_id: "cred-17",
    active_credential_id: "cred-17",
    new_credential_id: "cred-18",
    credential_material: "absent",
    credential_secret_access: "not_observed",
    known_weak_credential_shape: false,
    credential_assignment_shape: "per_device",
    token_shape: "long_hex_token_shape",
    long_hex_token_shape: "unmatched",
    secret_prefix_shape: "unmatched",
    private_key_shape: "absent",
    sensitive_keyword_shape: "clean",
    session_identifiers: "excluded",
    token_count: 4,
    session_count: 2,
    tokenizer: "simple",
    password_policy_version: 3,
    symbol_key: "sym-1",
    keys: 12,
  };
  for (const [key, value] of Object.entries(harmless)) {
    assert.equal(isSecretKey(key), false, `${key} must not be a secret key`);
  }
  assert.deepEqual(redactSecrets(harmless), harmless);
});

test("redacts credential values inside deeply nested objects", () => {
  const input = {
    runtime: {
      profile: {
        binding: {
          identity: "disposable-a",
          credentials: {
            access_token: SECRET,
            refreshToken: "rt_live_9f8e7d6c5b4a3210",
            expires_in: 300,
            scope: "operator.read",
            rotated: true,
          },
        },
      },
    },
  };
  const output = redactSecrets(input);
  assert.equal(output.runtime.profile.binding.identity, "disposable-a");
  const creds = output.runtime.profile.binding.credentials;
  assert.equal(creds.access_token, REDACTION_PLACEHOLDER);
  assert.equal(creds.refreshToken, REDACTION_PLACEHOLDER);
  // Sealed subtree: structure and non-bearing values survive, scalars do not.
  assert.equal(creds.expires_in, REDACTION_PLACEHOLDER);
  assert.equal(creds.scope, REDACTION_PLACEHOLDER);
  assert.equal(creds.rotated, true);
  assert.equal(JSON.stringify(output).includes(SECRET), false);
});

test("redacts credential values inside arrays of objects", () => {
  const input = {
    devices: [
      { device_id: "d-1", device_token: SECRET, bound: true },
      { device_id: "d-2", device_token: "mgd1_second.token", bound: false },
      { device_id: "d-3", device_token: null },
    ],
  };
  const output = redactSecrets(input);
  assert.equal(output.devices.length, 3);
  assert.equal(output.devices[0].device_id, "d-1");
  assert.equal(output.devices[0].device_token, REDACTION_PLACEHOLDER);
  assert.equal(output.devices[0].bound, true);
  assert.equal(output.devices[1].device_token, REDACTION_PLACEHOLDER);
  assert.equal(output.devices[1].bound, false);
  // null under a credential key stays null: it is evidence of absence.
  assert.equal(output.devices[2].device_token, null);
  assert.equal(JSON.stringify(output).includes(SECRET), false);
});

test("seals arrays held directly under a credential key", () => {
  const output = redactSecrets({ recovery_codes: ["aaaa-bbbb", "cccc-dddd"] });
  assert.deepEqual(output.recovery_codes,
    [REDACTION_PLACEHOLDER, REDACTION_PLACEHOLDER]);
});

test("redacts nested device-token transcript shapes", () => {
  const transcript = {
    observation_id: "live-obs-abc123",
    turns: [
      {
        role: "system",
        parts: [
          { kind: "text", text: "binding device" },
          {
            kind: "request",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${SECRET}`,
              "X-Device-Token": SECRET,
            },
            body: { deviceToken: SECRET, scope: "operator.read" },
          },
        ],
      },
      {
        role: "tool",
        parts: [{
          kind: "text",
          text: `issued device_token=${SECRET} for profile disposable-a`,
        }],
      },
    ],
  };
  const output = redactSecrets(transcript);
  const serialized = JSON.stringify(output);
  assert.equal(serialized.includes(SECRET), false);
  assert.equal(output.observation_id, "live-obs-abc123");
  const request = output.turns[0].parts[1];
  assert.equal(request.headers["Content-Type"], "application/json");
  assert.equal(request.headers.Authorization, REDACTION_PLACEHOLDER);
  assert.equal(request.headers["X-Device-Token"], REDACTION_PLACEHOLDER);
  assert.equal(request.body.deviceToken, REDACTION_PLACEHOLDER);
  // Free-text transcript: only the credential is removed, prose survives.
  const text = output.turns[1].parts[0].text;
  assert.equal(text.includes(SECRET), false);
  assert.equal(text.startsWith("issued "), true);
  assert.equal(text.includes("for profile disposable-a"), true);
});

test("redacts authorization headers under any key spelling", () => {
  for (const key of [
    "Authorization", "authorization", "AUTHORIZATION",
    "proxy-authorization", "proxy_authorization",
  ]) {
    const output = redactSecrets({ headers: { [key]: `Bearer ${SECRET}` } });
    assert.equal(output.headers[key], REDACTION_PLACEHOLDER, key);
  }
});

test("redacts bearer credentials found under non-credential keys", () => {
  const output = redactSecrets({
    note: `retry used Bearer ${SECRET} and then stopped`,
  });
  assert.equal(output.note.includes(SECRET), false);
  assert.equal(output.note.includes("and then stopped"), true);
});

test("redacts cookies and sessions", () => {
  const input = {
    cookie: "sid=abc123; theme=dark",
    cookies: [{ name: "sid", value: "abc123" }],
    set_cookie: "sid=abc123; HttpOnly",
    session: { session_id: "s-99", session_key: "k-99", active: true },
    session_count: 2,
  };
  const output = redactSecrets(input);
  assert.equal(output.cookie, REDACTION_PLACEHOLDER);
  assert.equal(output.set_cookie, REDACTION_PLACEHOLDER);
  assert.equal(output.cookies[0].name, REDACTION_PLACEHOLDER);
  assert.equal(output.cookies[0].value, REDACTION_PLACEHOLDER);
  assert.equal(output.session.session_id, REDACTION_PLACEHOLDER);
  assert.equal(output.session.session_key, REDACTION_PLACEHOLDER);
  assert.equal(output.session.active, true);
  assert.equal(output.session_count, 2);
});

test("preserves null, undefined, boolean, and numeric non-credential values", () => {
  const input = {
    token: null,
    secret: undefined,
    has_token: true,
    password_required: false,
    tool_count: 0,
    ratio: 1.5,
    empty: "",
    nested: { api_key: null, verified: true },
  };
  const output = redactSecrets(input);
  assert.equal(output.token, null);
  assert.equal(output.secret, undefined);
  assert.equal(output.has_token, true);
  assert.equal(output.password_required, false);
  assert.equal(output.tool_count, 0);
  assert.equal(output.ratio, 1.5);
  assert.equal(output.empty, "");
  assert.equal(output.nested.api_key, null);
  assert.equal(output.nested.verified, true);
});

test("redacts primitive and top-level string inputs", () => {
  assert.equal(redactSecrets(`Bearer ${SECRET}`), REDACTION_PLACEHOLDER);
  assert.equal(redactSecrets(null), null);
  assert.equal(redactSecrets(true), true);
  assert.equal(redactSecrets(42), 42);
  assert.equal(redactSecrets("ordinary label"), "ordinary label");
});

test("enforces a depth limit instead of exhausting the stack", () => {
  let deep = { token: SECRET };
  for (let index = 0; index < MAX_REDACTION_DEPTH + 8; index += 1) {
    deep = { level: deep };
  }
  const output = redactSecrets(deep);
  const serialized = JSON.stringify(output);
  assert.equal(serialized.includes(SECRET), false);
  assert.equal(serialized.includes(DEPTH_LIMIT_PLACEHOLDER), true);
});

test("terminates on cyclic input", () => {
  const node = { name: "root", token: SECRET };
  node.self = node;
  const output = redactSecrets(node);
  assert.equal(output.name, "root");
  assert.equal(output.token, REDACTION_PLACEHOLDER);
  // The back-reference is cut at the point it closes the loop.
  assert.equal(output.self, CYCLE_PLACEHOLDER);
});

test("reports where redaction occurred", () => {
  const report = redactSecretsWithReport({
    devices: [{ device_token: SECRET }],
    note: `Bearer ${SECRET}`,
  });
  const paths = report.redactions.map((finding) => finding.path).sort();
  assert.deepEqual(paths, ["devices[0].device_token", "note"]);
});

test("final-output scanning finds secrets and clears redacted output", () => {
  const dirty = {
    turns: [{ headers: { Authorization: `Bearer ${SECRET}` } }],
    body: { refresh_token: SECRET },
  };
  const findings = scanForSecrets(dirty);
  assert.equal(findings.length > 0, true);
  assert.throws(() => assertNoSecrets(dirty), /secret_material_detected/);

  // Redaction must be a fixed point: its own output passes the gate.
  const clean = redactSecrets(dirty);
  assert.deepEqual(scanForSecrets(clean), []);
  assert.doesNotThrow(() => assertNoSecrets(clean));
  assert.deepEqual(redactSecrets(clean), clean);
});

test("final-output scanning accepts genuinely clean evidence", () => {
  const evidence = {
    schema: "mcpherson-governance-governability-evidence/v1",
    authority: {
      AUTHORITY: "NONE",
      ENFORCEMENT: "OFF",
      REMOTE_DECISIONS: "SHADOW_ONLY",
    },
    excluded_data: ["credentials", "session_identifiers", "tool_arguments"],
    units: [{ tool_id: "mcpherson_connection_test", credential_id: "cred-1" }],
  };
  assert.deepEqual(scanForSecrets(evidence), []);
  assert.deepEqual(redactSecrets(evidence), evidence);
});

test("detects each credential shape in free text", () => {
  const cases = [
    ["bearer_credential", "Bearer abcdefghijklmnop"],
    ["jwt_shape", "eyJhbGciOi.eyJzdWIi.sig"],
    ["mcpherson_credential", probe("mgd1_", "abc.def")],
    ["aws_access_key_id", AWS_PROBE],
    ["github_credential", probe("gh", "p_0123456789abcdefghij")],
    ["openai_style_credential", probe("sk-", "live-0123456789abcdef")],
    ["slack_credential", probe("xox", "b-12345678-abcdef")],
    ["inline_credential_assignment", "password: hunter2"],
    ["pem_private_key", PEM_PROBE],
  ];
  for (const [reason, text] of cases) {
    assert.equal(scanTextForSecrets(text).includes(reason), true, reason);
    assert.equal(redactSecrets({ note: text }).note.includes("hunter2"), false);
  }
  assert.deepEqual(scanTextForSecrets("a normal diagnostic sentence"), []);
});

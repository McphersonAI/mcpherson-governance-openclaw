// Q-44 — ClawHub v0.8.0 security remediation and hardening regressions.
//
// F1 (purpose_capability): shadow-v070/normalize.mjs copied the first
//   whitespace-delimited command token verbatim into the Hosted request.
// F2 (instruction_scope): shadow-v070/runtime.mjs recorded activity after
//   `observa stop`.
// Hardening round (all preserved below, with every earlier audit repro):
//   H1 keyed argument digest (no unkeyed full-parameter SHA-256 on the wire)
//   H2 executable names only as reviewed canonical names or a coarse class
//   H3 bound-write honours stop / enabled:false / unreadable controls
//   H4 no silent coverage loss: sanitized NOT_EVALUATED status, CR handling
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, randomBytes } from "node:crypto";
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createGovernanceConnector } from "../plugins/openclaw-connector/index.mjs";
import { controlPath, setControl } from "../plugins/openclaw-connector/controls.mjs";
import {
  classifyCommand, COMMAND_COVERAGE_REASONS, extractArgv0, normalizeShadowRequest, stableStringify,
} from "../plugins/openclaw-connector/shadow-v070/normalize.mjs";
import {
  ARGUMENT_DIGEST_KEY_FILE, argumentDigestKeyPath, createArgumentDigester, loadOrCreateArgumentDigestKey,
} from "../plugins/openclaw-connector/shadow-v070/argument-digest.mjs";
import { CANONICAL_EXECUTABLES, EXECUTABLE_CLASS_UNLISTED } from "../plugins/openclaw-connector/shadow-v070/executables.mjs";
import { createShadowRuntime } from "../plugins/openclaw-connector/shadow-v070/runtime.mjs";
import { createMemoryEvidenceWriter } from "../plugins/openclaw-connector/shadow-v070/evidence.mjs";
import { SHADOW_EVIDENCE_FILE } from "../plugins/openclaw-connector/shadow-v070/constants.mjs";
import { NativeLedger } from "../plugins/openclaw-connector/native-ledger.mjs";
import { registerBoundWrite, BOUND_WRITE_TOOL } from "../plugins/openclaw-connector/bound-write.mjs";
import { buildBundle } from "../plugins/openclaw-connector/v7/packages/enforcement-core/index.mjs";
import { runObserva } from "../cli/cli.mjs";
import { cleanupTemps, makeProfileHome } from "./cli-fixtures.mjs";
import { cleanupProfiles, flush, makeClientSpy, makeProfile, TEST_CREDENTIAL } from "./helpers.mjs";

after(cleanupProfiles);
after(cleanupTemps);

const IDS = Object.freeze({
  deploymentId: "deployment-q44",
  agentId: "agent-q44",
  runtimeVersion: "2026.10.9",
  runtimeInstanceId: "instance-q44",
  requestId: "11111111-2222-4333-8444-555555555555",
});
const TEST_KEY = Buffer.alloc(32, 0x5a);
const testDigester = (key = TEST_KEY) => createArgumentDigester("/unused", { loadKey: () => Buffer.from(key) });
const DOMAIN = "observa-openclaw-shadow-argument-digest/v1\n";
const unkeyed = (params) => `sha256:${createHash("sha256").update(stableStringify(params)).digest("hex")}`;
const keyed = (params, key = TEST_KEY) => `sha256:${createHmac("sha256", key).update(DOMAIN).update(stableStringify(params)).digest("hex")}`;
const REASONS = new Set(Object.values(COMMAND_COVERAGE_REASONS));

function normalize(command, extra = {}) {
  const digester = testDigester();
  return normalizeShadowRequest({
    event: { toolName: "exec", params: { command }, toolCallId: "call-1", runId: "run-1" },
    ctx: { agentId: IDS.agentId, toolCallId: "call-1", runId: "run-1" },
    observedAt: "2026-11-07T00:00:00.000Z",
    argumentDigest: (params) => digester.digest(params),
    ...IDS,
    ...extra,
  });
}
const wireOf = (result) => (result.ok ? result.body.toString("utf8") : JSON.stringify(result));

function assertNotEvaluated(result, label, fragments = [], reason = null) {
  assert.equal(result.ok, false, label);
  assert.equal(result.notEvaluated, true, label);
  assert.ok(REASONS.has(result.reason) || result.reason === "argument_digest_key_unavailable", `${label}: bounded reason ${result.reason}`);
  if (reason) assert.equal(result.reason, reason, label);
  assert.equal(result.body, undefined, `${label}: no request body`);
  assert.equal(result.request, undefined, `${label}: no request`);
  for (const fragment of fragments) assert.equal(JSON.stringify(result).includes(fragment), false, `${label} leaked ${fragment}`);
}

// ---------------------------------------------------------------------------
// F1 — command parsing (ClawHub repro and audit rounds 1-3, preserved)
// ---------------------------------------------------------------------------

describe("Q-44 F1: shell-command secrets never reach the Hosted shadow request", () => {
  it("reproduces the ClawHub test: API_KEY=synthetic-test-value does not survive serialization", () => {
    const result = normalize("API_KEY=synthetic-test-value ls -la");
    assert.equal(result.ok, true);
    const wire = wireOf(result);
    assert.equal(wire.includes("synthetic-test-value"), false);
    assert.equal(wire.includes("API_KEY"), false);
    assert.equal(result.request.argv0, "ls");
    assert.equal(result.request.resource_ref, "exec:argv0:ls");
  });

  it("skips any number of literal-safe leading assignments with mixed IFS whitespace", () => {
    for (const command of [
      "A=1 B=two\tC=three\n  curl https://example.invalid",
      "  aws_secret_access_key=AKIAxyz  TOKEN=abc/def==  curl -s x",
      "GITHUB_TOKEN=ghp_0123456789abcdef curl",
    ]) {
      const result = normalize(command);
      assert.equal(result.ok, true, command);
      assert.equal(result.request.argv0, "curl", command);
      for (const leaked of ["AKIAxyz", "abc/def", "ghp_0123456789abcdef", "TOKEN", "three"]) {
        assert.equal(wireOf(result).includes(leaked), false, `${command} leaked ${leaked}`);
      }
    }
  });

  it("reduces path-invoked executables to their basename, then to canonical name or class", () => {
    assert.equal(extractArgv0("/usr/bin/env FOO=bar node x.js"), "env");
    assert.equal(extractArgv0("/home/alice/sk-live-abc123/bin/run --flag"), EXECUTABLE_CLASS_UNLISTED);
    assert.equal(extractArgv0("./deploy.sh prod"), EXECUTABLE_CLASS_UNLISTED);
    assert.equal(extractArgv0("g++ main.cc"), "g++");
    assert.equal(wireOf(normalize("/home/alice/sk-live-abc123/bin/run")).includes("sk-live"), false);
  });

  it("v0.8.0-era shapes with no safe executable identity are NOT_EVALUATED locally", () => {
    const cases = [
      ["API_KEY=synthetic-test-value", COMMAND_COVERAGE_REASONS.ASSIGNMENTS_ONLY],
      ["'API_KEY=synthetic-test-value' ls", COMMAND_COVERAGE_REASONS.COMMAND_WORD_SYNTAX],
      ["\"$(cat ~/.secret)\" foo", COMMAND_COVERAGE_REASONS.COMMAND_WORD_SYNTAX],
      ["(TOKEN=abc curl x)", COMMAND_COVERAGE_REASONS.COMMAND_WORD_SYNTAX],
      ["$(printf secret)", COMMAND_COVERAGE_REASONS.COMMAND_WORD_SYNTAX],
      ["/opt/tools/", COMMAND_COVERAGE_REASONS.COMMAND_WORD_SYNTAX],
      [`${"x".repeat(65)} arg`, COMMAND_COVERAGE_REASONS.COMMAND_WORD_SYNTAX],
      ["curl;rm", COMMAND_COVERAGE_REASONS.COMMAND_WORD_SYNTAX],
    ];
    for (const [command, reason] of cases) {
      assert.equal(classifyCommand(command).status, "UNRECOGNIZED", command);
      assertNotEvaluated(normalize(command), command, ["synthetic-test-value", "secret"], reason);
    }
  });

  it("keeps missing-command handling as identity_incomplete (not a coverage claim)", () => {
    for (const command of [undefined, "", "   \n\t "]) {
      const result = normalize(command);
      assert.equal(result.ok, false);
      assert.equal(result.reason, "identity_incomplete");
      assert.ok(result.missing.includes("event.params.command"));
    }
  });

  it("audit round 1 repros: whitespace inside an assignment value never yields a fragment", () => {
    for (const [command, fragment] of [
      ['PGPASSWORD="my Tr0ub4dor pass" psql -h db', "Tr0ub4dor"],
      ["API_KEY=sk-live-AAAA\\ BBBBsecretBBBB ls", "BBBBsecretBBBB"],
      ['TOKEN="first\nghp_0123456789abcdefABCD\nlast" gh api', "ghp_0123456789abcdefABCD"],
      ['SECRET="correct horse battery staple" cmd', "horse"],
      ['TOKEN="x /tmp/ghp_abcdef0123456789 y" curl', "ghp_abcdef0123456789"],
      ["TOKEN='a b c' curl", "b c"],
      ["A=$(cat /secret) B=1 curl", "/secret"],
      ["A=`printf s3cret` curl", "s3cret"],
    ]) assertNotEvaluated(normalize(command), command, [fragment], COMMAND_COVERAGE_REASONS.ASSIGNMENT_SYNTAX);
  });

  it("Unicode/control characters in an assignment value are refused, never split", () => {
    for (const ch of ["\u00a0", "\u2003", "\u3000", "\u200b", "\u2028", "\r", "\v", "\f", "\0"]) {
      assertNotEvaluated(normalize(`API_KEY=abc${ch}s3cretTail ls`), JSON.stringify(ch), ["s3cretTail"], COMMAND_COVERAGE_REASONS.ASSIGNMENT_SYNTAX);
    }
  });

  it("audit round 2 repros: arrays, heredocs, here-strings, redirections and globs", () => {
    for (const command of [
      "KEYS=(alpha S3CRETVALUE omega) cmd",
      "TOKENS=(ghp_aaaaaaaa ghp_S3CRETVALUE ghp_cccccccc) gh api",
      "A=x<<EOF\nS3CRETVALUE\nEOF",
      "A=x<<< S3CRETVALUE docker login --password-stdin",
      "A=x< S3CRETVALUE cmd", "A=x> S3CRETVALUE cmd", "A=x2> S3CRETVALUE cmd", "A=x>| S3CRETVALUE cmd",
      ">/run/secrets/S3CRETVALUE cmd", "2>/tmp/S3CRETVALUE.log make", "</home/u/.aws/S3CRETVALUE aws",
      "&>/x/S3CRETVALUE cmd", "*/S3CRETVALUE ls", "!/S3CRETVALUE", "#/S3CRETVALUE",
      "A=x;S3CRETVALUE", "A[0]=S3CRETVALUE cmd",
    ]) assertNotEvaluated(normalize(command), command, ["S3CRETVALUE"]);
  });

  it("any shell-syntax character in an assignment value refuses the command (generative)", () => {
    // ASCII space/tab/newline excluded: after them the shell genuinely runs the
    // next word as the command, which is then canonical-or-class (H2).
    for (const ch of [..."'\"\\$`()<>;&|{}[]*?!#^\u00a0\r\v\f"]) {
      for (const shape of [`A=x${ch} S3CRETVALUE cmd`, `A=${ch}S3CRETVALUE cmd`, `A=x${ch}S3CRETVALUE cmd`]) {
        assert.equal(wireOf(normalize(shape)).includes("S3CRETVALUE"), false, JSON.stringify(shape));
      }
    }
  });

  it("literal-safe assignment values still resolve to the real executable", () => {
    for (const [command, argv0] of [
      ["AWS_REGION=us-east-1 PGHOST=db.internal:5432 aws s3 ls", "aws"],
      ["PATH=/usr/local/bin:/usr/bin NODE_OPTIONS=--max-old-space-size=4096 node x", "node"],
      ["EMPTY= HOME=~/work ~/bin/tool run", EXECUTABLE_CLASS_UNLISTED],
      ["URL=user@host.example,b%20c tool", EXECUTABLE_CLASS_UNLISTED],
    ]) {
      const result = normalize(command);
      assert.equal(result.ok, true, command);
      assert.equal(result.request.argv0, argv0, command);
    }
  });

  it("never serializes any word of a quoted/escaped multi-word secret (property check)", () => {
    const word = () => randomBytes(6).toString("base64url").replace(/^[-_]/u, "k");
    for (let i = 0; i < 500; i += 1) {
      const words = [word(), word(), word(), word()];
      const sep = [" ", "\t", "\n", "\u00a0"][i % 4];
      const value = [`"${words.join(sep)}"`, `'${words.join(sep)}'`, words.join(`\\${sep}`)][i % 3];
      const wire = wireOf(normalize(`SECRET=${value} curl -s x`));
      for (const w of words) assert.equal(wire.includes(w), false, `${value} leaked ${w}`);
    }
  });

  it("never serializes a random secret placed in assignment position (property check)", () => {
    for (let i = 0; i < 500; i += 1) {
      const secret = randomBytes(12).toString("base64url");
      const name = `V${randomBytes(3).toString("hex")}`;
      const result = normalize(`${name}=${secret} ls -la`);
      assert.equal(result.ok, true);
      assert.equal(wireOf(result).includes(secret), false);
      assert.equal(wireOf(result).includes(name), false);
    }
  });
});

// ---------------------------------------------------------------------------
// H2 — executable names: reviewed canonical names or a coarse class only
// ---------------------------------------------------------------------------

describe("Q-44 H2: unknown executable names are never transmitted verbatim", () => {
  it("secret-like command words travel only as the coarse class", () => {
    for (const command of [
      "AKIAIOSFODNN7EXAMPLE --help",
      "sk-live-0123456789abcdefABCDEF run",
      "ghp_0123456789abcdefghijklmnopqrstuvwxyz12",
      "xoxb-1234567890-abcdefghij",
      "my-private-deploy-tool --prod",
      "Tr0ub4dor",
      "/srv/customer-acme-prod/bin/sync",
      "A=1 AKIAIOSFODNN7EXAMPLE",
      "LS", "Ls", "ls2", "curl.exe",
    ]) {
      const result = normalize(command);
      assert.equal(result.ok, true, command);
      assert.equal(result.request.argv0, EXECUTABLE_CLASS_UNLISTED, command);
      assert.equal(result.request.resource_ref, `exec:argv0:${EXECUTABLE_CLASS_UNLISTED}`, command);
      assert.equal(result.executableClass, "UNLISTED", command);
      const word = command.split(/[ \t\n]+/u).filter((t) => !t.includes("=")).at(0);
      const base = word.slice(word.lastIndexOf("/") + 1);
      assert.equal(wireOf(result).includes(base), false, `${command} leaked ${base}`);
    }
  });

  it("random non-canonical names never reach the wire (property check, 3,000 names)", () => {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-";
    for (let i = 0; i < 3000; i += 1) {
      const length = 6 + (i % 40);
      let name = "Q";
      for (const byte of randomBytes(length - 1)) name += alphabet[byte % alphabet.length];
      if (CANONICAL_EXECUTABLES.has(name)) continue;
      const result = normalize(`${name} --flag`);
      assert.equal(result.ok, true, name);
      assert.equal(result.request.argv0, EXECUTABLE_CLASS_UNLISTED, name);
      assert.equal(wireOf(result).includes(name), false, name);
    }
  });

  it("Unicode or control characters in the command word are NOT_EVALUATED", () => {
    for (const command of ["l\u015b -la", "ls\u00a0secret", "ls\u0000x", "ls\u200bx", "c\u0301url", "ls\u2028x"]) {
      assertNotEvaluated(normalize(command), JSON.stringify(command), ["secret"], COMMAND_COVERAGE_REASONS.COMMAND_WORD_SYNTAX);
    }
  });

  it("canonical names are public tool names and include the Hosted baseline lanes", () => {
    assert.ok(CANONICAL_EXECUTABLES.has("touch") && CANONICAL_EXECUTABLES.has("mkdir"));
    for (const name of CANONICAL_EXECUTABLES) {
      assert.match(name, /^[a-z][a-z0-9+.-]{0,15}$/u, name);
      assert.equal(normalize(`${name} x`).request.argv0, name, name);
    }
    assert.match(EXECUTABLE_CLASS_UNLISTED, /^[A-Za-z0-9._:-]{1,80}$/u, "class is a wire-safe resource_ref part");
    assert.equal(CANONICAL_EXECUTABLES.has(EXECUTABLE_CLASS_UNLISTED), false);
  });
});

// ---------------------------------------------------------------------------
// H1 — keyed argument digest
// ---------------------------------------------------------------------------

describe("Q-44 H1: argument_digest is an HMAC under a dedicated per-installation key", () => {
  it("the wire digest is HMAC-SHA256 (domain-separated), never the unkeyed SHA-256", () => {
    const params = { command: "DB_PASSWORD=summer2024 psql -h db" };
    const result = normalize(params.command);
    assert.equal(result.ok, true);
    assert.match(result.request.argument_digest, /^sha256:[a-f0-9]{64}$/u, "Hosted contract format preserved");
    assert.equal(result.request.argument_digest, keyed(params));
    assert.notEqual(result.request.argument_digest, unkeyed(params));
  });

  it("the independent auditor's dictionary recovery no longer works without the key", () => {
    const target = normalize("DB_PASSWORD=summer2024 psql -h db").request.argument_digest;
    const guesses = ["password", "123456", "letmein", "summer2024", "winter2025", "hunter2"];
    const recovered = guesses.find((g) => unkeyed({ command: `DB_PASSWORD=${g} psql -h db` }) === target);
    assert.equal(recovered, undefined, "unkeyed guessing must not confirm the secret");
  });

  it("same installation + same arguments -> same digest; another installation -> different", () => {
    const a = normalize("ls -la").request.argument_digest;
    const b = normalize("ls -la").request.argument_digest;
    const otherKey = randomBytes(32);
    const digester = testDigester(otherKey);
    const c = normalize("ls -la", { argumentDigest: (p) => digester.digest(p) }).request.argument_digest;
    assert.equal(a, b);
    assert.notEqual(a, c);
  });

  for (const [label, argumentDigest] of [
    ["missing digester", null],
    ["throwing digester", () => { throw new Error("EIO"); }],
    ["unkeyed-looking malformed digest", () => "sha256:XYZ"],
    ["non-string digest", () => 42],
  ]) {
    it(`${label}: no request is built and there is no unkeyed fallback`, () => {
      assertNotEvaluated(normalize("ls", { argumentDigest }), label, [], "argument_digest_key_unavailable");
    });
  }

  it("the key file is created once, 32 bytes, mode 0600, and reused", () => {
    const dir = mkdtempSync(join(tmpdir(), "observa-q44-key-"));
    const first = loadOrCreateArgumentDigestKey(dir);
    const path = argumentDigestKeyPath(dir);
    assert.equal(first.length, 32);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(statSync(path).size, 32);
    assert.deepEqual(loadOrCreateArgumentDigestKey(dir), first);
    assert.equal(ARGUMENT_DIGEST_KEY_FILE, "shadow-argument-digest.key");
  });

  for (const [label, prepare] of [
    ["wrong size", (path) => writeFileSync(path, Buffer.alloc(16, 1), { mode: 0o600 })],
    ["wrong mode", (path) => { writeFileSync(path, Buffer.alloc(32, 1), { mode: 0o600 }); chmodSync(path, 0o644); }],
    ["symlink", (path, dir) => { writeFileSync(join(dir, "elsewhere"), Buffer.alloc(32, 1), { mode: 0o600 }); symlinkSync(join(dir, "elsewhere"), path); }],
  ]) {
    it(`an existing ${label} key is unavailable and is never overwritten`, () => {
      const dir = mkdtempSync(join(tmpdir(), "observa-q44-key-"));
      const path = argumentDigestKeyPath(dir);
      prepare(path, dir);
      const before = readFileSync(path);
      assert.throws(() => loadOrCreateArgumentDigestKey(dir), { code: "ARGUMENT_DIGEST_KEY_UNAVAILABLE" });
      assert.deepEqual(readFileSync(path), before, "key file untouched");
    });
  }

  it("close() zeroes the in-memory key", () => {
    const key = Buffer.alloc(32, 9);
    const digester = createArgumentDigester("/unused", { loadKey: () => key });
    digester.digest({ command: "ls" });
    digester.close();
    assert.ok(key.every((b) => b === 0));
  });
});

// ---------------------------------------------------------------------------
// Runtime harness (shadow)
// ---------------------------------------------------------------------------

function harness({ controlInspector, enabled = true, argumentDigester = testDigester(), transport = null } = {}) {
  const calls = { credential: 0, transport: 0, bodies: [] };
  const writer = createMemoryEvidenceWriter();
  const config = { enabled, deploymentId: IDS.deploymentId, agentId: IDS.agentId, stateDir: "/nonexistent", receiptDir: "/nonexistent" };
  const runtime = createShadowRuntime({
    config,
    runtimeVersion: IDS.runtimeVersion,
    runtimeInstanceId: IDS.runtimeInstanceId,
    evidenceWriter: writer,
    argumentDigester,
    transport: transport ?? {
      evaluate: async (body) => {
        calls.transport += 1; calls.bodies.push(Buffer.from(body).toString("utf8"));
        throw Object.assign(new Error("UNAVAILABLE"), { code: "UNAVAILABLE" });
      },
      close() {},
    },
    credentialProvider: async (_dir, cb) => { calls.credential += 1; return cb("mgd1_x"); },
    controlInspector: controlInspector ?? (() => ({ blocked: false, priority: null, remoteStatus: null })),
  });
  return { runtime, writer, calls };
}

const HOSTED_FIELDS = [
  "schema", "request_id", "observed_at", "deployment_id", "agent_id", "tool_id", "tool_name", "runtime_tool_kind",
  "operation", "action_class", "resource_class", "resource_ref", "argv0", "argument_digest", "correlation_ref",
  "tool_call_id", "run_id", "runtime_name", "runtime_version", "runtime_instance_id", "mode", "authority",
  "enforcement", "active", "request_hash",
].sort();

describe("Q-44 runtime: captured outbound bytes and local records", () => {
  it("unsupported syntax: sanitized NOT_EVALUATED record, zero credential or transport", async () => {
    const { runtime, writer, calls } = harness();
    await runtime.beforeToolCall(
      { toolName: "exec", params: { command: "API_KEY=\"synthetic test value\" ls" }, toolCallId: "c", runId: "r" },
      { agentId: IDS.agentId, toolCallId: "c", runId: "r" },
    );
    assert.equal(calls.credential + calls.transport, 0);
    assert.equal(writer.records.length, 1);
    const [record] = writer.records;
    assert.equal(record.action, "NOT_EVALUATED");
    assert.equal(record.coverage, "NOT_EVALUATED");
    assert.equal(record.reason_code, COMMAND_COVERAGE_REASONS.ASSIGNMENT_SYNTAX);
    assert.equal(record.execution_effect, "NONE");
    assert.equal(JSON.stringify(writer.records).includes("synthetic"), false);
    assert.equal(runtime.status().totals.notEvaluated, 1);
  });

  it("CRLF: `ls\\r\\n` is NOT_EVALUATED (shells run `ls\\r`), `echo hi\\r\\n` is `echo`", () => {
    assertNotEvaluated(normalize("ls\r\n"), "ls CRLF", [], COMMAND_COVERAGE_REASONS.COMMAND_WORD_CR);
    assertNotEvaluated(normalize("ls\r\nrm -rf x\r\n"), "multi-line CRLF", [], COMMAND_COVERAGE_REASONS.COMMAND_WORD_CR);
    const echo = normalize("echo hi\r\n");
    assert.equal(echo.ok, true);
    assert.equal(echo.request.argv0, "echo");
  });

  it("the Hosted transport receives exactly the 25-field contract with a keyed digest", async () => {
    const { runtime, calls } = harness();
    const command = "API_KEY=synthetic-test-value AKIAIOSFODNN7EXAMPLE ls";
    await runtime.beforeToolCall(
      { toolName: "exec", params: { command }, toolCallId: "c", runId: "r" },
      { agentId: IDS.agentId, toolCallId: "c", runId: "r" },
    );
    assert.equal(calls.bodies.length, 1);
    const body = calls.bodies[0];
    const request = JSON.parse(body);
    assert.deepEqual(Object.keys(request).sort(), HOSTED_FIELDS);
    for (const fragment of ["synthetic-test-value", "API_KEY", "AKIAIOSFODNN7EXAMPLE", command]) {
      assert.equal(body.includes(fragment), false, fragment);
    }
    assert.equal(request.argv0, EXECUTABLE_CLASS_UNLISTED);
    assert.equal(request.argument_digest, keyed({ command }));
    const { request_hash: hash, ...unhashed } = request;
    assert.equal(hash, `sha256:${createHash("sha256").update(stableStringify(unhashed)).digest("hex")}`, "Hosted re-derivation matches");
  });
});

// ---------------------------------------------------------------------------
// F2 — stop makes the shadow runtime inert (preserved + extended)
// ---------------------------------------------------------------------------

let seq = 0;
async function driveEverySeam(runtime, agentId = IDS.agentId) {
  seq += 1;
  const id = { toolCallId: `call-${seq}`, runId: `run-${seq}` };
  const ctx = { agentId, ...id };
  await runtime.beforeToolCall({ toolName: "exec", params: { command: "ls" }, ...id }, ctx);
  await runtime.beforeToolCall({ toolName: "exec", params: { command: "A=\"x y\" ls" }, ...id, toolCallId: `${id.toolCallId}-ne` }, { ...ctx, toolCallId: `${id.toolCallId}-ne` });
  await runtime.beforeToolCall({ toolName: "read", params: {}, ...id }, ctx);
  await runtime.beforeToolCall({ toolName: "exec", params: { command: "ls" }, ...id }, { ...ctx, agentId: "other" });
  await runtime.beforeToolCall({ params: {} }, ctx);
  for (const type of ["tool.execution.started", "tool.execution.completed", "tool.execution.error", "tool.execution.blocked"]) {
    runtime.onDiagnosticEvent({ type, toolName: "exec", seq: 1, ...id }, { trusted: true });
  }
  runtime.afterToolCall({ toolName: "exec", result: { stdout: "x" }, ...id }, ctx);
  await flush();
}

const STOPPED_STATES = {
  "durable disabled control": () => ({ blocked: true, priority: "DISABLED", remoteStatus: "NOT_ATTEMPTED" }),
  "throwing control inspector": () => { throw new Error("EIO"); },
  "malformed control answer": () => ({ nonsense: true }),
  "blocked with unknown priority": () => ({ blocked: true, priority: "SOMETHING_NEW" }),
};

describe("Q-44 F2: stop makes the shadow runtime fully inert", () => {
  for (const [label, controlInspector] of Object.entries(STOPPED_STATES)) {
    it(`${label}: zero records, zero credential reads, zero transport calls, no key use`, async () => {
      let keyLoads = 0;
      const digester = createArgumentDigester("/unused", { loadKey: () => { keyLoads += 1; return Buffer.from(TEST_KEY); } });
      const { runtime, writer, calls } = harness({ controlInspector, argumentDigester: digester });
      await driveEverySeam(runtime);
      assert.deepEqual(writer.records, []);
      assert.equal(calls.credential + calls.transport, 0);
      assert.equal(keyLoads, 0, "the key is not even loaded while stopped");
      assert.equal(Object.values(runtime.status().totals).reduce((a, b) => a + b, 0), 0);
      assert.equal(runtime.status().correlations, 0);
    });
  }

  it("config.enabled=false is inert even with a permissive injected inspector", async () => {
    const { runtime, writer, calls } = harness({ enabled: false });
    await driveEverySeam(runtime);
    assert.deepEqual(writer.records, []);
    assert.equal(calls.credential + calls.transport, 0);
  });

  it("a stop issued mid-session silences after_tool_call and diagnostics for in-flight calls", async () => {
    let stopped = false;
    const { runtime, writer } = harness({
      controlInspector: () => (stopped ? STOPPED_STATES["durable disabled control"]() : { blocked: false, priority: null, remoteStatus: null }),
    });
    const id = { toolCallId: "inflight", runId: "inflight-run" };
    const ctx = { agentId: IDS.agentId, ...id };
    await runtime.beforeToolCall({ toolName: "exec", params: { command: "ls" }, ...id }, ctx);
    await flush();
    const beforeStop = writer.records.length;
    assert.ok(beforeStop > 0);
    stopped = true;
    runtime.onDiagnosticEvent({ type: "tool.execution.completed", toolName: "exec", seq: 9, ...id }, { trusted: true });
    runtime.afterToolCall({ toolName: "exec", result: {}, ...id }, ctx);
    await flush();
    assert.equal(writer.records.length, beforeStop);
  });

  it("a stop that lands after hook entry, before evaluation, records nothing and sends nothing", async () => {
    let stopped = false;
    const calls = { credential: 0, transport: 0 };
    const writer = createMemoryEvidenceWriter();
    const runtime = createShadowRuntime({
      config: { enabled: true, deploymentId: IDS.deploymentId, agentId: IDS.agentId, stateDir: "/nonexistent", receiptDir: "/nonexistent" },
      runtimeVersion: IDS.runtimeVersion, runtimeInstanceId: IDS.runtimeInstanceId, evidenceWriter: writer,
      argumentDigester: testDigester(),
      transport: { evaluate: async () => { calls.transport += 1; throw new Error("unexpected"); }, close() {} },
      credentialProvider: async (_dir, cb) => { calls.credential += 1; return cb("mgd1_x"); },
      makeRequestId: () => { stopped = true; return IDS.requestId; },
      controlInspector: () => (stopped ? STOPPED_STATES["durable disabled control"]() : { blocked: false, priority: null, remoteStatus: null }),
    });
    await runtime.beforeToolCall(
      { toolName: "exec", params: { command: "ls" }, toolCallId: "race", runId: "race-run" },
      { agentId: IDS.agentId, toolCallId: "race", runId: "race-run" },
    );
    await flush();
    assert.deepEqual(writer.records, []);
    assert.deepEqual(calls, { credential: 0, transport: 0 });
  });

  it("a stop that lands while the Hosted evaluation is in flight records no decision", async () => {
    let stopped = false;
    const { runtime, writer } = harness({
      transport: { evaluate: async () => { stopped = true; throw Object.assign(new Error("UNAVAILABLE"), { code: "UNAVAILABLE" }); }, close() {} },
      controlInspector: () => (stopped ? STOPPED_STATES["durable disabled control"]() : { blocked: false, priority: null, remoteStatus: null }),
    });
    await runtime.beforeToolCall(
      { toolName: "exec", params: { command: "ls" }, toolCallId: "flight", runId: "flight-run" },
      { agentId: IDS.agentId, toolCallId: "flight", runId: "flight-run" },
    );
    await flush();
    assert.deepEqual(writer.records, []);
  });

  it("ordinary shutdown is not a stop: an in-flight evaluation still records its decision", async () => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const { runtime, writer } = harness({
      transport: { evaluate: async () => { await gate; throw Object.assign(new Error("UNAVAILABLE"), { code: "UNAVAILABLE" }); }, close() {} },
    });
    const pending = runtime.beforeToolCall(
      { toolName: "exec", params: { command: "ls" }, toolCallId: "shut", runId: "shut-run" },
      { agentId: IDS.agentId, toolCallId: "shut", runId: "shut-run" },
    );
    await flush();
    const closing = runtime.close();
    release();
    await pending;
    await closing;
    const decisions = writer.records.filter((r) => r.kind === "SHADOW_DECISION");
    assert.deepEqual(decisions.map((r) => r.action), ["INDETERMINATE"], "baseline v0.8.0 behaviour preserved");
    await runtime.beforeToolCall(
      { toolName: "exec", params: { command: "ls" }, toolCallId: "after-close", runId: "after-close-run" },
      { agentId: IDS.agentId, toolCallId: "after-close", runId: "after-close-run" },
    );
    assert.equal(writer.records.filter((r) => r.kind === "SHADOW_DECISION").length, 1, "a closed runtime admits nothing new");
  });

  it("resuming (observa enable) restores recording; repeated stop is idempotent", async () => {
    let stopped = true;
    const { runtime, writer } = harness({
      controlInspector: () => (stopped ? STOPPED_STATES["durable disabled control"]() : { blocked: false, priority: null, remoteStatus: null }),
    });
    await driveEverySeam(runtime);
    assert.equal(writer.records.length, 0);
    stopped = false;
    await driveEverySeam(runtime);
    const resumed = writer.records.length;
    assert.ok(writer.records.some((r) => r.kind === "SHADOW_DECISION"));
    assert.ok(writer.records.some((r) => r.kind === "RESULT_EVIDENCE"));
    assert.ok(writer.records.some((r) => r.action === "NOT_EVALUATED"));
    stopped = true;
    await driveEverySeam(runtime);
    await driveEverySeam(runtime);
    assert.equal(writer.records.length, resumed);
  });

  it("the gateway_start attestation is lifecycle-only: once per process, no activity", async () => {
    const { runtime, writer, calls } = harness({ controlInspector: STOPPED_STATES["durable disabled control"] });
    runtime.onGatewayStart();
    runtime.onGatewayStart();
    await flush();
    assert.equal(writer.records.length, 1);
    const [record] = writer.records;
    assert.equal(record.kind, "SHADOW_ATTESTATION");
    for (const field of ["tool_name", "tool_call_id", "run_id", "request_id", "argv0", "agent_id"]) {
      assert.equal(Object.hasOwn(record, field), false, field);
    }
    assert.equal(calls.credential + calls.transport, 0);
  });

  for (const priority of ["KILL_SWITCH", "SYSTEM_LOCK"]) {
    it(`${priority} keeps its documented contract: local records, zero Hosted contact`, async () => {
      const { runtime, writer, calls } = harness({
        controlInspector: () => ({ blocked: true, priority, remoteStatus: `${priority}_ACTIVE` }),
      });
      await driveEverySeam(runtime);
      assert.equal(calls.credential + calls.transport, 0);
      const decision = writer.records.find((r) => r.reason_code === "kill_state");
      assert.ok(decision);
      assert.equal(decision.kill_state, priority);
      assert.ok(writer.records.some((r) => r.kind === "RESULT_EVIDENCE"));
    });
  }
});

// ---------------------------------------------------------------------------
// H3 — bound-write stop / disabled / unreadable control
// ---------------------------------------------------------------------------

function boundLab({ enabled = true } = {}) {
  const root = mkdtempSync(join(tmpdir(), "observa-q44-bound-"));
  mkdirSync(join(root, "bound-synthetic"), { mode: 0o700 });
  const bundle = buildBundle({ schema: "mcpherson-governance-enforcement-policy-bundle/v1", bundle_id: "synthetic-policy", bundle_version: "1",
    engine_range: { min_inclusive: "0.7.0", max_inclusive: "0.7.0" }, default_decision: "DENY", conflict_strategy: "lattice", approval_ttl_seconds: 60,
    rules: [
      { rule_id: "allow", description_label: "synthetic-allow", priority: 10, enabled: true, match: { all: [{ field: "resource_ref", op: "eq", value: "allow.txt" }] }, effect: { decision: "ALLOW" } },
      { rule_id: "approve", description_label: "synthetic-approval", priority: 10, enabled: true, match: { all: [{ field: "resource_ref", op: "eq", value: "approve.txt" }] },
        effect: { decision: "REQUIRE_APPROVAL", required_approval_subject: "openclaw-operator", required_approval_scope: "exclusive-create-once" } },
    ] });
  writeFileSync(join(root, "bound-policy.json"), JSON.stringify({ schema: "observa-openclaw-bound-policy/v1", mode: "SYNTHETIC", tool_id: BOUND_WRITE_TOOL,
    deployment_id: "deployment-test", agent_id: "main", tenant_id: "tenant-test", workspace_id: "workspace-test",
    expires_at: new Date(Date.now() + 3600000).toISOString(), bundle }), { mode: 0o600 });
  const ledger = new NativeLedger(root);
  let before; let tool;
  const config = { enabled, stateDir: root, deploymentId: "deployment-test" };
  const handle = registerBoundWrite({ pluginConfig: { boundNode: { enabled: true, mode: "SYNTHETIC", customerAuthorization: false } },
    on(_name, fn) { before = fn; }, registerTool(value) { tool = value; } }, { config, ledger });
  let n = 0;
  const event = (name) => ({ toolName: BOUND_WRITE_TOOL, params: { name, content: "synthetic-private-sentinel" }, runId: "run-test", toolCallId: `call-${name}-${n += 1}` });
  const ctx = { toolName: BOUND_WRITE_TOOL, agentId: "main", sessionId: "session-test" };
  return { root, ledger, before: (e) => before(e, ctx), tool, event, config, handle, count: () => ledger.records().length };
}

const BOUND_STOPS = {
  "durable disabled control": (lab) => setControl(lab.root, "disabled", true),
  "config enabled:false": (lab) => { lab.config.enabled = false; },
  "unreadable disabled control file": (lab) => { const p = controlPath(lab.root, "disabled"); writeFileSync(p, "garbage", { mode: 0o600 }); chmodSync(p, 0o000); },
  "tampered disabled control file": (lab) => writeFileSync(controlPath(lab.root, "disabled"), "{\"x\":1}", { mode: 0o600 }),
};

describe("Q-44 H3: bound-write honours stop without turning refusals into effects", () => {
  for (const [label, stop] of Object.entries(BOUND_STOPS)) {
    it(`${label}: refused, no file, and no new ledger records`, () => {
      const lab = boundLab();
      try {
        stop(lab);
        const before = lab.count();
        for (const name of ["allow.txt", "approve.txt", "denied.txt"]) {
          const e = lab.event(name);
          assert.equal(lab.before(e).block, true, `${label} ${name} refused`);
          assert.throws(() => lab.tool.execute(e.toolCallId, e.params));
        }
        assert.equal(existsSync(join(lab.root, "bound-synthetic/allow.txt")), false, "no synthetic effect");
        assert.equal(lab.count(), before, "no ordinary recording after stop");
        assert.equal(lab.handle.status().enabled, false);
      } finally { lab.ledger.close(); }
    });
  }

  it("an approval callback arriving after stop records nothing and permits nothing", () => {
    const lab = boundLab();
    try {
      const e = lab.event("approve.txt");
      const pending = lab.before(e);
      assert.ok(pending.requireApproval, "approval requested while enabled");
      setControl(lab.root, "disabled", true);
      const before = lab.count();
      pending.requireApproval.onResolution("allow-once");
      assert.equal(lab.count(), before, "no HOST_APPROVAL_RESOLUTION after stop");
      assert.throws(() => lab.tool.execute(e.toolCallId, e.params));
      assert.equal(existsSync(join(lab.root, "bound-synthetic/approve.txt")), false);
    } finally { lab.ledger.close(); }
  });

  for (const name of ["killswitch", "lock"]) {
    it(`${name} keeps its documented contract: refused with a local BOUND_REFUSAL record`, () => {
      const lab = boundLab();
      try {
        setControl(lab.root, name, true);
        const before = lab.count();
        assert.equal(lab.before(lab.event("allow.txt")).block, true);
        const added = lab.ledger.records().slice(before).map((r) => r.payload.kind);
        assert.deepEqual(added, ["BOUND_REFUSAL"]);
      } finally { lab.ledger.close(); }
    });
  }

  it("re-enable restores the documented ALLOW path; repeated stop stays silent", () => {
    const lab = boundLab();
    try {
      setControl(lab.root, "disabled", true);
      setControl(lab.root, "disabled", true);
      assert.equal(lab.before(lab.event("allow.txt")).block, true);
      setControl(lab.root, "disabled", false);
      const e = lab.event("allow.txt");
      assert.equal(lab.before(e), undefined);
      lab.tool.execute(e.toolCallId, e.params);
      assert.ok(existsSync(join(lab.root, "bound-synthetic/allow.txt")));
      setControl(lab.root, "disabled", true);
      const before = lab.count();
      assert.equal(lab.before(lab.event("allow.txt")).block, true);
      assert.equal(lab.count(), before);
    } finally { lab.ledger.close(); }
  });
});

// ---------------------------------------------------------------------------
// End to end: real plugin, real control files, real key, every evidence file
// ---------------------------------------------------------------------------

function snapshotFiles(root) {
  const out = {};
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.isFile()) out[path.slice(root.length)] = createHash("sha256").update(readFileSync(path)).digest("hex");
    }
  };
  walk(root);
  return out;
}
const allBytes = (root) => {
  const chunks = [];
  const walk = (dir) => { for (const e of readdirSync(dir, { withFileTypes: true })) { const p = join(dir, e.name); if (e.isDirectory()) walk(p); else if (e.isFile() && !p.endsWith(ARGUMENT_DIGEST_KEY_FILE)) chunks.push(readFileSync(p)); } };
  walk(root);
  return Buffer.concat(chunks);
};

function makeHost({ stateDir, receiptDir }) {
  const hooks = new Map();
  return {
    api: {
      pluginConfig: { enabled: true, apiUrl: "https://hosted.invalid", stateDir, receiptDir },
      config: { agents: { entries: { main: {} } } },
      runtime: { version: "2026.10.9" },
      logger: { error() {}, warn() {}, info() {} },
      registerTool() {},
      on(name, handler) {
        hooks.set(name, [...(hooks.get(name) ?? []), handler]);
        return () => hooks.set(name, hooks.get(name).filter((entry) => entry !== handler));
      },
    },
    async emit(name, ...args) { for (const handler of hooks.get(name) ?? []) await handler(...args); },
  };
}

async function registerPlugin(config, { client = makeClientSpy(), gate = null } = {}) {
  const host = makeHost({ stateDir: config.stateDir, receiptDir: config.receiptDir });
  const diagnostics = [];
  const bodies = [];
  const plugin = createGovernanceConnector({
    client,
    transport: async () => { throw new Error("no transport in tests"); },
    shadowTransport: {
      evaluate: async (body) => {
        bodies.push(Buffer.from(body).toString("utf8"));
        if (gate) await gate;
        throw Object.assign(new Error("UNAVAILABLE"), { code: "UNAVAILABLE" });
      },
      close() {},
    },
    credentialProvider: async (callback) => callback("mgd1_x"),
    subscribeDiagnostics: (listener) => { diagnostics.push(listener); return () => {}; },
  });
  const registered = plugin.register(host.api);
  return { host, registered, diagnostics, bodies, client };
}

async function everyHook(env, n, command = "ls") {
  const config = env.registered.config;
  const id = { toolCallId: `e2e-${n}`, runId: `e2e-run-${n}` };
  const ctx = { agentId: config.agentId, sessionId: "s1", ...id };
  await env.host.emit("session_start", { sessionId: "s1" }, ctx);
  await env.host.emit("model_call_started", { callId: `m${n}` }, ctx);
  // The real host supplies toolName in both event and context.
  const execCtx = { ...ctx, toolName: "exec" };
  await env.host.emit("before_tool_call", { toolName: "exec", params: { command }, ...id }, execCtx);
  for (const l of env.diagnostics) l({ type: "tool.execution.completed", toolName: "exec", seq: n, ...id }, { trusted: true });
  await env.host.emit("after_tool_call", { toolName: "exec", params: { command }, result: { content: [], details: { status: "completed", exitCode: 0 } }, ...id }, execCtx);
  const conn = { toolCallId: `conn-${n}`, runId: id.runId };
  const connCtx = { ...ctx, ...conn, toolName: "mcpherson_connection_test" };
  await env.host.emit("before_tool_call", { toolName: "mcpherson_connection_test", params: {}, ...conn }, connCtx);
  await env.host.emit("after_tool_call", { toolName: "mcpherson_connection_test", params: {}, result: { content: [] }, ...conn }, connCtx);
  await new Promise((resolve) => setTimeout(resolve, 50));
  await env.host.emit("model_call_ended", { callId: `m${n}`, outcome: "completed" }, ctx);
  await env.host.emit("session_end", { sessionId: "s1" }, ctx);
  await flush();
}

describe("Q-44 end to end through the registered plugin", () => {
  it("`observa stop` from another process freezes EVERY file and all Hosted traffic", async () => {
    const { root, config } = makeProfile({ enabled: true });
    const env = await registerPlugin(config);
    await env.host.emit("gateway_start");
    await everyHook(env, 1, "API_KEY=synthetic-test-value AKIAIOSFODNN7EXAMPLE status");
    assert.ok(env.bodies.length >= 1, "shadow Hosted path really exercised");
    for (const body of env.bodies) {
      for (const f of ["synthetic-test-value", "AKIAIOSFODNN7EXAMPLE", "API_KEY"]) assert.equal(body.includes(f), false, f);
    }
    const before = snapshotFiles(root);
    const sent = { shadow: env.bodies.length, client: env.client.calls.length };
    const paths = new Set(env.client.calls.map((c) => c.path));
    for (const path of ["/v1/runtime/inventory", "/v1/health", "/v1/decisions", "/v1/observations"]) {
      assert.ok(paths.has(path), `${path} lane really exercised before stop (saw ${[...paths].join(",")})`);
    }
    setControl(config.stateDir, "disabled", true);
    const afterStop = snapshotFiles(root);
    for (let n = 2; n < 5; n += 1) await everyHook(env, n);
    const later = snapshotFiles(root);
    assert.deepEqual(later, afterStop, "no file created or changed after stop acknowledgment");
    const controlRel = controlPath(config.stateDir, "disabled").slice(root.length);
    assert.deepEqual(Object.keys(afterStop).filter((k) => !(k in before)), [controlRel], "stop adds only its control file");
    for (const [k, v] of Object.entries(before)) assert.equal(afterStop[k], v, `${k} unchanged by the stop itself`);
    assert.equal(env.bodies.length, sent.shadow, "no shadow submission after stop");
    assert.equal(env.client.calls.length, sent.client, "no Hosted client call after stop");
    await env.registered.shutdown();
  });

  it("stop during an in-flight shadow evaluation and pipeline call writes nothing afterwards", async () => {
    const { root, config } = makeProfile({ enabled: true });
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const client = makeClientSpy();
    let decideEntered = 0;
    const decide = client.decide;
    client.decide = async (...args) => { decideEntered += 1; await gate; return decide(...args); };
    const env = await registerPlugin(config, { gate, client });
    await env.host.emit("gateway_start");
    await flush();
    const id = { toolCallId: "inflight", runId: "inflight-run" };
    const ctx = { agentId: config.agentId, toolName: "exec", ...id };
    const pending = env.host.emit("before_tool_call", { toolName: "exec", params: { command: "ls" }, ...id }, ctx);
    const conn = { toolCallId: "inflight-conn", runId: "inflight-run" };
    const pendingPipeline = env.host.emit("before_tool_call", { toolName: "mcpherson_connection_test", params: {}, ...conn },
      { agentId: config.agentId, toolName: "mcpherson_connection_test", ...conn });
    await flush();
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(env.bodies.length, 1, "shadow request already transmitted (cannot be recalled)");
    assert.equal(decideEntered, 1, "pipeline observation in flight at stop");
    setControl(config.stateDir, "disabled", true);
    const atStop = snapshotFiles(root);
    release();
    await pending;
    await pendingPipeline;
    await new Promise((resolve) => setTimeout(resolve, 50));
    for (const l of env.diagnostics) l({ type: "tool.execution.completed", toolName: "exec", seq: 1, ...id }, { trusted: true });
    await env.host.emit("after_tool_call", { toolName: "exec", params: { command: "ls" }, result: {}, ...id }, ctx);
    await flush();
    assert.deepEqual(snapshotFiles(root), atStop, "settling the in-flight call records nothing after stop");
    await env.registered.shutdown();
  });

  it("an attributed tool's completion receipt is not written if stop lands while its attempt is in flight", async () => {
    const { root, config } = makeProfile({ enabled: true });
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const client = makeClientSpy();
    let decideEntered = 0;
    const decide = client.decide;
    client.decide = async (...args) => { decideEntered += 1; await gate; return decide(...args); };
    const env = await registerPlugin(config, { client });
    const conn = { toolCallId: "late-conn", runId: "late-run" };
    const ctx = { agentId: config.agentId, toolName: "mcpherson_connection_test", ...conn };
    const before = env.host.emit("before_tool_call", { toolName: "mcpherson_connection_test", params: {}, ...conn }, ctx);
    await flush();
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(decideEntered, 1, "pipeline attempt in flight");
    await env.host.emit("after_tool_call", { toolName: "mcpherson_connection_test", params: {}, result: { content: [] }, ...conn }, ctx);
    setControl(config.stateDir, "disabled", true);
    const atStop = snapshotFiles(root);
    release();
    await before;
    await new Promise((resolve) => setTimeout(resolve, 50));
    await flush();
    assert.deepEqual(snapshotFiles(root), atStop, "no completion (or attempt) receipt after stop");
    await env.registered.shutdown();
  });

  it("restart while stopped records no activity; re-enable resumes; repeated stop freezes again", async () => {
    const { root, config } = makeProfile({ enabled: true });
    setControl(config.stateDir, "disabled", true);
    const first = await registerPlugin(config);
    await first.host.emit("gateway_start");
    await everyHook(first, 1);
    await first.registered.shutdown();
    const restarted = await registerPlugin(config);
    await restarted.host.emit("gateway_start");
    const afterRestart = snapshotFiles(root);
    await everyHook(restarted, 2);
    assert.deepEqual(snapshotFiles(root), afterRestart, "no activity after restart while stopped");
    assert.equal(restarted.bodies.length + first.bodies.length, 0);
    assert.equal(existsSync(argumentDigestKeyPath(config.stateDir)), false, "key not created while stopped");
    const shadow = join(config.receiptDir, SHADOW_EVIDENCE_FILE);
    const lifecycleOnly = readFileSync(shadow, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
    assert.ok(lifecycleOnly.every((r) => r.kind === "SHADOW_ATTESTATION"), "only lifecycle attestations while stopped");

    setControl(config.stateDir, "disabled", false);
    await everyHook(restarted, 3);
    assert.ok(restarted.bodies.length >= 1, "re-enable resumes Hosted shadow evaluation");
    assert.ok(existsSync(argumentDigestKeyPath(config.stateDir)), "key created on first governed request");
    setControl(config.stateDir, "disabled", true);
    setControl(config.stateDir, "disabled", true);
    const frozen = snapshotFiles(root);
    const sent = restarted.bodies.length;
    await everyHook(restarted, 4);
    assert.deepEqual(snapshotFiles(root), frozen);
    assert.equal(restarted.bodies.length, sent);
    await restarted.registered.shutdown();
  });

  it("the real per-installation key never appears in any outbound body or local file", async () => {
    const { root, config } = makeProfile({ enabled: true });
    const env = await registerPlugin(config);
    await everyHook(env, 1, "DB_PASSWORD=summer2024 psql -h db");
    const key = readFileSync(argumentDigestKeyPath(config.stateDir));
    assert.equal(key.length, 32);
    assert.equal(statSync(argumentDigestKeyPath(config.stateDir)).mode & 0o777, 0o600);
    assert.equal(key.equals(Buffer.from(TEST_CREDENTIAL)), false, "not the pairing credential");
    const forms = [key.toString("hex"), key.toString("base64"), key.toString("base64url")];
    const files = allBytes(root).toString("latin1");
    for (const form of forms) {
      assert.equal(files.includes(form), false, "key absent from every other local file");
      for (const body of env.bodies) assert.equal(body.includes(form), false, "key absent from outbound bytes");
    }
    assert.equal(files.includes("summer2024"), false, "secret absent from every local journal/receipt/ledger");
    const request = JSON.parse(env.bodies[0]);
    assert.equal(request.argv0, "psql");
    assert.equal(request.argument_digest, keyed({ command: "DB_PASSWORD=summer2024 psql -h db" }, key));
    assert.notEqual(request.argument_digest, unkeyed({ command: "DB_PASSWORD=summer2024 psql -h db" }));
    await env.registered.shutdown();
  });
});

// ---------------------------------------------------------------------------
// H4 — no silent coverage loss in the CLI
// ---------------------------------------------------------------------------

describe("Q-44 H4: coverage limitations are reported, never presented as decisions", () => {
  it("status/decisions report NOT_EVALUATED counts and bounded reasons only", async () => {
    const { home, receiptDir } = makeProfileHome({ evidence: true });
    const file = join(receiptDir, SHADOW_EVIDENCE_FILE);
    const row = (reason) => JSON.stringify({ schema: "observa-openclaw-shadow-evidence/v1", mode: "SHADOW", authority: "NONE", enforcement: "OFF",
      active: false, runtime_name: "openclaw", runtime_version: "2026.10.9", ts: new Date().toISOString(), kind: "SHADOW_DECISION",
      action: "NOT_EVALUATED", coverage: "NOT_EVALUATED", reason_code: reason, execution_effect: "NONE", agent_id: "main", tool_name: "exec" });
    writeFileSync(file, `${readFileSync(file, "utf8")}${row("assignment_syntax_unsupported")}\n${row("command_word_carriage_return")}\n${row("API_KEY=leak")}\n`, { mode: 0o600 });
    const env = { PATH: "/usr/bin:/bin" };
    const decisions = JSON.parse((await runObserva(["decisions", "--json"], { env, home })).stdout);
    assert.equal(decisions.decisions.some((d) => d.decision === "NOT_EVALUATED"), false, "never listed as a decision");
    assert.equal(decisions.evidence.not_evaluated.count, 3);
    assert.deepEqual(decisions.evidence.not_evaluated.reasons, { assignment_syntax_unsupported: 1, command_word_carriage_return: 1, other: 1 });
    const human = (await runObserva(["status"], { env, home })).stdout;
    assert.match(human, /Coverage limitation: Observa did not evaluate 3 governed action\(s\)/u);
    assert.match(human, /NOT covered, verified or approved/u);
    assert.equal(human.includes("API_KEY"), false, "raw reason text is never echoed");
  });
});

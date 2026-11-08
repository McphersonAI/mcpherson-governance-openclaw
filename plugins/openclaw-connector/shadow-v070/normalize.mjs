import { createHash, randomUUID } from "node:crypto";
import {
  SHADOW_GOVERNED_TOOLS,
  SHADOW_MAX_REQUEST_BYTES,
  SHADOW_RELEASE,
  SHADOW_REQUEST_SCHEMA,
} from "./constants.mjs";
import { canonicalExecutable, EXECUTABLE_CLASS_UNLISTED } from "./executables.mjs";

const SAFE_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const SAFE_REF_PART = /^[A-Za-z0-9._:-]{1,80}$/;
const KEYED_DIGEST = /^sha256:[a-f0-9]{64}$/;

export function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
}

export function sha256(value) {
  return `sha256:${createHash("sha256").update(String(value)).digest("hex")}`;
}

// Q-44: the shadow request is metadata-only, so the executable identity is
// derived structurally and never copied verbatim from the command string.
// Leading POSIX environment assignments (`API_KEY=value cmd`) are skipped
// without being retained, only the executable basename is considered, and the
// result must be a conservative executable-name token. Anything else is
// UNRECOGNIZED and is refused locally before a Hosted request exists.
//
// Words are split only on the default shell IFS (space, tab, newline). The
// parse is ALLOWLIST-only, never a denylist of shell syntax:
//   - a leading `NAME=value` word is skipped only when its value consists
//     solely of literal-safe characters (no quoting, escaping, expansion,
//     arrays, redirections, heredocs, globs, separators or non-ASCII). Such a
//     value cannot extend past the next IFS character and cannot turn the
//     following word into data, so the next word really is the next word.
//     Any other `NAME=` word makes the whole command UNRECOGNIZED;
//   - the executable word itself must be entirely path-safe before its
//     basename is taken, so redirection/glob prefixes (`>/run/secrets/x`)
//     cannot smuggle a filename into argv0.
//
// The command word's basename is then mapped through the reviewed canonical
// executable list (executables.mjs). Listed names travel verbatim; every other
// executable travels only as the coarse class EXECUTABLE_CLASS_UNLISTED, so a
// secret used as a command word is never transmitted.
//
// Carriage returns are NOT normalized: OpenClaw passes the command verbatim to
// `$SHELL -c`, and bash/zsh/sh treat CR as a word character (`ls\r` is a
// different, normally nonexistent, command). Such a command is reported as a
// sanitized NOT_EVALUATED coverage limitation instead.
const SHELL_IFS = /[ \t\n]+/u;
const ASSIGNMENT_PREFIX = /^[A-Za-z_][A-Za-z0-9_]*=/u;
const LITERAL_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9._:/@%+,=~-]*$/u;
const PATH_SAFE_WORD = /^[A-Za-z0-9._/~+-]+$/u;
const SAFE_EXECUTABLE = /^[A-Za-z0-9_][A-Za-z0-9._+-]{0,63}$/u;

/** Bounded, sanitized reasons Observa did not evaluate a command. */
export const COMMAND_COVERAGE_REASONS = Object.freeze({
  ASSIGNMENT_SYNTAX: "assignment_syntax_unsupported",
  ASSIGNMENTS_ONLY: "assignments_only",
  COMMAND_WORD_SYNTAX: "command_word_syntax_unsupported",
  COMMAND_WORD_CR: "command_word_carriage_return",
});

const unsupported = (reason) => Object.freeze({ status: "UNRECOGNIZED", argv0: null, executableClass: null, reason });

export function classifyCommand(command) {
  if (typeof command !== "string") return Object.freeze({ status: "MISSING", argv0: null, executableClass: null, reason: null });
  const tokens = command.split(SHELL_IFS).filter(Boolean);
  if (tokens.length === 0) return Object.freeze({ status: "MISSING", argv0: null, executableClass: null, reason: null });
  let index = 0;
  while (index < tokens.length && ASSIGNMENT_PREFIX.test(tokens[index])) {
    if (!LITERAL_ASSIGNMENT.test(tokens[index])) return unsupported(COMMAND_COVERAGE_REASONS.ASSIGNMENT_SYNTAX);
    index += 1;
  }
  const token = tokens[index];
  if (token === undefined) return unsupported(COMMAND_COVERAGE_REASONS.ASSIGNMENTS_ONLY);
  if (!PATH_SAFE_WORD.test(token)) {
    return unsupported(token.endsWith("\r") && PATH_SAFE_WORD.test(token.slice(0, -1))
      ? COMMAND_COVERAGE_REASONS.COMMAND_WORD_CR
      : COMMAND_COVERAGE_REASONS.COMMAND_WORD_SYNTAX);
  }
  const basename = token.slice(token.lastIndexOf("/") + 1);
  if (!SAFE_EXECUTABLE.test(basename)) return unsupported(COMMAND_COVERAGE_REASONS.COMMAND_WORD_SYNTAX);
  const argv0 = canonicalExecutable(basename);
  return Object.freeze({
    status: "OK",
    argv0,
    executableClass: argv0 === EXECUTABLE_CLASS_UNLISTED ? "UNLISTED" : "CANONICAL",
    reason: null,
  });
}

export function extractArgv0(command) {
  return classifyCommand(command).argv0;
}

function resourceRef(argv0) {
  return SAFE_REF_PART.test(argv0)
    ? `exec:argv0:${argv0}`
    : `exec:argv0-sha256:${sha256(argv0).slice(7, 31)}`;
}

export function correlationIdentity(event, ctx) {
  const choose = (left, right) => {
    const a = typeof left === "string" && left.length > 0 ? left : null;
    const b = typeof right === "string" && right.length > 0 ? right : null;
    if (a !== null && b !== null && a !== b) return { value: null, conflict: true };
    return { value: a ?? b, conflict: false };
  };
  const tool = choose(event?.toolCallId, ctx?.toolCallId);
  const run = choose(event?.runId, ctx?.runId);
  const toolCallId = tool.value;
  const runId = run.value;
  return {
    tool_call_id: toolCallId,
    run_id: runId,
    conflict: tool.conflict || run.conflict,
    key: !tool.conflict && !run.conflict && toolCallId && runId
      ? `${toolCallId}\n${runId}` : null,
  };
}

export function executionCorrelationRef({ runtimeInstanceId, runId, toolCallId }) {
  return sha256(stableStringify({
    schema: "openclaw-execution-link/v1",
    runtime_instance_id: runtimeInstanceId,
    run_id: runId,
    tool_call_id: toolCallId,
  }));
}

export function classifyShadowScope({ event, ctx, agentId }) {
  const rawTool = typeof event?.toolName === "string" ? event.toolName : null;
  if (!rawTool) return Object.freeze({ scope: "ERROR", reason: "tool_identity_incomplete" });
  const governed = SHADOW_GOVERNED_TOOLS[rawTool] ?? null;
  if (!governed) {
    return Object.freeze({ scope: "PASS_UNGOVERNED", tool_name: rawTool });
  }
  const observedAgent = typeof ctx?.agentId === "string" ? ctx.agentId : null;
  if (observedAgent !== agentId) {
    return Object.freeze({
      scope: observedAgent ? "PASS_OUT_OF_SCOPE_PRINCIPAL" : "ERROR",
      reason: observedAgent ? "agent_out_of_scope" : "agent_identity_incomplete",
      tool_name: governed.canonical_name,
      tool_name_raw: rawTool,
      agent_id_raw: observedAgent,
    });
  }
  return Object.freeze({
    scope: "GOVERNED",
    governed,
    tool_name: governed.canonical_name,
    tool_name_raw: rawTool,
    alias: rawTool !== governed.canonical_name,
    agent_id_raw: observedAgent,
  });
}

export function normalizeShadowRequest({
  event,
  ctx,
  deploymentId,
  agentId,
  runtimeVersion,
  runtimeInstanceId,
  requestId = randomUUID(),
  observedAt = new Date().toISOString(),
  // Q-44: keyed digester (argument-digest.mjs). Required: without it no
  // request is built; there is no unkeyed fallback.
  argumentDigest = null,
}) {
  const scope = classifyShadowScope({ event, ctx, agentId });
  if (scope.scope !== "GOVERNED") return Object.freeze({ ok: false, scope });
  const correlation = correlationIdentity(event, ctx);
  const commandIdentity = classifyCommand(event?.params?.command);
  if (commandIdentity.status === "UNRECOGNIZED") {
    // Coverage limitation for Observa telemetry only; the OpenClaw command
    // itself is untouched. The reason is a fixed enum, never command text.
    return Object.freeze({ ok: false, scope, notEvaluated: true, reason: commandIdentity.reason, missing: [] });
  }
  const argv0 = commandIdentity.argv0;
  const missing = [];
  if (!argv0) missing.push("event.params.command");
  if (!correlation.tool_call_id) missing.push("toolCallId");
  if (!correlation.run_id) missing.push("runId");
  if (correlation.conflict) missing.push("correlation_identity_conflict");
  for (const [name, value] of Object.entries({ deploymentId, agentId, runtimeVersion, runtimeInstanceId, requestId })) {
    if (typeof value !== "string" || !SAFE_ID.test(value)) missing.push(name);
  }
  if (!Number.isFinite(Date.parse(observedAt))) missing.push("observedAt");
  if (missing.length > 0) {
    return Object.freeze({ ok: false, scope, reason: "identity_incomplete", missing });
  }
  let argumentDigestValue = null;
  try {
    argumentDigestValue = typeof argumentDigest === "function" ? argumentDigest(event.params) : null;
  } catch {
    argumentDigestValue = null;
  }
  if (typeof argumentDigestValue !== "string" || !KEYED_DIGEST.test(argumentDigestValue)) {
    return Object.freeze({ ok: false, scope, notEvaluated: true, reason: "argument_digest_key_unavailable", missing: [] });
  }

  const request = {
    schema: SHADOW_REQUEST_SCHEMA,
    request_id: requestId,
    observed_at: observedAt,
    deployment_id: deploymentId,
    agent_id: agentId,
    tool_id: scope.governed.tool_id,
    tool_name: scope.tool_name,
    runtime_tool_kind: scope.governed.runtime_tool_kind,
    operation: "execute",
    action_class: scope.governed.action_class,
    resource_class: scope.governed.resource_class,
    resource_ref: resourceRef(argv0),
    argv0,
    argument_digest: argumentDigestValue,
    correlation_ref: executionCorrelationRef({
      runtimeInstanceId, runId: correlation.run_id,
      toolCallId: correlation.tool_call_id,
    }),
    tool_call_id: correlation.tool_call_id,
    run_id: correlation.run_id,
    runtime_name: "openclaw",
    runtime_version: runtimeVersion,
    runtime_instance_id: runtimeInstanceId,
    mode: SHADOW_RELEASE.mode,
    authority: SHADOW_RELEASE.authority,
    enforcement: SHADOW_RELEASE.enforcement,
    active: SHADOW_RELEASE.active,
  };
  request.request_hash = sha256(stableStringify(request));
  const bytes = Buffer.from(stableStringify(request), "utf8");
  if (bytes.length > SHADOW_MAX_REQUEST_BYTES) {
    return Object.freeze({ ok: false, scope, reason: "request_oversize", missing: [] });
  }
  return Object.freeze({
    ok: true,
    scope,
    correlation,
    request: Object.freeze(request),
    executableClass: commandIdentity.executableClass,
    body: bytes,
    fingerprint: `${scope.tool_name}\n${agentId}\n${request.argument_digest}`,
  });
}

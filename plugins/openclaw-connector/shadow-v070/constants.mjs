export const SHADOW_RELEASE = Object.freeze({
  schema: "observa-openclaw-shadow-release/v1",
  package_name: "@mcphersonai/mcpherson-governance-openclaw",
  version: "0.7.4",
  mode: "SHADOW",
  authority: "NONE",
  enforcement: "OFF",
  active: false,
  active_capable: false,
});

export const SHADOW_EVALUATION_PATH = "/v1/openclaw/shadow/evaluate";
export const SHADOW_REQUEST_SCHEMA = "observa-openclaw-shadow-evaluation/v1";
export const SHADOW_RESPONSE_SCHEMA = "observa-openclaw-shadow-decision/v1";
export const MIN_SHADOW_OPENCLAW_VERSION = "2026.8.2";
export const SHADOW_DECISION_TIMEOUT_MS = 3_000;
export const SHADOW_HOOK_TIMEOUT_MS = 5_000;
export const SHADOW_MAX_RESPONSE_BYTES = 32 * 1024;
export const SHADOW_MAX_REQUEST_BYTES = 8 * 1024;
export const SHADOW_DECISION_WINDOW = 1_024;
export const SHADOW_CORRELATION_WINDOW = 1_024;
export const SHADOW_EVIDENCE_FILE = "shadow-v070-evidence.jsonl";

export const SHADOW_ACTIONS = Object.freeze({
  ALLOW: "SHADOW_WOULD_ALLOW",
  DENY: "SHADOW_WOULD_DENY",
  REQUIRE_APPROVAL: "SHADOW_WOULD_REQUIRE_APPROVAL",
  INDETERMINATE: "INDETERMINATE",
  ERROR: "ERROR",
});

export const SHADOW_ABSTRACT_DECISIONS = Object.freeze([
  "ALLOW",
  "DENY",
  "REQUIRE_APPROVAL",
  "INDETERMINATE",
  "ERROR",
]);

export const SHADOW_GOVERNED_TOOLS = Object.freeze({
  exec: Object.freeze({
    canonical_name: "exec",
    tool_id: "openclaw:exec",
    action_class: "command_execution",
    resource_class: "host-command",
    runtime_tool_kind: "OPENCLAW_EXEC",
  }),
  openclawexec: Object.freeze({
    canonical_name: "exec",
    tool_id: "openclaw:exec",
    action_class: "command_execution",
    resource_class: "host-command",
    runtime_tool_kind: "OPENCLAW_EXEC",
  }),
});

export const SHADOW_FORBIDDEN_CONFIG_KEYS = Object.freeze([
  "mode",
  "authority",
  "active",
  "enforcement",
  "allowActiveEnforcement",
  "denyEnforcement",
  "approvalEnforcement",
  "approvalAuthority",
  "operatorToken",
  "operatorTokenFile",
]);

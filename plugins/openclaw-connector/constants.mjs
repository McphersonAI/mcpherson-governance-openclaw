export const PLUGIN_ID = "mcpherson-governance-connector";
export const PLUGIN_NAME = "McPherson Governance Connector";
export const PLUGIN_VERSION = "0.6.3-beta.6";

// Source-owned runtime compatibility floor. It is enforced by the connector at
// activation time and is deliberately not delegated to package-manager or
// host-side compatibility metadata, which is not enforced by every installer.
export const MIN_SUPPORTED_OPENCLAW_VERSION = "2026.6.5";

// The connector's state root is always this directory name inside the ACTIVE
// OpenClaw profile state directory.
export const CONNECTOR_STATE_DIR_NAME = "mcpherson-governance-connector";

// These are source-owned authority ceilings. They are deliberately not derived
// from configuration, environment variables, policy documents, or API data.
export const REMOTE_AUTHORITY = false;
export const ENFORCEABLE_REMOTE_DECISIONS = Object.freeze([]);
export const DEFAULT_MODES = Object.freeze({
  remote_shadow: true,
  remote_authority: false,
  deny_enforcement: false,
  approval_enforcement: false,
});

export const RECEIPT_MODE = "POST_HOOK";
export const SUPPORTED_POST_HOOK = "after_tool_call";
export const API_VERSION = "mgp/1";
export const DEFAULT_OBSERVATION_BUDGET_MS = 150;
export const MAX_OBSERVATION_BUDGET_MS = 500;
export const ABSOLUTE_OBSERVATION_CAP_MS = 5_000;
export const DEFAULT_CONNECT_TIMEOUT_MS = 2_000;
export const MAX_OBSERVATIONS_IN_FLIGHT = 4;
export const MAX_OBSERVATION_QUEUE = 16;
export const MAX_OUTBOUND_BYTES = 8 * 1024;
export const MAX_RESPONSE_BYTES = 32 * 1024;
export const MAX_NETWORK_RETRIES = 1;
export const CIRCUIT_FAILURE_THRESHOLD = 5;
export const CIRCUIT_OPEN_MS = 60_000;

export const CONNECTION_TOOL_NAME = "mcpherson_connection_test";
export const CONNECTION_MARKER = "MCPHERSON_GOVERNANCE_CONNECTION_OK_V1";
export const CANARY_TOOL_NAME = "mcpherson_governance_canary";
export const CANARY_TOKEN = "mcpherson-canary-block-v1";
export const CANARY_MARKER = "MCPHERSON_GOVERNANCE_CANARY_OK_V1";

export const RECEIPT_SCHEMA = "mcpherson-governance-evidence/v2";
export const RECEIPT_FILE = "connector-receipts.jsonl";
export const CREDENTIAL_FILE = "deployment-credential";
export const KILL_SWITCH_FILE = "governance-killswitch.on";
export const SYSTEM_LOCK_FILE = "system.lock";
export const DISABLED_FILE = "connector-disabled.on";
export const CANARY_CONTROL_FILE = "canary-control.json";

export const DECISIONS = Object.freeze([
  "ALLOW",
  "ALLOW_AND_LOG",
  "REQUIRE_APPROVAL",
  "DENY",
  "SHADOW_ONLY",
  "HOLD",
]);

export const ATTEMPT_OUTCOMES = Object.freeze(["UNKNOWN", "NOT_OBSERVED"]);
export const COMPLETION_OUTCOMES = Object.freeze(["COMPLETED", "FAILED", "TIMED_OUT"]);

export const FORBIDDEN_AUTHORITY_CONFIG_KEYS = Object.freeze([
  "REMOTE_AUTHORITY",
  "remoteAuthority",
  "remote_authority",
  "ENFORCEABLE_REMOTE_DECISIONS",
  "enforceableRemoteDecisions",
  "allowActiveEnforcement",
  "denyEnforcement",
  "deny_enforcement",
  "approvalEnforcement",
  "approval_enforcement",
  "requireApproval",
  "block",
]);

export const OUTBOUND_FIELDS = Object.freeze([
  "api_version",
  "request_id",
  "nonce",
  "timestamp",
  "agent_id",
  "tool_id",
  "tool_schema_version",
  "tool_schema_hash",
  "action_class",
  "resource_class",
  "recipient_type",
  "recipient_count",
  "attachment_indicator",
  "data_sensitivity_label",
  "reversibility_label",
  "request_hash",
  "policy_version",
  "correlation_ref",
]);

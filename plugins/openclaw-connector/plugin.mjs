import { fileURLToPath } from "node:url";
import { createGovernanceConnector } from "./index.mjs";
import { ensureObservaEntrypoint } from "./cli-entrypoint.mjs";
import { onInternalDiagnosticEvent } from "openclaw/plugin-sdk/diagnostic-runtime";

// The installed package root: the directory the managed `observa` launcher runs.
const PACKAGE_ROOT = fileURLToPath(new URL("../..", import.meta.url));

// Only filesystem locations may be overridden by environment. Identity,
// transport authority, decisions, enforcement, and credentials cannot be.
const pathOverrides = Object.freeze({
  ...(process.env.MCP_GOVERNANCE_STATE_DIR ? { stateDir: process.env.MCP_GOVERNANCE_STATE_DIR } : {}),
  ...(process.env.MCP_GOVERNANCE_RECEIPT_DIR ? { receiptDir: process.env.MCP_GOVERNANCE_RECEIPT_DIR } : {}),
});

export default createGovernanceConnector({
  pathOverrides,
  subscribeDiagnostics: onInternalDiagnosticEvent,
  cliEntrypoint: (config) => ensureObservaEntrypoint({ packageRoot: PACKAGE_ROOT, stateDir: config.stateDir }),
});

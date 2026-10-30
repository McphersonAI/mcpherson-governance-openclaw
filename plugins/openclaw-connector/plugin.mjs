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
  cliEntrypoint: (config, api) => {
    // The public API identifies the durable installation; import.meta may be
    // a disposable host capture in OpenClaw 2026.10.9.
    const packageRoot = api.rootDir ?? PACKAGE_ROOT;
    const namespaced = ensureObservaEntrypoint({ packageRoot, stateDir: config.stateDir, entrypointName: "observa-openclaw" });
    return ensureObservaEntrypoint({ packageRoot, stateDir: config.stateDir, namespaced });
  },
});

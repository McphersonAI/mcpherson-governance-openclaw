import { createGovernanceConnector } from "./index.mjs";

// Only filesystem locations may be overridden by environment. Identity,
// transport authority, decisions, enforcement, and credentials cannot be.
const pathOverrides = Object.freeze({
  ...(process.env.MCP_GOVERNANCE_STATE_DIR ? { stateDir: process.env.MCP_GOVERNANCE_STATE_DIR } : {}),
  ...(process.env.MCP_GOVERNANCE_RECEIPT_DIR ? { receiptDir: process.env.MCP_GOVERNANCE_RECEIPT_DIR } : {}),
});

export default createGovernanceConnector({ pathOverrides });


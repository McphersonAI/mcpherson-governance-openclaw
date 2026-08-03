import {
  closeSync,
  constants as C,
  fchmodSync,
  fsyncSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import {
  PLUGIN_ID,
  PLUGIN_VERSION,
  RECEIPT_FILE,
} from "./constants.mjs";
import {
  validateAttemptReceipt,
  validateCompletionReceipt,
} from "./runtime/governance-core/index.mjs";
import { ensureSecureDir, errorCode, openRegularOwnedFile } from "./secure-files.mjs";

const SAFE_ID = /^[A-Za-z0-9._:-]{1,160}$/;
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const ALLOWED_KEYS = Object.freeze({
  connector_lifecycle: new Set([
    "schema", "record_id", "record_type", "plugin_id", "plugin_version",
    "timestamp", "event", "receipt_mode", "remote_authority", "enforceable_remote_decisions",
  ]),
});

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function assertTimestamp(value) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)) || /\r|\n/.test(value)) fail("RECEIPT_TIMESTAMP_INVALID");
}

function ulid(now = Date.now()) {
  let time = BigInt(now);
  let random = BigInt(`0x${randomBytes(10).toString("hex")}`);
  let value = (time << 80n) | random;
  let output = "";
  for (let index = 0; index < 26; index += 1) {
    output = CROCKFORD[Number(value & 31n)] + output;
    value >>= 5n;
  }
  return output;
}

export function validateReceipt(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) fail("RECEIPT_INVALID");
  if (record.record_type === "connector_lifecycle") {
    const allowed = ALLOWED_KEYS.connector_lifecycle;
    if (Object.keys(record).some((key) => !allowed.has(key))) fail("LIFECYCLE_FIELD_INVALID");
    if (record.schema !== "mcpherson-governance-connector-lifecycle/v1" || record.plugin_id !== PLUGIN_ID || record.plugin_version !== PLUGIN_VERSION) fail("LIFECYCLE_IDENTITY_INVALID");
    if (!["POST_HOOK", "ATTEMPT_ONLY"].includes(record.receipt_mode)
        || !["gateway_start", "gateway_stop"].includes(record.event)
        || record.remote_authority !== false
        || !Array.isArray(record.enforceable_remote_decisions)
        || record.enforceable_remote_decisions.length !== 0) fail("LIFECYCLE_CAPABILITY_INVALID");
    if (typeof record.record_id !== "string" || !SAFE_ID.test(record.record_id)) fail("LIFECYCLE_ID_INVALID");
    assertTimestamp(record.timestamp);
    return true;
  }
  const validation = record.receipt_type === "attempt_receipt"
    ? validateAttemptReceipt(record)
    : record.receipt_type === "completion_receipt"
      ? validateCompletionReceipt(record)
      : { ok: false };
  if (!validation.ok) fail("RECEIPT_CONTRACT_INVALID");
  return true;
}

function base(receiptType, now = new Date()) {
  return {
    receipt_id: ulid(now.getTime()),
    receipt_type: receiptType,
    timestamp: now.toISOString(),
  };
}

export function makeAttemptReceipt(fields, now = new Date()) {
  const receipt = {
    ...base("attempt_receipt", now),
    decision_id: fields.decisionId ?? null,
    request_hash: fields.requestHash,
    deployment_id: fields.deploymentId,
    agent_id: fields.agentId,
    tool_id: fields.toolId,
    attempt_at: fields.attemptAt || now.toISOString(),
    outcome: fields.outcome || "NOT_OBSERVED",
    remote_status: fields.remoteStatus,
    local_disposition: fields.localDisposition || "NONE",
    correlation_ref: fields.correlationRef,
  };
  validateReceipt(receipt);
  return Object.freeze(receipt);
}

export function makeCompletionReceipt(fields, now = new Date()) {
  const receipt = {
    ...base("completion_receipt", now),
    decision_id: fields.decisionId ?? null,
    request_hash: fields.requestHash,
    deployment_id: fields.deploymentId,
    agent_id: fields.agentId,
    tool_id: fields.toolId,
    completed_at: fields.completedAt || now.toISOString(),
    outcome: fields.outcome,
    observation_basis: "DIRECT_SUPPORTED_POST_HOOK",
    correlation_ref: fields.correlationRef,
    ...(fields.errorCategory ? { error_category: fields.errorCategory } : {}),
  };
  validateReceipt(receipt);
  return Object.freeze(receipt);
}

export function makeLifecycleReceipt(fields, now = new Date()) {
  const receipt = {
    schema: "mcpherson-governance-connector-lifecycle/v1",
    record_id: ulid(now.getTime()),
    record_type: "connector_lifecycle",
    plugin_id: PLUGIN_ID,
    plugin_version: PLUGIN_VERSION,
    timestamp: now.toISOString(),
    event: fields.event,
    receipt_mode: fields.receiptMode,
    remote_authority: false,
    enforceable_remote_decisions: [],
  };
  validateReceipt(receipt);
  return Object.freeze(receipt);
}

export class HardenedReceiptWriter {
  #path;
  #logger;
  #closed = false;
  #counts = { attempt_receipt: 0, completion_receipt: 0, connector_lifecycle: 0 };

  constructor(receiptDir, logger = null) {
    ensureSecureDir(receiptDir);
    this.#path = join(receiptDir, RECEIPT_FILE);
    this.#logger = logger;
  }

  write(record) {
    if (this.#closed) return { ok: false, error: "WRITER_CLOSED" };
    validateReceipt(record);
    let fd;
    try {
      fd = openRegularOwnedFile(this.#path, C.O_WRONLY | C.O_APPEND | C.O_CREAT | C.O_NONBLOCK, 0o600);
      fchmodSync(fd, 0o600);
      writeSync(fd, `${JSON.stringify(record)}\n`, null, "utf8");
      fsyncSync(fd);
      this.#counts[record.receipt_type || record.record_type] += 1;
      return { ok: true };
    } catch (error) {
      if (this.#logger && typeof this.#logger.error === "function") this.#logger.error(`[${PLUGIN_ID}] receipt write failed (${errorCode(error)})`);
      return { ok: false, error: errorCode(error) };
    } finally { if (fd !== undefined) closeSync(fd); }
  }

  status() {
    return Object.freeze({ path: this.#path, closed: this.#closed, counts: Object.freeze({ ...this.#counts }) });
  }

  close() { this.#closed = true; }
}

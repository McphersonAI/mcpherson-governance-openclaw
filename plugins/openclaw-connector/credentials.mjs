import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readdirSync,
} from "node:fs";
import { basename, join } from "node:path";
import { CREDENTIAL_FILE } from "./constants.mjs";
import {
  ATOMIC_WRITE_TRANSITIONS,
  atomicReplaceSecureFile,
  atomicWriteSecureFile,
  ensureSecureDir,
  errorCode,
  readSecureFile,
  secureUnlink,
  writeExclusiveSecureFile,
} from "./secure-files.mjs";

const TOKEN_RE = /^mgd1_([a-f0-9]{32})\.([A-Za-z0-9_-]{43})$/;
const ID_RE = /^[a-f0-9]{32}$/;
const FINGERPRINT_RE = /^sha256:[a-f0-9]{16}$/;
const ROTATION_RECOVERY_FILE = "credential-rotation-recovery.json";
const ROTATION_SCHEMA = "mcpherson-credential-rotation-recovery/v3";
const ROTATION_JOURNAL_TEMP_PREFIX = ".credential-rotation-journal-tmp-";
export const JOURNAL_DURABILITY_TRANSITIONS = ATOMIC_WRITE_TRANSITIONS;
export const ROTATION_OVERLAP_MS = 5 * 60_000;
export const LOCAL_ROTATION_STATES = Object.freeze({
  PENDING: "PENDING",
  ACTIVATED: "ACTIVATED_REVOCATION_PENDING",
  COMPLETED: "COMPLETED",
  EXPIRING: "PENDING_EXPIRED_ROLLBACK",
  CANCELLED: "CANCELLED",
});
export const LOCAL_ROTATION_TRANSITIONS = Object.freeze([
  "JOURNAL_PENDING",
  "NEW_FILE_FSYNCED",
  "JOURNAL_NEW_STAGED",
  "OLD_FILE_PRESERVED",
  "JOURNAL_OLD_PRESERVED",
  "NEW_VERIFIED",
  "JOURNAL_NEW_VERIFIED",
  "ACTIVE_REPLACED_DIR_FSYNCED",
  "JOURNAL_ACTIVE_INSTALLED",
  "ACTIVE_USE_CONFIRMED",
  "JOURNAL_ACTIVE_CONFIRMED",
  "REVOCATION_REQUESTED",
  "SERVER_COMPLETED",
  "JOURNAL_SERVER_COMPLETED",
  "RETIRED_UNLINKED_DIR_FSYNCED",
  "JOURNAL_RETIRED_REMOVED",
  "JOURNAL_UNLINKED_DIR_FSYNCED",
]);
export const LOCAL_ROTATION_EXPIRY_TRANSITIONS = Object.freeze([
  "JOURNAL_PENDING_EXPIRY_CONFIRMED",
  "OLD_RESTORED_DIR_FSYNCED",
  "JOURNAL_OLD_RESTORED",
  "SERVER_PENDING_CANCELLED",
  "JOURNAL_SERVER_CANCELLED",
  "JOURNAL_UNLINKED_DIR_FSYNCED",
]);

const STEPS = new Set([
  "JOURNALED",
  "NEW_STAGED",
  "OLD_PRESERVED",
  "NEW_VERIFIED",
  "ACTIVE_INSTALLED",
  "ACTIVE_CONFIRMED",
  "REVOCATION_REQUESTED",
  "SERVER_COMPLETED",
  "RETIRED_REMOVED",
  "PENDING_EXPIRY_CONFIRMED",
  "OLD_RESTORED",
  "SERVER_CANCELLED",
]);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function rotationError(code, journal, extra = {}) {
  const error = new Error(code);
  error.code = code;
  error.recovery = Object.freeze({
    status: journal.state,
    step: journal.step,
    serverRotationId: journal.serverRotationId,
    oldCredentialId: journal.oldCredentialId,
    oldFingerprint: journal.oldFingerprint,
    newCredentialId: journal.newCredentialId,
    newFingerprint: journal.newFingerprint,
    pendingDeadline: journal.pendingDeadline,
    overlapDeadline: journal.overlapDeadline,
    cancelledAt: journal.cancelledAt,
    serverActivationConfirmed: journal.serverActivationConfirmed,
    recoveryCommand: journal.state === LOCAL_ROTATION_STATES.CANCELLED
      ? null
      : "node connector-ctl.mjs recover --new-credential-file <original-expected-path>",
    ...extra,
  });
  return error;
}

function instant(now) {
  const value = now();
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) fail("CREDENTIAL_ROTATION_TIME_INVALID");
  return date.toISOString();
}

function plusMilliseconds(iso, milliseconds) {
  return new Date(Date.parse(iso) + milliseconds).toISOString();
}

function defaultFileOps(overrides = {}, rename = null, injectFileFault = null) {
  return Object.freeze({
    atomicWrite: overrides.atomicWrite ?? atomicWriteSecureFile,
    writeExclusive: overrides.writeExclusive ?? ((path, bytes) => writeExclusiveSecureFile(
      path,
      bytes,
      { injectFault: injectFileFault },
    )),
    replace: overrides.replace ?? ((from, to) => atomicReplaceSecureFile(
      from,
      to,
      { ...(rename ? { rename } : {}), injectFault: injectFileFault },
    )),
    read: overrides.read ?? readSecureFile,
    unlink: overrides.unlink ?? secureUnlink,
  });
}

async function checkpoint(injectFault, point, phase, journal) {
  if (typeof injectFault !== "function") return;
  await injectFault(Object.freeze({
    point,
    phase,
    state: journal?.state ?? null,
    step: journal?.step ?? null,
    serverRotationId: journal?.serverRotationId ?? null,
    oldCredentialId: journal?.oldCredentialId ?? null,
    newCredentialId: journal?.newCredentialId ?? null,
  }));
}

export function credentialPath(stateDir) { return join(stateDir, CREDENTIAL_FILE); }

export function parseCredential(value) {
  const string = Buffer.isBuffer(value) ? value.toString("utf8").trim() : String(value).trim();
  const match = TOKEN_RE.exec(string);
  if (!match) fail("CREDENTIAL_FORMAT_INVALID");
  return Object.freeze({
    credentialId: match[1],
    fingerprint: `sha256:${createHash("sha256").update(string).digest("hex").slice(0, 16)}`,
  });
}

export function installCredential(stateDir, value) {
  ensureSecureDir(stateDir);
  const bytes = Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(String(value), "utf8");
  let normalized;
  try {
    parseCredential(bytes);
    normalized = Buffer.from(`${bytes.toString("utf8").trim()}\n`);
    atomicWriteSecureFile(
      credentialPath(stateDir),
      normalized,
      { exclusiveDestination: true },
    );
    return parseCredential(bytes);
  } finally {
    bytes.fill(0);
    if (normalized) normalized.fill(0);
  }
}

export async function withCredential(stateDir, callback) {
  const bytes = readSecureFile(credentialPath(stateDir), 512);
  try {
    const token = bytes.toString("utf8").trim();
    const descriptor = parseCredential(token);
    return await callback(token, descriptor);
  } finally { bytes.fill(0); }
}

export function rotationRecoveryPath(stateDir) { return join(stateDir, ROTATION_RECOVERY_FILE); }

function stageFilename(credentialId) { return `.credential-next-${credentialId}`; }
function retiredFilename(credentialId) { return `.credential-retired-${credentialId}`; }

function validateJournal(value) {
  const exactKeys = [
    "activatedAt",
    "activeConfirmedAt",
    "cancelledAt",
    "completedAt",
    "newCredentialId",
    "newFingerprint",
    "oldCredentialId",
    "oldFingerprint",
    "overlapDeadline",
    "pendingDeadline",
    "retiredFile",
    "schema",
    "serverActivationConfirmed",
    "serverRotationId",
    "stageFile",
    "startedAt",
    "state",
    "step",
  ];
  const stateStepValid = value?.state === LOCAL_ROTATION_STATES.PENDING
    && ["JOURNALED", "NEW_STAGED", "OLD_PRESERVED", "NEW_VERIFIED"].includes(value?.step)
    || value?.state === LOCAL_ROTATION_STATES.ACTIVATED
      && ["ACTIVE_INSTALLED", "ACTIVE_CONFIRMED", "REVOCATION_REQUESTED"].includes(value?.step)
    || value?.state === LOCAL_ROTATION_STATES.COMPLETED
      && ["SERVER_COMPLETED", "RETIRED_REMOVED"].includes(value?.step)
    || value?.state === LOCAL_ROTATION_STATES.EXPIRING
      && ["PENDING_EXPIRY_CONFIRMED", "OLD_RESTORED"].includes(value?.step)
    || value?.state === LOCAL_ROTATION_STATES.CANCELLED
      && value?.step === "SERVER_CANCELLED";
  const validInstant = (candidate) => Number.isFinite(Date.parse(candidate));
  const stateFieldsValid = value?.state === LOCAL_ROTATION_STATES.PENDING
    ? value.activatedAt === null && value.overlapDeadline === null
      && value.pendingDeadline === null && value.activeConfirmedAt === null
      && value.completedAt === null && value.cancelledAt === null
      && !value.serverActivationConfirmed
    : value?.state === LOCAL_ROTATION_STATES.ACTIVATED
      ? validInstant(value.activatedAt) && validInstant(value.overlapDeadline)
        && value.pendingDeadline === null && value.completedAt === null
        && value.cancelledAt === null
        && (value.step === "ACTIVE_INSTALLED"
          ? value.activeConfirmedAt === null && !value.serverActivationConfirmed
          : validInstant(value.activeConfirmedAt) && value.serverActivationConfirmed)
      : value?.state === LOCAL_ROTATION_STATES.COMPLETED
        ? validInstant(value.activatedAt) && validInstant(value.overlapDeadline)
          && validInstant(value.activeConfirmedAt) && validInstant(value.completedAt)
          && value.pendingDeadline === null && value.cancelledAt === null
          && value.serverActivationConfirmed
        : value?.state === LOCAL_ROTATION_STATES.EXPIRING
          ? validInstant(value.activatedAt) && validInstant(value.overlapDeadline)
            && validInstant(value.pendingDeadline) && value.activeConfirmedAt === null
            && value.completedAt === null && value.cancelledAt === null
            && !value.serverActivationConfirmed
          : value?.state === LOCAL_ROTATION_STATES.CANCELLED
            && validInstant(value.activatedAt) && validInstant(value.overlapDeadline)
            && validInstant(value.pendingDeadline) && validInstant(value.cancelledAt)
            && value.activeConfirmedAt === null && value.completedAt === null
            && !value.serverActivationConfirmed;
  if (!value || typeof value !== "object" || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(exactKeys)
      || value.schema !== ROTATION_SCHEMA
      || !Object.values(LOCAL_ROTATION_STATES).includes(value.state)
      || !STEPS.has(value.step)
      || !stateStepValid
      || !stateFieldsValid
      || !ID_RE.test(value.serverRotationId)
      || !ID_RE.test(value.oldCredentialId)
      || !ID_RE.test(value.newCredentialId)
      || value.oldCredentialId === value.newCredentialId
      || !FINGERPRINT_RE.test(value.oldFingerprint)
      || !FINGERPRINT_RE.test(value.newFingerprint)
      || value.stageFile !== stageFilename(value.newCredentialId)
      || value.retiredFile !== retiredFilename(value.oldCredentialId)
      || basename(value.stageFile) !== value.stageFile
      || basename(value.retiredFile) !== value.retiredFile
      || !Number.isFinite(Date.parse(value.startedAt))
      || value.activatedAt !== null && !Number.isFinite(Date.parse(value.activatedAt))
      || value.overlapDeadline !== null && !Number.isFinite(Date.parse(value.overlapDeadline))
      || value.pendingDeadline !== null && !Number.isFinite(Date.parse(value.pendingDeadline))
      || value.activeConfirmedAt !== null && !Number.isFinite(Date.parse(value.activeConfirmedAt))
      || value.completedAt !== null && !Number.isFinite(Date.parse(value.completedAt))
      || value.cancelledAt !== null && !Number.isFinite(Date.parse(value.cancelledAt))
      || typeof value.serverActivationConfirmed !== "boolean"
  ) {
    fail("CREDENTIAL_ROTATION_JOURNAL_INVALID");
  }
  const rendered = JSON.stringify(value);
  if (TOKEN_RE.test(rendered) || rendered.includes("mgd1_")) {
    fail("CREDENTIAL_ROTATION_JOURNAL_SECRET");
  }
  return Object.freeze({ ...value });
}

function reconcileRotationJournalTemps(stateDir) {
  const target = rotationRecoveryPath(stateDir);
  const paths = readdirSync(stateDir)
    .filter((name) => name.startsWith(ROTATION_JOURNAL_TEMP_PREFIX))
    .map((name) => join(stateDir, name));
  if (paths.length === 0) return;
  const owned = [];
  const valid = [];
  for (const path of paths) {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600
        || typeof process.getuid === "function" && stat.uid !== process.getuid()) {
      fail("CREDENTIAL_ROTATION_JOURNAL_TEMP_INSECURE");
    }
    owned.push(path);
    if (existsSync(target)) continue;
    let bytes;
    try {
      bytes = readSecureFile(path, 4096);
      const value = validateJournal(JSON.parse(bytes.toString("utf8")));
      valid.push({ path, bytes: Buffer.from(bytes), value });
    } catch {
      // An owned exact-prefix zero/partial temp is an interrupted journal write,
      // not an authority-bearing record. It is retired below with directory fsync.
    } finally { if (bytes) bytes.fill(0); }
  }
  try {
    if (!existsSync(target) && valid.length > 0) {
      const canonical = JSON.stringify(valid[0].value);
      if (valid.some((entry) => JSON.stringify(entry.value) !== canonical)) {
        fail("CREDENTIAL_ROTATION_JOURNAL_TEMP_CONFLICT");
      }
      atomicWriteSecureFile(target, valid[0].bytes, {
        exclusiveDestination: true,
        temporaryPrefix: ROTATION_JOURNAL_TEMP_PREFIX,
      });
    }
  } finally {
    for (const entry of valid) entry.bytes.fill(0);
  }
  for (const path of owned) secureUnlink(path);
}

export function readRotationRecovery(stateDir) {
  reconcileRotationJournalTemps(stateDir);
  const bytes = readSecureFile(rotationRecoveryPath(stateDir), 4096);
  try {
    return validateJournal(JSON.parse(bytes.toString("utf8")));
  } catch (error) {
    if (error?.code === "CREDENTIAL_ROTATION_JOURNAL_INVALID") throw error;
    fail("CREDENTIAL_ROTATION_JOURNAL_INVALID");
  } finally { bytes.fill(0); }
}

async function persistJournal(stateDir, journal, point, options, exclusive = false) {
  const value = validateJournal({ schema: ROTATION_SCHEMA, ...journal });
  await checkpoint(options.injectFault, point, "before", value);
  options.fileOps.atomicWrite(
    rotationRecoveryPath(stateDir),
    Buffer.from(`${JSON.stringify(value)}\n`),
    {
      exclusiveDestination: exclusive,
      injectFault: options.injectJournalFault,
      temporaryPrefix: ROTATION_JOURNAL_TEMP_PREFIX,
    },
  );
  await checkpoint(options.injectFault, point, "after", value);
  return value;
}

function descriptorAt(path, fileOps, { optional = false } = {}) {
  let bytes;
  try {
    bytes = fileOps.read(path, 512);
    return parseCredential(bytes);
  } catch (error) {
    if (optional && errorCode(error) === "ENOENT") return null;
    throw error;
  } finally { if (bytes) bytes.fill(0); }
}

function descriptorAtAfterInterruptedCreate(path, fileOps, {
  optional = false,
  recoverIncomplete = false,
} = {}) {
  try {
    return descriptorAt(path, fileOps, { optional });
  } catch (error) {
    if (!recoverIncomplete || errorCode(error) !== "INVALID_SIZE") throw error;
    fileOps.unlink(path);
    return null;
  }
}

async function withCredentialFile(path, fileOps, callback) {
  const bytes = fileOps.read(path, 512);
  try {
    const token = bytes.toString("utf8").trim();
    return await callback(token, parseCredential(token));
  } finally { bytes.fill(0); }
}

function field(value, camel, snake = camel) {
  if (!value || typeof value !== "object") return undefined;
  return Object.hasOwn(value, camel) ? value[camel] : value[snake];
}

function exactVerification(value, journal) {
  return field(value, "status") === "VERIFIED"
    && field(value, "credentialId", "credential_id") === journal.newCredentialId
    && field(value, "rotationId", "rotation_id") === journal.serverRotationId;
}

function exactActiveConfirmation(value, journal) {
  const deadline = field(value, "overlapDeadline", "overlap_deadline");
  const activatedMs = Date.parse(journal.activatedAt);
  const deadlineMs = Date.parse(deadline);
  return field(value, "status") === "ACTIVE"
    && field(value, "credentialId", "credential_id") === journal.newCredentialId
    && field(value, "rotationId", "rotation_id") === journal.serverRotationId
    && field(value, "rotationStatus", "rotation_status") === LOCAL_ROTATION_STATES.ACTIVATED
    && Number.isFinite(deadlineMs)
    && deadlineMs >= activatedMs;
}

function exactExpiredPending(value, journal, observedAt) {
  const pendingDeadline = field(value, "pendingDeadline", "pending_deadline");
  return field(value, "state", "rotation_status") === LOCAL_ROTATION_STATES.PENDING
    && field(value, "rotationId", "rotation_id") === journal.serverRotationId
    && field(value, "oldCredentialId", "old_credential_id") === journal.oldCredentialId
    && field(value, "oldFingerprint", "old_fingerprint") === journal.oldFingerprint
    && field(value, "newCredentialId", "new_credential_id") === journal.newCredentialId
    && field(value, "newFingerprint", "new_fingerprint") === journal.newFingerprint
    && Number.isFinite(Date.parse(pendingDeadline))
    && Date.parse(pendingDeadline) <= Date.parse(observedAt)
    && field(value, "activatedAt", "activated_at") === null
    && field(value, "cancelledAt", "cancelled_at") === null;
}

function exactPendingCancellation(value, journal) {
  return field(value, "state", "rotation_status") === LOCAL_ROTATION_STATES.CANCELLED
    && field(value, "rotationId", "rotation_id") === journal.serverRotationId
    && field(value, "oldCredentialId", "old_credential_id") === journal.oldCredentialId
    && field(value, "oldFingerprint", "old_fingerprint") === journal.oldFingerprint
    && field(value, "newCredentialId", "new_credential_id") === journal.newCredentialId
    && field(value, "newFingerprint", "new_fingerprint") === journal.newFingerprint
    && Number.isFinite(Date.parse(field(value, "cancelledAt", "cancelled_at")))
    && Number.isFinite(Date.parse(field(value, "outputRetiredAt", "output_retired_at")));
}

function exactRevocation(value, journal) {
  return field(value, "status") === "REVOKED"
    && field(value, "credentialId", "credential_id") === journal.oldCredentialId
    && field(value, "activeCredentialId", "active_credential_id") === journal.newCredentialId
    && field(value, "rotationId", "rotation_id") === journal.serverRotationId
    && field(value, "rotationStatus", "rotation_status") === LOCAL_ROTATION_STATES.COMPLETED;
}

function assertDescriptor(actual, credentialId, fingerprint, code) {
  if (!actual || actual.credentialId !== credentialId || actual.fingerprint !== fingerprint) fail(code);
}

function sanitizeCallbackFailure(code, journal) {
  return rotationError(code, journal);
}

async function driveRotation(stateDir, callbacks, options, pendingBytes = null) {
  let journal = readRotationRecovery(stateDir);
  const activePath = credentialPath(stateDir);
  const stagedPath = join(stateDir, journal.stageFile);
  const retiredPath = join(stateDir, journal.retiredFile);

  if (journal.state === LOCAL_ROTATION_STATES.PENDING) {
    const active = descriptorAt(activePath, options.fileOps);
    if (active.credentialId === journal.newCredentialId
        && active.fingerprint === journal.newFingerprint) {
      assertDescriptor(
        descriptorAt(retiredPath, options.fileOps),
        journal.oldCredentialId,
        journal.oldFingerprint,
        "CREDENTIAL_ROTATION_RETIRED_MISMATCH",
      );
      const inferredActivation = journal.activatedAt ?? instant(options.now);
      journal = await persistJournal(stateDir, {
        ...journal,
        state: LOCAL_ROTATION_STATES.ACTIVATED,
        step: "ACTIVE_INSTALLED",
        activatedAt: inferredActivation,
        overlapDeadline: journal.overlapDeadline
          ?? plusMilliseconds(inferredActivation, ROTATION_OVERLAP_MS),
        serverActivationConfirmed: false,
      }, "ACTIVE_REPLACED_DIR_FSYNCED", options);
    } else {
      assertDescriptor(
        active,
        journal.oldCredentialId,
        journal.oldFingerprint,
        "CREDENTIAL_ROTATION_ACTIVE_MISMATCH",
      );
      let staged = descriptorAtAfterInterruptedCreate(
        stagedPath,
        options.fileOps,
        { optional: true, recoverIncomplete: journal.step === "JOURNALED" },
      );
      if (!staged) {
        if (!pendingBytes) throw rotationError("CREDENTIAL_ROTATION_PENDING_MATERIAL_MISSING", journal);
        assertDescriptor(
          parseCredential(pendingBytes),
          journal.newCredentialId,
          journal.newFingerprint,
          "CREDENTIAL_ROTATION_PENDING_MATERIAL_MISMATCH",
        );
        await checkpoint(options.injectFault, "NEW_FILE_FSYNCED", "before", journal);
        const stagedBytes = Buffer.from(`${pendingBytes.toString("utf8").trim()}\n`);
        try {
          options.fileOps.writeExclusive(stagedPath, stagedBytes);
        } catch (error) {
          if (errorCode(error) === "SIMULATED_CRASH") throw error;
          throw rotationError("CREDENTIAL_ROTATION_STAGE_CREATE_FAILED", journal);
        } finally { stagedBytes.fill(0); }
        await checkpoint(options.injectFault, "NEW_FILE_FSYNCED", "after", journal);
        staged = descriptorAt(stagedPath, options.fileOps);
      }
      assertDescriptor(
        staged,
        journal.newCredentialId,
        journal.newFingerprint,
        "CREDENTIAL_ROTATION_STAGED_MISMATCH",
      );
      journal = await persistJournal(stateDir, {
        ...journal, step: "NEW_STAGED",
      }, "JOURNAL_NEW_STAGED", options);

      let retired = descriptorAtAfterInterruptedCreate(
        retiredPath,
        options.fileOps,
        { optional: true, recoverIncomplete: journal.step === "NEW_STAGED" },
      );
      if (!retired) {
        const oldBytes = options.fileOps.read(activePath, 512);
        try {
          await checkpoint(options.injectFault, "OLD_FILE_PRESERVED", "before", journal);
          options.fileOps.writeExclusive(retiredPath, oldBytes);
          await checkpoint(options.injectFault, "OLD_FILE_PRESERVED", "after", journal);
        } finally { oldBytes.fill(0); }
        retired = descriptorAt(retiredPath, options.fileOps);
      }
      assertDescriptor(
        retired,
        journal.oldCredentialId,
        journal.oldFingerprint,
        "CREDENTIAL_ROTATION_RETIRED_MISMATCH",
      );
      journal = await persistJournal(stateDir, {
        ...journal, step: "OLD_PRESERVED",
      }, "JOURNAL_OLD_PRESERVED", options);

      let verified;
      try {
        await checkpoint(options.injectFault, "NEW_VERIFIED", "before", journal);
        verified = await withCredentialFile(stagedPath, options.fileOps, callbacks.verify);
      } catch (error) {
        if (error?.code === "SIMULATED_CRASH") throw error;
        throw sanitizeCallbackFailure("CREDENTIAL_VERIFICATION_FAILED", journal);
      }
      if (!exactVerification(verified, journal)) {
        throw rotationError("CREDENTIAL_VERIFICATION_UNCONFIRMED", journal);
      }
      await checkpoint(options.injectFault, "NEW_VERIFIED", "after", journal);
      journal = await persistJournal(stateDir, {
        ...journal, step: "NEW_VERIFIED",
      }, "JOURNAL_NEW_VERIFIED", options);

      await checkpoint(options.injectFault, "ACTIVE_REPLACED_DIR_FSYNCED", "before", journal);
      try { options.fileOps.replace(stagedPath, activePath); }
      catch (error) {
        if (errorCode(error) === "SIMULATED_CRASH") throw error;
        throw rotationError("CREDENTIAL_ROTATION_INSTALL_FAILED", journal);
      }
      await checkpoint(options.injectFault, "ACTIVE_REPLACED_DIR_FSYNCED", "after", journal);
      const activatedAt = instant(options.now);
      journal = await persistJournal(stateDir, {
        ...journal,
        state: LOCAL_ROTATION_STATES.ACTIVATED,
        step: "ACTIVE_INSTALLED",
        activatedAt,
        overlapDeadline: plusMilliseconds(activatedAt, ROTATION_OVERLAP_MS),
        serverActivationConfirmed: false,
      }, "JOURNAL_ACTIVE_INSTALLED", options);
    }
  }

  if (journal.state === LOCAL_ROTATION_STATES.ACTIVATED) {
    assertDescriptor(
      descriptorAt(activePath, options.fileOps),
      journal.newCredentialId,
      journal.newFingerprint,
      "CREDENTIAL_ROTATION_ACTIVE_MISMATCH",
    );
    assertDescriptor(
      descriptorAt(retiredPath, options.fileOps),
      journal.oldCredentialId,
      journal.oldFingerprint,
      "CREDENTIAL_ROTATION_RETIRED_MISMATCH",
    );
    if (journal.step === "ACTIVE_INSTALLED") {
      let confirmation;
      try {
        await checkpoint(options.injectFault, "ACTIVE_USE_CONFIRMED", "before", journal);
        confirmation = await withCredentialFile(activePath, options.fileOps, callbacks.confirmActive);
      } catch (error) {
        if (error?.code === "SIMULATED_CRASH") throw error;
        throw sanitizeCallbackFailure("CREDENTIAL_ACTIVE_USE_UNCONFIRMED", journal);
      }
      const observedAt = instant(options.now);
      if (exactActiveConfirmation(confirmation, journal)) {
        await checkpoint(options.injectFault, "ACTIVE_USE_CONFIRMED", "after", journal);
        journal = await persistJournal(stateDir, {
          ...journal,
          step: "ACTIVE_CONFIRMED",
          overlapDeadline: field(confirmation, "overlapDeadline", "overlap_deadline"),
          activeConfirmedAt: observedAt,
          serverActivationConfirmed: true,
        }, "JOURNAL_ACTIVE_CONFIRMED", options);
      } else if (exactExpiredPending(confirmation, journal, observedAt)) {
        await checkpoint(options.injectFault, "ACTIVE_USE_CONFIRMED", "after", journal);
        journal = await persistJournal(stateDir, {
          ...journal,
          state: LOCAL_ROTATION_STATES.EXPIRING,
          step: "PENDING_EXPIRY_CONFIRMED",
          pendingDeadline: field(confirmation, "pendingDeadline", "pending_deadline"),
        }, "JOURNAL_PENDING_EXPIRY_CONFIRMED", options);
      } else {
        throw rotationError("CREDENTIAL_ACTIVE_USE_UNCONFIRMED", journal);
      }
    }

    if (journal.state === LOCAL_ROTATION_STATES.ACTIVATED
        && journal.step === "ACTIVE_CONFIRMED") {
      journal = await persistJournal(stateDir, {
        ...journal, step: "REVOCATION_REQUESTED",
      }, "REVOCATION_REQUESTED", options);
    }
    if (journal.state === LOCAL_ROTATION_STATES.ACTIVATED
        && journal.step === "REVOCATION_REQUESTED") {
      let revoked;
      try {
        await checkpoint(options.injectFault, "SERVER_COMPLETED", "before", journal);
        revoked = await callbacks.revokeOld(
          Object.freeze({
            credentialId: journal.oldCredentialId,
            fingerprint: journal.oldFingerprint,
          }),
          Object.freeze({
            credentialId: journal.newCredentialId,
            fingerprint: journal.newFingerprint,
          }),
          journal.serverRotationId,
        );
      } catch (error) {
        if (error?.code === "SIMULATED_CRASH") throw error;
        throw sanitizeCallbackFailure("CREDENTIAL_OLD_REVOCATION_UNCONFIRMED", journal);
      }
      if (!exactRevocation(revoked, journal)) {
        throw rotationError("CREDENTIAL_OLD_REVOCATION_UNCONFIRMED", journal);
      }
      await checkpoint(options.injectFault, "SERVER_COMPLETED", "after", journal);
      journal = await persistJournal(stateDir, {
        ...journal,
        state: LOCAL_ROTATION_STATES.COMPLETED,
        step: "SERVER_COMPLETED",
        completedAt: field(revoked, "completedAt", "completed_at") ?? instant(options.now),
      }, "JOURNAL_SERVER_COMPLETED", options);
    }
  }

  if (journal.state === LOCAL_ROTATION_STATES.EXPIRING) {
    if (journal.step === "PENDING_EXPIRY_CONFIRMED") {
      const active = descriptorAt(activePath, options.fileOps);
      if (active.credentialId === journal.newCredentialId
          && active.fingerprint === journal.newFingerprint) {
        assertDescriptor(
          descriptorAt(retiredPath, options.fileOps),
          journal.oldCredentialId,
          journal.oldFingerprint,
          "CREDENTIAL_ROTATION_RETIRED_MISMATCH",
        );
        await checkpoint(options.injectFault, "OLD_RESTORED_DIR_FSYNCED", "before", journal);
        try { options.fileOps.replace(retiredPath, activePath); }
        catch (error) {
          if (errorCode(error) === "SIMULATED_CRASH") throw error;
          throw rotationError("CREDENTIAL_ROTATION_OLD_RESTORE_FAILED", journal);
        }
        await checkpoint(options.injectFault, "OLD_RESTORED_DIR_FSYNCED", "after", journal);
      } else {
        assertDescriptor(
          active,
          journal.oldCredentialId,
          journal.oldFingerprint,
          "CREDENTIAL_ROTATION_ACTIVE_MISMATCH",
        );
        if (descriptorAt(retiredPath, options.fileOps, { optional: true }) !== null) {
          fail("CREDENTIAL_ROTATION_RETIRED_RESIDUE");
        }
      }
      journal = await persistJournal(stateDir, {
        ...journal, step: "OLD_RESTORED",
      }, "JOURNAL_OLD_RESTORED", options);
    }

    assertDescriptor(
      descriptorAt(activePath, options.fileOps),
      journal.oldCredentialId,
      journal.oldFingerprint,
      "CREDENTIAL_ROTATION_ACTIVE_MISMATCH",
    );
    if (descriptorAt(retiredPath, options.fileOps, { optional: true }) !== null) {
      fail("CREDENTIAL_ROTATION_RETIRED_RESIDUE");
    }
    if (typeof callbacks.cancelPending !== "function") {
      throw rotationError("CREDENTIAL_ROTATION_PENDING_CANCEL_CALLBACK_REQUIRED", journal);
    }
    let cancelled;
    try {
      await checkpoint(options.injectFault, "SERVER_PENDING_CANCELLED", "before", journal);
      cancelled = await callbacks.cancelPending(
        Object.freeze({
          credentialId: journal.oldCredentialId,
          fingerprint: journal.oldFingerprint,
        }),
        Object.freeze({
          credentialId: journal.newCredentialId,
          fingerprint: journal.newFingerprint,
        }),
        journal.serverRotationId,
      );
    } catch (error) {
      if (error?.code === "SIMULATED_CRASH") throw error;
      throw sanitizeCallbackFailure("CREDENTIAL_ROTATION_PENDING_CANCELLATION_UNCONFIRMED", journal);
    }
    if (!exactPendingCancellation(cancelled, journal)) {
      throw rotationError("CREDENTIAL_ROTATION_PENDING_CANCELLATION_UNCONFIRMED", journal);
    }
    await checkpoint(options.injectFault, "SERVER_PENDING_CANCELLED", "after", journal);
    journal = await persistJournal(stateDir, {
      ...journal,
      state: LOCAL_ROTATION_STATES.CANCELLED,
      step: "SERVER_CANCELLED",
      cancelledAt: field(cancelled, "cancelledAt", "cancelled_at"),
    }, "JOURNAL_SERVER_CANCELLED", options);
  }

  if (journal.state === LOCAL_ROTATION_STATES.CANCELLED) {
    assertDescriptor(
      descriptorAt(activePath, options.fileOps),
      journal.oldCredentialId,
      journal.oldFingerprint,
      "CREDENTIAL_ROTATION_ACTIVE_MISMATCH",
    );
    if (descriptorAt(retiredPath, options.fileOps, { optional: true }) !== null) {
      fail("CREDENTIAL_ROTATION_RETIRED_RESIDUE");
    }
    if (!options.deferJournalRemoval) {
      await checkpoint(options.injectFault, "JOURNAL_UNLINKED_DIR_FSYNCED", "before", journal);
      try { options.fileOps.unlink(rotationRecoveryPath(stateDir)); }
      catch { throw rotationError("CREDENTIAL_ROTATION_CANCELLATION_INCOMPLETE", journal); }
      await checkpoint(options.injectFault, "JOURNAL_UNLINKED_DIR_FSYNCED", "after", null);
    }
    throw rotationError("CREDENTIAL_ROTATION_PENDING_EXPIRED", journal, {
      activeCredentialId: journal.oldCredentialId,
      activeFingerprint: journal.oldFingerprint,
    });
  }

  if (journal.state === LOCAL_ROTATION_STATES.COMPLETED) {
    assertDescriptor(
      descriptorAt(activePath, options.fileOps),
      journal.newCredentialId,
      journal.newFingerprint,
      "CREDENTIAL_ROTATION_ACTIVE_MISMATCH",
    );
    await checkpoint(options.injectFault, "RETIRED_UNLINKED_DIR_FSYNCED", "before", journal);
    try { options.fileOps.unlink(retiredPath); }
    catch { throw rotationError("CREDENTIAL_RETIREMENT_INCOMPLETE", journal); }
    await checkpoint(options.injectFault, "RETIRED_UNLINKED_DIR_FSYNCED", "after", journal);
    journal = await persistJournal(stateDir, {
      ...journal, step: "RETIRED_REMOVED",
    }, "JOURNAL_RETIRED_REMOVED", options);
    if (!options.deferJournalRemoval) {
      await checkpoint(options.injectFault, "JOURNAL_UNLINKED_DIR_FSYNCED", "before", journal);
      try { options.fileOps.unlink(rotationRecoveryPath(stateDir)); }
      catch { throw rotationError("CREDENTIAL_ROTATION_COMPLETION_INCOMPLETE", journal); }
      await checkpoint(options.injectFault, "JOURNAL_UNLINKED_DIR_FSYNCED", "after", null);
    }
  }

  return Object.freeze({
    old: Object.freeze({
      credentialId: journal.oldCredentialId,
      fingerprint: journal.oldFingerprint,
    }),
    current: Object.freeze({
      credentialId: journal.newCredentialId,
      fingerprint: journal.newFingerprint,
    }),
    serverRotationId: journal.serverRotationId,
    status: LOCAL_ROTATION_STATES.COMPLETED,
  });
}

function validateCallbacks({ verify, confirmActive, revokeOld, cancelPending }) {
  if (typeof verify !== "function" || typeof confirmActive !== "function"
      || typeof revokeOld !== "function"
      || cancelPending !== null && typeof cancelPending !== "function") {
    fail("CREDENTIAL_ROTATION_CALLBACK_INVALID");
  }
}

export async function rotateCredential(stateDir, newValue, {
  rotationId,
  verify,
  confirmActive,
  revokeOld,
  cancelPending = null,
  now = () => new Date(),
  injectFault = null,
  injectJournalFault = null,
  injectFileFault = null,
  deferJournalRemoval = false,
  fileOps: fileOpOverrides = {},
  rename = null,
}) {
  validateCallbacks({ verify, confirmActive, revokeOld, cancelPending });
  if (!ID_RE.test(rotationId)) fail("CREDENTIAL_ROTATION_ID_INVALID");
  ensureSecureDir(stateDir);
  reconcileRotationJournalTemps(stateDir);
  const newBytes = Buffer.isBuffer(newValue) ? Buffer.from(newValue) : Buffer.from(String(newValue), "utf8");
  let oldBytes;
  try {
    const newDescriptor = parseCredential(newBytes);
    oldBytes = readSecureFile(credentialPath(stateDir), 512);
    const oldDescriptor = parseCredential(oldBytes);
    if (oldDescriptor.credentialId === newDescriptor.credentialId) fail("CREDENTIAL_ROTATION_SAME_CREDENTIAL");
    const startedAt = instant(now);
    const journal = {
      schema: ROTATION_SCHEMA,
      state: LOCAL_ROTATION_STATES.PENDING,
      step: "JOURNALED",
      serverRotationId: rotationId,
      oldCredentialId: oldDescriptor.credentialId,
      oldFingerprint: oldDescriptor.fingerprint,
      newCredentialId: newDescriptor.credentialId,
      newFingerprint: newDescriptor.fingerprint,
      stageFile: stageFilename(newDescriptor.credentialId),
      retiredFile: retiredFilename(oldDescriptor.credentialId),
      startedAt,
      activatedAt: null,
      pendingDeadline: null,
      overlapDeadline: null,
      activeConfirmedAt: null,
      completedAt: null,
      cancelledAt: null,
      serverActivationConfirmed: false,
    };
    const options = {
      now,
      injectFault,
      injectJournalFault,
      deferJournalRemoval,
      fileOps: defaultFileOps(fileOpOverrides, rename, injectFileFault),
    };
    await persistJournal(stateDir, journal, "JOURNAL_PENDING", options, true);
    return await driveRotation(
      stateDir,
      { verify, confirmActive, revokeOld, cancelPending },
      options,
      newBytes,
    );
  } finally {
    newBytes.fill(0);
    if (oldBytes) oldBytes.fill(0);
  }
}

export async function recoverCredentialRotation(stateDir, {
  verify,
  confirmActive,
  revokeOld,
  cancelPending = null,
  pendingValue = null,
  now = () => new Date(),
  injectFault = null,
  injectJournalFault = null,
  injectFileFault = null,
  deferJournalRemoval = false,
  fileOps: fileOpOverrides = {},
}) {
  validateCallbacks({ verify, confirmActive, revokeOld, cancelPending });
  ensureSecureDir(stateDir);
  const pendingBytes = pendingValue === null
    ? null
    : Buffer.isBuffer(pendingValue) ? Buffer.from(pendingValue) : Buffer.from(String(pendingValue));
  try {
    return await driveRotation(
      stateDir,
      { verify, confirmActive, revokeOld, cancelPending },
      {
        now,
        injectFault,
        injectJournalFault,
        deferJournalRemoval,
        fileOps: defaultFileOps(fileOpOverrides, null, injectFileFault),
      },
      pendingBytes,
    );
  } finally { if (pendingBytes) pendingBytes.fill(0); }
}

export async function finalizeCredentialRotation(stateDir, {
  fileOps: fileOpOverrides = {},
  injectFault = null,
} = {}) {
  ensureSecureDir(stateDir);
  const journal = readRotationRecovery(stateDir);
  const terminal = journal.state === LOCAL_ROTATION_STATES.COMPLETED
      && journal.step === "RETIRED_REMOVED"
    || journal.state === LOCAL_ROTATION_STATES.CANCELLED
      && journal.step === "SERVER_CANCELLED";
  if (!terminal) {
    throw rotationError("CREDENTIAL_ROTATION_FINALIZE_REFUSED", journal);
  }
  const fileOps = defaultFileOps(fileOpOverrides);
  await checkpoint(injectFault, "JOURNAL_UNLINKED_DIR_FSYNCED", "before", journal);
  try { fileOps.unlink(rotationRecoveryPath(stateDir)); }
  catch { throw rotationError("CREDENTIAL_ROTATION_COMPLETION_INCOMPLETE", journal); }
  await checkpoint(injectFault, "JOURNAL_UNLINKED_DIR_FSYNCED", "after", null);
  return Object.freeze({
    status: journal.state,
    credentialId: journal.state === LOCAL_ROTATION_STATES.COMPLETED
      ? journal.newCredentialId : journal.oldCredentialId,
    fingerprint: journal.state === LOCAL_ROTATION_STATES.COMPLETED
      ? journal.newFingerprint : journal.oldFingerprint,
  });
}

export function deleteCredential(stateDir) { secureUnlink(credentialPath(stateDir)); }

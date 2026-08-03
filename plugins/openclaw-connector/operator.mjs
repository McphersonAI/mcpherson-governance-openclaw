import { spawnSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { PLUGIN_ID, RECEIPT_MODE } from "./constants.mjs";
import { GovernanceApiClient } from "./client.mjs";
import {
  credentialPath,
  deleteCredential,
  finalizeCredentialRotation,
  parseCredential,
  readRotationRecovery,
  recoverCredentialRotation,
  rotateCredential,
  rotationRecoveryPath,
  withCredential,
} from "./credentials.mjs";
import { inspectControl, setControl } from "./controls.mjs";
import {
  atomicWriteSecureFile,
  ensureSecureDir,
  errorCode,
  readSecureFile,
  secureUnlink,
  writeExclusiveSecureFile,
} from "./secure-files.mjs";

const UNPAIR_RECOVERY_FILE = "credential-unpair-recovery.json";
const UNPAIR_SCHEMA = "mcpherson-credential-unpair-recovery/v1";
const ROTATION_ID_RE = /^[a-f0-9]{32}$/;
const FINGERPRINT_RE = /^sha256:[a-f0-9]{16}$/;
const CREDENTIAL_LIFECYCLE_LOCK_FILE = "credential-lifecycle.lock";
const TRUSTED_ROTATION_ACTIONS = Object.freeze({
  status: "credential-rotation-status",
  activate: "credential-rotation-activate",
  complete: "credential-rotation-complete",
  recover: "credential-rotation-recover",
});

function lifecycleLockPath(stateDir) {
  return join(stateDir, CREDENTIAL_LIFECYCLE_LOCK_FILE);
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (errorCode(error) === "ESRCH") return false;
    return true;
  }
}

function acquireCredentialLifecycleLock(stateDir, operation) {
  ensureSecureDir(stateDir);
  const path = lifecycleLockPath(stateDir);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      writeExclusiveSecureFile(path, Buffer.from(`${JSON.stringify({
        schema: "mcpherson-credential-lifecycle-lock/v1",
        operation,
        pid: process.pid,
      })}\n`));
      let released = false;
      return () => {
        if (released) return;
        secureUnlink(path);
        released = true;
      };
    } catch (error) {
      if (errorCode(error) !== "EEXIST") throw error;
      let bytes;
      try {
        bytes = readSecureFile(path, 1024);
        const lock = JSON.parse(bytes.toString("utf8"));
        if (JSON.stringify(Object.keys(lock || {}).sort()) !== JSON.stringify([
          "operation", "pid", "schema",
        ]) || lock.schema !== "mcpherson-credential-lifecycle-lock/v1"
            || !["rotate", "recover", "unpair"].includes(lock.operation)
            || !Number.isInteger(lock.pid) || lock.pid < 1) {
          throw Object.assign(new Error("CREDENTIAL_LIFECYCLE_LOCK_INVALID"), {
            code: "CREDENTIAL_LIFECYCLE_LOCK_INVALID",
          });
        }
        if (processIsAlive(lock.pid)) {
          throw Object.assign(new Error("CREDENTIAL_LIFECYCLE_BUSY"), {
            code: "CREDENTIAL_LIFECYCLE_BUSY",
          });
        }
      } finally { if (bytes) bytes.fill(0); }
      secureUnlink(path);
    }
  }
  throw Object.assign(new Error("CREDENTIAL_LIFECYCLE_BUSY"), {
    code: "CREDENTIAL_LIFECYCLE_BUSY",
  });
}

function rotationResidues(stateDir) {
  return readdirSync(stateDir).filter((name) => (
    name === "credential-rotation-recovery.json"
    || name.startsWith(".credential-rotation-journal-tmp-")
    || name.startsWith(".credential-next-")
    || name.startsWith(".credential-retired-")
  )).sort();
}

export function unpairRecoveryPath(stateDir) {
  return join(stateDir, UNPAIR_RECOVERY_FILE);
}

function readUnpairRecovery(stateDir) {
  let bytes;
  try {
    bytes = readSecureFile(unpairRecoveryPath(stateDir), 2048);
    const value = JSON.parse(bytes.toString("utf8"));
    if (JSON.stringify(Object.keys(value || {}).sort()) !== JSON.stringify([
      "credentialId", "fingerprint", "schema", "state",
    ])
        || value?.schema !== UNPAIR_SCHEMA
        || !["REVOCATION_REQUESTED", "SERVER_REVOKED_LOCAL_DELETE_PENDING"].includes(value.state)
        || !/^[a-f0-9]{32}$/.test(value.credentialId)
        || !/^sha256:[a-f0-9]{16}$/.test(value.fingerprint)
        || JSON.stringify(value).includes("mgd1_")) {
      throw Object.assign(new Error("UNPAIR_RECOVERY_INVALID"), { code: "UNPAIR_RECOVERY_INVALID" });
    }
    return Object.freeze(value);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return null;
    if (error?.code === "UNPAIR_RECOVERY_INVALID") throw error;
    throw Object.assign(new Error("UNPAIR_RECOVERY_INVALID"), { code: "UNPAIR_RECOVERY_INVALID" });
  } finally { if (bytes) bytes.fill(0); }
}

function writeUnpairRecovery(stateDir, descriptor, state, exclusive = false) {
  atomicWriteSecureFile(unpairRecoveryPath(stateDir), `${JSON.stringify({
    schema: UNPAIR_SCHEMA,
    state,
    credentialId: descriptor.credentialId,
    fingerprint: descriptor.fingerprint,
  })}\n`, exclusive ? { exclusiveDestination: true } : undefined);
}

function refuseRotationDuringUnpair(stateDir) {
  const recovery = readUnpairRecovery(stateDir);
  if (recovery === null) return;
  const error = new Error("CREDENTIAL_ROTATION_UNPAIR_IN_PROGRESS");
  error.code = "CREDENTIAL_ROTATION_UNPAIR_IN_PROGRESS";
  error.recovery = Object.freeze({
    state: recovery.state,
    credentialId: recovery.credentialId,
    fingerprint: recovery.fingerprint,
    connectorDisabled: true,
    recoveryCommand: "node connector-ctl.mjs unpair",
  });
  throw error;
}

function publicErrorCode(error) {
  const code = errorCode(error);
  return /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? code : "ERROR";
}

function rotationField(value, camel, snake = camel) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return Object.hasOwn(value, camel) ? value[camel] : value[snake];
}

function assertNonsecretRotationResponse(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || JSON.stringify(value).includes("mgd1_")) {
    throw Object.assign(new Error("ROTATION_OPERATOR_RESPONSE_INVALID"), {
      code: "ROTATION_OPERATOR_RESPONSE_INVALID",
    });
  }
  return value;
}

function assertRotationBinding(value, binding, allowedStates) {
  assertNonsecretRotationResponse(value);
  const state = rotationField(value, "state", "rotation_status");
  const pendingDeadline = rotationField(value, "pendingDeadline", "pending_deadline");
  const activatedAt = rotationField(value, "activatedAt", "activated_at");
  const overlapDeadline = rotationField(value, "overlapDeadline", "overlap_deadline");
  const cancelledAt = rotationField(value, "cancelledAt", "cancelled_at");
  const outputRetiredAt = rotationField(value, "outputRetiredAt", "output_retired_at");
  const stateFieldsValid = state === "PENDING"
    ? Number.isFinite(Date.parse(pendingDeadline))
      && activatedAt === null && overlapDeadline === null && cancelledAt === null
    : state === "ACTIVATED_REVOCATION_PENDING"
      ? Number.isFinite(Date.parse(pendingDeadline))
        && Number.isFinite(Date.parse(activatedAt))
        && Number.isFinite(Date.parse(overlapDeadline)) && cancelledAt === null
      : state === "CANCELLED"
        && Number.isFinite(Date.parse(pendingDeadline))
        && Number.isFinite(Date.parse(cancelledAt))
        && Number.isFinite(Date.parse(outputRetiredAt));
  if (!allowedStates.includes(state)
      || !stateFieldsValid
      || rotationField(value, "rotationId", "rotation_id") !== binding.rotationId
      || rotationField(value, "deploymentId", "deployment_id") !== binding.deploymentId
      || rotationField(value, "oldCredentialId", "old_credential_id") !== binding.oldCredentialId
      || rotationField(value, "oldFingerprint", "old_fingerprint") !== binding.oldFingerprint
      || rotationField(value, "newCredentialId", "new_credential_id") !== binding.newCredentialId
      || rotationField(value, "newFingerprint", "new_fingerprint") !== binding.newFingerprint) {
    throw Object.assign(new Error("ROTATION_OPERATOR_BINDING_MISMATCH"), {
      code: "ROTATION_OPERATOR_BINDING_MISMATCH",
    });
  }
  return value;
}

function rotationCallbacks({ binding, client, serverOperator, now }) {
  const status = () => serverOperator("status", Object.freeze({
    rotationId: binding.rotationId,
  }));
  const credentialProof = async (token, descriptor) => {
    const identity = await client.credentialIdentity(token, {
      expectedCredentialId: descriptor.credentialId,
      expectedDeploymentId: binding.deploymentId,
    });
    if (identity.credentialId !== binding.newCredentialId
        || identity.fingerprint !== binding.newFingerprint
        || identity.deploymentId !== binding.deploymentId) {
      throw Object.assign(new Error("ROTATION_CREDENTIAL_IDENTITY_MISMATCH"), {
        code: "ROTATION_CREDENTIAL_IDENTITY_MISMATCH",
      });
    }
    return identity;
  };
  return Object.freeze({
    async verify(token, descriptor) {
      if (descriptor.credentialId !== binding.newCredentialId
          || descriptor.fingerprint !== binding.newFingerprint) {
        throw Object.assign(new Error("ROTATION_LOCAL_NEW_MISMATCH"), {
          code: "ROTATION_LOCAL_NEW_MISMATCH",
        });
      }
      assertRotationBinding(await status(), binding, ["PENDING"]);
      await credentialProof(token, descriptor);
      return Object.freeze({
        status: "VERIFIED",
        credentialId: descriptor.credentialId,
        rotationId: binding.rotationId,
      });
    },
    async confirmActive(token, descriptor) {
      let server = assertRotationBinding(
        await status(),
        binding,
        ["PENDING", "ACTIVATED_REVOCATION_PENDING"],
      );
      if (rotationField(server, "state", "rotation_status") === "PENDING"
          && Date.parse(rotationField(server, "pendingDeadline", "pending_deadline"))
            <= new Date(now()).getTime()) {
        return server;
      }
      await credentialProof(token, descriptor);
      if (rotationField(server, "state", "rotation_status") === "PENDING") {
        server = assertRotationBinding(await serverOperator("activate", Object.freeze({
          rotationId: binding.rotationId,
          newCredentialId: descriptor.credentialId,
        })), binding, ["ACTIVATED_REVOCATION_PENDING"]);
      }
      return Object.freeze({
        status: "ACTIVE",
        credentialId: binding.newCredentialId,
        rotationId: binding.rotationId,
        rotationStatus: "ACTIVATED_REVOCATION_PENDING",
        overlapDeadline: rotationField(server, "overlapDeadline", "overlap_deadline"),
      });
    },
    async revokeOld(oldDescriptor, newDescriptor, rotationId) {
      if (rotationId !== binding.rotationId
          || oldDescriptor.credentialId !== binding.oldCredentialId
          || oldDescriptor.fingerprint !== binding.oldFingerprint
          || newDescriptor.credentialId !== binding.newCredentialId
          || newDescriptor.fingerprint !== binding.newFingerprint) {
        throw Object.assign(new Error("ROTATION_LOCAL_BINDING_MISMATCH"), {
          code: "ROTATION_LOCAL_BINDING_MISMATCH",
        });
      }
      return assertNonsecretRotationResponse(await serverOperator("complete", Object.freeze({
        rotationId: binding.rotationId,
        newCredentialId: binding.newCredentialId,
      })));
    },
    async cancelPending(oldDescriptor, newDescriptor, rotationId) {
      if (rotationId !== binding.rotationId
          || oldDescriptor.credentialId !== binding.oldCredentialId
          || oldDescriptor.fingerprint !== binding.oldFingerprint
          || newDescriptor.credentialId !== binding.newCredentialId
          || newDescriptor.fingerprint !== binding.newFingerprint) {
        throw Object.assign(new Error("ROTATION_LOCAL_BINDING_MISMATCH"), {
          code: "ROTATION_LOCAL_BINDING_MISMATCH",
        });
      }
      return assertRotationBinding(await serverOperator("recover", Object.freeze({
        rotationId: binding.rotationId,
      })), binding, ["CANCELLED"]);
    },
  });
}

function operatorPathFailure(code) {
  throw Object.assign(new Error(code), { code });
}

export function trustedOperatorPath(path) {
  if (typeof path !== "string" || !isAbsolute(path)) {
    operatorPathFailure("ROTATION_OPERATOR_PATH_INVALID");
  }
  const absolute = resolve(path);
  let canonical;
  try { canonical = realpathSync(absolute); }
  catch { operatorPathFailure("ROTATION_OPERATOR_PATH_INVALID"); }
  if (canonical !== absolute) operatorPathFailure("ROTATION_OPERATOR_PATH_SYMLINKED");

  const parents = [];
  for (let current = dirname(absolute);; current = dirname(current)) {
    parents.push(current);
    if (current === "/") break;
  }
  for (const parent of parents.reverse()) {
    const stat = lstatSync(parent);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0
        || (stat.mode & 0o022) !== 0) {
      operatorPathFailure("ROTATION_OPERATOR_PARENT_INSECURE");
    }
  }
  const stat = lstatSync(absolute);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== 0
      || (stat.mode & 0o022) !== 0 || (stat.mode & 0o111) === 0) {
    operatorPathFailure("ROTATION_OPERATOR_PATH_INSECURE");
  }
  return absolute;
}

export function makeCommandRotationOperator(path, {
  runner = spawnSync,
  sudo = "/usr/bin/sudo",
} = {}) {
  const command = trustedOperatorPath(path);
  return async (action, fields) => {
    // Revalidate the canonical file and every parent immediately before each
    // execution so a path changed after CLI startup fails closed.
    trustedOperatorPath(command);
    const operatorAction = TRUSTED_ROTATION_ACTIONS[action];
    if (!operatorAction || !ROTATION_ID_RE.test(fields?.rotationId)
        || (["activate", "complete"].includes(action)
          && !ROTATION_ID_RE.test(fields?.newCredentialId))) {
      throw Object.assign(new Error("ROTATION_OPERATOR_INVOCATION_INVALID"), {
        code: "ROTATION_OPERATOR_INVOCATION_INVALID",
      });
    }
    const args = ["--non-interactive", command, operatorAction, fields.rotationId];
    if (action === "activate" || action === "complete") args.push(fields.newCredentialId);
    const result = runner(sudo, args, { encoding: "utf8", stdio: "pipe" });
    if (result.error || result.status !== 0 || typeof result.stdout !== "string"
        || Buffer.byteLength(result.stdout) > 8192 || result.stdout.includes("mgd1_")) {
      throw Object.assign(new Error("ROTATION_OPERATOR_FAILED"), {
        code: "ROTATION_OPERATOR_FAILED",
      });
    }
    let parsed;
    try { parsed = JSON.parse(result.stdout); }
    catch {
      throw Object.assign(new Error("ROTATION_OPERATOR_RESPONSE_INVALID"), {
        code: "ROTATION_OPERATOR_RESPONSE_INVALID",
      });
    }
    return assertNonsecretRotationResponse(parsed);
  };
}

function bindingFromJournal(journal, deploymentId) {
  return Object.freeze({
    rotationId: journal.serverRotationId,
    deploymentId,
    oldCredentialId: journal.oldCredentialId,
    oldFingerprint: journal.oldFingerprint,
    newCredentialId: journal.newCredentialId,
    newFingerprint: journal.newFingerprint,
  });
}

function rotationCleanupError(code, config, cause) {
  let journal = null;
  try { journal = readRotationRecovery(config.stateDir); } catch { /* retain safe generic metadata */ }
  const error = new Error(code, { cause });
  error.code = code;
  error.recovery = Object.freeze({
    status: journal?.state ?? "UNKNOWN",
    step: journal?.step ?? null,
    serverRotationId: journal?.serverRotationId ?? null,
    oldCredentialId: journal?.oldCredentialId ?? null,
    oldFingerprint: journal?.oldFingerprint ?? null,
    newCredentialId: journal?.newCredentialId ?? null,
    newFingerprint: journal?.newFingerprint ?? null,
    connectorDisabled: true,
    recoveryCommand: "node connector-ctl.mjs recover --new-credential-file <original-expected-path>",
  });
  return error;
}

async function retireRotationDeliveryAndFinalize(config, newCredentialFile, {
  injectDeliveryFault = null,
  injectFinalizationFault = null,
} = {}) {
  if (newCredentialFile === null) {
    throw rotationCleanupError("CREDENTIAL_ROTATION_DELIVERY_PATH_REQUIRED", config);
  }
  try {
    secureUnlink(newCredentialFile, { injectFault: injectDeliveryFault });
  } catch (error) {
    if (errorCode(error) === "SIMULATED_CRASH") throw error;
    throw rotationCleanupError("CREDENTIAL_DELIVERY_RETIREMENT_INCOMPLETE", config, error);
  }
  try {
    await finalizeCredentialRotation(config.stateDir, {
      injectFault: injectFinalizationFault,
    });
  } catch (error) {
    if (errorCode(error) === "SIMULATED_CRASH") throw error;
    throw rotationCleanupError("CREDENTIAL_ROTATION_COMPLETION_INCOMPLETE", config, error);
  }
}

export async function rotateConnectorCredential(config, newCredentialFile, {
  rotationId,
  serverOperator,
  client = null,
  now = () => new Date(),
  rotate = rotateCredential,
  injectDeliveryFault = null,
  injectFinalizationFault = null,
} = {}) {
  if (!ROTATION_ID_RE.test(rotationId) || typeof serverOperator !== "function") {
    throw Object.assign(new Error("ROTATION_OPERATOR_CONFIGURATION_INVALID"), {
      code: "ROTATION_OPERATOR_CONFIGURATION_INVALID",
    });
  }
  if (resolve(newCredentialFile) === resolve(credentialPath(config.stateDir))) {
    throw Object.assign(new Error("ROTATION_DELIVERY_PATH_INVALID"), {
      code: "ROTATION_DELIVERY_PATH_INVALID",
    });
  }
  const releaseLifecycleLock = acquireCredentialLifecycleLock(config.stateDir, "rotate");
  let bytes;
  let ownedClient = client;
  try {
    disableConnector(config);
    refuseRotationDuringUnpair(config.stateDir);
    const status = connectorStatus(config);
    if (!status.pairing.paired || !ROTATION_ID_RE.test(status.pairing.credentialId)
        || !FINGERPRINT_RE.test(status.pairing.fingerprint)) {
      throw Object.assign(new Error("ROTATION_OLD_CREDENTIAL_UNAVAILABLE"), {
        code: "ROTATION_OLD_CREDENTIAL_UNAVAILABLE",
      });
    }
    bytes = readSecureFile(newCredentialFile, 512);
    const next = parseCredential(bytes);
    const binding = Object.freeze({
      rotationId,
      deploymentId: config.deploymentId,
      oldCredentialId: status.pairing.credentialId,
      oldFingerprint: status.pairing.fingerprint,
      newCredentialId: next.credentialId,
      newFingerprint: next.fingerprint,
    });
    ownedClient ??= new GovernanceApiClient({
      baseUrl: config.apiUrl,
      connectTimeoutMs: config.connectTimeoutMs,
      caFile: config.caFile,
    });
    const result = await rotate(config.stateDir, bytes, {
      rotationId,
      ...rotationCallbacks({ binding, client: ownedClient, serverOperator, now }),
      now,
      deferJournalRemoval: true,
    });
    await retireRotationDeliveryAndFinalize(config, newCredentialFile, {
      injectDeliveryFault,
      injectFinalizationFault,
    });
    return Object.freeze({
      ...result,
      connectorDisabled: true,
      deliveryRemoved: true,
    });
  } catch (error) {
    if (error?.code === "CREDENTIAL_ROTATION_PENDING_EXPIRED"
        && existsSync(rotationRecoveryPath(config.stateDir))) {
      await retireRotationDeliveryAndFinalize(config, newCredentialFile, {
        injectDeliveryFault,
        injectFinalizationFault,
      });
    }
    throw error;
  } finally {
    if (bytes) bytes.fill(0);
    try {
      if (!client) await ownedClient?.shutdown();
    } finally { releaseLifecycleLock(); }
  }
}

export async function recoverConnectorCredentialRotation(config, {
  newCredentialFile,
  serverOperator,
  client = null,
  now = () => new Date(),
  recover = recoverCredentialRotation,
  injectDeliveryFault = null,
  injectFinalizationFault = null,
} = {}) {
  if (typeof newCredentialFile !== "string" || newCredentialFile.length === 0) {
    throw Object.assign(new Error("CREDENTIAL_ROTATION_DELIVERY_PATH_REQUIRED"), {
      code: "CREDENTIAL_ROTATION_DELIVERY_PATH_REQUIRED",
    });
  }
  if (typeof serverOperator !== "function") {
    throw Object.assign(new Error("ROTATION_OPERATOR_CONFIGURATION_INVALID"), {
      code: "ROTATION_OPERATOR_CONFIGURATION_INVALID",
    });
  }
  if (resolve(newCredentialFile) === resolve(credentialPath(config.stateDir))) {
    throw Object.assign(new Error("ROTATION_DELIVERY_PATH_INVALID"), {
      code: "ROTATION_DELIVERY_PATH_INVALID",
    });
  }
  const releaseLifecycleLock = acquireCredentialLifecycleLock(config.stateDir, "recover");
  let pendingBytes = null;
  let ownedClient = client;
  try {
    disableConnector(config);
    const journal = readRotationRecovery(config.stateDir);
    const binding = bindingFromJournal(journal, config.deploymentId);
    try { pendingBytes = readSecureFile(newCredentialFile, 512); }
    catch (error) { if (errorCode(error) !== "ENOENT") throw error; }
    if (pendingBytes !== null) {
      const descriptor = parseCredential(pendingBytes);
      if (descriptor.credentialId !== binding.newCredentialId
          || descriptor.fingerprint !== binding.newFingerprint) {
        throw Object.assign(new Error("ROTATION_PENDING_DELIVERY_MISMATCH"), {
          code: "ROTATION_PENDING_DELIVERY_MISMATCH",
        });
      }
    }
    ownedClient ??= new GovernanceApiClient({
      baseUrl: config.apiUrl,
      connectTimeoutMs: config.connectTimeoutMs,
      caFile: config.caFile,
    });
    const callbacks = rotationCallbacks({ binding, client: ownedClient, serverOperator, now });
    const result = await recover(config.stateDir, {
      ...callbacks,
      pendingValue: pendingBytes,
      now,
      deferJournalRemoval: true,
    });
    await retireRotationDeliveryAndFinalize(config, newCredentialFile, {
      injectDeliveryFault,
      injectFinalizationFault,
    });
    return Object.freeze({
      ...result,
      connectorDisabled: true,
      deliveryRemoved: true,
    });
  } catch (error) {
    if (error?.code === "CREDENTIAL_ROTATION_PENDING_EXPIRED"
        && existsSync(rotationRecoveryPath(config.stateDir))) {
      await retireRotationDeliveryAndFinalize(config, newCredentialFile, {
        injectDeliveryFault,
        injectFinalizationFault,
      });
    }
    throw error;
  } finally {
    if (pendingBytes) pendingBytes.fill(0);
    try {
      if (!client) await ownedClient?.shutdown();
    } finally { releaseLifecycleLock(); }
  }
}

export function connectorStatus(config, pipelineStatus = null, receiptStatus = null, receiptMode = RECEIPT_MODE) {
  if (!["POST_HOOK", "ATTEMPT_ONLY"].includes(receiptMode)) {
    throw new TypeError("invalid_receipt_mode");
  }
  let pairing = { paired: false, credentialId: null, fingerprint: null };
  try {
    const path = credentialPath(config.stateDir);
    const stat = lstatSync(path, { bigint: false });
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600
      || typeof process.getuid === "function" && stat.uid !== process.getuid()) {
      pairing = { paired: false, credentialId: null, fingerprint: null, error: "INSECURE_CREDENTIAL_FILE" };
    } else {
      const bytes = readSecureFile(path, 512);
      try {
        const descriptor = parseCredential(bytes);
        pairing = { paired: true, credentialId: descriptor.credentialId, fingerprint: descriptor.fingerprint };
      } finally { bytes.fill(0); }
    }
  } catch (error) {
    if (errorCode(error) !== "ENOENT") pairing = { paired: false, credentialId: null, fingerprint: null, error: errorCode(error) };
  }
  return Object.freeze({
    pluginId: PLUGIN_ID,
    enabled: config.enabled && !inspectControl(config.stateDir, "disabled").active,
    mode: "remote_shadow",
    remoteAuthority: false,
    receiptMode,
    controls: Object.freeze({
      killswitch: inspectControl(config.stateDir, "killswitch").status,
      lock: inspectControl(config.stateDir, "lock").status,
      canary: inspectControl(config.stateDir, "canary").status,
      disabled: inspectControl(config.stateDir, "disabled").status,
    }),
    pairing: Object.freeze(pairing),
    pipeline: pipelineStatus,
    receipts: receiptStatus,
  });
}

export function disableConnector(config) { return setControl(config.stateDir, "disabled", true); }
export function enableConnector(config) { return setControl(config.stateDir, "disabled", false); }

export async function unpairConnector(config, {
  client = null,
  clientFactory = (clientConfig) => new GovernanceApiClient({
    baseUrl: clientConfig.apiUrl,
    connectTimeoutMs: clientConfig.connectTimeoutMs,
    caFile: clientConfig.caFile,
  }),
  deleteLocal = deleteCredential,
} = {}) {
  const releaseLifecycleLock = acquireCredentialLifecycleLock(config.stateDir, "unpair");
  let localDescriptor = null;
  let serverRevocationConfirmed = false;
  let localDeleteAttempted = false;
  let recovery = null;
  let ownedClient = client;
  try {
    setControl(config.stateDir, "disabled", true);
    const residues = rotationResidues(config.stateDir);
    if (residues.length > 0) {
      const conflict = new Error("UNPAIR_ROTATION_IN_PROGRESS");
      conflict.code = "UNPAIR_ROTATION_IN_PROGRESS";
      conflict.rotationResidues = residues;
      throw conflict;
    }
    recovery = readUnpairRecovery(config.stateDir);
    if (recovery?.state === "SERVER_REVOKED_LOCAL_DELETE_PENDING") {
      localDescriptor = Object.freeze({
        credentialId: recovery.credentialId,
        fingerprint: recovery.fingerprint,
      });
      serverRevocationConfirmed = true;
      if (existsSync(credentialPath(config.stateDir))) {
        const bytes = readSecureFile(credentialPath(config.stateDir), 512);
        try {
          const descriptor = parseCredential(bytes);
          if (descriptor.credentialId !== recovery.credentialId
              || descriptor.fingerprint !== recovery.fingerprint) {
            throw Object.assign(new Error("UNPAIR_RECOVERY_CREDENTIAL_MISMATCH"), {
              code: "UNPAIR_RECOVERY_CREDENTIAL_MISMATCH",
            });
          }
        } finally { bytes.fill(0); }
        localDeleteAttempted = true;
        deleteLocal(config.stateDir);
      }
      secureUnlink(unpairRecoveryPath(config.stateDir));
      return Object.freeze({
        ok: true,
        credentialId: recovery.credentialId,
        status: "REVOKED",
        localCredentialDeleted: true,
        recovered: true,
      });
    }
    const result = await withCredential(config.stateDir, async (credential, descriptor) => {
      localDescriptor = descriptor;
      if (recovery) {
        if (recovery.credentialId !== descriptor.credentialId
            || recovery.fingerprint !== descriptor.fingerprint) {
          throw Object.assign(new Error("UNPAIR_RECOVERY_CREDENTIAL_MISMATCH"), {
            code: "UNPAIR_RECOVERY_CREDENTIAL_MISMATCH",
          });
        }
      } else {
        writeUnpairRecovery(config.stateDir, descriptor, "REVOCATION_REQUESTED", true);
        recovery = readUnpairRecovery(config.stateDir);
      }
      ownedClient ??= clientFactory(config);
      const confirmed = await ownedClient.revokeSelf(credential);
      if (confirmed.status !== "REVOKED" || confirmed.credentialId !== descriptor.credentialId) {
        throw Object.assign(new Error("UNPAIR_REVOCATION_UNCONFIRMED"), { code: "UNPAIR_REVOCATION_UNCONFIRMED" });
      }
      serverRevocationConfirmed = true;
      writeUnpairRecovery(
        config.stateDir,
        descriptor,
        "SERVER_REVOKED_LOCAL_DELETE_PENDING",
      );
      recovery = readUnpairRecovery(config.stateDir);
      return { descriptor, confirmed };
    });
    localDeleteAttempted = true;
    deleteLocal(config.stateDir);
    secureUnlink(unpairRecoveryPath(config.stateDir));
    return Object.freeze({ ok: true, credentialId: result.descriptor.credentialId, status: "REVOKED", localCredentialDeleted: true });
  } catch (error) {
    const credentialId = localDescriptor?.credentialId || "unknown";
    const localCredentialRetained = existsSync(credentialPath(config.stateDir));
    const rotationInProgress = errorCode(error) === "UNPAIR_ROTATION_IN_PROGRESS";
    const command = rotationInProgress
      ? "node connector-ctl.mjs recover --new-credential-file <original-expected-path>"
      : "node connector-ctl.mjs unpair";
    const wrapped = new Error(`Unpair incomplete: connector disabled; credential ${credentialId}; recovery ${command} (${publicErrorCode(error)})`);
    wrapped.code = "UNPAIR_INCOMPLETE";
    wrapped.recovery = Object.freeze({
      credentialId,
      fingerprint: localDescriptor?.fingerprint || null,
      serverRevocationConfirmed,
      localDeleteAttempted,
      localCredentialRetained,
      connectorDisabled: true,
      command,
      ...(rotationInProgress ? { rotationResidues: error.rotationResidues } : {}),
    });
    throw wrapped;
  } finally {
    try {
      if (!client) await ownedClient?.shutdown();
    } finally { releaseLifecycleLock(); }
  }
}

export function uninstallConnector({ runner = spawnSync } = {}) {
  const result = runner("openclaw", ["plugins", "uninstall", PLUGIN_ID], { encoding: "utf8", stdio: "pipe" });
  if (result.error || result.status !== 0) throw Object.assign(new Error("UNINSTALL_FAILED"), { code: "UNINSTALL_FAILED" });
  return Object.freeze({ ok: true, receiptsPreserved: true });
}

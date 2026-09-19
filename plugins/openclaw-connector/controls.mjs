import { closeSync, constants as C, fstatSync } from "node:fs";
import { join } from "node:path";
import {
  DISABLED_FILE,
  KILL_SWITCH_FILE,
  SYSTEM_LOCK_FILE,
} from "./constants.mjs";
import {
  atomicWriteSecureFile,
  ensureSecureDir,
  errorCode,
  openRegularOwnedFile,
  readSecureFile,
  secureUnlink,
} from "./secure-files.mjs";

const CONTROL_SCHEMA = "mcpherson-governance-control/v1";
const CONTROL_FILES = Object.freeze({
  killswitch: KILL_SWITCH_FILE,
  lock: SYSTEM_LOCK_FILE,
  disabled: DISABLED_FILE,
});

export function controlPath(stateDir, name) {
  if (!(name in CONTROL_FILES)) throw Object.assign(new Error("CONTROL_NAME_INVALID"), { code: "CONTROL_NAME_INVALID" });
  return join(stateDir, CONTROL_FILES[name]);
}

export function inspectControl(stateDir, name) {
  const path = controlPath(stateDir, name);
  let fd;
  try {
    fd = openRegularOwnedFile(path, C.O_RDONLY | C.O_NONBLOCK, 0o600);
    const stat = fstatSync(fd);
    closeSync(fd);
    fd = undefined;
    if ((stat.mode & 0o777) !== 0o600 || stat.size > 256) return Object.freeze({ active: true, status: "invalid_fail_safe", path });
    const value = JSON.parse(readSecureFile(path, 256).toString("utf8"));
    const keys = value && typeof value === "object" && !Array.isArray(value) ? Object.keys(value).sort() : [];
    if (keys.length !== 3 || keys[0] !== "enabled" || keys[1] !== "name" || keys[2] !== "schema"
      || value.schema !== CONTROL_SCHEMA || value.name !== name || value.enabled !== true) {
      return Object.freeze({ active: true, status: "invalid_fail_safe", path });
    }
    return Object.freeze({ active: true, status: "active", path });
  } catch (error) {
    if (errorCode(error) === "ENOENT") return Object.freeze({ active: false, status: "absent", path });
    return Object.freeze({ active: true, status: `invalid_${errorCode(error).toLowerCase()}`, path });
  } finally { if (fd !== undefined) closeSync(fd); }
}

export function setControl(stateDir, name, enabled) {
  ensureSecureDir(stateDir);
  const path = controlPath(stateDir, name);
  if (enabled) {
    atomicWriteSecureFile(path, `${JSON.stringify({ schema: CONTROL_SCHEMA, name, enabled: true })}\n`);
  } else {
    secureUnlink(path);
  }
  return inspectControl(stateDir, name);
}

export function inspectNetworkControls(stateDir) {
  const disabled = inspectControl(stateDir, "disabled");
  const killswitch = inspectControl(stateDir, "killswitch");
  const lock = inspectControl(stateDir, "lock");
  if (disabled.active) return Object.freeze({ blocked: true, priority: "DISABLED", remoteStatus: "NOT_ATTEMPTED", disabled, killswitch, lock });
  if (killswitch.active) return Object.freeze({ blocked: true, priority: "KILL_SWITCH", remoteStatus: "KILL_SWITCH_ACTIVE", disabled, killswitch, lock });
  if (lock.active) return Object.freeze({ blocked: true, priority: "SYSTEM_LOCK", remoteStatus: "SYSTEM_LOCK_ACTIVE", disabled, killswitch, lock });
  return Object.freeze({ blocked: false, priority: null, remoteStatus: null, disabled, killswitch, lock });
}

// This is the single ordinary-observation gate. Source configuration disable
// is checked before touching control files; the durable priority is then
// disabled > kill switch > system lock. These controls stop observation and
// never produce an OpenClaw hook result.
export function inspectObservationControls(config) {
  if (config?.enabled !== true) {
    return Object.freeze({
      blocked: true,
      priority: "DISABLED",
      remoteStatus: "NOT_ATTEMPTED",
      disabled: Object.freeze({ active: true, status: "config_disabled", path: null }),
      killswitch: null,
      lock: null,
    });
  }
  return inspectNetworkControls(config.stateDir);
}

// ---------------------------------------------------------------------------
// Centralized Hosted-outbound authority
// ---------------------------------------------------------------------------
//
// `inspectObservationControls` above is the ONE decision function for Hosted
// outbound authority. Everything below is the enforcement seam over it, so no
// Hosted path has to re-implement the precedence, the fail-safe shape, or the
// ordering rule.
//
// The ordering rule is the whole point of this seam:
//
//     decide  ->  (allowed)  ->  read credential  ->  build request  ->  send
//
// never
//
//     read credential  ->  build authenticated request  ->  discover refusal
//
// A refused path performs ZERO credential reads and ZERO network attempts. The
// gate is re-consulted before every transport attempt and every retry, so a
// control that becomes active between scheduling and sending still refuses.

// Every Hosted destination this connector may ever contact from the plugin
// runtime. Adding a Hosted path means adding it here and routing it through a
// gate; a purpose the gate does not know is refused.
export const HOSTED_OUTBOUND_PURPOSES = Object.freeze([
  "observation",
  "shadow_evaluation",
  "runtime_inventory",
  "runtime_heartbeat",
]);

export class HostedOutboundRefused extends Error {
  constructor(remoteStatus, { purpose = null, priority = null } = {}) {
    super(remoteStatus);
    this.name = "HostedOutboundRefused";
    this.code = remoteStatus;
    this.remoteStatus = remoteStatus;
    this.purpose = purpose;
    this.priority = priority;
  }
}

const BLOCKED_INVALID = Object.freeze({
  blocked: true,
  priority: "INVALID_CONTROL_STATE",
  remoteStatus: "NOT_ATTEMPTED",
  disabled: null,
  killswitch: null,
  lock: null,
});
const BLOCKED_UNREADABLE = Object.freeze({
  blocked: true,
  priority: "CONTROL_READ_FAILED",
  remoteStatus: "NOT_ATTEMPTED",
  disabled: null,
  killswitch: null,
  lock: null,
});

// Fail closed on every abnormal answer: a throwing inspector, a non-object, or
// a shape that does not carry an explicit boolean decision all mean "blocked".
export function inspectHostedOutboundControls(inspector) {
  let value;
  try { value = inspector(); }
  catch { return BLOCKED_UNREADABLE; }
  if (!value || typeof value !== "object" || typeof value.blocked !== "boolean") return BLOCKED_INVALID;
  return value;
}

/**
 * One gate per Hosted publisher. `assert` is the only way through it, and the
 * `run` helper enforces the credential ordering rule for callers that need a
 * credential: the gate is asserted before the credential provider is invoked,
 * again once the credential is in hand, and again before every transport
 * attempt through the `beforeAttempt` callback it hands the caller.
 */
export function createHostedOutboundGate({
  config,
  purpose,
  controlInspector = null,
  credentialProvider = null,
} = {}) {
  if (!HOSTED_OUTBOUND_PURPOSES.includes(purpose)) {
    throw Object.assign(new Error("HOSTED_OUTBOUND_PURPOSE_UNKNOWN"), { code: "HOSTED_OUTBOUND_PURPOSE_UNKNOWN" });
  }
  const inspector = controlInspector || (() => inspectObservationControls(config));
  const inspect = () => inspectHostedOutboundControls(inspector);
  const assert = () => {
    const controls = inspect();
    if (controls.blocked) {
      throw new HostedOutboundRefused(controls.remoteStatus || "NOT_ATTEMPTED", {
        purpose,
        priority: controls.priority ?? null,
      });
    }
    return controls;
  };
  return Object.freeze({
    purpose,
    inspect,
    allowed: () => inspect().blocked === false,
    assert,
    // Credentialed Hosted call. Refusal at any checkpoint aborts before the
    // next one, so a refused call never reaches the credential or the socket.
    async run(send) {
      assert();
      if (credentialProvider === null) {
        throw Object.assign(new Error("HOSTED_OUTBOUND_CREDENTIAL_PROVIDER_REQUIRED"), {
          code: "HOSTED_OUTBOUND_CREDENTIAL_PROVIDER_REQUIRED",
        });
      }
      return credentialProvider(async (credential, descriptor) => {
        assert();
        return send(credential, { beforeAttempt: assert, descriptor });
      });
    },
  });
}

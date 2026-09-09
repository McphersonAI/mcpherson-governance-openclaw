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

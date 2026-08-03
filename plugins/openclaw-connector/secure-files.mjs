import {
  closeSync,
  constants as C,
  fchmodSync,
  fstatSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, join } from "node:path";

export const SECURE_FILE_TRANSITIONS = Object.freeze([
  "EXCLUSIVE_CREATED",
  "EXCLUSIVE_WRITTEN",
  "EXCLUSIVE_FILE_FSYNCED",
  "EXCLUSIVE_DIR_FSYNCED",
  "ATOMIC_RENAMED",
  "ATOMIC_DIR_FSYNCED",
]);

export const ATOMIC_WRITE_TRANSITIONS = Object.freeze([
  "ATOMIC_TEMP_CREATED",
  "ATOMIC_TEMP_WRITTEN",
  "ATOMIC_TEMP_FILE_FSYNCED",
  "ATOMIC_DESTINATION_INSTALLED",
  "ATOMIC_TEMP_UNLINKED",
  "ATOMIC_DESTINATION_DIR_FSYNCED",
]);

export const SECURE_UNLINK_TRANSITIONS = Object.freeze([
  "SECURE_UNLINKED",
  "SECURE_UNLINK_DIR_FSYNCED",
]);

function checkpoint(injectFault, point, phase) {
  if (typeof injectFault !== "function") return;
  const result = injectFault(Object.freeze({ point, phase }));
  if (result && typeof result.then === "function") {
    throw Object.assign(new Error("async_secure_file_fault_injector_refused"), {
      code: "ASYNC_SECURE_FILE_FAULT_INJECTOR_REFUSED",
    });
  }
}

export function errorCode(error) {
  return error && typeof error === "object" && "code" in error ? String(error.code) : "ERROR";
}

export function ensureSecureDir(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const fd = openSync(path, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW);
  try {
    const stat = fstatSync(fd);
    if (!stat.isDirectory()) throw Object.assign(new Error("not_directory"), { code: "NOT_DIRECTORY" });
    if (typeof process.getuid === "function" && stat.uid !== process.getuid()) throw Object.assign(new Error("wrong_owner"), { code: "WRONG_OWNER" });
    fchmodSync(fd, 0o700);
    if ((fstatSync(fd).mode & 0o777) !== 0o700) throw Object.assign(new Error("insecure_directory"), { code: "INSECURE_DIRECTORY" });
  } finally { closeSync(fd); }
}

export function openRegularOwnedFile(path, flags, mode = 0o600) {
  const fd = openSync(path, flags | C.O_NOFOLLOW, mode);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw Object.assign(new Error("not_regular_file"), { code: "NOT_REGULAR_FILE" });
    if (typeof process.getuid === "function" && stat.uid !== process.getuid()) throw Object.assign(new Error("wrong_owner"), { code: "WRONG_OWNER" });
    return fd;
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

export function readSecureFile(path, maxBytes = 4096) {
  let fd;
  try {
    fd = openRegularOwnedFile(path, C.O_RDONLY | C.O_NONBLOCK);
    const stat = fstatSync(fd);
    if ((stat.mode & 0o777) !== 0o600) throw Object.assign(new Error("insecure_permissions"), { code: "INSECURE_PERMISSIONS" });
    if (stat.size < 1 || stat.size > maxBytes) throw Object.assign(new Error("invalid_size"), { code: "INVALID_SIZE" });
    return readFileSync(fd);
  } finally { if (fd !== undefined) closeSync(fd); }
}

export function fsyncDirectory(path) {
  const fd = openSync(path, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function writeAll(fd, data) {
  let offset = 0;
  while (offset < data.byteLength) {
    const written = writeSync(fd, data, offset, data.byteLength - offset);
    if (!Number.isInteger(written) || written < 1) {
      throw Object.assign(new Error("short_write"), { code: "SHORT_WRITE" });
    }
    offset += written;
  }
}

export function writeExclusiveSecureFile(path, bytes, { injectFault = null } = {}) {
  const dir = dirname(path);
  ensureSecureDir(dir);
  const data = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  let fd;
  let created = false;
  try {
    checkpoint(injectFault, "EXCLUSIVE_CREATED", "before");
    fd = openRegularOwnedFile(path, C.O_WRONLY | C.O_CREAT | C.O_EXCL, 0o600);
    created = true;
    checkpoint(injectFault, "EXCLUSIVE_CREATED", "after");
    checkpoint(injectFault, "EXCLUSIVE_WRITTEN", "before");
    writeAll(fd, data);
    checkpoint(injectFault, "EXCLUSIVE_WRITTEN", "after");
    fchmodSync(fd, 0o600);
    if ((fstatSync(fd).mode & 0o777) !== 0o600) {
      throw Object.assign(new Error("insecure_permissions"), { code: "INSECURE_PERMISSIONS" });
    }
    checkpoint(injectFault, "EXCLUSIVE_FILE_FSYNCED", "before");
    fsyncSync(fd);
    checkpoint(injectFault, "EXCLUSIVE_FILE_FSYNCED", "after");
    closeSync(fd);
    fd = undefined;
    checkpoint(injectFault, "EXCLUSIVE_DIR_FSYNCED", "before");
    fsyncDirectory(dir);
    checkpoint(injectFault, "EXCLUSIVE_DIR_FSYNCED", "after");
  } catch (error) {
    if (fd !== undefined) {
      closeSync(fd);
      fd = undefined;
    }
    if (created && errorCode(error) !== "SIMULATED_CRASH") {
      try {
        unlinkSync(path);
        fsyncDirectory(dir);
      } catch (cleanupError) {
        throw Object.assign(new Error("secure_file_cleanup_failed", { cause: error }), {
          code: "SECURE_FILE_CLEANUP_FAILED",
          cleanupCode: errorCode(cleanupError),
        });
      }
    }
    throw error;
  }
}

export function atomicReplaceSecureFile(stagedPath, activePath, {
  rename = renameSync,
  injectFault = null,
} = {}) {
  if (dirname(stagedPath) !== dirname(activePath)) {
    throw Object.assign(new Error("cross_directory_replace_refused"), {
      code: "CROSS_DIRECTORY_REPLACE_REFUSED",
    });
  }
  for (const path of [stagedPath, activePath]) {
    const fd = openRegularOwnedFile(path, C.O_RDONLY | C.O_NONBLOCK);
    try {
      if ((fstatSync(fd).mode & 0o777) !== 0o600) {
        throw Object.assign(new Error("insecure_permissions"), { code: "INSECURE_PERMISSIONS" });
      }
    } finally { closeSync(fd); }
  }
  checkpoint(injectFault, "ATOMIC_RENAMED", "before");
  rename(stagedPath, activePath);
  checkpoint(injectFault, "ATOMIC_RENAMED", "after");
  checkpoint(injectFault, "ATOMIC_DIR_FSYNCED", "before");
  fsyncDirectory(dirname(activePath));
  checkpoint(injectFault, "ATOMIC_DIR_FSYNCED", "after");
}

export function atomicWriteSecureFile(path, bytes, {
  exclusiveDestination = false,
  injectFault = null,
  temporaryPrefix = ".tmp-",
} = {}) {
  const dir = dirname(path);
  ensureSecureDir(dir);
  if (typeof temporaryPrefix !== "string"
      || !/^\.[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(temporaryPrefix)) {
    throw Object.assign(new Error("invalid_temporary_prefix"), {
      code: "INVALID_TEMPORARY_PREFIX",
    });
  }
  const tmp = join(
    dir,
    `${temporaryPrefix}${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
  );
  let fd;
  let abrupt = false;
  try {
    checkpoint(injectFault, "ATOMIC_TEMP_CREATED", "before");
    fd = openRegularOwnedFile(tmp, C.O_WRONLY | C.O_CREAT | C.O_EXCL, 0o600);
    checkpoint(injectFault, "ATOMIC_TEMP_CREATED", "after");
    const data = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    checkpoint(injectFault, "ATOMIC_TEMP_WRITTEN", "before");
    writeAll(fd, data);
    checkpoint(injectFault, "ATOMIC_TEMP_WRITTEN", "after");
    fchmodSync(fd, 0o600);
    checkpoint(injectFault, "ATOMIC_TEMP_FILE_FSYNCED", "before");
    fsyncSync(fd);
    checkpoint(injectFault, "ATOMIC_TEMP_FILE_FSYNCED", "after");
    closeSync(fd);
    fd = undefined;
    checkpoint(injectFault, "ATOMIC_DESTINATION_INSTALLED", "before");
    if (exclusiveDestination) {
      linkSync(tmp, path);
    } else {
      renameSync(tmp, path);
    }
    checkpoint(injectFault, "ATOMIC_DESTINATION_INSTALLED", "after");
    checkpoint(injectFault, "ATOMIC_TEMP_UNLINKED", "before");
    if (exclusiveDestination) unlinkSync(tmp);
    checkpoint(injectFault, "ATOMIC_TEMP_UNLINKED", "after");
    const installedFd = openRegularOwnedFile(path, C.O_RDONLY | C.O_NONBLOCK, 0o600);
    try { fchmodSync(installedFd, 0o600); } finally { closeSync(installedFd); }
    checkpoint(injectFault, "ATOMIC_DESTINATION_DIR_FSYNCED", "before");
    fsyncDirectory(dir);
    checkpoint(injectFault, "ATOMIC_DESTINATION_DIR_FSYNCED", "after");
  } catch (error) {
    abrupt = errorCode(error) === "SIMULATED_CRASH";
    throw error;
  } finally {
    if (fd !== undefined) closeSync(fd);
    if (!abrupt) {
      try { unlinkSync(tmp); } catch (error) { if (errorCode(error) !== "ENOENT") throw error; }
    }
  }
}

export function secureUnlink(path, { injectFault = null } = {}) {
  try {
    const fd = openRegularOwnedFile(path, C.O_RDONLY | C.O_NONBLOCK);
    closeSync(fd);
    checkpoint(injectFault, "SECURE_UNLINKED", "before");
    unlinkSync(path);
    checkpoint(injectFault, "SECURE_UNLINKED", "after");
    checkpoint(injectFault, "SECURE_UNLINK_DIR_FSYNCED", "before");
    fsyncDirectory(dirname(path));
    checkpoint(injectFault, "SECURE_UNLINK_DIR_FSYNCED", "after");
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error;
  }
}

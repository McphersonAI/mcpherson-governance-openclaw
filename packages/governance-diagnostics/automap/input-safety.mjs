// Bounded, read-only static-input handling for all v0.6 diagnostic input.
//
// Every diagnostic file read — discovery sources and every later CLI
// artifact input — goes through the same bounded reader. It never imports
// discovered code, never invokes a connector method, and never contacts a
// network service or model. The worst outcome of a hostile input is a
// deterministic error record.
//
// TOCTOU discipline: the file is opened with O_NOFOLLOW so a symlink swapped
// in after the lstat check cannot be followed, and the size bound and
// regular-file requirement are re-verified with fstat on the open
// descriptor before any byte is read.

import {
  closeSync, fstatSync, lstatSync, openSync, readSync, realpathSync,
  constants as fsConstants,
} from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";

export const MAX_SOURCE_FILE_BYTES = 1024 * 1024;
export const MAX_SCHEMA_DEPTH = 32;
export const SUPPORTED_SOURCE_EXTENSION = ".json";

function failure(reason, path) {
  return Object.freeze({ ok: false, reason, path });
}

function openBounded(resolvedPath, display, maxBytes) {
  let descriptor = null;
  try {
    try {
      descriptor = openSync(resolvedPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    } catch (error) {
      return error?.code === "ELOOP"
        ? failure("symlink_refused", display)
        : failure(error?.code === "ENOENT" ? "missing" : "unreadable", display);
    }
    const stat = fstatSync(descriptor);
    if (!stat.isFile()) return failure("not_regular_file", display);
    if (stat.size > maxBytes) return failure("oversize", display);
    const buffer = Buffer.alloc(Number(stat.size));
    let offset = 0;
    while (offset < buffer.length) {
      const bytesRead = readSync(descriptor, buffer, offset, buffer.length - offset, offset);
      if (bytesRead <= 0) break;
      offset += bytesRead;
    }
    if (offset !== buffer.length) return failure("unreadable", display);
    return Object.freeze({ ok: true, bytes: buffer });
  } catch {
    return failure("unreadable", display);
  } finally {
    if (descriptor !== null) closeSync(descriptor);
  }
}

function parseBounded(bytes, display) {
  const text = bytes.toString("utf8");
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return failure("malformed_json", display);
  }
  const depth = jsonDepth(value, MAX_SCHEMA_DEPTH + 1);
  if (depth > MAX_SCHEMA_DEPTH) return failure("schema_depth_exceeded", display);
  return Object.freeze({
    ok: true,
    path: display,
    value,
    rawBytes: bytes,
    bytes: bytes.length,
  });
}

/**
 * Resolve `candidatePath` strictly inside `rootPath` and read it as bounded
 * UTF-8 JSON. Rejects: escapes of the root (including symlink escapes), the
 * path itself being a symlink (via O_NOFOLLOW at open time), non-regular
 * files, unsupported extensions, oversize files, and malformed JSON.
 */
export function readBoundedJson(rootPath, candidatePath, options = {}) {
  const maxBytes = options.maxBytes ?? MAX_SOURCE_FILE_BYTES;
  let root;
  try {
    root = realpathSync(resolve(rootPath));
  } catch {
    return failure("root_unresolvable", String(rootPath));
  }
  const resolved = resolve(root, String(candidatePath));
  const relativePath = relative(root, resolved);
  if (relativePath.startsWith("..") || isAbsolute(relativePath)) {
    return failure("path_escapes_root", String(candidatePath));
  }
  const display = relativePath.split(sep).join("/");
  if (!display.endsWith(SUPPORTED_SOURCE_EXTENSION)) {
    return failure("unsupported_file_type", display);
  }
  let stat;
  try {
    stat = lstatSync(resolved);
  } catch {
    return failure("missing", display);
  }
  if (stat.isSymbolicLink()) return failure("symlink_refused", display);
  if (!stat.isFile()) return failure("not_regular_file", display);
  let real;
  try {
    real = realpathSync(resolved);
  } catch {
    return failure("missing", display);
  }
  if (real !== resolved && !(real === root || real.startsWith(root + sep))) {
    return failure("symlink_escape_refused", display);
  }
  const opened = openBounded(resolved, display, maxBytes);
  if (!opened.ok) return opened;
  return parseBounded(opened.bytes, display);
}

/**
 * Bounded, symlink-refusing read of one explicitly supplied artifact file
 * (CLI inputs). The same size, depth, extension, O_NOFOLLOW, and fstat
 * discipline as discovery, without a separate containment root: the caller
 * names the exact file, and any symlink at that path is refused rather than
 * followed.
 */
export function readBoundedArtifact(filePath, options = {}) {
  const maxBytes = options.maxBytes ?? MAX_SOURCE_FILE_BYTES;
  const display = String(filePath);
  if (!display.endsWith(SUPPORTED_SOURCE_EXTENSION)) {
    return failure("unsupported_file_type", display);
  }
  const opened = openBounded(resolve(display), display, maxBytes);
  if (!opened.ok) return opened;
  return parseBounded(opened.bytes, display);
}

// Depth-limited: recursion stops at the budget, so a hostile deeply nested
// document can exhaust neither the check nor the call stack.
export function jsonDepth(value, limit) {
  if (value === null || typeof value !== "object") return 0;
  if (limit <= 0) return limit + 1;
  let deepest = 1;
  const entries = Array.isArray(value) ? value : Object.values(value);
  for (const entry of entries) {
    const childDepth = 1 + jsonDepth(entry, limit - 1);
    if (childDepth > deepest) deepest = childDepth;
    if (childDepth > limit) return childDepth;
  }
  return deepest;
}

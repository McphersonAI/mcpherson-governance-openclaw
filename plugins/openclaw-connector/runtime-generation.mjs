// One permanent, empty file per generation. O_CREAT|O_EXCL is the allocation
// linearization point. Claims are never removed, rewritten, or reclaimed,
// including after a failed or crashed allocation. No clock or PID authority.
import { closeSync, constants as C, fstatSync, fsyncSync, opendirSync } from "node:fs";
import { join } from "node:path";
import {
  ensureSecureDir, errorCode, fsyncDirectory, openRegularOwnedFile,
} from "./secure-files.mjs";

// Names of explicitly unsupported legacy artifacts, not writers.
export const RUNTIME_GENERATION_FILE = "runtime-generation";
export const RUNTIME_GENERATION_LOCK_FILE = "runtime-generation.lock";
export const RUNTIME_GENERATION_CLAIMS_DIR = "runtime-generation-claims-v1";
export const RUNTIME_GENERATION_MAX_CLAIMS = 100_000;
const CLAIM = /^([1-9][0-9]{0,15})\.claim$/;
const MAX_ATTEMPTS = 256;
const fail = (code) => { throw Object.assign(new Error(code), { code }); };

function entries(path, visit) {
  const dir = opendirSync(path);
  try {
    let entry; let count = 0;
    while ((entry = dir.readSync()) !== null) {
      if (++count > RUNTIME_GENERATION_MAX_CLAIMS) fail("RUNTIME_GENERATION_SCAN_LIMIT");
      visit(entry.name);
    }
  } finally { dir.closeSync(); }
}

function refuseLegacyState(stateDir) {
  // Even a valid old counter without a lock may already have rolled back.
  // It cannot establish the historical high-water mark. No automatic
  // migration/deletion is safe. Include abandoned atomic-write temporaries.
  entries(stateDir, (name) => {
    const folded = name.toLowerCase();
    if (name !== RUNTIME_GENERATION_CLAIMS_DIR
        && (folded.startsWith("runtime-generation") || folded.startsWith(".runtime-generation"))) {
      fail("RUNTIME_GENERATION_LEGACY_STATE_UNSAFE");
    }
  });
}

function maximumClaim(claims) {
  let maximum = 0;
  entries(claims, (name) => {
    const match = CLAIM.exec(name);
    const generation = match ? Number(match[1]) : NaN;
    if (!Number.isSafeInteger(generation)) fail("RUNTIME_GENERATION_CORRUPT");
    // An empty claim is complete at exclusive creation. No payload write can
    // be delayed or torn. Unknown names, nonempty files and links refuse.
    const fd = openRegularOwnedFile(join(claims, name), C.O_RDONLY | C.O_NONBLOCK);
    try {
      const stat = fstatSync(fd);
      if (stat.size !== 0 || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600) {
        fail("RUNTIME_GENERATION_CORRUPT");
      }
    } finally { closeSync(fd); }
    maximum = Math.max(maximum, generation);
  });
  return maximum;
}

/** Allocate once per publisher start. Requires a local filesystem with atomic
 * exclusive creation and fsync. Retain claims for the credential's lifetime;
 * deleting/restoring history is unsupported. Ambiguity/exhaustion refuses. */
export function allocateRuntimeGeneration(stateDir) {
  if (typeof stateDir !== "string" || stateDir.length === 0) fail("RUNTIME_GENERATION_STATE_DIR_REQUIRED");
  ensureSecureDir(stateDir);
  refuseLegacyState(stateDir);
  const claims = join(stateDir, RUNTIME_GENERATION_CLAIMS_DIR);
  ensureSecureDir(claims);
  fsyncDirectory(stateDir);
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
    refuseLegacyState(stateDir);
    const next = maximumClaim(claims) + 1;
    if (!Number.isSafeInteger(next)) fail("RUNTIME_GENERATION_EXHAUSTED");
    let fd;
    try {
      fd = openRegularOwnedFile(join(claims, `${next}.claim`), C.O_WRONLY | C.O_CREAT | C.O_EXCL);
    } catch (error) {
      if (errorCode(error) === "EEXIST") continue;
      throw error;
    }
    // Never use a helper that unlinks its destination on failure. This name
    // remains reserved if validation, fsync or close subsequently fails.
    try {
      const stat = fstatSync(fd);
      if (stat.size !== 0 || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600) {
        fail("RUNTIME_GENERATION_CORRUPT");
      }
      fsyncSync(fd);
    } finally { closeSync(fd); }
    fsyncDirectory(claims);
    // Detect legacy writers appearing during this attempt, before publishing.
    refuseLegacyState(stateDir);
    return next;
  }
  fail("RUNTIME_GENERATION_CONTENTION_LIMIT");
}

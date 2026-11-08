// Q-44: keyed argument digest for the Hosted SHADOW evaluation request.
//
// The Hosted contract (observa-openclaw-shadow-evaluation/v1, 25 exact fields)
// requires `argument_digest` to be present and to match ^sha256:[a-f0-9]{64}$.
// Hosted never recomputes it, never compares it across installations, does not
// index it, and the V7 evaluator cannot match on it; it is stored and carried
// into the SIMULATION envelope as an opaque digest. An UNKEYED SHA-256 of the
// full parameters is a confirmation oracle for low-entropy secrets, so the
// digest is an HMAC-SHA256 under a dedicated, locally retained, per-installation
// key. Same arguments on the same installation still yield the same digest; no
// one without the key can test guesses against it.
//
// The key is NEVER uploaded, logged or exported, is NOT derived from the pairing
// credential or any signing key, and has its own file. If the key cannot be
// created or read, no digest is produced and the caller sends nothing — there is
// no fallback to an unkeyed hash.
import { createHmac, randomBytes } from "node:crypto";
import { join } from "node:path";
import { errorCode, readSecureFile, writeExclusiveSecureFile } from "../secure-files.mjs";
import { stableStringify } from "./normalize.mjs";

export const ARGUMENT_DIGEST_KEY_FILE = "shadow-argument-digest.key";
export const ARGUMENT_DIGEST_KEY_BYTES = 32;
const DOMAIN = "observa-openclaw-shadow-argument-digest/v1\n";

export class ArgumentDigestKeyUnavailable extends Error {
  constructor() {
    super("ARGUMENT_DIGEST_KEY_UNAVAILABLE");
    this.code = "ARGUMENT_DIGEST_KEY_UNAVAILABLE";
  }
}

export function argumentDigestKeyPath(stateDir) {
  return join(stateDir, ARGUMENT_DIGEST_KEY_FILE);
}

function readKey(path) {
  const bytes = readSecureFile(path, ARGUMENT_DIGEST_KEY_BYTES);
  if (bytes.length !== ARGUMENT_DIGEST_KEY_BYTES) {
    bytes.fill(0);
    throw new ArgumentDigestKeyUnavailable();
  }
  return bytes;
}

// Absent -> create exactly once (exclusive create, 0600, owned). Present but
// wrong size, wrong mode, wrong owner, symlinked or unreadable -> unavailable;
// an existing file is never overwritten or repaired here.
export function loadOrCreateArgumentDigestKey(stateDir) {
  const path = argumentDigestKeyPath(stateDir);
  try {
    return readKey(path);
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw new ArgumentDigestKeyUnavailable();
  }
  const fresh = randomBytes(ARGUMENT_DIGEST_KEY_BYTES);
  try {
    writeExclusiveSecureFile(path, fresh);
  } catch (error) {
    fresh.fill(0);
    // Lost a creation race: use the winner's key, never ours.
    if (errorCode(error) === "EEXIST") {
      try { return readKey(path); } catch { throw new ArgumentDigestKeyUnavailable(); }
    }
    throw new ArgumentDigestKeyUnavailable();
  }
  return fresh;
}

/** Lazily keyed digester. `digest(params)` returns `sha256:<hmac-sha256 hex>`. */
export function createArgumentDigester(stateDir, { loadKey = loadOrCreateArgumentDigestKey } = {}) {
  let key = null;
  return Object.freeze({
    digest(params) {
      if (key === null) key = loadKey(stateDir);
      const mac = createHmac("sha256", key).update(DOMAIN).update(stableStringify(params ?? null)).digest("hex");
      return `sha256:${mac}`;
    },
    close() {
      if (key !== null) { key.fill(0); key = null; }
    },
  });
}

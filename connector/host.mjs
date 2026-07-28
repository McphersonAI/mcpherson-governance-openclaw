// OpenClaw host resolution: active-profile state root and the runtime
// compatibility gate.
//
// Both concerns read the host runtime object OpenClaw hands to `register(api)`.
// Nothing here executes a subprocess, reads a package manifest off disk, or
// trusts package-manager compatibility enforcement.

import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { CONNECTOR_STATE_DIR_NAME, MIN_SUPPORTED_OPENCLAW_VERSION } from "./constants.mjs";

const VERSION = /^(\d+)\.(\d+)\.(\d+)(?:([-+])(.*))?$/;
const MANIFEST_MAX_BYTES = 64 * 1024;
const MANIFEST_MAX_DEPTH = 6;

function nonEmptyAbsolute(value) {
  return typeof value === "string" && value.trim().length > 0 && isAbsolute(value.trim())
    ? value.trim()
    : null;
}

// Ordered, profile-safe resolution of the ACTIVE OpenClaw state directory.
//
//   1. the host's own resolver (`api.runtime.state.resolveStateDir`), which is
//      the value OpenClaw itself uses for the active profile;
//   2. OPENCLAW_STATE_DIR, which `openclaw --profile <name>` exports before the
//      plugin process starts;
//   3. the default profile root.
//
// Step 3 is reached only when neither the host nor the environment names a
// profile, i.e. when the default profile really is active. No step reads,
// copies, or migrates state from any other profile.
export function resolveOpenClawStateDir({ runtime = null, env = process.env, home = homedir } = {}) {
  const resolver = runtime?.state?.resolveStateDir;
  if (typeof resolver === "function") {
    try {
      const hostValue = nonEmptyAbsolute(resolver(env));
      if (hostValue !== null) return hostValue;
    } catch { /* fall through to the environment */ }
  }
  const fromEnv = nonEmptyAbsolute(env?.OPENCLAW_STATE_DIR);
  if (fromEnv !== null) return fromEnv;
  return join(home(), ".openclaw");
}

// The connector's own state root always lives INSIDE the active OpenClaw
// state directory, so a named profile keeps its connector state, receipts,
// controls, and credential with that profile.
export function connectorStateRoot(openclawStateDir) {
  const root = nonEmptyAbsolute(openclawStateDir);
  return join(root === null ? join(homedir(), ".openclaw") : root, CONNECTOR_STATE_DIR_NAME);
}

// The supported runtime version source. `PluginRuntime.version` is declared by
// the OpenClaw plugin SDK and is populated by the host itself.
export function readHostOpenClawVersion(api) {
  const value = api?.runtime?.version;
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

// Secondary source, used ONLY when the host declares a runtime version it could
// not itself resolve (OpenClaw's own fallback for that case is the literal
// string "unknown"). This is a bounded, read-only filesystem lookup of the
// host's installed package manifest. It executes no subprocess, opens no
// socket, and never throws into the activation decision.
export function readHostManifestVersion({ entry = process.argv[1] } = {}) {
  try {
    if (typeof entry !== "string" || entry.length === 0) return null;
    let current = dirname(realpathSync(entry));
    for (let depth = 0; depth < MANIFEST_MAX_DEPTH; depth += 1) {
      const candidate = join(current, "package.json");
      if (existsSync(candidate)) {
        const stat = statSync(candidate);
        if (stat.isFile() && stat.size <= MANIFEST_MAX_BYTES) {
          const parsed = JSON.parse(readFileSync(candidate, "utf8"));
          if (parsed?.name === "openclaw" && typeof parsed.version === "string") {
            const value = parsed.version.trim();
            return isParseableOpenClawVersion(value) ? value : null;
          }
        }
      }
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
  } catch { /* an unreadable host manifest simply yields no secondary value */ }
  return null;
}

// Resolves what this host can actually tell us about its own version.
//
//   declared:false — the host does not implement the SDK runtime version field
//                    at all (a harness or non-OpenClaw embedder).
//   declared:true, version:<string> — a usable version, from `source`.
//   declared:true, version:null      — the host claims a version but neither
//                    source could determine one.
export function resolveHostOpenClawVersion(api, options = {}) {
  const declaredValue = api?.runtime?.version;
  if (typeof declaredValue !== "string") {
    return Object.freeze({ declared: false, version: null, source: null });
  }
  const direct = declaredValue.trim();
  if (isParseableOpenClawVersion(direct)) {
    return Object.freeze({ declared: true, version: direct, source: "runtime" });
  }
  const fromManifest = readHostManifestVersion(options);
  if (fromManifest !== null) {
    return Object.freeze({ declared: true, version: fromManifest, source: "host_manifest" });
  }
  return Object.freeze({ declared: true, version: null, source: null });
}

function parseVersion(value) {
  const match = typeof value === "string" ? VERSION.exec(value.trim()) : null;
  if (match === null) return null;
  return Object.freeze({
    parts: Object.freeze([Number(match[1]), Number(match[2]), Number(match[3])]),
    // A pre-release build of a version ranks BELOW that version. A build-metadata
    // suffix (`+…`) does not.
    preRelease: match[4] === "-",
  });
}

export function isParseableOpenClawVersion(value) {
  return parseVersion(value) !== null;
}

// Returns < 0, 0, or > 0. Returns null when either side is not a parseable
// OpenClaw version.
export function compareOpenClawVersions(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  if (a === null || b === null) return null;
  for (let index = 0; index < 3; index += 1) {
    if (a.parts[index] !== b.parts[index]) return a.parts[index] < b.parts[index] ? -1 : 1;
  }
  if (a.preRelease === b.preRelease) return 0;
  return a.preRelease ? -1 : 1;
}

export function compatibilityMessage(hostVersion, minimum = MIN_SUPPORTED_OPENCLAW_VERSION) {
  const reported = hostVersion === null
    ? "a version it could not determine"
    : hostVersion;
  return `McPherson Governance Connector requires OpenClaw >=${minimum}; this host reports ${
    reported
  }. Connector activation is refused: no governance requests, no observation receipts, and no shadow observation occur. OpenClaw and every other plugin continue to run normally.`;
}

function normalizeReading(input) {
  if (input === null || input === undefined) {
    return { declared: false, version: null, source: null };
  }
  if (typeof input === "string") {
    const value = input.trim();
    return { declared: true, version: value.length > 0 ? value : null, source: "runtime" };
  }
  const version = typeof input.version === "string" && input.version.trim().length > 0
    ? input.version.trim()
    : null;
  return { declared: input.declared === true, version, source: input.source ?? null };
}

// The runtime activation gate.
//
//   SUPPORTED   — the host's version is known and >= the minimum. May activate.
//   UNSUPPORTED — the host declares a version and it is either BELOW the
//                 minimum or could not be determined by either supported
//                 source. A host that cannot be shown to satisfy the declared
//                 support contract is not treated as satisfying it, so this
//                 refuses. Refusal is inert, never blocking.
//   UNKNOWN     — the host does not implement the SDK runtime version field at
//                 all. That is a harness or embedder rather than an OpenClaw
//                 release making a claim about itself, so the gate does not
//                 invent a refusal the host never asked for.
export function evaluateHostCompatibility(
  reading,
  minimum = MIN_SUPPORTED_OPENCLAW_VERSION,
) {
  const { declared, version, source } = normalizeReading(reading);
  if (!declared) {
    return Object.freeze({
      status: "UNKNOWN", activate: true, hostVersion: null, versionSource: null,
      minimumVersion: minimum, message: null,
    });
  }
  const comparison = compareOpenClawVersions(version, minimum);
  if (comparison === null || comparison < 0) {
    return Object.freeze({
      status: "UNSUPPORTED",
      activate: false,
      hostVersion: version,
      versionSource: source,
      minimumVersion: minimum,
      message: compatibilityMessage(version, minimum),
    });
  }
  return Object.freeze({
    status: "SUPPORTED", activate: true, hostVersion: version, versionSource: source,
    minimumVersion: minimum, message: null,
  });
}

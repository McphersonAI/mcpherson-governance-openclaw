// Managed `observa` launcher.
//
// OpenClaw installs plugins with package lifecycle scripts disabled and never
// links a plugin package's `bin` entries, and its supported plugin CLI surface
// (`api.registerCli`) only adds `openclaw <command>` subcommands. There is no
// host mechanism that puts a plugin's own executable on PATH. This module is
// the smallest replacement: on gateway start the plugin places one small,
// owner-controlled launcher named `observa` beside the `openclaw` launcher the
// user already runs. The launcher holds no product code. It imports the CLI of
// the installed plugin directory, so an update of that directory is picked up
// with no rewrite, and a removed plugin produces a deterministic diagnostic.
//
// Ownership rules:
//   - an absent `observa` is created exclusively (never raced over);
//   - a launcher written by this plugin is refreshed atomically;
//   - anything else (Observa Local Node, a package-manager link, an unknown
//     file) is never modified or removed, and the conflict is recorded.
//
// No network, no subprocess, no environment values are persisted.
import { randomBytes } from "node:crypto";
import {
  accessSync, closeSync, constants as C, fchmodSync, fstatSync, fsyncSync, linkSync,
  lstatSync, openSync, readFileSync, readSync, realpathSync, renameSync, unlinkSync, writeSync,
} from "node:fs";
import { userInfo } from "node:os";
import { basename, delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { PLUGIN_VERSION } from "./constants.mjs";
import { atomicWriteSecureFile, errorCode, fsyncDirectory, readSecureFile } from "./secure-files.mjs";

export const ENTRYPOINT_NAME = "observa";
export const ENTRYPOINT_MARKER = "observa-openclaw-entrypoint/v1";
export const ENTRYPOINT_RECORD_FILE = "cli-entrypoint.json";
export const ENTRYPOINT_RECORD_SCHEMA = "observa-openclaw-entrypoint-record/v1";
export const PACKAGE_NAME = "@mcphersonai/mcpherson-governance-openclaw";
// Packages that also ship an `observa` command. Their command is never touched.
export const LOCAL_NODE_PACKAGES = Object.freeze([
  "@mcpherson-ai/observa-local-node",
  "@mcphersonai/observa-cli",
]);
export const ENTRYPOINT_STATES = Object.freeze([
  "INSTALLED", "CURRENT", "UPDATED",
  "COLLISION_LOCAL_NODE", "COLLISION_UNKNOWN", "PROVIDED_BY_PACKAGE_MANAGER",
  "NO_LAUNCHER_DIR", "UNSAFE_BIN_DIR", "UNSUPPORTED_PLATFORM", "FAILED",
]);
const MAX_LAUNCHER_BYTES = 16 * 1024;
// OpenClaw 2026.8.2 ships a ~130 KiB package.json; stay well above that.
const MAX_MANIFEST_BYTES = 1024 * 1024;
const ROOT_LINE = /^const PLUGIN_ROOT = ("(?:[^"\\\n]|\\.)*");$/m;

const fail = (code) => { throw Object.assign(new Error(code), { code }); };
const uid = () => (typeof process.getuid === "function" ? process.getuid() : null);
const shellQuote = (value) => `'${String(value).replace(/'/g, "'\\''")}'`;

function readManifestName(dir) {
  try {
    const path = join(dir, "package.json");
    const st = lstatSync(path);
    if (!st.isFile() || st.size > MAX_MANIFEST_BYTES) return null;
    const value = JSON.parse(readFileSync(path, "utf8"));
    return typeof value?.name === "string" ? value.name : null;
  } catch { return null; }
}

// Names of the packages that contain `path`, innermost first, stopping at the
// enclosing node_modules boundary. Used only to recognise another product.
function owningPackages(path) {
  const names = [];
  let current = dirname(path);
  for (let depth = 0; depth < 8; depth += 1) {
    const name = readManifestName(current);
    if (name !== null) names.push(name);
    const parent = dirname(current);
    if (parent === current || basename(parent) === "node_modules") break;
    current = parent;
  }
  return names;
}

function findOpenClawPackage(entry) {
  if (typeof entry !== "string" || entry.length === 0) return null;
  let current;
  try { current = dirname(realpathSync(entry)); } catch { return null; }
  for (let depth = 0; depth < 6; depth += 1) {
    if (readManifestName(current) === "openclaw") return current;
    const parent = dirname(current);
    if (parent === current) return null;
    current = parent;
  }
  return null;
}

function launchesOpenClaw(dir, launcher) {
  try { return realpathSync(join(dir, "openclaw")) === launcher; } catch { return false; }
}

/**
 * Directories that hold the `openclaw` launcher of the OpenClaw package this
 * process runs, in preference order: the directory the gateway was started
 * from, PATH entries, then the npm global-prefix bin directory. A directory
 * qualifies only if its `openclaw` resolves to this exact package, which is
 * what makes it the directory the operator already runs OpenClaw from.
 */
export function resolveLauncherDirs({ argv1 = process.argv[1], env = process.env } = {}) {
  const pkg = findOpenClawPackage(argv1);
  if (pkg === null) return [];
  let launcher;
  try { launcher = realpathSync(join(pkg, "openclaw.mjs")); } catch { return []; }
  const candidates = [];
  if (typeof argv1 === "string" && isAbsolute(argv1)) candidates.push(dirname(argv1));
  for (const entry of String(env?.PATH ?? "").split(delimiter)) {
    if (entry && isAbsolute(entry)) candidates.push(entry);
  }
  if (basename(pkg) === "openclaw" && basename(dirname(pkg)) === "node_modules"
      && basename(dirname(dirname(pkg))) === "lib") {
    candidates.push(join(dirname(dirname(dirname(pkg))), "bin"));
  }
  // One entry per real directory, keeping the first (PATH-visible) spelling.
  const seen = new Set();
  return candidates.map((dir) => resolve(dir)).filter((dir) => {
    if (!launchesOpenClaw(dir, launcher)) return false;
    const real = realpathSync(dir);
    if (seen.has(real)) return false;
    seen.add(real);
    return true;
  });
}

// A user-private group (the Debian/Ubuntu default): the group carries the
// user's own name and has no other members, so group write is owner write.
function privateGroup(gid) {
  if (typeof process.getgid !== "function" || gid !== process.getgid()) return false;
  if (process.platform !== "linux") return false;
  try {
    const name = userInfo().username;
    const text = readFileSync("/etc/group", "utf8");
    if (text.length > 1024 * 1024) return false;
    for (const line of text.split("\n")) {
      const [group, , id, members = ""] = line.split(":");
      if (Number(id) !== gid) continue;
      const others = members.split(",").filter((member) => member && member !== name);
      return group === name && others.length === 0;
    }
  } catch { /* unknown group membership is not private */ }
  return false;
}

/**
 * A launcher directory is safe when it and every ancestor is a real directory
 * that no other user can write: owned by this user or root, never
 * world-writable (a sticky ancestor such as /tmp excepted), and group-writable
 * only for this user's private group. Returns the resolved directory.
 */
export function safeLauncherDir(dir) {
  const me = uid();
  const real = realpathSync(dir);
  for (let current = real; ; current = dirname(current)) {
    const st = lstatSync(current);
    const own = current === real;
    if (st.isSymbolicLink() || !st.isDirectory()) fail("UNSAFE_BIN_DIR");
    if (me !== null && st.uid !== me && (own || st.uid !== 0)) fail("UNSAFE_BIN_DIR");
    // A sticky ancestor (/tmp: 1777) lets others add entries but not replace
    // ours; the launcher directory itself must never rely on that.
    const sticky = !own && Boolean(st.mode & 0o1000);
    if ((st.mode & 0o002) && !sticky) fail("UNSAFE_BIN_DIR");
    if ((st.mode & 0o020) && !sticky && !privateGroup(st.gid)) fail("UNSAFE_BIN_DIR");
    if (dirname(current) === current) break;
  }
  accessSync(real, C.W_OK);
  return real;
}

function readLauncher(path) {
  let fd;
  try {
    fd = openSync(path, C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK);
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > MAX_LAUNCHER_BYTES) return null;
    const bytes = Buffer.alloc(st.size);
    let count = 0;
    while (count < bytes.length) {
      const n = readSync(fd, bytes, count, bytes.length - count, count);
      if (!n) break;
      count += n;
    }
    return { text: bytes.subarray(0, count).toString("utf8"), stat: st };
  } catch { return null; } finally { if (fd !== undefined) closeSync(fd); }
}

/**
 * Classify whatever currently answers to `<dir>/observa`.
 *   ABSENT       nothing there
 *   OWNED        a launcher this plugin wrote (marker, owner, single link)
 *   LOCAL_NODE   Observa Local Node's command
 *   PACKAGE      a package-manager link to this package (npm install -g)
 *   UNKNOWN      anything else, including dangling links and other owners
 */
export function classifyEntrypoint(path) {
  let st;
  try { st = lstatSync(path); } catch (error) {
    return Object.freeze({ kind: errorCode(error) === "ENOENT" ? "ABSENT" : "UNKNOWN", path });
  }
  if (st.isSymbolicLink()) {
    let real;
    try { real = realpathSync(path); } catch { return Object.freeze({ kind: "UNKNOWN", path }); }
    const packages = owningPackages(real);
    if (packages.some((name) => LOCAL_NODE_PACKAGES.includes(name))) return Object.freeze({ kind: "LOCAL_NODE", path });
    if (packages.includes(PACKAGE_NAME)) return Object.freeze({ kind: "PACKAGE", path });
    return Object.freeze({ kind: "UNKNOWN", path });
  }
  if (!st.isFile()) return Object.freeze({ kind: "UNKNOWN", path });
  const launcher = readLauncher(path);
  if (launcher === null) return Object.freeze({ kind: "UNKNOWN", path });
  const lines = launcher.text.split("\n");
  const match = ROOT_LINE.exec(launcher.text);
  let root = null;
  try { root = match ? JSON.parse(match[1]) : null; } catch { root = null; }
  const marked = lines[0] === "#!/usr/bin/env node" && lines[1] === `// ${ENTRYPOINT_MARKER}`
    && typeof root === "string" && isAbsolute(root);
  const me = uid();
  if (marked && launcher.stat.nlink === 1 && (me === null || launcher.stat.uid === me)) {
    return Object.freeze({ kind: "OWNED", path, root, text: launcher.text, ino: launcher.stat.ino });
  }
  return Object.freeze({ kind: "UNKNOWN", path });
}

/** The complete launcher text for one installed plugin directory. */
export function renderEntrypoint(pluginRoot) {
  if (typeof pluginRoot !== "string" || !isAbsolute(pluginRoot) || /[\0\n\r\u2028\u2029]/.test(pluginRoot)) {
    fail("ENTRYPOINT_ROOT_INVALID");
  }
  return `#!/usr/bin/env node
// ${ENTRYPOINT_MARKER}
// Managed by the McPherson Governance OpenClaw plugin (mcpherson-governance-connector).
// This launcher holds no product code. It runs the Observa CLI of the plugin
// installed in PLUGIN_ROOT and passes every argument through unchanged. The
// plugin refreshes it on gateway start; \`observa uninstall\` removes it.
"use strict";
const PLUGIN_ROOT = ${JSON.stringify(pluginRoot)};
const PACKAGE_NAME = ${JSON.stringify(PACKAGE_NAME)};
(async () => {
  const fs = await import("node:fs");
  const path = await import("node:path");
  const url = await import("node:url");
  const self = process.argv[1] || "observa";
  const quoted = "'" + String(self).replace(/'/g, "'\\\\''") + "'";
  const stop = (code, detail) => {
    process.stderr.write(code + ": " + detail + "\\n");
    process.exitCode = 1;
  };
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  // Mirrors OpenClaw's own plugin path safety: owner or root, never world-writable.
  const trusted = (file, directory) => {
    const st = fs.lstatSync(file);
    if (st.isSymbolicLink() || (directory ? !st.isDirectory() : !st.isFile())) return false;
    if (uid !== null && st.uid !== uid && st.uid !== 0) return false;
    return (st.mode & 0o002) === 0;
  };
  const entry = path.join(PLUGIN_ROOT, "observa.mjs");
  try {
    const manifest = path.join(PLUGIN_ROOT, "package.json");
    if (!trusted(PLUGIN_ROOT, true) || !trusted(manifest, false) || !trusted(entry, false)) {
      return stop("OBSERVA_PLUGIN_UNTRUSTED", "The plugin files at " + PLUGIN_ROOT
        + " are not owner-controlled. Nothing was run.");
    }
    const identity = JSON.parse(fs.readFileSync(manifest, "utf8"));
    if (!identity || identity.name !== PACKAGE_NAME) {
      return stop("OBSERVA_PLUGIN_IDENTITY_MISMATCH", PLUGIN_ROOT
        + " no longer holds the McPherson Governance OpenClaw plugin. Nothing was run.");
    }
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return stop("OBSERVA_PLUGIN_NOT_INSTALLED", "The McPherson Governance OpenClaw plugin is no longer at "
        + PLUGIN_ROOT + ".\\nThis launcher was created by that plugin. If you just updated the plugin, restart\\n"
        + "the OpenClaw gateway; it re-points this launcher. Otherwise reinstall it with\\n"
        + "  openclaw plugins install clawhub:" + PACKAGE_NAME + "\\n"
        + "and restart the gateway, or remove this launcher with\\n  rm " + quoted);
    }
    return stop("OBSERVA_PLUGIN_UNREADABLE", "The plugin at " + PLUGIN_ROOT + " could not be verified. Nothing was run.");
  }
  try {
    await import(url.pathToFileURL(entry).href);
  } catch {
    stop("OBSERVA_PLUGIN_ENTRYPOINT_INVALID", "The plugin CLI at " + PLUGIN_ROOT
      + " could not start. Reinstall the plugin. No other Observa command was run.");
  }
})();
`;
}

function writeLauncherTemp(dir, text) {
  const temp = join(dir, `.observa-entrypoint-${process.pid}-${randomBytes(6).toString("hex")}.tmp`);
  const fd = openSync(temp, C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW, 0o700);
  try {
    const bytes = Buffer.from(text, "utf8");
    let offset = 0;
    while (offset < bytes.length) offset += writeSync(fd, bytes, offset, bytes.length - offset);
    fchmodSync(fd, 0o755);
    fsyncSync(fd);
  } catch (error) {
    closeSync(fd);
    try { unlinkSync(temp); } catch { /* best effort */ }
    throw error;
  }
  closeSync(fd);
  return temp;
}

// Exclusive creation: link() refuses an existing name, so a file that appears
// between classification and creation is never replaced.
function createLauncher(dir, target, text) {
  const temp = writeLauncherTemp(dir, text);
  try { linkSync(temp, target); } finally { unlinkSync(temp); }
  fsyncDirectory(dir);
}

// Refresh our own launcher. The target is re-classified immediately before the
// atomic rename and must still be the same owned file.
function replaceLauncher(dir, target, text, ino) {
  const temp = writeLauncherTemp(dir, text);
  try {
    const current = classifyEntrypoint(target);
    if (current.kind !== "OWNED" || current.ino !== ino) fail("ENTRYPOINT_CHANGED");
    renameSync(temp, target);
  } catch (error) {
    try { unlinkSync(temp); } catch { /* already renamed or gone */ }
    throw error;
  }
  fsyncDirectory(dir);
}

function remediation(state, path, root) {
  const direct = root ? `node ${shellQuote(join(root, "observa.mjs"))} <command>` : null;
  if (state === "COLLISION_LOCAL_NODE") {
    return `${path} belongs to Observa Local Node and was left unchanged. To use this plugin's CLI as observa, `
      + `remove Local Node's global command (npm uninstall -g @mcpherson-ai/observa-local-node) and restart the `
      + `OpenClaw gateway.${direct ? ` Until then run: ${direct}` : ""}`;
  }
  if (state === "COLLISION_UNKNOWN") {
    return `${path} is not managed by this plugin and was left unchanged. Rename or remove it, then restart the `
      + `OpenClaw gateway.${direct ? ` Until then run: ${direct}` : ""}`;
  }
  if (state === "PROVIDED_BY_PACKAGE_MANAGER") {
    return `${path} is a package-manager link to this package and was left unchanged.`;
  }
  if (["NO_LAUNCHER_DIR", "UNSAFE_BIN_DIR", "UNSUPPORTED_PLATFORM", "FAILED"].includes(state)) {
    return `No observa command was installed.${direct ? ` Run: ${direct}` : ""}`;
  }
  return null;
}

function record(stateDir, result) {
  if (typeof stateDir !== "string" || !isAbsolute(stateDir)) return;
  const value = {
    schema: ENTRYPOINT_RECORD_SCHEMA,
    state: result.state,
    path: result.path,
    plugin_root: result.pluginRoot,
    plugin_version: PLUGIN_VERSION,
    recorded_at: new Date().toISOString(),
    remediation: result.remediation,
  };
  atomicWriteSecureFile(join(stateDir, ENTRYPOINT_RECORD_FILE), `${JSON.stringify(value)}\n`);
}

/**
 * Ensure `observa` launches this installed plugin. Idempotent. Never throws:
 * the result names the outcome, and it is recorded in the connector state
 * directory for `observa status`.
 */
export function ensureObservaEntrypoint({
  packageRoot, stateDir = null, argv1 = process.argv[1], env = process.env,
  platform = process.platform,
} = {}) {
  let pluginRoot = null;
  let result;
  try {
    pluginRoot = realpathSync(packageRoot);
    if (readManifestName(pluginRoot) !== PACKAGE_NAME) fail("ENTRYPOINT_ROOT_INVALID");
    if (platform === "win32") {
      result = { state: "UNSUPPORTED_PLATFORM", path: null };
    } else {
      const dirs = resolveLauncherDirs({ argv1, env });
      let dir = null;
      let visible = null;
      for (const candidate of dirs) {
        try { dir = safeLauncherDir(candidate); visible = candidate; break; } catch { /* try the next launcher directory */ }
      }
      if (dirs.length === 0) result = { state: "NO_LAUNCHER_DIR", path: null };
      else if (dir === null) result = { state: "UNSAFE_BIN_DIR", path: join(dirs[0], ENTRYPOINT_NAME) };
      else {
        // Written through the verified real directory; reported as the
        // directory the operator's PATH names.
        const target = join(dir, ENTRYPOINT_NAME);
        const shown = join(visible, ENTRYPOINT_NAME);
        const text = renderEntrypoint(pluginRoot);
        const current = classifyEntrypoint(target);
        if (current.kind === "ABSENT") {
          createLauncher(dir, target, text);
          result = { state: "INSTALLED", path: shown };
        } else if (current.kind === "OWNED") {
          if (current.text === text) result = { state: "CURRENT", path: shown };
          else {
            replaceLauncher(dir, target, text, current.ino);
            result = { state: "UPDATED", path: shown };
          }
        } else {
          result = {
            state: current.kind === "LOCAL_NODE" ? "COLLISION_LOCAL_NODE"
              : current.kind === "PACKAGE" ? "PROVIDED_BY_PACKAGE_MANAGER" : "COLLISION_UNKNOWN",
            path: shown,
          };
        }
      }
    }
  } catch (error) {
    result = { state: "FAILED", path: result?.path ?? null, code: errorCode(error) };
  }
  const outcome = Object.freeze({
    ...result, pluginRoot, remediation: remediation(result.state, result.path, pluginRoot),
  });
  try { record(stateDir, outcome); } catch { /* the launcher outcome stands without its record */ }
  return outcome;
}

export function readEntrypointRecord(stateDir) {
  try {
    const value = JSON.parse(readSecureFile(join(stateDir, ENTRYPOINT_RECORD_FILE), 8192).toString("utf8"));
    if (value?.schema !== ENTRYPOINT_RECORD_SCHEMA || !ENTRYPOINT_STATES.includes(value.state)) return null;
    if (value.path !== null && (typeof value.path !== "string" || !isAbsolute(value.path))) return null;
    return Object.freeze(value);
  } catch { return null; }
}

/**
 * Remove the launcher only if it is this plugin's own launcher for this
 * installed plugin directory. Local Node, package-manager links, unknown
 * files and launchers of another plugin install are left in place.
 */
export function removeObservaEntrypoint({ pluginRoot, stateDir = null, argv1 = process.argv[1] } = {}) {
  const root = pluginRoot;
  const candidates = new Set();
  const recorded = stateDir ? readEntrypointRecord(stateDir) : null;
  if (recorded?.path) candidates.add(recorded.path);
  if (typeof argv1 === "string" && isAbsolute(argv1) && basename(argv1) === ENTRYPOINT_NAME) candidates.add(argv1);
  const removed = [];
  const kept = [];
  for (const path of candidates) {
    const current = classifyEntrypoint(path);
    if (current.kind === "ABSENT") continue;
    if (current.kind === "OWNED" && current.root === root) {
      unlinkSync(path);
      try { fsyncDirectory(dirname(path)); } catch { /* removal already visible */ }
      removed.push(path);
    } else kept.push({ path, kind: current.kind });
  }
  return Object.freeze({ removed: Object.freeze(removed), kept: Object.freeze(kept) });
}

/** First `observa` on a PATH string, classified. Read-only. */
export function resolveObservaOnPath(pathValue = process.env.PATH) {
  for (const entry of String(pathValue ?? "").split(delimiter)) {
    if (!entry || !isAbsolute(entry)) continue;
    const found = classifyEntrypoint(join(entry, ENTRYPOINT_NAME));
    if (found.kind !== "ABSENT") return Object.freeze({ kind: found.kind, path: found.path, root: found.root ?? null });
  }
  return Object.freeze({ kind: "ABSENT", path: null, root: null });
}

// Bounded, metadata-only OpenClaw live observation adapter.
//
// This adapter has no activation, registration, hook, session, payload, or
// action path. It executes exactly two operator.read gateway RPCs against an
// package-bound OpenClaw executable, reads the existing connector
// receipt ledger through a descriptor-bound bounded reader, and creates a
// fresh directory of sanitized diagnostic artifacts. It supplies only the
// fixed loopback URL and privately validated stored device credential, and
// never emits source paths, credentials, command output,
// descriptions, session identifiers, request hashes, correlation references,
// deployment identifiers, decisions, payloads, or receipt bodies.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import {
  accessSync,
  closeSync,
  constants as FS_CONSTANTS,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import {
  dirname,
  isAbsolute,
  join,
  parse,
  relative,
  resolve,
  sep,
} from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import {
  validateAttemptReceipt,
  validateCompletionReceipt,
} from "../governance-core/contracts.mjs";
import { canonicalizeJson } from "../governance-core/canonical.mjs";
import { isCalendarUtcTimestamp } from "../governance-diagnostics/schema-validate.mjs";
import {
  redactSecretsWithReport,
  scanForSecrets,
} from "../governance-diagnostics/redaction.mjs";
import {
  assertValidArtifact,
  validateEnvelope,
} from "../governance-diagnostics/contracts.mjs";
import {
  OPENCLAW_APPROVED_RUNTIME_VERSIONS,
  OPENCLAW_CANARY_TARGET,
  OPENCLAW_CANARY_TARGETS,
  approvedTargetBindingById,
  approvedTargetBindingIdFor,
  resolveOpenClawCanaryTarget,
  validateOpenClawCanaryTargetManifest,
} from "./target-binding.mjs";

export const OPENCLAW_LIVE_ADAPTER_VERSION = "0.6-live.2";
// The originally audited runtime. Retained as the primary target identity;
// every approved runtime version is in OPENCLAW_LIVE_RUNTIME_VERSIONS.
export const OPENCLAW_LIVE_RUNTIME_VERSION =
  OPENCLAW_CANARY_TARGET.semantic_version;
export const OPENCLAW_LIVE_RUNTIME_VERSIONS =
  OPENCLAW_APPROVED_RUNTIME_VERSIONS;
export const OPENCLAW_LIVE_RPC_METHODS = OPENCLAW_CANARY_TARGET.rpc_methods;
export const OPENCLAW_LIVE_PROFILE_MODES = Object.freeze([
  "DEFAULT",
  "NAMED",
]);
export const OPENCLAW_DEFAULT_PROFILE_IDENTITY = "default";
export const OPENCLAW_LIVE_ENDPOINT = OPENCLAW_CANARY_TARGET.endpoint_identity;
export const OPENCLAW_LIVE_SAFE_PATH = "/usr/local/bin:/usr/bin:/bin";
// Derived from the exact OpenClaw 2026.6.5 home, paths, gateway dispatch,
// credentials, global dotenv, shell-env, container, version, CLI proxy,
// managed-proxy, and debug-proxy modules. Every key is deliberately present
// and empty so state/global dotenv loading cannot reintroduce a redirect,
// credential, shell import, build spoof, or proxy selector.
export const OPENCLAW_LIVE_EMPTY_ENVIRONMENT_KEYS = Object.freeze([
  "USERPROFILE",
  "PREFIX",
  "ANDROID_DATA",
  "OPENCLAW_INCLUDE_ROOTS",
  "OPENCLAW_GATEWAY_URL",
  "OPENCLAW_GATEWAY_PORT",
  "OPENCLAW_GATEWAY_TOKEN",
  "OPENCLAW_GATEWAY_PASSWORD",
  "MCP_GOVERNANCE_STATE_DIR",
  "MCP_GOVERNANCE_RECEIPT_DIR",
  "OPENCLAW_SERVICE_KIND",
  "OPENCLAW_OAUTH_DIR",
  "OPENCLAW_LOAD_SHELL_ENV",
  "OPENCLAW_DEFER_SHELL_ENV_FALLBACK",
  "OPENCLAW_SHELL_ENV_TIMEOUT_MS",
  "OPENCLAW_CONTAINER",
  "OPENCLAW_CONTAINER_ALLOW_LOOPBACK_PROXY_URL",
  "OPENCLAW_CLI_CONTAINER_BYPASS",
  "OPENCLAW_ALLOW_INSECURE_PRIVATE_WS",
  "GIT_COMMIT",
  "GIT_SHA",
  "OPENCLAW_PROXY_URL",
  "OPENCLAW_PROXY_ACTIVE",
  "OPENCLAW_PROXY_LOOPBACK_MODE",
  "OPENCLAW_PROXY_CA_FILE",
  "OPENCLAW_DEBUG_PROXY_ENABLED",
  "OPENCLAW_DEBUG_PROXY_REQUIRE",
  "OPENCLAW_DEBUG_PROXY_URL",
  "OPENCLAW_DEBUG_PROXY_ALLOW_DIRECT_CONNECT_WITH_MANAGED_PROXY",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "all_proxy",
  "no_proxy",
]);
export const OPENCLAW_LIVE_REDIRECT_ENVIRONMENT_KEYS =
  Object.freeze([
    ...OPENCLAW_LIVE_EMPTY_ENVIRONMENT_KEYS.slice(0, 3),
    "OPENCLAW_PROFILE",
    "OPENCLAW_HOME",
    "OPENCLAW_STATE_DIR",
    "OPENCLAW_CONFIG_PATH",
    ...OPENCLAW_LIVE_EMPTY_ENVIRONMENT_KEYS.slice(3),
  ]);
export const OPENCLAW_LIVE_CHILD_ENVIRONMENT_KEYS = Object.freeze([
  "HOME",
  "PATH",
  "OPENCLAW_AUTH_STORE_READONLY",
  "OPENCLAW_PROFILE",
  "OPENCLAW_HOME",
  "OPENCLAW_STATE_DIR",
  "OPENCLAW_CONFIG_PATH",
  ...OPENCLAW_LIVE_EMPTY_ENVIRONMENT_KEYS,
]);
export const LIVE_CAPABILITY_SNAPSHOT_SCHEMA =
  "mcpherson-governance-live-capability-snapshot/v1";
export const LIVE_RECEIPT_SUMMARY_SCHEMA =
  "mcpherson-governance-live-shadow-receipt-summary/v1";
export const LIVE_LATENCY_EVENT_SCHEMA =
  "mcpherson-governance-live-latency-event/v1";
export const LIVE_LATENCY_EVENT_SET_SCHEMA =
  "mcpherson-governance-live-latency-event-set/v1";
export const LIVE_OBSERVATION_MANIFEST_SCHEMA =
  "mcpherson-governance-live-observation-manifest/v1";

export const LIVE_OUTPUT_FILES = Object.freeze({
  snapshot: "capability-snapshot.json",
  evidence: "governability-evidence.json",
  receipts: "shadow-receipt-summary.json",
  latency: "latency-events.json",
  manifest: "observation-manifest.json",
});

const SAFE_ID_RE = /^[A-Za-z0-9._:-]{1,96}$/;
const OPENCLAW_PROFILE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const OBSERVATION_ID_RE = /^live-obs-[a-f0-9]{64}$/;
const TARGET_BINDING_ID_RE = /^[a-f0-9]{64}$/;
const PROFILE_BINDING_SCHEMA =
  "mcpherson-governance-openclaw-local-profile-binding/v1";
const PROFILE_BINDING_MAX_LIFETIME_MS = 24 * 60 * 60 * 1000;
const PUBLIC_PACKAGE_NAME = "@mcphersonai/mcpherson-governance-openclaw";
const PUBLIC_PLUGIN_ID = "mcpherson-governance-connector";
const CONNECTOR_RECEIPT_DIRECTORY = "receipts";
const CONNECTOR_RECEIPT_FILENAME = "connector-receipts.jsonl";
const OBSERVATION_ID_SENTINEL = `live-obs-${"0".repeat(64)}`;
const MAX_RPC_BYTES = 2 * 1024 * 1024;
const MAX_RECEIPT_BYTES = 32 * 1024 * 1024;
const MAX_RECEIPT_LINES = 1_000_000;
const MAX_RECEIPT_LINE_BYTES = 32 * 1024;
const MAX_OUTPUT_ARTIFACT_BYTES = 64 * 1024 * 1024;
const MAX_RUNTIME_VERSION_OUTPUT_BYTES = 128;
// OpenClaw stable releases are MAJOR.MINOR.PATCH with an optional numeric
// revision suffix, as in `2026.7.1-2`. The suffix is deliberately restricted
// to digits so prerelease-shaped versions such as `2026.7.2-beta.7` do not
// parse at all. Approval is still decided solely by the approved target set;
// this grammar only bounds what may be read.
const SEMANTIC_VERSION_PATTERN =
  "(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)"
  + "(?:-(?:0|[1-9][0-9]*))?";
const BARE_VERSION_OUTPUT_RE = new RegExp(`^(${SEMANTIC_VERSION_PATTERN})$`);
const DECORATED_VERSION_OUTPUT_RE = new RegExp(
  `^OpenClaw (${SEMANTIC_VERSION_PATTERN}) \\(([0-9a-f]{1,64})\\)$`,
);
const LIFECYCLE_KEYS = Object.freeze([
  "schema", "record_id", "record_type", "plugin_id", "plugin_version",
  "timestamp", "event", "receipt_mode", "remote_authority",
  "enforceable_remote_decisions",
]);
// Exact connector version whose lifecycle records this observer accepts. It is
// deliberately a single exact value, never a range or a prefix: a ledger that
// mixes connector versions must fail closed rather than be silently merged into
// one current-version ledger. `parseReceiptLedger` validates every line with no
// window filter, so one stale record invalidates the ledger by design — the
// documented upgrade path is to rotate the ledger at the version boundary,
// after the previous connector process has exited and written its final
// `gateway_stop`.
//
// This constant is kept identical to `PLUGIN_VERSION` in
// `plugins/openclaw-connector/constants.mjs`. It is duplicated rather than
// imported so the observer keeps no runtime edge into the connector tree; the
// two are held equal by tests/release/version-synchronization.test.mjs.
export const LIVE_LIFECYCLE_PLUGIN_VERSION = "0.6.3-beta.6";
// Exact OpenClaw 2026.6.5 gateway credential surface, taken from the
// installed runtime schema keys `gateway.auth.*` and `gateway.tailscale.*`
// and the shipped gateway configuration reference. Unknown members of either
// object are refused so a future credential field cannot widen the surface
// silently.
const GATEWAY_AUTH_FIELDS = Object.freeze([
  "mode", "token", "password", "trustedProxy", "allowTailscale", "rateLimit",
]);
const GATEWAY_TAILSCALE_FIELDS = Object.freeze([
  "mode", "resetOnExit", "serviceName", "preserveFunnel",
]);
// SecretRef object contract and per-source identifier rules from the exact
// version's `docs/gateway/secrets.md`.
const SECRET_REF_SOURCES = Object.freeze(["env", "file", "exec"]);
const SECRET_REF_PROVIDER_RE = /^[a-z][a-z0-9_-]{0,63}$/;
const SECRET_REF_ENV_ID_RE = /^[A-Z][A-Z0-9_]{0,127}$/;
// OpenClaw file providers use `value` in singleValue mode or an RFC 6901 JSON
// pointer in json mode. No provider value is dereferenced by this observer.
const SECRET_REF_FILE_ID_RE = /^(?:value|\/(?:[^~]|~[01])*)$/;
const SECRET_REF_EXEC_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$/;
const MAX_SECRET_REF_ID_LENGTH = 256;
const REPOSITORY_ROOT = realpathSync(fileURLToPath(new URL("../..", import.meta.url)));
const UNSAFE_EVIDENCE_COMPONENT_RE =
  /^(?:\.git|\.openclaw(?:-.+)?|\.agents?|agents?|credentials?|configuration|configs?|plugins?|services?|runtime)$/i;
export const LIVE_AUTHORITY_FIELDS = Object.freeze({
  authority: "NONE",
  enforcement: false,
  automatic_mapping_activation: false,
  outbound_actions: false,
  registry_mutation: false,
});

function fail(code, detail = null) {
  const error = new TypeError(code);
  error.code = code;
  if (detail !== null) error.detail = detail;
  throw error;
}

function safeId(value, code) {
  if (typeof value !== "string" || !SAFE_ID_RE.test(value)) fail(code);
  return value;
}

function timestamp(value, code) {
  if (typeof value !== "string" || !isCalendarUtcTimestamp(value)) fail(code);
  return value;
}

function exactKeys(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function allowedKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).every((key) => keys.includes(key));
}

function withinOrEqual(parent, child) {
  const delta = relative(parent, child);
  return delta === "" || (!delta.startsWith(`..${sep}`) && delta !== ".."
    && !isAbsolute(delta));
}

function assertNoSymlinkComponents(inputPath, {
  allowMissingFinal = false,
  code = "live_path_symlink_component_refused",
} = {}) {
  if (!isAbsolute(inputPath)) fail("live_path_not_absolute");
  const rawComponents = inputPath.slice(parse(inputPath).root.length).split(/[\\/]+/);
  if (rawComponents.includes("..")) fail("live_path_traversal_refused");
  const components = rawComponents.filter((entry) => entry !== "" && entry !== ".");
  let cursor = parse(inputPath).root;
  for (let index = 0; index < components.length; index += 1) {
    cursor = join(cursor, components[index]);
    try {
      const stat = lstatSync(cursor);
      if (stat.isSymbolicLink()) fail(code);
    } catch (error) {
      if (error?.code?.startsWith?.("live_")) throw error;
      if (error?.code === "ENOENT"
          && allowMissingFinal && index === components.length - 1) {
        return resolve(inputPath);
      }
      fail("live_path_component_unreadable");
    }
  }
  return resolve(inputPath);
}

function approvedTemporaryRoots() {
  const candidates = [tmpdir(), "/tmp", "/private/tmp"];
  const roots = [];
  for (const candidate of candidates) {
    try {
      const physical = realpathSync(candidate);
      if (!roots.includes(physical)) roots.push(physical);
    } catch {
      // An unavailable platform-specific temporary root is not approved.
    }
  }
  return roots;
}

/**
 * Evidence must be a brand-new directory beneath a physical OS temporary
 * root, outside the repository and runtime/profile/configuration trees, with
 * no symlinked or traversal component. Source files may be siblings but can
 * never be inside the evidence root.
 */
export function assertSafeOpenClawEvidenceRoot({
  outDir,
  sourceInputs = [],
  allowExistingFinal = false,
}) {
  if (!isAbsolute(outDir)) fail("live_output_directory_not_absolute");
  const normalized = assertNoSymlinkComponents(outDir, {
    allowMissingFinal: !allowExistingFinal,
    code: "live_output_symlink_component_refused",
  });
  const parentPhysical = realpathSync(dirname(normalized));
  const physical = join(parentPhysical, normalized.split(sep).at(-1));
  if (physical === parse(physical).root) {
    fail("live_output_root_not_approved_temporary");
  }
  if (withinOrEqual(REPOSITORY_ROOT, physical)
      || withinOrEqual(physical, REPOSITORY_ROOT)) {
    fail("live_output_repository_overlap");
  }
  const approvedRoot = approvedTemporaryRoots().find(
    (root) => physical !== root && withinOrEqual(root, physical),
  );
  if (!approvedRoot) fail("live_output_root_not_approved_temporary");
  const relativeParts = relative(approvedRoot, physical).split(sep).filter(Boolean);
  if (relativeParts.some((entry) => UNSAFE_EVIDENCE_COMPONENT_RE.test(entry))) {
    fail("live_output_sensitive_directory_overlap");
  }
  for (const source of sourceInputs) {
    if (!isAbsolute(source)) fail("live_source_path_not_absolute");
    const sourcePhysical = realpathSync(assertNoSymlinkComponents(source, {
      code: "live_source_symlink_component_refused",
    }));
    if (withinOrEqual(physical, sourcePhysical)
        || withinOrEqual(sourcePhysical, physical)) {
      fail("live_output_source_overlap");
    }
  }
  return Object.freeze({ ok: true, physical_path: physical });
}

function hasLiveAuthorityFields(value) {
  return value?.authority === LIVE_AUTHORITY_FIELDS.authority
    && value?.enforcement === LIVE_AUTHORITY_FIELDS.enforcement
    && value?.automatic_mapping_activation
      === LIVE_AUTHORITY_FIELDS.automatic_mapping_activation
    && value?.outbound_actions === LIVE_AUTHORITY_FIELDS.outbound_actions
    && value?.registry_mutation === LIVE_AUTHORITY_FIELDS.registry_mutation;
}

function hasLiveBindingFields(value) {
  return TARGET_BINDING_ID_RE.test(value?.target_binding_id ?? "")
    && /^[a-f0-9]{40}$/.test(value?.source_commit ?? "")
    && OPENCLAW_LIVE_PROFILE_MODES.includes(value?.profile_mode)
    && typeof value?.profile === "string"
    && value?.profile_identity === value?.profile
    && value?.runtime_identity === OPENCLAW_CANARY_TARGET.runtime_identity
    && value?.endpoint_identity === OPENCLAW_LIVE_ENDPOINT
    && approvedTargetForReportedRuntime(
      value?.runtime_semantic_version,
      value?.runtime_build_identifier,
    ) !== null;
}

// Resolve the approved target a recorded (version, short-commit) pair names.
// Fails closed: the pair must identify exactly one approved target, so a
// version from one approved build can never be paired with another's commit.
function approvedTargetForReportedRuntime(semanticVersion, buildIdentifier) {
  const matched = OPENCLAW_CANARY_TARGETS.filter((target) => (
    target.semantic_version === semanticVersion
      && target.full_build_commit.slice(0, 7) === buildIdentifier
  ));
  return matched.length === 1 ? matched[0] : null;
}

function sameLiveBinding(left, right) {
  return left?.target_binding_id === right?.target_binding_id
    && left?.source_commit === right?.source_commit
    && left?.profile_mode === right?.profile_mode
    && left?.profile === right?.profile
    && left?.profile_identity === right?.profile_identity
    && left?.runtime_identity === right?.runtime_identity
    && left?.endpoint_identity === right?.endpoint_identity
    && left?.runtime_semantic_version === right?.runtime_semantic_version
    && left?.runtime_build_identifier === right?.runtime_build_identifier;
}

function matchesAuditedTarget(value, auditedPackage, approvedBinding) {
  // The profile binding pins exactly one approved target. Resolve it from the
  // approved set and fail closed if the pinned id is not a member.
  const target = approvedTargetBindingById(
    auditedPackage.source_commit,
    approvedBinding.package_target_binding_id,
  );
  if (target === null) return false;
  return value?.target_binding_id === approvedBinding.binding_id
    && value?.source_commit === auditedPackage.source_commit
    && value?.profile_mode === approvedBinding.profile_mode
    && value?.profile === approvedBinding.profile_identity
    && value?.profile_identity === approvedBinding.profile_identity
    && value?.runtime_identity === target.runtime_identity
    && value?.endpoint_identity === target.endpoint_identity
    && value?.runtime_semantic_version === target.semantic_version
    && value?.runtime_build_identifier === target.full_build_commit.slice(0, 7)
    && value?.authority === target.authority
    && value?.enforcement === target.enforcement
    && value?.automatic_mapping_activation
      === target.automatic_mapping_activation
    && value?.outbound_actions === target.outbound_actions
    && value?.registry_mutation === target.registry_mutation;
}

export function buildSafeOpenClawEnvironment(
  account,
  profileSelection,
  environment = process.env,
) {
  if (!environment || typeof environment !== "object"
      || Array.isArray(environment)
      || !account || typeof account !== "object" || Array.isArray(account)
      || typeof account.home !== "string" || !isAbsolute(account.home)
      || typeof account.stateRoot !== "string" || !isAbsolute(account.stateRoot)
      || typeof account.configPath !== "string" || !isAbsolute(account.configPath)
      || !profileSelection || typeof profileSelection !== "object") {
    fail("live_runtime_environment_invalid");
  }
  const safeEnvironment = {
    HOME: account.home,
    PATH: OPENCLAW_LIVE_SAFE_PATH,
    OPENCLAW_AUTH_STORE_READONLY: "1",
    OPENCLAW_PROFILE: profileSelection.mode === "NAMED"
      ? profileSelection.identity : "",
    OPENCLAW_HOME: account.home,
    OPENCLAW_STATE_DIR: account.stateRoot,
    OPENCLAW_CONFIG_PATH: account.configPath,
  };
  for (const key of OPENCLAW_LIVE_EMPTY_ENVIRONMENT_KEYS) {
    safeEnvironment[key] = "";
  }
  return Object.freeze(safeEnvironment);
}

export function resolveOpenClawProfileSelection(profileMode, profile) {
  if (typeof profileMode !== "string"
      || !OPENCLAW_LIVE_PROFILE_MODES.includes(profileMode)) {
    fail("live_profile_mode_invalid");
  }
  if (profileMode === "DEFAULT") {
    if (profile !== undefined) fail("live_default_profile_ambiguous");
    return Object.freeze({
      mode: "DEFAULT",
      identity: OPENCLAW_DEFAULT_PROFILE_IDENTITY,
      argvPrefix: Object.freeze([]),
    });
  }
  if (typeof profile !== "string" || !OPENCLAW_PROFILE_NAME_RE.test(profile)) {
    fail("live_named_profile_invalid");
  }
  if (profile.toLowerCase() === OPENCLAW_DEFAULT_PROFILE_IDENTITY) {
    fail("live_named_default_profile_refused");
  }
  // OpenClaw 2026.6.5 reserves `dev` and silently changes its gateway port to
  // 19001. This observer is package-bound to the audited 18789 loopback
  // endpoint, so accepting that profile would create an unusable binding.
  if (profile.toLowerCase() === "dev") {
    fail("live_named_reserved_profile_refused");
  }
  return Object.freeze({
    mode: "NAMED",
    identity: profile,
    argvPrefix: Object.freeze(["--profile", profile]),
  });
}

function defaultCommandRunner(executable, args, options) {
  return spawnSync(executable, args, {
    encoding: "utf8",
    shell: false,
    windowsHide: true,
    timeout: options.timeoutMs,
    maxBuffer: options.maxBytes,
    env: options.environment,
    cwd: options.cwd,
  });
}

function readOwnedRegularFile(path, {
  maxBytes,
  privateMode = false,
  ownerUid = typeof process.geteuid === "function" ? process.geteuid() : null,
  code,
}) {
  assertNoSymlinkComponents(path, { code: `${code}_symlink_refused` });
  let fd;
  try {
    const pathStat = lstatSync(path);
    if (pathStat.isSymbolicLink() || !pathStat.isFile()
        || pathStat.size > maxBytes) {
      fail(code);
    }
    if (ownerUid !== null && pathStat.uid !== ownerUid) {
      fail(`${code}_owner_mismatch`);
    }
    if (privateMode && (pathStat.mode & 0o077) !== 0) {
      fail(`${code}_permissions_insecure`);
    }
    fd = openSync(
      path,
      FS_CONSTANTS.O_RDONLY
        | (FS_CONSTANTS.O_NOFOLLOW ?? 0)
        | (FS_CONSTANTS.O_NONBLOCK ?? 0),
    );
    const descriptorStat = fstatSync(fd);
    if (!descriptorStat.isFile()
        || descriptorStat.dev !== pathStat.dev
        || descriptorStat.ino !== pathStat.ino
        || descriptorStat.size > maxBytes) {
      fail(`${code}_identity_changed`);
    }
    return readFileSync(fd);
  } catch (error) {
    if (error?.code?.startsWith?.("live_")) throw error;
    fail(code);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function parsePrivateJson(bytes, code) {
  try {
    const value = JSON.parse(bytes.toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) fail(code);
    return value;
  } catch (error) {
    if (error?.code?.startsWith?.("live_")) throw error;
    fail(code);
  }
}

export function readAuditedOpenClawPackageManifest(packageManifestPath) {
  if (typeof packageManifestPath !== "string"
      || !isAbsolute(packageManifestPath)) {
    fail("live_package_manifest_path_invalid");
  }
  const bytes = readOwnedRegularFile(packageManifestPath, {
    maxBytes: 4 * 1024 * 1024,
    code: "live_package_manifest_invalid",
  });
  const manifest = parsePrivateJson(bytes, "live_package_manifest_invalid");
  const target = validateOpenClawCanaryTargetManifest(manifest);
  if (manifest.package_name !== PUBLIC_PACKAGE_NAME
      || manifest.plugin_id !== PUBLIC_PLUGIN_ID
      || manifest.plugin_version !== LIVE_LIFECYCLE_PLUGIN_VERSION
      || !/^[a-f0-9]{40}$/.test(manifest.source_tree ?? "")) {
    fail("live_package_identity_invalid");
  }
  const sourceModules = Object.freeze([
    ["packages/openclaw-live-observer/index.mjs", fileURLToPath(import.meta.url)],
    [
      "packages/openclaw-live-observer/target-binding.mjs",
      fileURLToPath(new URL("./target-binding.mjs", import.meta.url)),
    ],
  ]);
  for (const [repositoryPath, modulePath] of sourceModules) {
    const sourceRecord = manifest.source_files.find(
      (entry) => entry?.path === repositoryPath,
    );
    const moduleBytes = readFileSync(modulePath);
    if (!sourceRecord
        || sourceRecord.bytes !== moduleBytes.length
        || sourceRecord.sha256
          !== createHash("sha256").update(moduleBytes).digest("hex")) {
      fail("live_package_source_binding_invalid");
    }
  }
  return Object.freeze({
    manifest,
    manifest_sha256: createHash("sha256").update(bytes).digest("hex"),
    package_name: manifest.package_name,
    plugin_id: manifest.plugin_id,
    plugin_version: manifest.plugin_version,
    source_commit: target.source_commit,
    source_tree: manifest.source_tree,
    target_bindings: target.target_bindings,
    target_binding_ids: target.target_binding_ids,
  });
}

function assertOwnedDirectory(path, ownerUid, code, { privateMode = false } = {}) {
  assertNoSymlinkComponents(path, { code: `${code}_symlink_refused` });
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    fail(code);
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) fail(code);
  if (stat.uid !== ownerUid) fail(`${code}_owner_mismatch`);
  if (privateMode && (stat.mode & 0o077) !== 0) {
    fail(`${code}_permissions_insecure`);
  }
  return realpathSync(path);
}

export function resolveExplicitOpenClawAccount(profileSelection, profileHome) {
  const effectiveUid = typeof process.geteuid === "function"
    ? process.geteuid() : lstatSync(profileHome).uid;
  if (!profileSelection || typeof profileSelection !== "object"
      || typeof profileHome !== "string" || !isAbsolute(profileHome)) {
    fail("live_profile_home_invalid");
  }
  const normalizedHome = assertNoSymlinkComponents(profileHome, {
    code: "live_profile_home_symlink_refused",
  });
  const physicalHome = assertOwnedDirectory(
    normalizedHome, effectiveUid, "live_profile_home_invalid",
  );
  if (physicalHome !== normalizedHome) fail("live_profile_home_physical_mismatch");
  const stateIdentity = profileSelection.mode === "DEFAULT"
    ? OPENCLAW_CANARY_TARGET.default_state_identity
    : `${OPENCLAW_CANARY_TARGET.named_state_prefix}${profileSelection.identity}`;
  const stateRoot = join(physicalHome, stateIdentity);
  const connectorStateRoot = join(stateRoot, PUBLIC_PLUGIN_ID);
  const receiptPath = join(
    connectorStateRoot, CONNECTOR_RECEIPT_DIRECTORY, CONNECTOR_RECEIPT_FILENAME,
  );
  return Object.freeze({
    uid: effectiveUid,
    home: physicalHome,
    stateIdentity,
    stateRoot,
    configPath: join(stateRoot, OPENCLAW_CANARY_TARGET.config_basename),
    runtimePath: join(physicalHome, OPENCLAW_CANARY_TARGET.runtime_identity),
    connectorStateRoot,
    receiptPath,
  });
}

function profileBindingId(document) {
  return createHash("sha256")
    .update(canonicalizeJson(document), "utf8")
    .digest("hex");
}

export function openClawProfileBindingId(document) {
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    fail("live_profile_binding_invalid");
  }
  const { binding_id: _bindingId, ...payload } = document;
  return profileBindingId(payload);
}

function buildProfileBindingDocument({
  auditedPackage,
  profileSelection,
  account,
  createdAt,
  expiresAt,
  targetBindingId,
}) {
  const payload = {
    schema: PROFILE_BINDING_SCHEMA,
    created_at: createdAt,
    expires_at: expiresAt,
    package_name: auditedPackage.package_name,
    plugin_id: auditedPackage.plugin_id,
    plugin_version: auditedPackage.plugin_version,
    source_commit: auditedPackage.source_commit,
    source_tree: auditedPackage.source_tree,
    package_manifest_sha256: auditedPackage.manifest_sha256,
    package_target_binding_id: targetBindingId,
    profile_mode: profileSelection.mode,
    profile_identity: profileSelection.identity,
    home_path: account.home,
    state_path: account.stateRoot,
    config_path: account.configPath,
    runtime_path: account.runtimePath,
    connector_state_path: account.connectorStateRoot,
    receipt_path: account.receiptPath,
    state_identity: account.stateIdentity,
    config_identity: OPENCLAW_CANARY_TARGET.config_basename,
    runtime_identity: OPENCLAW_CANARY_TARGET.runtime_identity,
  };
  return Object.freeze({
    ...payload,
    binding_id: profileBindingId(payload),
  });
}

function assertPrivateBindingOutputPath(bindingPath) {
  if (typeof bindingPath !== "string" || !isAbsolute(bindingPath)) {
    fail("live_profile_binding_path_invalid");
  }
  const normalized = assertNoSymlinkComponents(bindingPath, {
    allowMissingFinal: true,
    code: "live_profile_binding_symlink_refused",
  });
  const parent = dirname(normalized);
  const uid = typeof process.geteuid === "function"
    ? process.geteuid() : lstatSync(parent).uid;
  const physicalParent = assertOwnedDirectory(
    parent, uid, "live_profile_binding_parent_invalid", { privateMode: true },
  );
  const expected = join(physicalParent, normalized.split(sep).at(-1));
  if (expected !== normalized) fail("live_profile_binding_path_invalid");
  return normalized;
}

function bindingTime(value, code) {
  timestamp(value, code);
  return Date.parse(value);
}

function readApprovedOpenClawProfileBinding({
  profileBindingPath,
  profileBindingId,
  packageManifestPath,
  profileMode,
  profile,
  profileHome,
  now = () => new Date().toISOString(),
}) {
  if (typeof now !== "function") fail("live_profile_binding_options_invalid");
  const auditedPackage = readAuditedOpenClawPackageManifest(packageManifestPath);
  if (typeof profileBindingPath !== "string" || !isAbsolute(profileBindingPath)) {
    fail("live_profile_binding_path_invalid");
  }
  if (!TARGET_BINDING_ID_RE.test(profileBindingId ?? "")) {
    fail("live_profile_binding_id_invalid");
  }
  const bytes = readOwnedRegularFile(profileBindingPath, {
    maxBytes: 1024 * 1024,
    privateMode: true,
    code: "live_profile_binding_invalid",
  });
  const binding = parsePrivateJson(bytes, "live_profile_binding_malformed");
  const expectedKeys = [
    "schema", "binding_id", "created_at", "expires_at", "package_name",
    "plugin_id", "plugin_version", "source_commit", "source_tree",
    "package_manifest_sha256", "package_target_binding_id", "profile_mode",
    "profile_identity", "home_path", "state_path", "config_path",
    "runtime_path", "connector_state_path", "receipt_path", "state_identity",
    "config_identity", "runtime_identity",
  ];
  if (!exactKeys(binding, expectedKeys)
      || binding.schema !== PROFILE_BINDING_SCHEMA
      || !TARGET_BINDING_ID_RE.test(binding.binding_id ?? "")
      || openClawProfileBindingId(binding) !== binding.binding_id) {
    fail("live_profile_binding_invalid");
  }
  const canonicalBinding = `${JSON.stringify({
    schema: binding.schema,
    created_at: binding.created_at,
    expires_at: binding.expires_at,
    package_name: binding.package_name,
    plugin_id: binding.plugin_id,
    plugin_version: binding.plugin_version,
    source_commit: binding.source_commit,
    source_tree: binding.source_tree,
    package_manifest_sha256: binding.package_manifest_sha256,
    package_target_binding_id: binding.package_target_binding_id,
    profile_mode: binding.profile_mode,
    profile_identity: binding.profile_identity,
    home_path: binding.home_path,
    state_path: binding.state_path,
    config_path: binding.config_path,
    runtime_path: binding.runtime_path,
    connector_state_path: binding.connector_state_path,
    receipt_path: binding.receipt_path,
    state_identity: binding.state_identity,
    config_identity: binding.config_identity,
    runtime_identity: binding.runtime_identity,
    binding_id: binding.binding_id,
  }, null, 2)}\n`;
  if (!bytes.equals(Buffer.from(canonicalBinding, "utf8"))) {
    fail("live_profile_binding_noncanonical");
  }
  if (binding.binding_id !== profileBindingId) {
    fail("live_profile_binding_id_mismatch");
  }
  const currentMs = bindingTime(now(), "live_profile_binding_clock_invalid");
  const createdMs = bindingTime(
    binding.created_at, "live_profile_binding_created_at_invalid",
  );
  const expiresMs = bindingTime(
    binding.expires_at, "live_profile_binding_expires_at_invalid",
  );
  if (expiresMs <= createdMs
      || expiresMs - createdMs > PROFILE_BINDING_MAX_LIFETIME_MS) {
    fail("live_profile_binding_lifetime_invalid");
  }
  if (currentMs < createdMs || currentMs > expiresMs) {
    fail("live_profile_binding_stale");
  }
  if (binding.package_name !== auditedPackage.package_name
      || binding.plugin_id !== auditedPackage.plugin_id
      || binding.plugin_version !== auditedPackage.plugin_version
      || binding.source_commit !== auditedPackage.source_commit
      || binding.source_tree !== auditedPackage.source_tree
      || binding.package_manifest_sha256 !== auditedPackage.manifest_sha256
      || !auditedPackage.target_binding_ids.includes(
        binding.package_target_binding_id,
      )) {
    fail("live_profile_binding_package_mismatch");
  }
  const requestedMode = profileMode ?? binding.profile_mode;
  const requestedProfile = requestedMode === "NAMED"
    ? (profile ?? binding.profile_identity) : profile;
  const requestedHome = profileHome ?? binding.home_path;
  const profileSelection = resolveOpenClawProfileSelection(
    requestedMode, requestedProfile,
  );
  const account = resolveExplicitOpenClawAccount(profileSelection, requestedHome);
  if (binding.profile_mode !== profileSelection.mode
      || binding.profile_identity !== profileSelection.identity) {
    fail("live_profile_binding_profile_mismatch");
  }
  if (binding.home_path !== account.home
      || binding.state_path !== account.stateRoot
      || binding.config_path !== account.configPath
      || binding.runtime_path !== account.runtimePath
      || binding.connector_state_path !== account.connectorStateRoot
      || binding.receipt_path !== account.receiptPath
      || binding.state_identity !== account.stateIdentity
      || binding.config_identity !== OPENCLAW_CANARY_TARGET.config_basename
      || binding.runtime_identity !== OPENCLAW_CANARY_TARGET.runtime_identity) {
    fail("live_profile_binding_path_mismatch");
  }
  return Object.freeze({
    auditedPackage,
    binding: Object.freeze(binding),
    profileSelection,
    account,
  });
}

function containsIncludeDirective(value) {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some(containsIncludeDirective);
  return Object.entries(value).some(
    ([key, child]) => key === "$include" || containsIncludeDirective(child),
  );
}

/**
 * Structural SecretRef check. The reference is deliberately never resolved,
 * dereferenced, read, printed, copied into evidence, hashed, or passed to a
 * secret provider: only the declared shape of the reference itself is
 * inspected, so the credential value stays opaque to the observer.
 */
function isSupportedGatewaySecretRef(value) {
  if (!exactKeys(value, ["source", "provider", "id"])) return false;
  const { source, provider, id } = value;
  if (typeof source !== "string" || !SECRET_REF_SOURCES.includes(source)) {
    return false;
  }
  if (typeof provider !== "string" || !SECRET_REF_PROVIDER_RE.test(provider)) {
    return false;
  }
  if (typeof id !== "string" || id.length === 0
      || id.length > MAX_SECRET_REF_ID_LENGTH) {
    return false;
  }
  if (source === "env") return SECRET_REF_ENV_ID_RE.test(id);
  if (source === "file") return SECRET_REF_FILE_ID_RE.test(id);
  return SECRET_REF_EXEC_ID_RE.test(id)
    && !id.split("/").some((segment) => segment === "." || segment === "..");
}

/**
 * Evaluate effective gateway authentication semantics rather than rejecting
 * authentication fields because they exist. Exactly one supported shape is
 * accepted: a local loopback gateway whose `gateway.auth.mode` is `token`,
 * whose token is a SecretRef, and whose Tailscale identity path is provably
 * inert. Every other shape fails closed - a second effective credential
 * surface, a plaintext credential, an unsupported or unselected mode, a
 * malformed reference, or an unknown field in either bounded object.
 * Shell-environment and remote credential fallbacks are refused by the
 * `config.env` and `gateway.remote` gates that run before this one.
 */
function assertSupportedGatewayAuthentication(gateway) {
  const tailscale = gateway?.tailscale;
  if (tailscale !== undefined) {
    // `off` keeps Tailscale Serve/Funnel from publishing a second reachable
    // authentication path; the remaining members must stay unset so no
    // Serve-derived default can turn identity auth back on.
    if (!allowedKeys(tailscale, GATEWAY_TAILSCALE_FIELDS)
        || tailscale.mode !== "off"
        || tailscale.serviceName !== undefined
        || tailscale.preserveFunnel !== undefined
        || (tailscale.resetOnExit !== undefined
          && tailscale.resetOnExit !== false)) {
      fail("live_config_tailscale_authentication_refused");
    }
  }
  const auth = gateway?.auth;
  if (auth === undefined) fail("live_config_authentication_absent");
  if (!allowedKeys(auth, GATEWAY_AUTH_FIELDS)) {
    fail("live_config_authentication_invalid");
  }
  if (auth.mode !== "token") {
    fail("live_config_authentication_mode_unsupported");
  }
  // A configured second credential surface leaves the effective mode
  // ambiguous even when `mode` names one of them, so both are refused.
  if (auth.password !== undefined || auth.trustedProxy !== undefined) {
    fail("live_config_authentication_ambiguous");
  }
  // Tailscale identity headers would satisfy gateway auth without the token.
  if (auth.allowTailscale !== undefined && auth.allowTailscale !== false) {
    fail("live_config_authentication_ambiguous");
  }
  // A failed-auth limiter can reject the observation's own loopback calls.
  if (auth.rateLimit !== undefined) {
    fail("live_config_authentication_unsupported");
  }
  if (auth.token === undefined) fail("live_config_authentication_absent");
  if (!isSupportedGatewaySecretRef(auth.token)) {
    fail("live_config_authentication_secret_ref_invalid");
  }
}

export function inspectOpenClawCanaryConfig(account) {
  const statePhysical = assertOwnedDirectory(
    account.stateRoot,
    account.uid,
    "live_state_root_invalid",
    { privateMode: true },
  );
  if (statePhysical !== account.stateRoot
      || !withinOrEqual(account.home, statePhysical)) {
    fail("live_state_root_identity_mismatch");
  }
  const config = parsePrivateJson(readOwnedRegularFile(account.configPath, {
    maxBytes: 4 * 1024 * 1024,
    privateMode: true,
    ownerUid: account.uid,
    code: "live_config_invalid",
  }), "live_config_malformed");
  if (containsIncludeDirective(config)) fail("live_config_include_refused");
  if (config.env !== undefined) {
    if (!exactKeys(config.env, ["shellEnv"])
        || !config.env.shellEnv
        || typeof config.env.shellEnv !== "object"
        || Array.isArray(config.env.shellEnv)
        || !allowedKeys(config.env.shellEnv, ["enabled", "timeoutMs"])
        || config.env.shellEnv.enabled !== false) {
      fail("live_config_environment_ambiguous");
    }
  }
  if (config.proxy !== undefined) fail("live_config_proxy_refused");
  const connectorConfig = config?.plugins?.entries?.[PUBLIC_PLUGIN_ID]?.config;
  if (connectorConfig && typeof connectorConfig === "object"
      && !Array.isArray(connectorConfig)
      && (connectorConfig.stateDir !== undefined
        || connectorConfig.receiptDir !== undefined)) {
    fail("live_config_connector_path_override_refused");
  }
  const gateway = config.gateway;
  if (gateway !== undefined
      && (!gateway || typeof gateway !== "object" || Array.isArray(gateway))) {
    fail("live_config_gateway_invalid");
  }
  if (gateway?.mode !== undefined && gateway.mode !== "local") {
    fail("live_config_remote_mode_refused");
  }
  if (gateway?.remote !== undefined) fail("live_config_remote_refused");
  if (gateway?.port !== undefined && gateway.port !== 18789) {
    fail("live_config_endpoint_mismatch");
  }
  if (gateway?.bind !== undefined && gateway.bind !== "loopback") {
    fail("live_config_endpoint_mismatch");
  }
  if (gateway?.tls?.enabled === true) fail("live_config_endpoint_mismatch");
  assertSupportedGatewayAuthentication(gateway);
  return Object.freeze({
    state_root: statePhysical,
    config_path: account.configPath,
    endpoint: OPENCLAW_LIVE_ENDPOINT,
  });
}

function validateStoredDeviceAuthentication(account) {
  const identityDirectory = join(account.stateRoot, "identity");
  const identityPhysical = assertOwnedDirectory(
    identityDirectory,
    account.uid,
    "live_device_identity_directory_invalid",
    { privateMode: true },
  );
  if (!withinOrEqual(account.stateRoot, identityPhysical)) {
    fail("live_device_identity_containment_invalid");
  }
  const device = parsePrivateJson(readOwnedRegularFile(
    join(identityDirectory, "device.json"),
    {
      maxBytes: 1024 * 1024,
      privateMode: true,
      ownerUid: account.uid,
      code: "live_device_identity_invalid",
    },
  ), "live_device_identity_invalid");
  try {
    if (device.version !== 1
        || !/^[a-f0-9]{64}$/.test(device.deviceId ?? "")
        || typeof device.publicKeyPem !== "string"
        || typeof device.privateKeyPem !== "string") {
      fail("live_device_identity_invalid");
    }
    const publicKey = createPublicKey(device.publicKeyPem);
    const privateKey = createPrivateKey(device.privateKeyPem);
    if (publicKey.asymmetricKeyType !== "ed25519"
        || privateKey.asymmetricKeyType !== "ed25519") {
      fail("live_device_identity_invalid");
    }
    const probe = Buffer.from("openclaw-device-identity-self-check", "utf8");
    if (!verify(null, probe, publicKey, sign(null, probe, privateKey))) {
      fail("live_device_identity_invalid");
    }
    const spki = publicKey.export({ type: "spki", format: "der" });
    const derived = createHash("sha256").update(spki.subarray(-32)).digest("hex");
    if (derived !== device.deviceId) fail("live_device_identity_invalid");
  } catch (error) {
    if (error?.code?.startsWith?.("live_")) throw error;
    fail("live_device_identity_invalid");
  }
  const auth = parsePrivateJson(readOwnedRegularFile(
    join(identityDirectory, "device-auth.json"),
    {
      maxBytes: 1024 * 1024,
      privateMode: true,
      ownerUid: account.uid,
      code: "live_device_auth_invalid",
    },
  ), "live_device_auth_invalid");
  const operator = auth?.tokens?.operator;
  if (auth.version !== 1 || auth.deviceId !== device.deviceId
      || !operator || typeof operator !== "object" || Array.isArray(operator)
      || typeof operator.token !== "string" || operator.token.trim() === ""
      || operator.token.length > 16 * 1024
      || operator.role !== "operator"
      || !Array.isArray(operator.scopes)
      || !operator.scopes.some(
        (scope) => ["operator.read", "operator.write", "operator.admin"].includes(scope),
      )) {
    fail("live_device_auth_invalid");
  }
  return operator.token;
}

export function parseOpenClawVersionOutput(
  output,
  expectedVersion = OPENCLAW_LIVE_RUNTIME_VERSION,
) {
  if (typeof expectedVersion !== "string"
      || !BARE_VERSION_OUTPUT_RE.test(expectedVersion)) {
    fail("live_expected_version_invalid");
  }
  if (typeof output !== "string"
      || Buffer.byteLength(output, "utf8") === 0
      || Buffer.byteLength(output, "utf8") > MAX_RUNTIME_VERSION_OUTPUT_BYTES
      || /[\u0000-\u001f\u007f]/.test(output)) {
    fail("live_runtime_version_output_invalid");
  }
  const bare = BARE_VERSION_OUTPUT_RE.exec(output);
  let parsed;
  if (bare) {
    parsed = {
      semanticVersion: bare[1],
      buildIdentifier: null,
      format: "bare_semantic_version",
    };
  }
  if (!parsed) {
    const decorated = DECORATED_VERSION_OUTPUT_RE.exec(output);
    if (decorated) {
      parsed = {
        semanticVersion: decorated[1],
        buildIdentifier: decorated[2],
        format: "openclaw_decorated",
      };
    }
  }
  if (!parsed) fail("live_runtime_version_output_invalid");
  if (parsed.semanticVersion !== expectedVersion) {
    fail("live_runtime_version_mismatch");
  }
  return Object.freeze(parsed);
}

function parseRuntimeVersionStdout(stdout, expectedVersion) {
  if (typeof stdout !== "string"
      || Buffer.byteLength(stdout, "utf8") === 0
      || Buffer.byteLength(stdout, "utf8") > MAX_RUNTIME_VERSION_OUTPUT_BYTES) {
    fail("live_runtime_version_output_invalid");
  }
  const output = stdout.endsWith("\n") ? stdout.slice(0, -1) : stdout;
  return parseOpenClawVersionOutput(output, expectedVersion);
}

export function validateOpenClawCanaryRuntime({
  account,
  commandRunner = defaultCommandRunner,
  environment,
}) {
  const runtimePath = account.runtimePath;
  const packageRoot = dirname(runtimePath);
  const packagePath = join(packageRoot, "package.json");
  const buildInfoPath = join(packageRoot, "dist", "build-info.json");
  assertNoSymlinkComponents(runtimePath, {
    code: "live_runtime_symlink_refused",
  });
  try {
    const stat = lstatSync(runtimePath);
    if (stat.isSymbolicLink() || !stat.isFile()
        || stat.uid !== account.uid
        || realpathSync(runtimePath) !== runtimePath) {
      fail("live_runtime_identity_mismatch");
    }
    accessSync(runtimePath, FS_CONSTANTS.X_OK);
  } catch (error) {
    if (error?.code?.startsWith?.("live_")) throw error;
    fail("live_runtime_unavailable");
  }
  const runtimeBytes = readOwnedRegularFile(runtimePath, {
    maxBytes: 4 * 1024 * 1024,
    ownerUid: account.uid,
    code: "live_runtime_invalid",
  });
  const packageBytes = readOwnedRegularFile(packagePath, {
    maxBytes: 4 * 1024 * 1024,
    ownerUid: account.uid,
    code: "live_package_json_invalid",
  });
  const buildInfoBytes = readOwnedRegularFile(buildInfoPath, {
    maxBytes: 1024 * 1024,
    ownerUid: account.uid,
    code: "live_build_info_invalid",
  });
  const runtimeEntrySha256 =
    createHash("sha256").update(runtimeBytes).digest("hex");
  const packageJsonSha256 =
    createHash("sha256").update(packageBytes).digest("hex");
  const buildInfoSha256 =
    createHash("sha256").update(buildInfoBytes).digest("hex");
  const packageJson = parsePrivateJson(
    packageBytes, "live_package_json_invalid",
  );
  const buildInfo = parsePrivateJson(
    buildInfoBytes, "live_build_info_invalid",
  );
  // The build coordinate names at most one approved target. Everything after
  // this is checked against that one candidate, so approved values are never
  // combined across targets.
  const candidates = OPENCLAW_CANARY_TARGETS.filter((entry) => (
    entry.semantic_version === buildInfo.version
      && entry.full_build_commit === buildInfo.commit
  ));
  if (candidates.length !== 1) fail("live_build_info_identity_mismatch");
  const target = candidates[0];
  if (runtimeEntrySha256 !== target.runtime_entry_sha256) {
    fail("live_runtime_entry_hash_mismatch");
  }
  if (packageJsonSha256 !== target.package_json_sha256) {
    fail("live_package_json_hash_mismatch");
  }
  if (buildInfoSha256 !== target.build_info_sha256) {
    fail("live_build_info_hash_mismatch");
  }
  // Re-resolve from all five identity fields at once. This is redundant with
  // the checks above and deliberately so: it is the single place that decides
  // a runtime is approved, and it fails closed on any mixed or unknown build.
  if (resolveOpenClawCanaryTarget({
    semantic_version: buildInfo.version,
    full_build_commit: buildInfo.commit,
    runtime_entry_sha256: runtimeEntrySha256,
    package_json_sha256: packageJsonSha256,
    build_info_sha256: buildInfoSha256,
  }) !== target) {
    fail("live_runtime_target_not_approved");
  }
  if (packageJson.name !== "openclaw"
      || packageJson.version !== target.semantic_version
      || packageJson.bin?.openclaw !== "openclaw.mjs") {
    fail("live_package_json_identity_mismatch");
  }
  let result;
  try {
    result = commandRunner(runtimePath, ["--version"], {
      timeoutMs: 5_000,
      maxBytes: 64 * 1024,
      environment,
      cwd: account.home,
    });
  } catch {
    fail("live_runtime_version_probe_failed");
  }
  if (result?.error || result?.signal || result?.status !== 0) {
    fail("live_runtime_version_probe_failed");
  }
  const reported = parseRuntimeVersionStdout(
    result.stdout, target.semantic_version,
  );
  const decorated = target.full_build_commit.slice(0, 7);
  if (reported.format !== "openclaw_decorated"
      || reported.buildIdentifier !== decorated) {
    fail("live_runtime_build_identifier_mismatch");
  }
  return Object.freeze({
    resolved: runtimePath,
    version: reported.semanticVersion,
    versionOutputFormat: reported.format,
    buildIdentifier: reported.buildIdentifier,
    fullBuildCommit: buildInfo.commit,
    runtimeIdentity: target.runtime_identity,
    semanticVersion: target.semantic_version,
  });
}

function profileBindingSummary(approved, runtime) {
  return Object.freeze({
    ok: true,
    binding_id: approved.binding.binding_id,
    profile_mode: approved.profileSelection.mode,
    profile_identity: approved.profileSelection.identity,
    source_commit: approved.auditedPackage.source_commit,
    source_tree: approved.auditedPackage.source_tree,
    plugin_version: approved.auditedPackage.plugin_version,
    runtime_version: runtime.version,
    runtime_build_identifier: runtime.buildIdentifier,
    expires_at: approved.binding.expires_at,
  });
}

export function initializeOpenClawProfileBinding(options) {
  const allowed = [
    "profileMode", "profile", "profileHome", "profileBindingPath",
    "packageManifestPath", "now", "commandRunner", "environment",
  ];
  if (!allowedKeys(options, allowed)) fail("live_profile_binding_options_invalid");
  const {
    profileMode,
    profile,
    profileHome,
    profileBindingPath,
    packageManifestPath,
    now = () => new Date().toISOString(),
    commandRunner = defaultCommandRunner,
    environment = process.env,
  } = options;
  if (typeof now !== "function" || typeof commandRunner !== "function") {
    fail("live_profile_binding_options_invalid");
  }
  const auditedPackage = readAuditedOpenClawPackageManifest(packageManifestPath);
  const profileSelection = resolveOpenClawProfileSelection(profileMode, profile);
  const account = resolveExplicitOpenClawAccount(profileSelection, profileHome);
  const createdAt = timestamp(now(), "live_profile_binding_clock_invalid");
  const expiresAt = new Date(
    Date.parse(createdAt) + PROFILE_BINDING_MAX_LIFETIME_MS,
  ).toISOString();
  const safeEnvironment = buildSafeOpenClawEnvironment(
    account, profileSelection, environment,
  );
  inspectOpenClawCanaryConfig(account);
  const runtime = validateOpenClawCanaryRuntime({
    account,
    commandRunner,
    environment: safeEnvironment,
  });
  // Pin the one approved target this host actually runs. A binding never
  // carries the approved set, only the exact build it was initialized against.
  const targetBindingId = approvedTargetBindingIdFor(
    auditedPackage.source_commit,
    runtime.semanticVersion,
    runtime.fullBuildCommit,
  );
  if (targetBindingId === null) fail("live_runtime_target_not_approved");
  const binding = buildProfileBindingDocument({
    auditedPackage,
    profileSelection,
    account,
    createdAt,
    expiresAt,
    targetBindingId,
  });
  const outputPath = assertPrivateBindingOutputPath(profileBindingPath);
  try {
    writeFileSync(outputPath, `${JSON.stringify(binding, null, 2)}\n`, {
      flag: "wx",
      mode: 0o600,
    });
  } catch (error) {
    fail(error?.code === "EEXIST"
      ? "live_profile_binding_exists" : "live_profile_binding_unwritable");
  }
  const approved = Object.freeze({
    auditedPackage,
    binding,
    profileSelection,
    account,
  });
  return profileBindingSummary(approved, runtime);
}

export function verifyOpenClawProfileBinding(options) {
  const allowed = [
    "profileMode", "profile", "profileHome", "profileBindingPath",
    "profileBindingId",
    "packageManifestPath", "now", "commandRunner", "environment",
  ];
  if (!allowedKeys(options, allowed)) fail("live_profile_binding_options_invalid");
  const approved = readApprovedOpenClawProfileBinding(options);
  const commandRunner = options.commandRunner ?? defaultCommandRunner;
  if (typeof commandRunner !== "function") fail("live_profile_binding_options_invalid");
  const safeEnvironment = buildSafeOpenClawEnvironment(
    approved.account,
    approved.profileSelection,
    options.environment ?? process.env,
  );
  inspectOpenClawCanaryConfig(approved.account);
  const runtime = validateOpenClawCanaryRuntime({
    account: approved.account,
    commandRunner,
    environment: safeEnvironment,
  });
  return profileBindingSummary(approved, runtime);
}

function gatewayCall(
  runtime,
  profileSelection,
  method,
  params,
  commandRunner,
  environment,
  accountHome,
  operatorToken,
) {
  if (!OPENCLAW_LIVE_RPC_METHODS.includes(method)) {
    fail("live_rpc_method_not_allowlisted");
  }
  const args = [
    ...profileSelection.argvPrefix,
    "gateway",
    "call",
    method,
    "--url",
    OPENCLAW_LIVE_ENDPOINT,
    "--token",
    operatorToken,
  ];
  if (params !== null) {
    args.push("--params", canonicalizeJson(params));
  }
  args.push("--json", "--timeout", "5000");
  let result;
  try {
    result = commandRunner(runtime, args, {
      timeoutMs: 7_500,
      maxBytes: MAX_RPC_BYTES,
      environment,
      cwd: accountHome,
    });
  } catch {
    fail("live_rpc_failed", method);
  }
  if (result?.error?.code === "ENOBUFS") fail("live_rpc_response_too_large");
  if (result?.error || result?.signal || result?.status !== 0) {
    fail("live_rpc_failed", method);
  }
  const stdout = String(result.stdout ?? "");
  if (Buffer.byteLength(stdout, "utf8") > MAX_RPC_BYTES) {
    fail("live_rpc_response_too_large");
  }
  try {
    return JSON.parse(stdout);
  } catch {
    fail("live_rpc_json_invalid", method);
  }
}

function parseAgents(result, requestedAgentIds) {
  if (!result || typeof result !== "object" || Array.isArray(result)
      || !Array.isArray(result.agents)) {
    fail("live_agents_response_invalid");
  }
  const available = new Set();
  for (const agent of result.agents) {
    available.add(safeId(agent?.id, "live_agent_id_invalid"));
  }
  if (!Array.isArray(requestedAgentIds) || requestedAgentIds.length === 0) {
    fail("live_agent_allowlist_required");
  }
  const selected = [...new Set(requestedAgentIds.map(
    (id) => safeId(id, "live_agent_id_invalid"),
  ))];
  for (const id of selected) {
    if (!available.has(id)) fail("live_agent_not_found");
  }
  return selected.sort();
}

function parseToolCatalog(result, agentId, inventory) {
  if (!result || typeof result !== "object" || Array.isArray(result)
      || !Array.isArray(result.groups)) {
    fail("live_tools_catalog_invalid");
  }
  for (const group of result.groups) {
    if (!group || typeof group !== "object"
        || !["core", "plugin"].includes(group.source)
        || !Array.isArray(group.tools)) {
      fail("live_tools_catalog_invalid");
    }
    const source = group.source;
    const groupPluginId = source === "plugin"
      ? safeId(group.pluginId, "live_plugin_id_invalid")
      : null;
    for (const tool of group.tools) {
      const toolId = safeId(tool?.id, "live_tool_id_invalid");
      const pluginId = source === "plugin"
        ? safeId(tool.pluginId ?? groupPluginId, "live_plugin_id_invalid")
        : null;
      const identity = `${source}\0${pluginId ?? ""}\0${toolId}`;
      if (!inventory.has(identity)) {
        inventory.set(identity, {
          tool: toolId,
          source,
          ...(pluginId === null ? {} : { plugin_id: pluginId }),
          agent_ids: new Set(),
        });
      }
      inventory.get(identity).agent_ids.add(agentId);
    }
  }
}

function openBoundedReceiptLedger(receiptPath) {
  if (!isAbsolute(receiptPath)) fail("live_receipt_path_not_absolute");
  assertNoSymlinkComponents(receiptPath, {
    code: "live_receipt_symlink_component_refused",
  });
  let fd;
  try {
    const pathStat = lstatSync(receiptPath);
    if (pathStat.isSymbolicLink()) fail("live_receipt_symlink_refused");
    if (!pathStat.isFile()) fail("live_receipt_not_regular_file");
    if ((pathStat.mode & 0o077) !== 0) fail("live_receipt_permissions_insecure");
    if (typeof process.getuid === "function" && pathStat.uid !== process.getuid()) {
      fail("live_receipt_owner_mismatch");
    }
    fd = openSync(
      receiptPath,
      FS_CONSTANTS.O_RDONLY
        | (FS_CONSTANTS.O_NOFOLLOW ?? 0)
        | (FS_CONSTANTS.O_NONBLOCK ?? 0),
    );
    const descriptorStat = fstatSync(fd);
    if (!descriptorStat.isFile()
        || descriptorStat.dev !== pathStat.dev
        || descriptorStat.ino !== pathStat.ino) {
      fail("live_receipt_identity_changed");
    }
    if (descriptorStat.size > MAX_RECEIPT_BYTES) {
      fail("live_receipt_ledger_too_large");
    }
    return readFileSync(fd, { encoding: "utf8" });
  } catch (error) {
    if (error?.code?.startsWith?.("live_")) throw error;
    fail("live_receipt_ledger_unreadable");
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function validateLifecycle(record) {
  return exactKeys(record, LIFECYCLE_KEYS)
    && record.schema === "mcpherson-governance-connector-lifecycle/v1"
    && record.record_type === "connector_lifecycle"
    && record.plugin_id === "mcpherson-governance-connector"
    && record.plugin_version === LIVE_LIFECYCLE_PLUGIN_VERSION
    && SAFE_ID_RE.test(record.record_id)
    && isCalendarUtcTimestamp(record.timestamp)
    && ["gateway_start", "gateway_stop"].includes(record.event)
    && ["POST_HOOK", "ATTEMPT_ONLY"].includes(record.receipt_mode)
    && record.remote_authority === false
    && Array.isArray(record.enforceable_remote_decisions)
    && record.enforceable_remote_decisions.length === 0;
}

function parseReceiptLedger(text) {
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (lines.length > MAX_RECEIPT_LINES) fail("live_receipt_line_count_exceeded");
  const records = [];
  const ids = new Set();
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (Buffer.byteLength(line, "utf8") > MAX_RECEIPT_LINE_BYTES) {
      fail("live_receipt_line_too_large");
    }
    if (line.trim().length === 0) fail("live_receipt_blank_line");
    let record;
    try {
      record = JSON.parse(line);
    } catch {
      fail("live_receipt_json_invalid");
    }
    const valid = record?.receipt_type === "attempt_receipt"
      ? validateAttemptReceipt(record).ok
      : record?.receipt_type === "completion_receipt"
        ? validateCompletionReceipt(record).ok
        : validateLifecycle(record);
    if (!valid) fail("live_receipt_contract_invalid");
    const identity = record.receipt_id ?? record.record_id;
    if (ids.has(identity)) fail("live_receipt_id_duplicate");
    ids.add(identity);
    records.push(record);
  }
  return records;
}

function inWindow(value, startMs, endMs) {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && parsed >= startMs && parsed <= endMs;
}

function pairKey(record) {
  return [
    record.request_hash,
    record.correlation_ref,
    record.deployment_id,
    record.agent_id,
    record.tool_id,
  ].join("\0");
}

function aggregateReceipts(records, { start, end, agentIds }) {
  const startMs = Date.parse(start);
  const endMs = Date.parse(end);
  const approvedAgents = new Set(agentIds);
  const attempts = [];
  const completions = [];
  let receiptMode = "ATTEMPT_ONLY";
  for (const record of records) {
    if (record.record_type === "connector_lifecycle") {
      if (inWindow(record.timestamp, startMs, endMs)
          && record.receipt_mode === "POST_HOOK") {
        receiptMode = "POST_HOOK";
      }
      continue;
    }
    if (!approvedAgents.has(record.agent_id)) continue;
    if (record.receipt_type === "attempt_receipt"
        && inWindow(record.attempt_at, startMs, endMs)) {
      attempts.push(record);
    } else if (record.receipt_type === "completion_receipt"
        && inWindow(record.completed_at, startMs, endMs)) {
      completions.push(record);
      receiptMode = "POST_HOOK";
    }
  }
  const completionsByKey = new Map();
  for (const completion of completions) {
    const key = pairKey(completion);
    if (!completionsByKey.has(key)) completionsByKey.set(key, []);
    completionsByKey.get(key).push(completion);
  }
  for (const values of completionsByKey.values()) {
    values.sort((left, right) => (
      left.completed_at < right.completed_at ? -1 : 1
    ));
  }
  const aggregates = new Map();
  const latencyPairs = [];
  for (const attempt of attempts.sort((left, right) => (
    left.attempt_at < right.attempt_at ? -1 : 1
  ))) {
    const toolId = safeId(attempt.tool_id, "live_receipt_tool_id_invalid");
    if (!aggregates.has(toolId)) {
      aggregates.set(toolId, { attempts: 0, completions: 0 });
    }
    aggregates.get(toolId).attempts += 1;
    const queue = completionsByKey.get(pairKey(attempt)) ?? [];
    const matchIndex = queue.findIndex(
      (completion) => Date.parse(completion.completed_at)
        >= Date.parse(attempt.attempt_at),
    );
    if (matchIndex === -1) continue;
    const [completion] = queue.splice(matchIndex, 1);
    aggregates.get(toolId).completions += 1;
    const duration = Date.parse(completion.completed_at)
      - Date.parse(attempt.attempt_at);
    if (Number.isFinite(duration) && duration >= 0 && duration <= 1_000_000_000) {
      latencyPairs.push({ attempt, completion, duration });
    }
  }
  if ([...completionsByKey.values()].some((queue) => queue.length > 0)) {
    fail("live_receipt_completion_without_attempt");
  }
  return { aggregates, latencyPairs, receiptMode };
}

function aggregateId(toolId, start, end) {
  const digest = createHash("sha256")
    .update(canonicalizeJson({ tool_id: toolId, start, end }), "utf8")
    .digest("hex");
  return `rcpt-${digest.slice(0, 32)}`;
}

function liveBindingFields(binding) {
  return Object.freeze({
    target_binding_id: binding.targetBindingId,
    source_commit: binding.sourceCommit,
    profile_mode: binding.profileSelection.mode,
    profile: binding.profileSelection.identity,
    profile_identity: binding.profileSelection.identity,
    runtime_identity: OPENCLAW_CANARY_TARGET.runtime_identity,
    endpoint_identity: OPENCLAW_LIVE_ENDPOINT,
    runtime_semantic_version: binding.runtime.version,
    runtime_build_identifier: binding.runtime.buildIdentifier,
  });
}

function receiptSummary(
  aggregate, observationId, capturedAt, start, end, binding,
) {
  const receipts = [...aggregate.aggregates.entries()]
    .map(([toolId, counts]) => Object.freeze({
      receipt_id: aggregateId(toolId, start, end),
      granularity: "TOOL_LEVEL",
      native_tool_name: toolId,
      attempt_receipts: counts.attempts,
      completion_receipts: counts.completions,
      receipt_mode: aggregate.receiptMode === "POST_HOOK"
        ? "POST_HOOK"
        : "ATTEMPT_ONLY",
    }))
    .sort((left, right) => (
      left.native_tool_name < right.native_tool_name ? -1 : 1
    ));
  const result = Object.freeze({
    schema: LIVE_RECEIPT_SUMMARY_SCHEMA,
    observation_id: observationId,
    source_id: "openclaw-live",
    ...liveBindingFields(binding),
    ...LIVE_AUTHORITY_FIELDS,
    source_note: "Sanitized aggregate of the local OpenClaw connector receipt ledger; "
      + "payloads and receipt identities are not retained.",
    sanitization_confirmed: true,
    measurement_kind: "LIVE_SHADOW",
    captured_at: capturedAt,
    window_start: start,
    window_end: end,
    receipts,
  });
  assertValidArtifact(LIVE_RECEIPT_SUMMARY_SCHEMA, result);
  return result;
}

function latencyEventSet(aggregate, observationId, binding) {
  const events = aggregate.latencyPairs.map(({ attempt, completion, duration }, index) => {
    const result = Object.freeze({
      schema: LIVE_LATENCY_EVENT_SCHEMA,
      observation_id: observationId,
      source_id: "openclaw-live",
      ...liveBindingFields(binding),
      ...LIVE_AUTHORITY_FIELDS,
      instrumentation_version: OPENCLAW_LIVE_ADAPTER_VERSION,
      measurement_kind: "LIVE_SHADOW",
      sequence: index + 1,
      ts_utc: completion.completed_at,
      tags: Object.freeze({
        agent_id: attempt.agent_id,
        capability_id: "UNKNOWN",
        normalized_capability: `${attempt.tool_id}.invoke`,
        risk_tier: "UNKNOWN",
        policy_outcome: "UNKNOWN",
        cache_state: "NONE",
        path_kind: "LOCAL",
        remote_status: attempt.remote_status,
        mapping_status: "UNKNOWN",
        classification_status: "UNKNOWN",
      }),
      durations_ms: Object.freeze({ tool_execution_ms: duration }),
    });
    assertValidArtifact(LIVE_LATENCY_EVENT_SCHEMA, result);
    return result;
  });
  const result = Object.freeze({
    schema: LIVE_LATENCY_EVENT_SET_SCHEMA,
    observation_id: observationId,
    source_id: "openclaw-live",
    ...liveBindingFields(binding),
    ...LIVE_AUTHORITY_FIELDS,
    source_note: "Durations pair local connector attempt and supported post-hook "
      + "completion receipts; they are observation-window data, not an SLA.",
    measurement_kind: "LIVE_SHADOW",
    events,
  });
  assertValidArtifact(LIVE_LATENCY_EVENT_SET_SCHEMA, result);
  return result;
}

function capabilitySnapshot(
  inventory, agentIds, observationId, capturedAt, binding,
) {
  const tools = [...inventory.values()]
    .map((entry) => Object.freeze({
      tool: entry.tool,
      source: entry.source,
      ...(entry.plugin_id === undefined ? {} : { plugin_id: entry.plugin_id }),
      agent_ids: [...entry.agent_ids].sort(),
      operations: [Object.freeze({
        operation: "invoke",
        declared_effects: ["UNKNOWN"],
        completion_evidence: "UNKNOWN",
      })],
    }))
    .sort((left, right) => (
      `${left.source}:${left.plugin_id ?? ""}:${left.tool}`
        < `${right.source}:${right.plugin_id ?? ""}:${right.tool}` ? -1 : 1
    ));
  const result = Object.freeze({
    schema: LIVE_CAPABILITY_SNAPSHOT_SCHEMA,
    observation_id: observationId,
    source_id: "openclaw-live",
    ...liveBindingFields(binding),
    source_kind: "openclaw_live_gateway",
    sanitization_confirmed: true,
    measurement_kind: "LIVE_SHADOW",
    ...LIVE_AUTHORITY_FIELDS,
    captured_at: capturedAt,
    runtime: Object.freeze({
      product: "openclaw",
      version: binding.runtime.version,
      build_identifier: binding.runtime.buildIdentifier,
      profile_mode: binding.profileSelection.mode,
      profile: binding.profileSelection.identity,
      observation_methods: [...OPENCLAW_LIVE_RPC_METHODS],
    }),
    agents: agentIds.map((id) => Object.freeze({ id })),
    tools,
  });
  assertValidArtifact(LIVE_CAPABILITY_SNAPSHOT_SCHEMA, result);
  return result;
}

const ABSENT_SUPPLIERS = Object.freeze({
  VISIBLE: Object.freeze({
    owner: "source_platform",
    tenant: "source_platform",
    enabled_state: "runtime_integration",
  }),
  ATTRIBUTABLE: Object.freeze({
    human_owner: "source_platform",
    agent_identity: "runtime_integration",
    runtime_identity: "runtime_integration",
    tenant: "source_platform",
    connector_or_grant_identity: "connector",
    run_id: "runtime_integration",
    request_id: "runtime_integration",
    executor_relevant: "runtime_integration",
  }),
  SCOPED: Object.freeze({
    permitted_action: "policy_configuration",
    target_or_resource: "policy_configuration",
    parameter_constraints: "policy_configuration",
    tenant: "policy_configuration",
    limits: "policy_configuration",
    expiry: "policy_configuration",
    policy_version: "policy_configuration",
    source_state_relevant: "policy_configuration",
  }),
  INDEPENDENTLY_REVOCABLE: Object.freeze({
    administrative_claim: "source_platform",
    authoritative_revocation_state: "source_platform",
    execution_time_revocation_check: "runtime_integration",
    observed_refusal_evidence: "runtime_integration",
  }),
});

function absentFields(criterion) {
  return Object.fromEntries(
    Object.entries(ABSENT_SUPPLIERS[criterion]).map(([field, supplier]) => [
      field,
      Object.freeze({ status: "absent", refs: [], expected_supplier: supplier }),
    ]),
  );
}

function presentEvidence({
  criterion, field, value, unitId, capturedAt, kind, supplier,
}) {
  return Object.freeze({
    status: "present",
    asserts: true,
    value,
    refs: [`openclaw:${field}:${unitId}`],
    expected_supplier: supplier,
    evidence_kind: kind,
    supports: `${criterion}.${field}`,
    unit_ref: unitId,
    observed_at: capturedAt,
  });
}

function governabilityEvidence(snapshot, observationId, capturedAt, binding) {
  const units = snapshot.tools.map((tool) => {
    const unitId = tool.tool;
    return Object.freeze({
      unit_type: "capability",
      unit_id: unitId,
      evidence: Object.freeze({
        visible: Object.freeze({
          stable_identity: presentEvidence({
            criterion: "VISIBLE",
            field: "stable_identity",
            value: unitId,
            unitId,
            capturedAt,
            kind: "inventory_record",
            supplier: "runtime_integration",
          }),
          source: presentEvidence({
            criterion: "VISIBLE",
            field: "source",
            value: tool.source === "plugin" ? "openclaw_plugin" : "openclaw_core",
            unitId,
            capturedAt,
            kind: "inventory_record",
            supplier: "runtime_integration",
          }),
          runtime_association: presentEvidence({
            criterion: "VISIBLE",
            field: "runtime_association",
            value: `openclaw-${snapshot.runtime.version}`,
            unitId,
            capturedAt,
            kind: "integration_config",
            supplier: "runtime_integration",
          }),
          last_seen_at: presentEvidence({
            criterion: "VISIBLE",
            field: "last_seen_at",
            value: capturedAt,
            unitId,
            capturedAt,
            kind: "runtime_receipt",
            supplier: "runtime_integration",
          }),
          ...absentFields("VISIBLE"),
        }),
        attributable: Object.freeze(absentFields("ATTRIBUTABLE")),
        scoped: Object.freeze(absentFields("SCOPED")),
        independently_revocable: Object.freeze(
          absentFields("INDEPENDENTLY_REVOCABLE"),
        ),
      }),
    });
  });
  const digest = createHash("sha256")
    .update(canonicalizeJson({
      captured_at: capturedAt,
      unit_ids: units.map((unit) => unit.unit_id),
    }), "utf8")
    .digest("hex");
  const result = Object.freeze({
    schema: "mcpherson-governance-governability-evidence/v1",
    observation_id: observationId,
    source_id: "openclaw-live",
    ...liveBindingFields(binding),
    ...LIVE_AUTHORITY_FIELDS,
    evidence_set_id: `live-${digest.slice(0, 24)}`,
    sanitization_confirmed: true,
    captured_at: capturedAt,
    units,
  });
  assertValidArtifact(
    "mcpherson-governance-governability-evidence/v1",
    result,
  );
  return result;
}

// Single serialization choke point for every live-observation artifact. Both
// the written file and the observation-binding hash derive from this
// function, so redaction here is what the binding actually commits to.
//
// The observer already restricts itself to allowlisted metadata, so on a
// well-formed artifact redaction is a no-op and the bytes are unchanged from
// v0.6.1. It is retained as defence in depth: if credential material ever
// reaches this point it is removed before the bytes exist, and the redacted
// result is re-scanned so a shape the redactor could not neutralise fails
// closed instead of being written.
function artifactBytes(value) {
  const { value: redacted } = redactSecretsWithReport(value);
  if (scanForSecrets(redacted).length > 0) {
    fail("live_output_secret_material_detected");
  }
  return `${JSON.stringify(redacted, null, 2)}\n`;
}

function artifactHash(bytes) {
  return `sha256:${createHash("sha256").update(bytes, "utf8").digest("hex")}`;
}

function createOutputDirectory(outDir) {
  if (!isAbsolute(outDir)) fail("live_output_directory_not_absolute");
  try {
    mkdirSync(outDir, { mode: 0o700 });
  } catch (error) {
    fail(error?.code === "EEXIST"
      ? "live_output_directory_exists"
      : "live_output_directory_unwritable");
  }
}

function normalizeObservationIdForBinding(value) {
  if (Array.isArray(value)) return value.map(normalizeObservationIdForBinding);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [
    key,
    key === "observation_id"
      ? OBSERVATION_ID_SENTINEL
      : normalizeObservationIdForBinding(child),
  ]));
}

function observationBindingDescriptor(filename, value) {
  const bytes = artifactBytes(normalizeObservationIdForBinding(value));
  return Object.freeze({
    filename,
    sha256: artifactHash(bytes),
    bytes: Buffer.byteLength(bytes, "utf8"),
  });
}

export function openClawObservationIdFor({
  targetBindingId,
  sourceCommit,
  observationStart,
  observationEnd,
  evidenceFiles,
}) {
  if (!TARGET_BINDING_ID_RE.test(targetBindingId ?? "")
      || !/^[a-f0-9]{40}$/.test(sourceCommit ?? "")
      || !isCalendarUtcTimestamp(observationStart)
      || !isCalendarUtcTimestamp(observationEnd)
      || !Array.isArray(evidenceFiles)
      || evidenceFiles.length !== 4) {
    fail("live_observation_id_input_invalid");
  }
  const inventory = evidenceFiles.map((entry) => ({
    filename: entry.filename,
    sha256: entry.sha256,
    bytes: entry.bytes,
  })).sort((left, right) => left.filename.localeCompare(right.filename));
  const digest = createHash("sha256").update(canonicalizeJson({
    schema: "mcpherson-governance-openclaw-observation-id-input/v1",
    target_binding_id: targetBindingId,
    source_commit: sourceCommit,
    observation_start: observationStart,
    observation_end: observationEnd,
    evidence_files: inventory,
  }), "utf8").digest("hex");
  return `live-obs-${digest}`;
}

function writeArtifact(outDir, filename, value) {
  const bytes = artifactBytes(value);
  try {
    writeFileSync(join(outDir, filename), bytes, { flag: "wx", mode: 0o600 });
  } catch {
    fail("live_output_write_failed");
  }
  return Object.freeze({
    filename,
    sha256: artifactHash(bytes),
    bytes: Buffer.byteLength(bytes, "utf8"),
  });
}

function readVerifiedOutputFile(path, maxBytes) {
  let fd;
  try {
    const pathStat = lstatSync(path);
    if (pathStat.isSymbolicLink() || !pathStat.isFile()) {
      fail("live_output_artifact_not_regular");
    }
    if ((pathStat.mode & 0o077) !== 0) {
      fail("live_output_artifact_permissions_insecure");
    }
    if (typeof process.getuid === "function" && pathStat.uid !== process.getuid()) {
      fail("live_output_artifact_owner_mismatch");
    }
    fd = openSync(
      path,
      FS_CONSTANTS.O_RDONLY
        | (FS_CONSTANTS.O_NOFOLLOW ?? 0)
        | (FS_CONSTANTS.O_NONBLOCK ?? 0),
    );
    const descriptorStat = fstatSync(fd);
    if (!descriptorStat.isFile()
        || descriptorStat.dev !== pathStat.dev
        || descriptorStat.ino !== pathStat.ino) {
      fail("live_output_artifact_identity_changed");
    }
    if (descriptorStat.size > maxBytes) {
      fail("live_output_artifact_too_large");
    }
    return readFileSync(fd);
  } catch (error) {
    if (error?.code?.startsWith?.("live_")) throw error;
    fail("live_output_artifact_unreadable");
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function parseVerifiedJson(bytes) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("live_output_artifact_json_invalid");
  }
}

/**
 * Re-read and verify one completed observation directory.
 *
 * The verifier binds the exact fixed inventory, file ownership/modes,
 * manifest bytes and hashes, artifact contracts, runtime/profile/window
 * context, and manifest counts. It accepts no path from inside the manifest.
 */
export function verifyOpenClawLiveObservationDirectory({
  outDir,
  packageManifestPath,
  profileBindingPath,
  profileBindingId,
}) {
  const approved = readApprovedOpenClawProfileBinding({
    profileBindingPath,
    profileBindingId,
    packageManifestPath,
  });
  const { auditedPackage } = approved;
  assertSafeOpenClawEvidenceRoot({
    outDir,
    sourceInputs: [],
    allowExistingFinal: true,
  });
  let directoryStat;
  try {
    directoryStat = lstatSync(outDir);
  } catch {
    fail("live_output_directory_unreadable");
  }
  if (directoryStat.isSymbolicLink() || !directoryStat.isDirectory()) {
    fail("live_output_directory_not_regular");
  }
  if ((directoryStat.mode & 0o077) !== 0) {
    fail("live_output_directory_permissions_insecure");
  }
  if (typeof process.getuid === "function"
      && directoryStat.uid !== process.getuid()) {
    fail("live_output_directory_owner_mismatch");
  }
  const expectedFiles = Object.values(LIVE_OUTPUT_FILES).sort();
  const actualFiles = readdirSync(outDir).sort();
  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
    fail("live_output_inventory_mismatch");
  }

  const manifestBytes = readVerifiedOutputFile(
    join(outDir, LIVE_OUTPUT_FILES.manifest),
    2 * 1024 * 1024,
  );
  const manifest = parseVerifiedJson(manifestBytes);
  const manifestContract = validateEnvelope(
    LIVE_OBSERVATION_MANIFEST_SCHEMA, manifest,
  );
  if (!manifestContract.ok) fail("live_output_manifest_invalid");
  if (!OBSERVATION_ID_RE.test(manifest.observation_id ?? "")
      || !hasLiveAuthorityFields(manifest)
      || !hasLiveBindingFields(manifest)
      || !matchesAuditedTarget(manifest, auditedPackage, approved.binding)) {
    fail("live_output_manifest_authority_invalid");
  }
  if (manifest.artifacts.length !== 4
      || !Array.isArray(manifest.observation_binding_inventory)
      || manifest.observation_binding_inventory.length !== 4) {
    fail("live_output_manifest_inventory_invalid");
  }

  const expectedSchemas = Object.freeze({
    [LIVE_OUTPUT_FILES.snapshot]: LIVE_CAPABILITY_SNAPSHOT_SCHEMA,
    [LIVE_OUTPUT_FILES.evidence]:
      "mcpherson-governance-governability-evidence/v1",
    [LIVE_OUTPUT_FILES.receipts]: LIVE_RECEIPT_SUMMARY_SCHEMA,
    [LIVE_OUTPUT_FILES.latency]: LIVE_LATENCY_EVENT_SET_SCHEMA,
  });
  const parsed = new Map();
  const observationBindingInventory = [];
  for (const descriptor of manifest.artifacts) {
    const expectedSchema = expectedSchemas[descriptor.filename];
    if (expectedSchema === undefined || parsed.has(descriptor.filename)) {
      fail("live_output_manifest_inventory_invalid");
    }
    const bytes = readVerifiedOutputFile(
      join(outDir, descriptor.filename),
      MAX_OUTPUT_ARTIFACT_BYTES,
    );
    if (bytes.length !== descriptor.bytes
        || artifactHash(bytes) !== descriptor.sha256) {
      fail("live_output_artifact_hash_mismatch");
    }
    const value = parseVerifiedJson(bytes);
    const contract = validateEnvelope(expectedSchema, value);
    if (!contract.ok) fail("live_output_artifact_contract_invalid");
    if (value.observation_id !== manifest.observation_id
        || value.source_id !== "openclaw-live"
        || !hasLiveAuthorityFields(value)
        || !hasLiveBindingFields(value)
        || !sameLiveBinding(value, manifest)
        || !matchesAuditedTarget(value, auditedPackage, approved.binding)) {
      fail("live_output_artifact_source_binding_invalid");
    }
    parsed.set(descriptor.filename, value);
    observationBindingInventory.push(
      observationBindingDescriptor(descriptor.filename, value),
    );
  }
  if (parsed.size !== 4) fail("live_output_manifest_inventory_invalid");

  const snapshot = parsed.get(LIVE_OUTPUT_FILES.snapshot);
  const evidence = parsed.get(LIVE_OUTPUT_FILES.evidence);
  const receipts = parsed.get(LIVE_OUTPUT_FILES.receipts);
  const latency = parsed.get(LIVE_OUTPUT_FILES.latency);
  if (snapshot.captured_at !== manifest.captured_at
      || receipts.captured_at !== manifest.captured_at
      || evidence.captured_at !== manifest.captured_at
      || receipts.window_start !== manifest.window_start
      || receipts.window_end !== manifest.window_end
      || snapshot.runtime.product !== manifest.runtime.product
      || snapshot.runtime.version !== manifest.runtime.version
      || snapshot.runtime.build_identifier !== manifest.runtime.build_identifier
      || snapshot.runtime.profile_mode !== manifest.runtime.profile_mode
      || snapshot.runtime.profile !== manifest.runtime.profile
      || JSON.stringify(snapshot.runtime.observation_methods)
        !== JSON.stringify(manifest.runtime.observation_methods)) {
    fail("live_output_context_mismatch");
  }
  if (manifest.runtime.version !== manifest.runtime_semantic_version
      || manifest.runtime.build_identifier !== manifest.runtime_build_identifier
      || manifest.runtime.profile_mode !== manifest.profile_mode
      || manifest.runtime.profile !== manifest.profile
      || (manifest.profile_mode === "DEFAULT"
        && manifest.profile !== OPENCLAW_DEFAULT_PROFILE_IDENTITY)
      || (manifest.profile_mode === "NAMED"
        && manifest.profile.toLowerCase() === OPENCLAW_DEFAULT_PROFILE_IDENTITY)
      || Date.parse(manifest.window_start) > Date.parse(manifest.window_end)
      || Date.parse(manifest.captured_at) < Date.parse(manifest.window_end)) {
    fail("live_output_context_invalid");
  }
  const snapshotAgents = snapshot.agents.map((agent) => agent.id);
  if (new Set(snapshotAgents).size !== snapshotAgents.length) {
    fail("live_output_agent_inventory_invalid");
  }
  const approvedAgents = new Set(snapshotAgents);
  const snapshotToolIds = snapshot.tools.map((tool) => tool.tool);
  if (new Set(snapshotToolIds).size !== snapshotToolIds.length
      || snapshot.tools.some((tool) => (
        tool.agent_ids.some((agentId) => !approvedAgents.has(agentId))
      ))) {
    fail("live_output_tool_inventory_invalid");
  }
  const evidenceUnits = evidence.units.map((unit) => unit.unit_id).sort();
  if (new Set(evidenceUnits).size !== evidenceUnits.length) {
    fail("live_output_evidence_inventory_mismatch");
  }
  const snapshotTools = [...snapshotToolIds].sort();
  if (JSON.stringify(evidenceUnits) !== JSON.stringify(snapshotTools)) {
    fail("live_output_evidence_inventory_mismatch");
  }
  const receiptTools = receipts.receipts.map((receipt) => receipt.native_tool_name);
  if (new Set(receiptTools).size !== receiptTools.length
      || receipts.receipts.some((receipt) => (
        receipt.completion_receipts > receipt.attempt_receipts
      ))) {
    fail("live_output_receipt_inventory_invalid");
  }
  if (latency.events.some((event) => (
    event.observation_id !== manifest.observation_id
      || event.source_id !== manifest.source_id
      || !hasLiveAuthorityFields(event)
      || !hasLiveBindingFields(event)
      || !sameLiveBinding(event, manifest)
      || !approvedAgents.has(event.tags.agent_id)
      || Date.parse(event.ts_utc) < Date.parse(manifest.window_start)
      || Date.parse(event.ts_utc) > Date.parse(manifest.window_end)
  ))) {
    fail("live_output_latency_context_invalid");
  }
  const counts = {
    agents: snapshot.agents.length,
    tools: snapshot.tools.length,
    receipt_groups: receipts.receipts.length,
    latency_events: latency.events.length,
  };
  if (JSON.stringify(counts) !== JSON.stringify(manifest.counts)) {
    fail("live_output_manifest_counts_mismatch");
  }
  const expectedBindingInventory = [...observationBindingInventory]
    .sort((left, right) => left.filename.localeCompare(right.filename));
  const recordedBindingInventory = [...manifest.observation_binding_inventory]
    .sort((left, right) => left.filename.localeCompare(right.filename));
  if (canonicalizeJson(recordedBindingInventory)
        !== canonicalizeJson(expectedBindingInventory)) {
    fail("live_output_observation_binding_inventory_mismatch");
  }
  const recomputedObservationId = openClawObservationIdFor({
    targetBindingId: approved.binding.binding_id,
    sourceCommit: auditedPackage.source_commit,
    observationStart: manifest.window_start,
    observationEnd: manifest.window_end,
    evidenceFiles: expectedBindingInventory,
  });
  if (manifest.observation_id !== recomputedObservationId) {
    fail("live_output_observation_id_mismatch");
  }
  return Object.freeze({
    ok: true,
    observation_id: manifest.observation_id,
    target_binding_id: manifest.target_binding_id,
    source_id: "openclaw-live",
    manifest_sha256: artifactHash(manifestBytes),
    measurement_kind: "LIVE_SHADOW",
    source_commit: manifest.source_commit,
    profile_mode: manifest.profile_mode,
    profile: manifest.profile,
    runtime_semantic_version: manifest.runtime_semantic_version,
    runtime_build_identifier: manifest.runtime_build_identifier,
    captured_at: manifest.captured_at,
    window_start: manifest.window_start,
    window_end: manifest.window_end,
    artifacts: Object.freeze(Object.fromEntries(
      manifest.artifacts.map((entry) => [
        entry.filename,
        Object.freeze({ sha256: entry.sha256, bytes: entry.bytes }),
      ]),
    )),
    counts: Object.freeze(counts),
  });
}

/**
 * Mandatory downstream evidence boundary. Verification is performed first,
 * then one fixed-inventory artifact is re-read from the verified directory.
 * Callers cannot select a path from manifest content.
 */
export function readVerifiedOpenClawLiveArtifact({
  outDir,
  filename,
  packageManifestPath,
  profileBindingPath,
  profileBindingId,
}) {
  const allowed = Object.values(LIVE_OUTPUT_FILES)
    .filter((entry) => entry !== LIVE_OUTPUT_FILES.manifest);
  if (!allowed.includes(filename)) fail("live_output_artifact_name_invalid");
  const verification = verifyOpenClawLiveObservationDirectory({
    outDir,
    packageManifestPath,
    profileBindingPath,
    profileBindingId,
  });
  const bytes = readVerifiedOutputFile(
    join(outDir, filename), MAX_OUTPUT_ARTIFACT_BYTES,
  );
  const descriptor = verification.artifacts[filename];
  if (!descriptor
      || bytes.length !== descriptor.bytes
      || artifactHash(bytes) !== descriptor.sha256) {
    fail("live_output_artifact_hash_mismatch");
  }
  return Object.freeze({
    ok: true,
    verification,
    value: parseVerifiedJson(bytes),
  });
}

/**
 * Observe one local OpenClaw runtime without modifying it.
 *
 * `commandRunner` is injectable solely for deterministic adversarial tests.
 * The CLI exposes no injection. Production uses spawnSync with shell:false,
 * fixed argv, and paths reconstructed from a verified local profile binding.
 */
export function observeOpenClawLive(options) {
  const optionKeys = Object.freeze([
    "profileMode",
    "profile",
    "profileHome",
    "profileBindingPath",
    "profileBindingId",
    "packageManifestPath",
    "receiptPath",
    "outDir",
    "start",
    "end",
    "agentIds",
    "now",
    "commandRunner",
    "environment",
  ]);
  if (!allowedKeys(options, optionKeys)) fail("live_observer_options_invalid");
  const {
    profileMode,
    profile,
    profileHome,
    profileBindingPath,
    profileBindingId,
    packageManifestPath,
    receiptPath,
    outDir,
    start,
    end,
    agentIds = [],
    now = () => new Date().toISOString(),
    commandRunner = defaultCommandRunner,
    environment = process.env,
  } = options;
  if (typeof commandRunner !== "function"
      || typeof now !== "function") {
    fail("live_observer_options_invalid");
  }
  timestamp(start, "live_window_start_invalid");
  timestamp(end, "live_window_end_invalid");
  if (Date.parse(start) > Date.parse(end)) fail("live_window_order_invalid");
  const capturedAt = timestamp(now(), "live_capture_timestamp_invalid");
  if (Date.parse(capturedAt) < Date.parse(end)) {
    fail("live_capture_precedes_window_end");
  }
  readAuditedOpenClawPackageManifest(packageManifestPath);
  resolveOpenClawProfileSelection(profileMode, profile);
  const approved = readApprovedOpenClawProfileBinding({
    profileBindingPath,
    profileBindingId,
    packageManifestPath,
    profileMode,
    profile,
    profileHome,
  });
  const { auditedPackage, profileSelection, account } = approved;
  if (receiptPath !== account.receiptPath) {
    fail("live_receipt_path_binding_mismatch");
  }
  assertSafeOpenClawEvidenceRoot({
    outDir,
    sourceInputs: [
      account.runtimePath, packageManifestPath, profileBindingPath,
    ],
  });

  const safeEnvironment = buildSafeOpenClawEnvironment(
    account, profileSelection, environment,
  );
  if (canonicalizeJson(Object.keys(safeEnvironment).sort())
        !== canonicalizeJson([...OPENCLAW_LIVE_CHILD_ENVIRONMENT_KEYS].sort())) {
    fail("live_runtime_environment_inventory_invalid");
  }
  inspectOpenClawCanaryConfig(account);
  const ledgerText = openBoundedReceiptLedger(receiptPath);
  const records = parseReceiptLedger(ledgerText);
  const operatorToken = validateStoredDeviceAuthentication(account);
  const runtime = validateOpenClawCanaryRuntime({
    account,
    commandRunner,
    environment: safeEnvironment,
  });
  const binding = Object.freeze({
    sourceCommit: auditedPackage.source_commit,
    targetBindingId: approved.binding.binding_id,
    profileSelection,
    runtime,
  });
  const agentsResult = gatewayCall(
    runtime.resolved,
    profileSelection,
    "agents.list",
    null,
    commandRunner,
    safeEnvironment,
    account.home,
    operatorToken,
  );
  const selectedAgents = parseAgents(agentsResult, agentIds);
  const inventory = new Map();
  for (const agentId of selectedAgents) {
    const catalog = gatewayCall(
      runtime.resolved,
      profileSelection,
      "tools.catalog",
      { agentId, includePlugins: true },
      commandRunner,
      safeEnvironment,
      account.home,
      operatorToken,
    );
    parseToolCatalog(catalog, agentId, inventory);
  }
  if (inventory.size === 0) fail("live_tool_inventory_empty");
  const toolIdentityCounts = new Map();
  for (const entry of inventory.values()) {
    toolIdentityCounts.set(
      entry.tool,
      (toolIdentityCounts.get(entry.tool) ?? 0) + 1,
    );
  }
  if ([...toolIdentityCounts.values()].some((count) => count > 1)) {
    // Receipts identify only tool_id. Two catalog entries with the same
    // tool_id but different core/plugin provenance cannot be attributed
    // without guessing, so refuse the observation rather than collapse them.
    fail("live_tool_identity_ambiguous");
  }
  const aggregate = aggregateReceipts(records, {
    start, end, agentIds: selectedAgents,
  });
  const buildArtifacts = (observationId) => {
    const snapshot = capabilitySnapshot(
      inventory, selectedAgents, observationId, capturedAt, binding,
    );
    return Object.freeze({
      [LIVE_OUTPUT_FILES.snapshot]: snapshot,
      [LIVE_OUTPUT_FILES.evidence]: governabilityEvidence(
        snapshot, observationId, capturedAt, binding,
      ),
      [LIVE_OUTPUT_FILES.receipts]: receiptSummary(
        aggregate, observationId, capturedAt, start, end, binding,
      ),
      [LIVE_OUTPUT_FILES.latency]: latencyEventSet(
        aggregate, observationId, binding,
      ),
    });
  };
  const provisionalArtifacts = buildArtifacts(OBSERVATION_ID_SENTINEL);
  const observationBindingInventory = Object.entries(provisionalArtifacts)
    .map(([filename, value]) => observationBindingDescriptor(filename, value))
    .sort((left, right) => left.filename.localeCompare(right.filename));
  const observationId = openClawObservationIdFor({
    targetBindingId: binding.targetBindingId,
    sourceCommit: binding.sourceCommit,
    observationStart: start,
    observationEnd: end,
    evidenceFiles: observationBindingInventory,
  });
  const finalArtifacts = buildArtifacts(observationId);
  const snapshot = finalArtifacts[LIVE_OUTPUT_FILES.snapshot];
  const receipts = finalArtifacts[LIVE_OUTPUT_FILES.receipts];
  const latency = finalArtifacts[LIVE_OUTPUT_FILES.latency];

  createOutputDirectory(outDir);
  const artifacts = Object.entries(finalArtifacts).map(
    ([filename, value]) => writeArtifact(outDir, filename, value),
  );
  const manifest = Object.freeze({
    schema: LIVE_OBSERVATION_MANIFEST_SCHEMA,
    observation_id: observationId,
    source_id: "openclaw-live",
    ...liveBindingFields(binding),
    ...LIVE_AUTHORITY_FIELDS,
    adapter_version: OPENCLAW_LIVE_ADAPTER_VERSION,
    measurement_kind: "LIVE_SHADOW",
    sanitization_confirmed: true,
    captured_at: capturedAt,
    window_start: start,
    window_end: end,
    runtime: Object.freeze({
      product: "openclaw",
      version: runtime.version,
      build_identifier: runtime.buildIdentifier,
      profile_mode: profileSelection.mode,
      profile: profileSelection.identity,
      observation_methods: [...OPENCLAW_LIVE_RPC_METHODS],
    }),
    counts: Object.freeze({
      agents: selectedAgents.length,
      tools: snapshot.tools.length,
      receipt_groups: receipts.receipts.length,
      latency_events: latency.events.length,
    }),
    observation_binding_inventory: observationBindingInventory,
    artifacts,
    excluded_data: Object.freeze([
      "chat_content",
      "tool_arguments",
      "tool_results",
      "session_identifiers",
      "request_hashes",
      "correlation_references",
      "deployment_identifiers",
      "credentials",
      "runtime_paths",
      "receipt_bodies",
    ]),
  });
  assertValidArtifact(LIVE_OBSERVATION_MANIFEST_SCHEMA, manifest);
  const manifestDescriptor = writeArtifact(
    outDir, LIVE_OUTPUT_FILES.manifest, manifest,
  );
  const verification = verifyOpenClawLiveObservationDirectory({
    outDir,
    packageManifestPath,
    profileBindingPath,
    profileBindingId,
  });
  return Object.freeze({
    ok: true,
    verified: verification.ok,
    out_dir: outDir,
    manifest: manifestDescriptor,
    counts: manifest.counts,
  });
}

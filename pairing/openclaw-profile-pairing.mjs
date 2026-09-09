import { createHash, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync, closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync,
  readFileSync, realpathSync, renameSync, unlinkSync, writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { createRuntimeObservationBootstrap } from "./shadow-observation-contract.mjs";

const PLUGIN_ID = "mcpherson-governance-connector";
const PACKAGE_NAME = "@mcphersonai/mcpherson-governance-openclaw";
const CONNECTOR_ENTRY = join("plugins", "openclaw-connector", "plugin.mjs");
const PROFILE_RE = /^[A-Za-z0-9._-]{1,64}$/;
const TRANSACTION_RE = /^pair_[a-f0-9-]{36}$/;

function fail(code, detail = null) {
  const error = new Error(code);
  error.code = code;
  error.detail = detail;
  throw error;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function plainJson(bytes, code) {
  let parsed;
  try { parsed = JSON.parse(bytes.toString("utf8")); }
  catch { fail(code); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) fail(code);
  return parsed;
}

function assertRegular(path, code) {
  let stat;
  try { stat = lstatSync(path); } catch { fail(code); }
  if (!stat.isFile() || stat.isSymbolicLink()) fail(code);
  return stat;
}

function assertDirectory(path, code) {
  let stat;
  try { stat = lstatSync(path); } catch { fail(code); }
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail(code);
  return stat;
}

function exactRealpath(path, code) {
  try { return realpathSync(path); }
  catch { fail(code); }
}

function inside(parent, child) {
  const rel = relative(parent, child);
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

function packageIdentity(root, { name, version }, code) {
  assertDirectory(root, code);
  const manifestPath = join(root, "package.json");
  assertRegular(manifestPath, code);
  const manifest = plainJson(readFileSync(manifestPath), code);
  if (manifest.name !== name || manifest.version !== version) fail(code);
  return manifest;
}

function defaultRuntimeInspect({ profileState, openclawBin = "openclaw" }) {
  const result = spawnSync(openclawBin, [
    "plugins", "inspect", PLUGIN_ID, "--runtime", "--json",
  ], {
    encoding: "utf8",
    env: { ...process.env, OPENCLAW_STATE_DIR: profileState },
    maxBuffer: 2 * 1024 * 1024,
    timeout: 20_000,
  });
  if (result.error) fail("CONNECTOR_INSPECTION_UNAVAILABLE");
  if (result.status !== 0) return null;
  if (Buffer.byteLength(result.stdout ?? "", "utf8") > 2 * 1024 * 1024) {
    fail("CONNECTOR_INSPECTION_INVALID");
  }
  try { return JSON.parse(result.stdout); }
  catch { fail("CONNECTOR_INSPECTION_INVALID"); }
}

function validateRuntimePlugin(report, expectedVersion) {
  if (!report || typeof report !== "object" || Array.isArray(report)) {
    fail("CONNECTOR_NOT_INSTALLED");
  }
  const plugin = report.plugin;
  if (!Array.isArray(report.diagnostics)) fail("CONNECTOR_INSPECTION_INVALID");
  for (const diagnostic of report.diagnostics) {
    if (!diagnostic || typeof diagnostic !== "object" || Array.isArray(diagnostic)) {
      fail("CONNECTOR_INSPECTION_INVALID");
    }
    if (diagnostic.pluginId === PLUGIN_ID
        && typeof diagnostic.message === "string"
        && diagnostic.message.startsWith("duplicate plugin id ")) {
      fail("CONNECTOR_INSTALL_IDENTITY_AMBIGUOUS");
    }
  }
  if (!plugin || typeof plugin !== "object" || Array.isArray(plugin)) {
    fail("CONNECTOR_INSPECTION_INVALID");
  }
  if (plugin.id !== PLUGIN_ID || plugin.packageName !== PACKAGE_NAME) {
    fail("CONNECTOR_INSTALL_IDENTITY_INVALID");
  }
  if (plugin.version !== expectedVersion) fail("CONNECTOR_VERSION_MISMATCH");
  if (plugin.enabled !== true || plugin.activated !== true
      || plugin.status !== "loaded" || plugin.imported !== true) {
    fail("CONNECTOR_NOT_RUNTIME_LOADED");
  }
  if (typeof plugin.source !== "string" || !isAbsolute(plugin.source)) {
    fail("CONNECTOR_INSTALL_PATH_INVALID");
  }
  return plugin;
}

function validateConnectorRoot(connectorRoot, expectedVersion) {
  packageIdentity(connectorRoot,
    { name: PLUGIN_ID, version: expectedVersion }, "CONNECTOR_INSTALL_IDENTITY_INVALID");
  assertRegular(join(connectorRoot, "plugin.mjs"), "CONNECTOR_INSTALL_IDENTITY_INVALID");
  assertRegular(join(connectorRoot, "constants.mjs"), "CONNECTOR_INSTALL_IDENTITY_INVALID");
  return connectorRoot;
}

function managedNpmPackConnector(paths, report, plugin, expectedVersion) {
  const install = report.install;
  if (!install || install.source !== "npm" || install.artifactKind !== "npm-pack") return null;
  if (install.resolvedName !== PACKAGE_NAME
      || install.version !== expectedVersion
      || install.resolvedVersion !== expectedVersion
      || install.spec !== `${PACKAGE_NAME}@${expectedVersion}`
      || install.resolvedSpec !== `${PACKAGE_NAME}@${expectedVersion}`
      || typeof install.npmIntegrity !== "string"
      || !install.npmIntegrity.startsWith("sha512-")
      || !/^[a-f0-9]{40}$/.test(install.npmShasum ?? "")) {
    fail("CONNECTOR_INSTALL_IDENTITY_INVALID");
  }
  if (typeof install.installPath !== "string" || !isAbsolute(install.installPath)
      || typeof plugin.rootDir !== "string" || !isAbsolute(plugin.rootDir)) {
    fail("CONNECTOR_INSTALL_PATH_INVALID");
  }

  const managedProjects = join(paths.profileState, "npm", "projects");
  assertDirectory(managedProjects, "CONNECTOR_INSTALL_PATH_INVALID");
  const managedReal = exactRealpath(managedProjects, "CONNECTOR_INSTALL_PATH_INVALID");
  const installReal = exactRealpath(install.installPath, "CONNECTOR_INSTALL_PATH_INVALID");
  const pluginRootReal = exactRealpath(plugin.rootDir, "CONNECTOR_INSTALL_PATH_INVALID");
  if (!inside(managedReal, installReal) || installReal !== pluginRootReal) {
    fail("CONNECTOR_INSTALL_PATH_INVALID");
  }
  packageIdentity(installReal,
    { name: PACKAGE_NAME, version: expectedVersion }, "CONNECTOR_INSTALL_IDENTITY_INVALID");
  const expectedSource = join(installReal, CONNECTOR_ENTRY);
  assertRegular(expectedSource, "CONNECTOR_INSTALL_IDENTITY_INVALID");
  if (exactRealpath(plugin.source, "CONNECTOR_INSTALL_PATH_INVALID")
      !== exactRealpath(expectedSource, "CONNECTOR_INSTALL_PATH_INVALID")) {
    fail("CONNECTOR_INSTALL_PATH_INVALID");
  }
  return validateConnectorRoot(dirname(expectedSource), expectedVersion);
}

function legacyConnector(paths, plugin, expectedVersion) {
  const connectorRoot = paths.legacyConnectorRoot;
  const packageRoot = dirname(dirname(connectorRoot));
  const expectedSource = join(connectorRoot, "plugin.mjs");
  if (!existsSync(expectedSource)) return null;
  packageIdentity(packageRoot,
    { name: PACKAGE_NAME, version: expectedVersion }, "CONNECTOR_INSTALL_IDENTITY_INVALID");
  assertRegular(expectedSource, "CONNECTOR_INSTALL_IDENTITY_INVALID");
  if (exactRealpath(plugin.source, "CONNECTOR_INSTALL_PATH_INVALID")
      !== exactRealpath(expectedSource, "CONNECTOR_INSTALL_PATH_INVALID")) {
    fail("CONNECTOR_INSTALL_PATH_INVALID");
  }
  return validateConnectorRoot(connectorRoot, expectedVersion);
}

function resolveConnectorRoot(paths, report, expectedVersion) {
  const plugin = validateRuntimePlugin(report, expectedVersion);
  const managed = managedNpmPackConnector(paths, report, plugin, expectedVersion);
  if (managed) return { connectorRoot: managed, installLayout: "MANAGED_NPM_PACK" };
  const legacy = legacyConnector(paths, plugin, expectedVersion);
  if (legacy) return { connectorRoot: legacy, installLayout: "LEGACY_EXTENSION" };
  fail("CONNECTOR_INSTALL_LAYOUT_UNSUPPORTED");
}

function atomicWrite(path, bytes, mode = 0o600) {
  const directory = dirname(path);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const temporary = join(directory, `.${basename(path)}.tmp-${randomUUID()}`);
  let fd;
  try {
    fd = openSync(temporary, "wx", mode);
    writeFileSync(fd, bytes);
    fsyncSync(fd);
    closeSync(fd); fd = undefined;
    chmodSync(temporary, mode);
    renameSync(temporary, path);
    const dirFd = openSync(directory, "r");
    try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
  } catch (error) {
    if (fd !== undefined) try { closeSync(fd); } catch { /* already closed */ }
    try { if (existsSync(temporary)) unlinkSync(temporary); } catch { /* best effort temp cleanup */ }
    throw error;
  }
}

function writeJsonAtomic(path, value) {
  atomicWrite(path, Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8"));
}

export function resolveOpenClawProfile({ profile = "default", profileHome } = {}) {
  if (!PROFILE_RE.test(profile)) fail("PROFILE_NAME_INVALID");
  const home = resolve(profileHome ?? homedir());
  const isDefault = profile === "default";
  const state = join(home, isDefault ? ".openclaw" : `.openclaw-${profile}`);
  return Object.freeze({
    profile,
    profileMode: isDefault ? "DEFAULT" : "NAMED",
    profileState: state,
    configPath: join(state, "openclaw.json"),
    legacyConnectorRoot: join(
      state, "extensions", PLUGIN_ID, "plugins", "openclaw-connector"),
    connectorState: join(state, PLUGIN_ID),
  });
}

export function inspectOpenClawProfile({
  profile = "default",
  profileHome,
  replaceExisting = false,
  expectedConnectorVersion,
  runtimeInspect = defaultRuntimeInspect,
} = {}) {
  if (typeof expectedConnectorVersion !== "string" || expectedConnectorVersion.length > 64
      || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(expectedConnectorVersion)) {
    fail("CONNECTOR_EXPECTED_VERSION_INVALID");
  }
  const paths = resolveOpenClawProfile({ profile, profileHome });
  if (!existsSync(paths.profileState)) fail("PROFILE_STATE_MISSING");
  assertRegular(paths.configPath, "PROFILE_CONFIG_INVALID");
  const configBytes = readFileSync(paths.configPath);
  const config = plainJson(configBytes, "PROFILE_CONFIG_INVALID");
  const entry = config.plugins?.entries?.[PLUGIN_ID] ?? null;
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    fail("CONNECTOR_NOT_CONFIGURED");
  }
  const resolvedInstall = resolveConnectorRoot(paths,
    runtimeInspect({ profile, profileState: paths.profileState }), expectedConnectorVersion);
  const credentialFile = join(paths.connectorState, "deployment-credential");
  const hasCredential = existsSync(credentialFile);
  if (hasCredential) {
    assertRegular(credentialFile, "EXISTING_CREDENTIAL_INVALID");
    if (!replaceExisting) fail("EXISTING_CREDENTIAL_REQUIRES_REPLACE_FLAG");
  }
  return Object.freeze({
    ...paths,
    ...resolvedInstall,
    expectedConnectorVersion,
    credentialFile,
    hasCredential,
    configSha256: sha256(configBytes),
    currentEndpoint: typeof entry?.config?.apiUrl === "string" ? entry.config.apiUrl : null,
    currentEnabled: entry?.enabled === true && entry?.config?.enabled === true,
  });
}

/**
 * Create the non-authoritative observation bootstrap for exactly the profile
 * that passed preflight. It contains no tool identities or semantic metadata;
 * the profile hash only prevents copied config from becoming eligible in a
 * different OpenClaw state root.
 */
export function createPairingObservationBootstrap(inspection) {
  if (!inspection || typeof inspection.profileState !== "string"
      || !isAbsolute(inspection.profileState)) {
    fail("PAIRING_OBSERVATION_BOOTSTRAP_INPUT_INVALID");
  }
  return createRuntimeObservationBootstrap(inspection.profileState);
}

function updatedConfig(before, connectorConfig) {
  const plugins = before.plugins && typeof before.plugins === "object"
    && !Array.isArray(before.plugins) ? before.plugins : {};
  const entries = plugins.entries && typeof plugins.entries === "object"
    && !Array.isArray(plugins.entries) ? plugins.entries : {};
  const current = entries[PLUGIN_ID] && typeof entries[PLUGIN_ID] === "object"
    && !Array.isArray(entries[PLUGIN_ID]) ? entries[PLUGIN_ID] : {};
  return {
    ...before,
    plugins: {
      ...plugins,
      entries: {
        ...entries,
        [PLUGIN_ID]: { ...current, enabled: true, config: connectorConfig },
      },
    },
  };
}

function rollbackRoot(inspection) {
  return join(inspection.connectorState, "pairing-rollbacks");
}

function writeManifest(directory, manifest) {
  writeJsonAtomic(join(directory, "TRANSACTION.json"), manifest);
}

export async function commitOpenClawPairing({
  inspection,
  connectorConfig,
  credential,
  installCredential,
  credentialPath,
  verifyCredential,
  now = () => new Date(),
} = {}) {
  if (!inspection || typeof installCredential !== "function"
      || typeof credentialPath !== "function" || typeof verifyCredential !== "function") {
    fail("PAIRING_TRANSACTION_INPUT_INVALID");
  }
  const currentConfigBytes = readFileSync(inspection.configPath);
  if (sha256(currentConfigBytes) !== inspection.configSha256) {
    fail("PROFILE_CONFIG_CHANGED_SINCE_PREFLIGHT");
  }
  const before = plainJson(currentConfigBytes, "PROFILE_CONFIG_INVALID");
  const afterBytes = Buffer.from(`${JSON.stringify(updatedConfig(before, connectorConfig), null, 2)}\n`);
  const transactionId = `pair_${randomUUID()}`;
  const directory = join(rollbackRoot(inspection), transactionId);
  const stage = join(inspection.connectorState, `.pairing-stage-${transactionId}`);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);

  let oldCredential = null;
  if (inspection.hasCredential) oldCredential = readFileSync(inspection.credentialFile);
  const manifest = {
    schema: "observa-openclaw-pairing-transaction/v1",
    transaction_id: transactionId,
    created_at: now().toISOString(),
    profile_mode: inspection.profileMode,
    had_credential: inspection.hasCredential,
    config_before_sha256: sha256(currentConfigBytes),
    config_after_sha256: sha256(afterBytes),
    status: "STAGING",
    authority: "NONE",
    enforcement: "OFF",
  };
  let committedConfig = false;
  let committedCredential = false;
  try {
    atomicWrite(join(directory, "openclaw.json.before"), currentConfigBytes);
    if (oldCredential) atomicWrite(join(directory, "deployment-credential.before"), oldCredential);
    writeManifest(directory, manifest);

    const staged = installCredential(stage, credential);
    await verifyCredential(stage, staged);

    atomicWrite(inspection.configPath, afterBytes);
    committedConfig = true;
    const stagedCredential = credentialPath(stage);
    assertRegular(stagedCredential, "STAGED_CREDENTIAL_INVALID");
    mkdirSync(inspection.connectorState, { recursive: true, mode: 0o700 });
    renameSync(stagedCredential, inspection.credentialFile);
    chmodSync(inspection.credentialFile, 0o600);
    const credentialDirFd = openSync(inspection.connectorState, "r");
    try { fsyncSync(credentialDirFd); } finally { closeSync(credentialDirFd); }
    committedCredential = true;
    await verifyCredential(inspection.connectorState, staged);

    const activeCredential = readFileSync(inspection.credentialFile);
    let activeCredentialSha256;
    try { activeCredentialSha256 = sha256(activeCredential); }
    finally { activeCredential.fill(0); }

    writeManifest(directory, { ...manifest, status: "COMMITTED",
      committed_at: now().toISOString(),
      credential_after_sha256: activeCredentialSha256 });
    return Object.freeze({
      transactionId,
      rollbackDirectory: directory,
      credentialId: staged.credentialId,
      fingerprint: staged.fingerprint,
    });
  } catch (error) {
    try {
      if (committedConfig) atomicWrite(inspection.configPath, currentConfigBytes);
      if (committedCredential) {
        if (oldCredential) atomicWrite(inspection.credentialFile, oldCredential);
        else if (existsSync(inspection.credentialFile)) unlinkSync(inspection.credentialFile);
      }
      writeManifest(directory, { ...manifest, status: "ROLLED_BACK",
        rolled_back_at: now().toISOString() });
    } catch (rollbackError) {
      error.rollbackError = rollbackError?.code ?? rollbackError?.message;
    }
    throw error;
  } finally {
    if (oldCredential) oldCredential.fill(0);
    credential = null;
    try {
      const stagedCredential = credentialPath(stage);
      if (existsSync(stagedCredential)) unlinkSync(stagedCredential);
    } catch { /* no staged secret remains if the directory was never made */ }
  }
}

export function rollbackOpenClawPairing({ inspection, transactionId } = {}) {
  if (!inspection || !TRANSACTION_RE.test(transactionId ?? "")) {
    fail("ROLLBACK_TRANSACTION_INVALID");
  }
  const directory = join(rollbackRoot(inspection), transactionId);
  const manifestPath = join(directory, "TRANSACTION.json");
  assertRegular(manifestPath, "ROLLBACK_TRANSACTION_MISSING");
  const manifest = plainJson(readFileSync(manifestPath), "ROLLBACK_TRANSACTION_INVALID");
  if (manifest.transaction_id !== transactionId || manifest.status !== "COMMITTED") {
    fail("ROLLBACK_TRANSACTION_NOT_COMMITTED");
  }
  const beforeConfig = readFileSync(join(directory, "openclaw.json.before"));
  let beforeCredential = null;
  let currentCredential = null;
  try {
    const currentConfig = readFileSync(inspection.configPath);
    if (sha256(currentConfig) !== manifest.config_after_sha256
        || !existsSync(inspection.credentialFile)) {
      fail("ROLLBACK_PROFILE_CHANGED_SINCE_PAIRING");
    }
    currentCredential = readFileSync(inspection.credentialFile);
    if (sha256(currentCredential) !== manifest.credential_after_sha256) {
      fail("ROLLBACK_PROFILE_CHANGED_SINCE_PAIRING");
    }
    atomicWrite(inspection.configPath, beforeConfig);
    if (manifest.had_credential) {
      beforeCredential = readFileSync(join(directory, "deployment-credential.before"));
      atomicWrite(inspection.credentialFile, beforeCredential);
    } else if (existsSync(inspection.credentialFile)) {
      unlinkSync(inspection.credentialFile);
    }
    writeManifest(directory, { ...manifest, status: "ROLLED_BACK_BY_OPERATOR",
      rolled_back_at: new Date().toISOString() });
    return Object.freeze({ rolledBack: true, transactionId });
  } finally {
    if (beforeCredential) beforeCredential.fill(0);
    if (currentCredential) currentCredential.fill(0);
  }
}

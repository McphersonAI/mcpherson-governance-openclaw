#!/usr/bin/env node
// One-command pairing for a beta tester.
//
//   node observa-pair.mjs --api-url https://<dashboard> --profile default
//
// Everything the tester would otherwise do by hand happens here, in order:
//
//   pairing-code redemption -> installation registration -> scoped credential
//   issuance -> credential installation through the connector's OWN
//   installCredential -> endpoint/config binding -> connector enablement ->
//   connection verification
//
// The tester never copies a credential, never runs scp, never reads a service
// token, never touches a dashboard session, and never edits the credential
// file. The credential exists in this process for as long as it takes to hand
// it to the connector's installer, and is never printed or written outside the
// connector's owner-only credential/rollback state.
//
// This talks to the dashboard over TLS and to nothing else. It starts no
// gateway, contacts no model provider, and performs no action outside the
// named profile. The pairing code is read from a hidden terminal prompt (or an
// owner-only --code-file); it is never accepted in argv.
import { parseArgs } from "node:util";
import {
  closeSync, existsSync, openSync, readFileSync, readSync, writeSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { request as httpsRequest } from "node:https";
import { readSecureFile } from "./plugins/openclaw-connector/secure-files.mjs";
import {
  commitOpenClawPairing, createPairingObservationBootstrap,
  inspectOpenClawProfile, rollbackOpenClawPairing,
} from "./pairing/openclaw-profile-pairing.mjs";
const CANDIDATE_VERSION = "0.8.1";

let values;
try { ({ values } = parseArgs({
  options: {
    "code-file": { type: "string" },
    "api-url": { type: "string" },
    profile: { type: "string", default: "default" },
    "profile-home": { type: "string" },
    "deployment-id": { type: "string" },
    "installation-name": { type: "string" },
    "ca-file": { type: "string" },
    "agent-id": { type: "string", default: "main" },
    "policy-version": { type: "string", default: "3" },
    "replace-existing": { type: "boolean", default: false },
    "preflight-only": { type: "boolean", default: false },
    rollback: { type: "string" },
    help: { type: "boolean", default: false },
  },
})); } catch { die("Invalid pairing options. Run observa pair --help."); }

const USAGE = `
Pair this OpenClaw profile with your Observa dashboard.

  Required connector candidate: ${CANDIDATE_VERSION}

  node observa-pair.mjs --api-url https://<dashboard-host> --profile default

Options
  --api-url            your dashboard's https URL (required)
  --profile            profile to pair: default or a name  [default]
  --profile-home       home directory holding that profile [your home directory]
  --code-file          owner-only file containing the pairing code [hidden prompt]
  --deployment-id      name for this deployment            [the profile name]
  --installation-name  label shown in the dashboard        [the deployment id]
  --ca-file            CA certificate, if your dashboard uses a private CA
  --agent-id           agent id to report                  [main]
  --policy-version     policy version to report            [3]
  --replace-existing   migrate an existing connector credential; rollback is retained
  --preflight-only     verify profile/install/version without reading or redeeming a code
  --rollback <id>      restore the exact pre-pair config and credential snapshot
`;

function die(message) {
  process.stderr.write(`\n${message}\n`);
  process.exit(1);
}
const safeFailure = error => typeof error?.code === 'string' && /^(?:CONNECTOR|PROFILE|CONFIG|CREDENTIAL|PAIRING|ROLLBACK|EXISTING|UNSAFE)_[A-Z0-9_]{1,64}$/.test(error.code) ? error.code : 'OPERATION_REFUSED';

if (values.help) { process.stdout.write(USAGE); process.exit(0); }
if (!values["api-url"] && !values.rollback && !values["preflight-only"]) {
  die(`Missing --api-url.\n${USAGE}`);
}

function readPairingCode() {
  if (values["code-file"]) {
    const path = resolve(values["code-file"]);
    let bytes;
    try { bytes = readSecureFile(path, 512); }
    catch { die("--code-file must be a bounded, regular, owner-only file without links."); }
    try { return bytes.toString("utf8").trim(); }
    finally { bytes.fill(0); }
  }

  let tty;
  const chunks = [];
  try {
    tty = openSync("/dev/tty", "r+");
    const hidden = spawnSync("stty", ["-echo"], { stdio: [tty, tty, tty] });
    if (hidden.status !== 0) die("Could not hide terminal input; use a 0600 --code-file.");
    writeSync(tty, "Pairing code (input hidden): ");
    const byte = Buffer.alloc(1);
    while (chunks.length < 512 && readSync(tty, byte, 0, 1, null) === 1) {
      if (byte[0] === 10 || byte[0] === 13) break;
      chunks.push(byte[0]);
    }
    byte.fill(0);
    return Buffer.from(chunks).toString("utf8").trim();
  } catch {
    die("No interactive terminal; use a 0600 --code-file.");
  } finally {
    if (tty !== undefined) {
      spawnSync("stty", ["echo"], { stdio: [tty, tty, tty] });
      try { writeSync(tty, "\n"); } catch { /* terminal may have closed */ }
      closeSync(tty);
    }
    chunks.fill(0);
  }
}

const apiUrl = values["api-url"] ? (() => {
  let parsed;
  try { parsed = new URL(values["api-url"]); } catch { die("--api-url is not a URL."); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== '/') die("--api-url must be an HTTPS origin without credentials, path, query or fragment.");
  return parsed.origin;
})() : null;

const profile = values.profile;
const profileHome = resolve(values["profile-home"] ?? homedir());
const deploymentId = values["deployment-id"] ?? profile;
let inspection;
try {
  inspection = inspectOpenClawProfile({
    profile, profileHome, replaceExisting: values["replace-existing"] || Boolean(values.rollback),
    expectedConnectorVersion: CANDIDATE_VERSION,
  });
} catch (error) {
  let instructions = "Confirm the profile exists and install the candidate connector first.";
  if (error?.code === "EXISTING_CREDENTIAL_REQUIRES_REPLACE_FLAG") {
    instructions = "This preserves the old credential and config in an owner-only rollback "
      + "snapshot. Re-run with --replace-existing after confirming the endpoint migration.";
  } else if (error?.code === "CONNECTOR_VERSION_MISMATCH") {
    instructions = `Install the exact ${CANDIDATE_VERSION} candidate into this profile.`;
  } else if (error?.code === "CONNECTOR_NOT_RUNTIME_LOADED") {
    instructions = "Confirm OpenClaw reports this plugin enabled, activated, and loaded.";
  } else if (error?.code === "CONNECTOR_INSTALL_IDENTITY_AMBIGUOUS") {
    instructions = "OpenClaw reported multiple sources for this plugin id. Remove the stale "
      + "source, refresh the plugin registry, and confirm one exact candidate remains.";
  }
  die(`Pairing preflight refused: ${safeFailure(error)}\n${instructions}`);
}
const { connectorRoot, connectorState: stateDir, profileState } = inspection;

if (values.rollback) {
  try {
    rollbackOpenClawPairing({ inspection, transactionId: values.rollback });
  } catch (error) {
    die(`Rollback refused: ${safeFailure(error)}`);
  }
  process.stdout.write(`Rolled back pairing transaction ${values.rollback}.\n`);
  process.exit(0);
}

const { PLUGIN_VERSION } = await import(join(connectorRoot, "constants.mjs"));
if (PLUGIN_VERSION !== CANDIDATE_VERSION) {
  die(`Installed connector version is ${PLUGIN_VERSION}; expected `
    + `${CANDIDATE_VERSION}. Install the exact candidate before pairing.`);
}

if (values["preflight-only"]) {
  process.stdout.write(`Pairing preflight PASS.\n\n`
    + `  profile       ${inspection.profileMode}\n`
    + `  install       ${inspection.installLayout}\n`
    + `  version       ${CANDIDATE_VERSION}\n`
    + `  enabled       ${inspection.currentEnabled ? "YES" : "NO"}\n`
    + `  credential    ${inspection.hasCredential ? "PRESENT" : "ABSENT"}\n`
    + `  mode          SHADOW\n`
    + `  authority     NONE\n`
    + `  enforcement   OFF\n`
    + `  active        OFF\n`);
  process.exit(0);
}

const step = (n, text) => process.stdout.write(`[${n}/5] ${text}\n`);

// ---------------------------------------------------------------------------

function postJson(path, body, caFile) {
  return new Promise((resolvePromise, reject) => {
    const payload = Buffer.from(JSON.stringify(body), "utf8");
    const url = new URL(path, apiUrl);
    let timer;
    const finish = (error, value) => { clearTimeout(timer); payload.fill(0); if (error) reject(error); else resolvePromise(value); };
    const req = httpsRequest(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "content-length": String(payload.length),
        accept: "application/json",
        connection: "close",
      },
      ...(caFile ? { ca: readFileSync(caFile) } : {}),
      rejectUnauthorized: true,
    }, (res) => {
      const chunks = []; let size = 0;
      res.on("data", (c) => { size += c.length; if (size > 16384) req.destroy(new Error('PAIRING_RESPONSE_TOO_LARGE')); else chunks.push(c); });
      res.once('error', error => finish(error));
      res.once('aborted', () => finish(new Error('PAIRING_RESPONSE_ABORTED')));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let parsed = null;
        try { parsed = JSON.parse(text); } catch { /* reported below */ }
        finish(null, { status: res.statusCode ?? 0, body: parsed });
      });
    });
    req.once("error", error => finish(error));
    timer = setTimeout(() => req.destroy(new Error('PAIRING_REQUEST_TIMEOUT')), 15000); timer.unref();
    req.write(payload);
    req.end();
  });
}

const caFile = values["ca-file"] ? resolve(values["ca-file"]) : null;
if (caFile && !existsSync(caFile)) die("--ca-file was not found.");

// Validate the complete target config before consuming a single-use code.
const config = {
  enabled: true,
  apiUrl,
  deploymentId,
  agentId: values["agent-id"],
  policyVersion: Number(values["policy-version"]),
  runtimeObservation: createPairingObservationBootstrap(inspection),
  ...(caFile ? { caFile } : {}),
};
const { loadConnectorConfig } = await import(join(connectorRoot, "config.mjs"));
let loaded;
try {
  loaded = loadConnectorConfig(config, { openclawStateDir: profileState });
} catch (error) {
  die(`The connector refused this configuration: ${safeFailure(error)}`);
}

const pairingCode = readPairingCode();
if (!/^[A-Za-z0-9_-]{20,256}$/.test(pairingCode)) {
  die("The pairing code has an invalid shape.");
}

step(1, `Redeeming the pairing code with ${apiUrl}…`);
let redeemed;
try {
  redeemed = await postJson("/v1/pairing/redeem", {
    pairing_code: pairingCode,
    deployment_id: deploymentId,
    installation_name: values["installation-name"] ?? deploymentId,
  }, caFile);
} catch (error) {
  die(`Could not complete a bounded, verified dashboard connection.\n`
    + `Check --api-url, and --ca-file if your dashboard uses a private CA.`);
}
if (redeemed.status === 403) {
  die("That pairing code was not accepted. Codes are single-use and expire\n"
    + "after a few minutes — create a fresh one in the dashboard and retry.");
}
if (redeemed.status === 503) die("The dashboard's control plane is unavailable. Try again shortly.");
if (redeemed.status !== 200 || redeemed.body?.paired !== true) {
  die(`Pairing was not accepted (HTTP ${redeemed.status}). Check the Hosted address and request a fresh pairing code if needed.`);
}

// The credential lives in this variable and goes straight into the connector's
// installer below. It is never printed or written outside the connector's
// owner-only credential/rollback state.
const credential = redeemed.body.credential;
const identity = {
  credential_id: redeemed.body.credential_id,
  fingerprint: redeemed.body.fingerprint,
  installation_id: redeemed.body.installation_id,
  deployment_id: redeemed.body.deployment_id,
};
if (!/^[a-f0-9]{32}$/.test(identity.credential_id) || !/^sha256:[a-f0-9]{16}$/.test(identity.fingerprint)
    || typeof identity.installation_id !== 'string' || !/^[A-Za-z0-9._:-]{1,96}$/.test(identity.installation_id)
    || identity.deployment_id !== loaded.deploymentId) die('Hosted returned an invalid or contradictory pairing identity. No local pairing was activated.');

step(2, "Staging and verifying the credential…");
const { installCredential, credentialPath, withCredential } =
  await import(join(connectorRoot, "credentials.mjs"));
const { GovernanceApiClient } = await import(join(connectorRoot, "client.mjs"));
const client = new GovernanceApiClient({
  baseUrl: loaded.apiUrl,
  connectTimeoutMs: loaded.connectTimeoutMs,
  caFile: loaded.caFile,
});
const verifyCredential = async (candidateState, descriptor) => {
  if (descriptor.credentialId !== identity.credential_id || descriptor.fingerprint !== identity.fingerprint) {
    throw new Error("issued credential identity mismatch");
  }
  await withCredential(candidateState, async (value) => {
    const healthy = await client.health(value);
    if (healthy !== true) throw new Error("health check refused");
    await client.credentialIdentity(value, {
      expectedCredentialId: identity.credential_id,
      expectedDeploymentId: identity.deployment_id,
    });
  });
};

step(3, "Atomically binding the endpoint and enabling the connector…");
let committed;
let activationError;
try {
  committed = await commitOpenClawPairing({
    inspection,
    connectorConfig: config,
    credential,
    installCredential,
    credentialPath,
    verifyCredential,
  });
} catch (error) {
  activationError = error;
} finally {
  await client.shutdown().catch(() => {});
}
if (activationError) {
  die(`Pairing activation failed and local state was rolled back: `
    + `${safeFailure(activationError)}`);
}
process.stdout.write(`      credential ${committed.credentialId} (${committed.fingerprint})\n`);
process.stdout.write(`      endpoint ${loaded.apiUrl} as ${loaded.deploymentId}\n`);

step(4, "Dashboard identity and health verified before and after activation.");

step(5, "Paired.");
process.stdout.write(`
This OpenClaw profile is now connected to your dashboard in SHADOW mode.

  authority      NONE
  enforcement    OFF
  active         OFF
  decisions      WOULD_* (observation only — nothing is ever blocked or held)

Open the dashboard and you should see this installation listed as a connected
live shadow source. Supported OpenClaw tool hooks now produce metadata-only
OBSERVED / UNMAPPED evidence as your agents use tools. This does not map,
approve, authorize, or enforce those tools. Codex-native tools appear only when
the OpenClaw host relays them through its supported tool-hook contract.

Exact local rollback (the snapshot is owner-only and contains the prior credential):

  npm exec --yes --package ./mcphersonai-mcpherson-governance-openclaw-${CANDIDATE_VERSION}.tgz -- \\
    observa-pair --profile ${profile} --rollback ${committed.transactionId}

To disconnect permanently: revoke installation ${identity.installation_id} in
the dashboard, verify the old credential is refused, then run the rollback command.
`);

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
  closeSync, existsSync, openSync, readFileSync, readSync, statSync, writeSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { request as httpsRequest } from "node:https";
import {
  commitOpenClawPairing, createPairingObservationBootstrap,
  inspectOpenClawProfile, rollbackOpenClawPairing,
} from "./pairing/openclaw-profile-pairing.mjs";
const CANDIDATE_VERSION = "0.7.3";

const { values } = parseArgs({
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
});

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

if (values.help) { process.stdout.write(USAGE); process.exit(0); }
if (!values["api-url"] && !values.rollback && !values["preflight-only"]) {
  die(`Missing --api-url.\n${USAGE}`);
}

function readPairingCode() {
  if (values["code-file"]) {
    const path = resolve(values["code-file"]);
    const stat = statSync(path);
    if (!stat.isFile() || (stat.mode & 0o077) !== 0) {
      die("--code-file must be a regular owner-only file (mode 0600 or stricter).");
    }
    const bytes = readFileSync(path);
    if (bytes.length > 512) die("--code-file is too large.");
    try { return bytes.toString("utf8").trim(); }
    finally { bytes.fill(0); }
  }

  let tty;
  const chunks = [];
  try {
    tty = openSync("/dev/tty", "r+");
    writeSync(tty, "Pairing code (input hidden): ");
    const hidden = spawnSync("stty", ["-echo"], { stdio: [tty, tty, tty] });
    if (hidden.status !== 0) die("Could not hide terminal input; use a 0600 --code-file.");
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
  if (parsed.protocol !== "https:") die("--api-url must be https.");
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
  die(`Pairing preflight refused: ${error?.code ?? error?.message}\n${instructions}`);
}
const { connectorRoot, connectorState: stateDir, profileState } = inspection;

if (values.rollback) {
  try {
    rollbackOpenClawPairing({ inspection, transactionId: values.rollback });
  } catch (error) {
    die(`Rollback refused: ${error?.code ?? error?.message}`);
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
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let parsed = null;
        try { parsed = JSON.parse(text); } catch { /* reported below */ }
        resolvePromise({ status: res.statusCode ?? 0, body: parsed, text });
      });
    });
    req.once("error", reject);
    req.write(payload);
    req.end();
  });
}

const caFile = values["ca-file"] ? resolve(values["ca-file"]) : null;
if (caFile && !existsSync(caFile)) die(`--ca-file not found: ${caFile}`);

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
  die(`The connector refused this configuration: ${error?.code ?? error?.message}`);
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
  die(`Could not reach the dashboard: ${error?.code ?? error?.message}\n`
    + `Check --api-url, and --ca-file if your dashboard uses a private CA.`);
}
if (redeemed.status === 403) {
  die("That pairing code was not accepted. Codes are single-use and expire\n"
    + "after a few minutes — create a fresh one in the dashboard and retry.");
}
if (redeemed.status === 503) die("The dashboard's control plane is unavailable. Try again shortly.");
if (redeemed.status !== 200 || !redeemed.body?.paired) {
  die(`Pairing failed (HTTP ${redeemed.status}): ${redeemed.body?.reason ?? redeemed.text.slice(0, 200)}`);
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
process.stdout.write(`      installation ${identity.installation_id}\n`);

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
  if (descriptor.credentialId !== identity.credential_id) {
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
    + `${activationError?.remoteStatus ?? activationError?.code ?? activationError?.message}`);
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

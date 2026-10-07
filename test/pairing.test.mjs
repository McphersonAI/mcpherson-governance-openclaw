// Pairing protections that must survive the v0.7.3 repair unchanged, plus the
// one deliberate addition: the least-privilege hook policy in the plugin entry.
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  commitOpenClawPairing, resolveOpenClawProfile, rollbackOpenClawPairing,
} from "../pairing/openclaw-profile-pairing.mjs";
import { credentialPath, installCredential, parseCredential } from "../plugins/openclaw-connector/credentials.mjs";
import { TEST_CREDENTIAL, cleanupProfiles } from "./helpers.mjs";

const roots = [];
after(() => { cleanupProfiles(); for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

const OTHER_CREDENTIAL = "mgd1_fedcba9876543210fedcba9876543210.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const CONNECTOR_CONFIG = Object.freeze({ enabled: true, apiUrl: "https://hosted.invalid" });

function makeFakeProfile({ before = {}, credential = null } = {}) {
  const home = mkdtempSync(join(tmpdir(), "observa-pair-"));
  roots.push(home);
  const paths = resolveOpenClawProfile({ profile: "default", profileHome: home });
  mkdirSync(paths.profileState, { recursive: true, mode: 0o700 });
  mkdirSync(paths.connectorState, { recursive: true, mode: 0o700 });
  const bytes = Buffer.from(`${JSON.stringify(before, null, 2)}\n`);
  writeFileSync(paths.configPath, bytes, { mode: 0o600 });
  if (credential) installCredential(paths.connectorState, credential);
  return {
    home,
    inspection: {
      ...paths,
      credentialFile: join(paths.connectorState, "deployment-credential"),
      hasCredential: Boolean(credential),
      configSha256: createHash("sha256").update(bytes).digest("hex"),
    },
  };
}

const stagedInstall = (stage, value) => installCredential(stage, value);
const noVerify = async () => undefined;

async function pair(fixture) {
  return commitOpenClawPairing({
    inspection: fixture.inspection,
    connectorConfig: CONNECTOR_CONFIG,
    credential: TEST_CREDENTIAL,
    installCredential: stagedInstall,
    credentialPath,
    verifyCredential: noVerify,
  });
}

const entryOf = (fixture) => JSON.parse(readFileSync(fixture.inspection.configPath, "utf8"))
  .plugins.entries["mcpherson-governance-connector"];

describe("pairing writes the least-privilege hook policy", () => {
  it("a fresh pair denies prompt injection and conversation access", async () => {
    const fixture = makeFakeProfile();
    await pair(fixture);
    const entry = entryOf(fixture);
    assert.equal(entry.enabled, true);
    assert.equal(entry.hooks.allowPromptInjection, false);
    assert.equal(entry.hooks.allowConversationAccess, false);
    assert.deepEqual(entry.config, CONNECTOR_CONFIG);
  });

  it("an explicit operator grant is preserved through re-pairing", async () => {
    const fixture = makeFakeProfile({
      before: {
        plugins: {
          entries: {
            "mcpherson-governance-connector": {
              hooks: { allowPromptInjection: true, timeoutMs: 4321 },
            },
          },
        },
      },
    });
    await pair(fixture);
    const entry = entryOf(fixture);
    assert.equal(entry.hooks.allowPromptInjection, true, "operator intent wins");
    assert.equal(entry.hooks.timeoutMs, 4321);
    assert.equal(entry.hooks.allowConversationAccess, false, "the unset grant is still declined");
  });

  it("other plugins' entries and unrelated host config are untouched", async () => {
    const fixture = makeFakeProfile({
      before: { agents: { entries: { main: {} } }, plugins: { enabled: true, entries: { other: { enabled: true } } } },
    });
    await pair(fixture);
    const config = JSON.parse(readFileSync(fixture.inspection.configPath, "utf8"));
    assert.deepEqual(config.agents, { entries: { main: {} } });
    assert.deepEqual(config.plugins.entries.other, { enabled: true });
    assert.equal(config.plugins.enabled, true);
  });
});

describe("pairing transaction protections are unchanged", () => {
  it("refuses to commit when the profile config changed since preflight", async () => {
    const fixture = makeFakeProfile({ before: { plugins: { entries: {} } } });
    writeFileSync(fixture.inspection.configPath, '{"plugins":{"entries":{"other":{}}}}\n', { mode: 0o600 });
    await assert.rejects(() => pair(fixture), /PROFILE_CONFIG_CHANGED_SINCE_PREFLIGHT/);
  });

  it("rollback restores the exact prior config and credential", async () => {
    const fixture = makeFakeProfile({
      before: { plugins: { entries: {} } },
      credential: OTHER_CREDENTIAL,
    });
    const configBefore = readFileSync(fixture.inspection.configPath, "utf8");
    const credentialBefore = parseCredential(readFileSync(fixture.inspection.credentialFile));

    const committed = await pair(fixture);
    assert.notEqual(readFileSync(fixture.inspection.configPath, "utf8"), configBefore);
    assert.equal(
      parseCredential(readFileSync(fixture.inspection.credentialFile)).credentialId,
      parseCredential(TEST_CREDENTIAL).credentialId,
    );

    rollbackOpenClawPairing({ inspection: fixture.inspection, transactionId: committed.transactionId });
    assert.equal(readFileSync(fixture.inspection.configPath, "utf8"), configBefore, "config restored byte for byte");
    assert.deepEqual(
      parseCredential(readFileSync(fixture.inspection.credentialFile)),
      credentialBefore,
      "the prior credential is restored exactly",
    );
  });

  it("refuses a rollback identifier that is not an exact committed transaction", () => {
    const fixture = makeFakeProfile();
    for (const bad of ["", "pair_", "../escape", "pair_not-a-uuid"]) {
      assert.throws(
        () => rollbackOpenClawPairing({ inspection: fixture.inspection, transactionId: bad }),
        /ROLLBACK_TRANSACTION_INVALID|ROLLBACK_TRANSACTION_MISSING/,
        bad,
      );
    }
  });

  it("keeps the rollback snapshot and the credential owner-only", async () => {
    const fixture = makeFakeProfile({ credential: OTHER_CREDENTIAL });
    const committed = await pair(fixture);
    const { statSync } = await import("node:fs");
    assert.equal(statSync(fixture.inspection.credentialFile).mode & 0o777, 0o600);
    assert.equal(statSync(committed.rollbackDirectory).mode & 0o777, 0o700);
    assert.equal(statSync(join(committed.rollbackDirectory, "deployment-credential.before")).mode & 0o777, 0o600);
  });
});

describe("credential storage protections are unchanged", () => {
  it("refuses a malformed credential without writing anything", () => {
    const home = mkdtempSync(join(tmpdir(), "observa-cred-"));
    roots.push(home);
    for (const bad of ["", "not-a-token", "mgd1_short.x", TEST_CREDENTIAL.replace("mgd1_", "mgd2_")]) {
      assert.throws(() => installCredential(home, bad), /CREDENTIAL_FORMAT_INVALID/, JSON.stringify(bad));
    }
  });

  it("refuses to overwrite an existing credential in place", () => {
    const home = mkdtempSync(join(tmpdir(), "observa-cred2-"));
    roots.push(home);
    installCredential(home, TEST_CREDENTIAL);
    assert.throws(() => installCredential(home, OTHER_CREDENTIAL));
    assert.equal(
      parseCredential(readFileSync(credentialPath(home))).credentialId,
      parseCredential(TEST_CREDENTIAL).credentialId,
    );
  });

  it("refuses a credential file with loose permissions", async () => {
    const { withCredential } = await import("../plugins/openclaw-connector/credentials.mjs");
    const home = mkdtempSync(join(tmpdir(), "observa-cred3-"));
    roots.push(home);
    installCredential(home, TEST_CREDENTIAL);
    chmodSync(credentialPath(home), 0o644);
    await assert.rejects(() => withCredential(home, async () => "used"));
  });
});

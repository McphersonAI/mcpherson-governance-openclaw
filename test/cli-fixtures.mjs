// Fixtures for the CLI, launcher and Hosted-command suites. Everything lives
// under a fresh temporary directory whose path contains a space, and nothing
// here contacts a network.
import {
  chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

import { installCredential } from "../plugins/openclaw-connector/credentials.mjs";
import { makeCompletionReceipt, makeLifecycleReceipt } from "../plugins/openclaw-connector/receipts.mjs";
import { writePublicationStatus } from "../plugins/openclaw-connector/runtime-publication-status.mjs";
import { rosterRevision } from "../plugins/openclaw-connector/runtime-publication-contract.mjs";
import { TEST_CREDENTIAL } from "./helpers.mjs";

export const ROOT = fileURLToPath(new URL("..", import.meta.url));
export const PLUGIN = "mcpherson-governance-connector";
export const PACKAGE_NAME = "@mcphersonai/mcpherson-governance-openclaw";
export const DEPLOYMENT = "founder-dep";
export const AGENTS = Object.freeze(["aegis", "main", "sterling"]);

const temps = [];
export function tempDir(label = "observa cli") {
  const dir = mkdtempSync(join(tmpdir(), `${label.replace(/[^a-z ]/gi, "")} `));
  temps.push(dir);
  return dir;
}
export function cleanupTemps() {
  for (const dir of temps.splice(0)) {
    try { chmodTree(dir); } catch { /* best effort */ }
    rmSync(dir, { recursive: true, force: true });
  }
}
function chmodTree(dir) {
  chmodSync(dir, 0o700);
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    const st = statSync(path, { throwIfNoEntry: false });
    if (st?.isDirectory()) chmodTree(path);
  }
}

export const sha = (value) => `sha256:${createHash("sha256").update(value).digest("hex")}`;

/**
 * An OpenClaw profile home resembling the founder runtime: three configured
 * agents, a paired and enabled connector, historical COMPLETED activity, and
 * WOULD_* SHADOW decisions. Returns paths for assertions.
 */
export function makeProfileHome({
  profile = "default", paired = true, enabled = true, agents = AGENTS, evidence = true,
  journal = null, now = Date.now(),
} = {}) {
  const home = tempDir("observa home");
  const root = join(home, profile === "default" ? ".openclaw" : `.openclaw-${profile}`);
  const stateDir = join(root, PLUGIN);
  const receiptDir = join(stateDir, "receipts");
  mkdirSync(receiptDir, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700); chmodSync(stateDir, 0o700); chmodSync(receiptDir, 0o700);
  const extension = join(root, "extensions", PLUGIN);
  mkdirSync(extension, { recursive: true, mode: 0o700 });
  writeFileSync(join(extension, "package.json"), JSON.stringify({ name: PACKAGE_NAME, version: "0.7.4" }), { mode: 0o644 });
  const host = {
    agents: { entries: Object.fromEntries(agents.map((id) => [id, {}])) },
    plugins: { entries: { [PLUGIN]: { enabled: true, config: { enabled, apiUrl: "https://hosted.invalid", deploymentId: DEPLOYMENT, agentId: "main" } } } },
  };
  writeFileSync(join(root, "openclaw.json"), `${JSON.stringify(host, null, 2)}\n`, { mode: 0o600 });
  if (paired) installCredential(stateDir, TEST_CREDENTIAL);
  if (evidence) {
    const old = new Date(now - 3 * 86_400_000);
    const rows = [
      makeLifecycleReceipt({ event: "gateway_start", receiptMode: "POST_HOOK" }, new Date(now - 4 * 86_400_000)),
      makeCompletionReceipt({ requestHash: sha("r1"), deploymentId: DEPLOYMENT, agentId: "main", toolId: "exec", outcome: "COMPLETED", correlationRef: sha("corr-1") }, old),
      makeCompletionReceipt({ requestHash: sha("r2"), deploymentId: DEPLOYMENT, agentId: "sterling", toolId: "read", outcome: "COMPLETED", correlationRef: sha("corr-2") }, new Date(now - 2 * 86_400_000)),
      makeCompletionReceipt({ requestHash: sha("r3"), deploymentId: "some-other-deployment", agentId: "main", toolId: "exec", outcome: "COMPLETED", correlationRef: sha("corr-3") }, old),
    ];
    writeFileSync(join(receiptDir, "connector-receipts.jsonl"), rows.map((r) => JSON.stringify(r)).join("\n") + "\n", { mode: 0o600 });
    const decision = (action, agent, at) => ({
      schema: "observa-openclaw-shadow-evidence/v1", mode: "SHADOW", authority: "NONE", enforcement: "OFF",
      active: false, runtime_name: "openclaw", runtime_version: "2026.8.2", ts: new Date(at).toISOString(),
      kind: "SHADOW_DECISION", action, execution_effect: "NONE", agent_id: agent, tool_name: "exec",
    });
    const shadow = [
      decision("SHADOW_WOULD_ALLOW", "main", now - 3 * 86_400_000),
      decision("SHADOW_WOULD_DENY", "main", now - 3 * 86_400_000 + 1000),
      decision("SHADOW_WOULD_REQUIRE_APPROVAL", "sterling", now - 2 * 86_400_000),
    ];
    writeFileSync(join(receiptDir, "shadow-v070-evidence.jsonl"), shadow.map((r) => JSON.stringify(r)).join("\n") + "\n", { mode: 0o600 });
  }
  if (journal) writeJournal(stateDir, { agents, now, ...journal });
  return { home, root, stateDir, receiptDir, extension, profile };
}

/** A gateway publication journal as the 0.7.4 publisher writes it. */
export function writeJournal(stateDir, {
  agents = AGENTS, now = Date.now(), heartbeatAgeSeconds = 20, inventoryAgeSeconds = 3600,
  outcome = "HEARTBEAT_ACCEPTED", instance = "11111111-2222-4333-8444-555555555555", generation = 7,
} = {}) {
  const roster = [...agents].sort().map((agent_id) => ({ agent_id }));
  writePublicationStatus(stateDir, {
    runtime_instance_id: instance,
    runtime_generation: generation,
    roster_revision: rosterRevision(roster),
    agents: roster.map((a) => a.agent_id),
    cadence_seconds: 60,
    inventory_accepted_at: new Date(now - inventoryAgeSeconds * 1000).toISOString(),
    heartbeat_accepted_at: heartbeatAgeSeconds === null ? null : new Date(now - heartbeatAgeSeconds * 1000).toISOString(),
    heartbeats_accepted: 42,
    last_outcome: outcome,
    last_outcome_at: new Date(now - 5000).toISOString(),
    last_failure: null,
  });
  return { instance, generation, revision: rosterRevision(roster) };
}

/** Snapshot every file under a directory: path -> sha256 of bytes. */
export function snapshotTree(dir) {
  const out = {};
  const walk = (current) => {
    for (const name of readdirSync(current).sort()) {
      const path = join(current, name);
      const st = statSync(path);
      if (st.isDirectory()) walk(path);
      else out[path.slice(dir.length)] = sha(readFileSync(path));
    }
  };
  walk(dir);
  return out;
}

/**
 * A global-npm-style OpenClaw layout: <prefix>/lib/node_modules/openclaw and
 * <prefix>/bin/openclaw -> ../lib/node_modules/openclaw/openclaw.mjs, the
 * layout of the founder host (~/.local) and of `npm install -g openclaw`.
 */
export function makeOpenClawLayout(base = tempDir("observa prefix")) {
  const prefix = join(base, "prefix dir");
  const pkg = join(prefix, "lib", "node_modules", "openclaw");
  const bin = join(prefix, "bin");
  mkdirSync(pkg, { recursive: true });
  mkdirSync(bin, { recursive: true });
  // Real OpenClaw 2026.8.2 has a ~130 KiB manifest; keep the fixture as large.
  writeFileSync(join(pkg, "package.json"), JSON.stringify({ name: "openclaw", version: "2026.8.2", exports: Object.fromEntries(Array.from({ length: 2500 }, (_, i) => [`./plugin-sdk/module-${i}`, `./dist/plugin-sdk/module-${i}.js`])) }));
  writeFileSync(join(pkg, "openclaw.mjs"), "#!/usr/bin/env node\n", { mode: 0o755 });
  symlinkSync("../lib/node_modules/openclaw/openclaw.mjs", join(bin, "openclaw"));
  return { prefix, pkg, bin, launcher: join(bin, "openclaw") };
}

/**
 * A minimal installed "plugin" whose CLI prints the version it was given and
 * exactly the argv it received. It isolates launcher mechanics from product
 * behaviour; the packed-artifact suite runs the real CLI.
 */
export function makeFakePlugin(version = "fake-1", base = tempDir("observa plugin")) {
  const root = join(base, "extensions dir", PLUGIN);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  writeFileSync(join(root, "package.json"), JSON.stringify({ name: PACKAGE_NAME, version }), { mode: 0o644 });
  writeFileSync(join(root, "observa.mjs"),
    `#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify({ version: ${JSON.stringify(version)}, argv: process.argv.slice(2) }));\n`,
    { mode: 0o755 });
  return root;
}

/** A Local Node global install that owns an `observa` link in `bin`. */
export function makeLocalNode(prefix, bin) {
  const pkg = join(prefix, "lib", "node_modules", "@mcpherson-ai", "observa-local-node");
  const cli = join(pkg, "distribution", "observa-cli");
  mkdirSync(join(cli, "bin"), { recursive: true });
  writeFileSync(join(pkg, "package.json"), JSON.stringify({ name: "@mcpherson-ai/observa-local-node", version: "0.1.6", bin: { observa: "distribution/observa-cli/bin/observa.mjs" } }));
  writeFileSync(join(cli, "package.json"), JSON.stringify({ name: "@mcphersonai/observa-cli", version: "0.1.6" }));
  writeFileSync(join(cli, "bin", "observa.mjs"), "#!/usr/bin/env node\nprocess.stdout.write('LOCAL_NODE_OBSERVA');\n", { mode: 0o755 });
  symlinkSync("../lib/node_modules/@mcpherson-ai/observa-local-node/distribution/observa-cli/bin/observa.mjs", join(bin, "observa"));
  return join(bin, "observa");
}

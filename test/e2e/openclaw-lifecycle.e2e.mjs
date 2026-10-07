// Real-OpenClaw lifecycle proof for the packed artifact. Not part of `npm test`
// (it needs an installed OpenClaw, starts real gateways and may download from
// ClawHub/npm). Every scenario runs in its own HOME and its own copy of the
// OpenClaw npm prefix, so no scenario can see another's `observa`.
//
//   E2E_OPENCLAW_PREFIX  npm prefix with OpenClaw installed (bin/openclaw)
//   E2E_ARTIFACT         the packed candidate .tgz
//   E2E_WORK             scratch directory
//   E2E_BASE_SPEC        previous public release (default clawhub:...@0.7.3)
//   E2E_LOCAL_NODE_SPEC  Local Node package (default @mcpherson-ai/observa-local-node@0.1.6)
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, readlinkSync, writeFileSync,
} from "node:fs";
import { delimiter, dirname, join } from "node:path";

const PREFIX = process.env.E2E_OPENCLAW_PREFIX;
const ARTIFACT = process.env.E2E_ARTIFACT;
const WORK = process.env.E2E_WORK;
const BASE_SPEC = process.env.E2E_BASE_SPEC ?? "clawhub:@mcphersonai/mcpherson-governance-openclaw@0.7.3";
const LOCAL_NODE_SPEC = process.env.E2E_LOCAL_NODE_SPEC ?? "@mcpherson-ai/observa-local-node@0.1.6";
const PLUGIN = "mcpherson-governance-connector";
const TEST_CREDENTIAL = "mgd1_0123456789abcdef0123456789abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
if (!PREFIX || !ARTIFACT || !WORK) throw new Error("set E2E_OPENCLAW_PREFIX, E2E_ARTIFACT and E2E_WORK");

const results = [];
const sha = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
function check(scenario, name, ok, detail = "") {
  results.push({ scenario, name, ok: Boolean(ok), detail: String(detail).slice(0, 400) });
  process.stdout.write(`${ok ? "PASS" : "FAIL"} [${scenario}] ${name}${detail ? ` — ${String(detail).split("\n")[0].slice(0, 160)}` : ""}\n`);
}

function sandbox(name) {
  const base = join(WORK, `${name} sandbox`);
  const home = join(base, "home");
  const prefix = join(base, "prefix");
  mkdirSync(home, { recursive: true });
  cpSync(PREFIX, prefix, { recursive: true, verbatimSymlinks: true });
  const nodeDir = join(base, "node-bin");
  mkdirSync(nodeDir, { recursive: true });
  try { execFileSync("ln", ["-sf", process.execPath, join(nodeDir, "node")]); } catch { /* exists */ }
  const npmDir = dirname(execFileSync("sh", ["-c", "command -v npm"], { encoding: "utf8" }).trim());
  const env = { HOME: home, PATH: [join(prefix, "bin"), nodeDir, "/usr/bin", "/bin"].join(delimiter), TMPDIR: process.env.TMPDIR ?? "/tmp" };
  const run = (cmd, args, extra = {}) => {
    const r = spawnSync(cmd, args, { encoding: "utf8", env: { ...env, ...extra }, cwd: home, timeout: 300_000 });
    return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? String(r.error?.code ?? "") };
  };
  const which = () => run("sh", ["-c", "command -v observa || true"]).stdout.trim();
  const npm = (args) => spawnSync(join(npmDir, "npm"), args, { encoding: "utf8", env: { ...env, PATH: `${env.PATH}${delimiter}${npmDir}` }, cwd: home, timeout: 300_000 });
  return { name, base, home, prefix, env, run, which, npm, state: join(home, ".openclaw"), ext: join(home, ".openclaw", "extensions", PLUGIN) };
}

let port = 29100;
async function withGateway(box, fn) {
  const log = join(box.base, `gateway-${port}.log`);
  const child = spawn(join(box.prefix, "bin", "openclaw"), ["gateway", "--port", String(port++), "--allow-unconfigured"], {
    env: box.env, cwd: box.home, detached: true, stdio: ["ignore", "pipe", "pipe"],
  });
  let text = "";
  child.stdout.on("data", (d) => { text += d; });
  child.stderr.on("data", (d) => { text += d; });
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline && !/\[gateway\].*ready/.test(text) && child.exitCode === null) await new Promise((r) => setTimeout(r, 250));
  // gateway_start hooks are scheduled right after readiness.
  const settle = Date.now() + 15_000;
  while (Date.now() < settle && !/\[observa-cli\]/.test(text)) await new Promise((r) => setTimeout(r, 250));
  try { return await fn(text); } finally {
    try { process.kill(-child.pid, "SIGTERM"); } catch { /* gone */ }
    await new Promise((r) => setTimeout(r, 1500));
    try { process.kill(-child.pid, "SIGKILL"); } catch { /* gone */ }
    writeFileSync(log, text);
  }
}

function install(box, spec, extraArgs = []) {
  return box.run(join(box.prefix, "bin", "openclaw"), ["plugins", "install", spec, "--accept-capabilities", ...extraArgs]);
}
const observa = (box, args) => box.run("observa", args);
function pluginRow(box) {
  const out = box.run(join(box.prefix, "bin", "openclaw"), ["plugins", "list"]).stdout;
  return out.split("\n").find((line) => line.includes("mcpherson-governance")) ?? "";
}

function seedPairedState(box) {
  // A paired, enabled profile with history, without contacting any Hosted:
  // the endpoint is a closed loopback port, so publication simply fails.
  const config = JSON.parse(readFileSync(join(box.state, "openclaw.json"), "utf8"));
  config.agents = { ...(config.agents ?? {}), ownership: "explicit", entries: { aegis: {}, main: {}, sterling: {} } };
  config.plugins.entries[PLUGIN] = { ...config.plugins.entries[PLUGIN], enabled: true, config: { enabled: true, apiUrl: "https://127.0.0.1:9", deploymentId: "e2e-dep", agentId: "main" } };
  writeFileSync(join(box.state, "openclaw.json"), `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  const stateDir = join(box.state, PLUGIN);
  mkdirSync(join(stateDir, "receipts"), { recursive: true, mode: 0o700 });
  writeFileSync(join(stateDir, "deployment-credential"), `${TEST_CREDENTIAL}\n`, { mode: 0o600 });
  const receipt = { receipt_id: "01J00000000000000000000000", receipt_type: "completion_receipt", timestamp: "2026-09-20T00:00:00.000Z", decision_id: null, request_hash: `sha256:${"a".repeat(64)}`, deployment_id: "e2e-dep", agent_id: "main", tool_id: "exec", completed_at: "2026-09-20T00:00:00.000Z", outcome: "COMPLETED", observation_basis: "DIRECT_SUPPORTED_POST_HOOK", correlation_ref: `sha256:${"b".repeat(64)}` };
  writeFileSync(join(stateDir, "receipts", "evidence-history.jsonl"), `${JSON.stringify(receipt)}\n`, { mode: 0o600 });
  return stateDir;
}

// ---------------------------------------------------------------------------
// A. Clean install of the candidate
const a = sandbox("A clean");
{
  const out = install(a, `npm-pack:${ARTIFACT}`, ["--force"]);
  check("clean-install", "openclaw plugins install npm-pack:<candidate>", out.status === 0, out.stdout.split("\n").filter((l) => /Installed|Restart/.test(l)).join(" "));
  check("clean-install", "plugin listed enabled 0.7.4", /enabled/.test(pluginRow(a)) && /0\.7\.4/.test(pluginRow(a)), pluginRow(a));
  check("clean-install", "before any gateway start no observa (plugins load on restart)", a.which() === "", a.which());
  await withGateway(a, async (log) => {
    check("clean-install", "gateway loaded the plugin and logged the launcher", /\[observa-cli\] observa command INSTALLED/.test(log), (log.match(/\[observa-cli\][^\n]*/) ?? [""])[0]);
  });
  const resolved = a.which();
  check("clean-install", "command -v observa resolves beside openclaw", resolved === join(a.prefix, "bin", "observa"), resolved);
  const version = observa(a, ["--version"]);
  check("clean-install", "observa --version", version.status === 0 && version.stdout.trim() === "Observa 0.7.4", version.stdout.trim());
  const help = observa(a, ["--help"]);
  check("clean-install", "observa --help shows funnel", help.status === 0 && /request-access[\s\S]*request-status[\s\S]*pair[\s\S]*hosted-health[\s\S]*identify/.test(help.stdout));
  for (const args of [["status"], ["agents"], ["agent", "main"], ["activity", "--limit", "5"], ["decisions", "--limit", "5"]]) {
    const r = observa(a, args);
    check("clean-install", `observa ${args.join(" ")}`, r.status === 0, (r.stdout || r.stderr).split("\n")[0]);
  }
  const rs = observa(a, ["request-status", "--api-url", "https://observa.example"]);
  check("clean-install", "observa request-status (no request yet) is deterministic", rs.status === 1 && /^ACCESS_NO_REQUEST/.test(rs.stderr), rs.stderr.trim());
  const hh = observa(a, ["hosted-health"]);
  check("clean-install", "observa hosted-health unpaired -> NOT_PAIRED + funnel", hh.status === 2 && /NOT_PAIRED[\s\S]*request-access[\s\S]*request-status[\s\S]*pair/.test(hh.stdout), hh.stdout.split("\n")[0]);
  const id = observa(a, ["identify"]);
  check("clean-install", "observa identify unpaired -> local roster, NOT_PAIRED", id.status === 0 && /Configured agents \(1[\s\S]*main[\s\S]*NOT_PAIRED/.test(id.stdout), id.stdout.split("\n").slice(1, 3).join(" "));
  const status = observa(a, ["status"]).stdout;
  check("clean-install", "status reports the launcher as this plugin", /CLI entrypoint\s+observa -> this plugin/.test(status), (status.match(/CLI entrypoint[^\n]*/) ?? [""])[0]);
}

// B. Reinstall (idempotent: one launcher, following the current install)
const record = (box) => {
  try { return JSON.parse(readFileSync(join(box.state, PLUGIN, "cli-entrypoint.json"), "utf8")); } catch { return {}; }
};
{
  const launcher = join(a.prefix, "bin", "observa");
  await withGateway(a, async (log) => {
    check("reinstall", "a second gateway start leaves the launcher CURRENT", /observa command CURRENT/.test(log), (log.match(/\[observa-cli\][^\n]*/) ?? [""])[0]);
  });
  const ino = lstatSync(launcher).ino;
  const out = install(a, `npm-pack:${ARTIFACT}`, ["--force"]);
  check("reinstall", "reinstall with --force", out.status === 0, out.stderr.split("\n")[0]);
  await withGateway(a, async (log) => {
    // npm-pack installs live in per-generation directories, so a reinstall is
    // a new plugin root: the launcher follows it (UPDATED) or is already right.
    check("reinstall", "gateway re-points or keeps the launcher", /observa command (CURRENT|UPDATED)/.test(log), (log.match(/\[observa-cli\][^\n]*/) ?? [""])[0]);
  });
  const root = record(a).plugin_root;
  const text = readFileSync(launcher, "utf8");
  check("reinstall", "launcher targets the currently installed plugin root", root && text.includes(JSON.stringify(root)) && existsSync(join(root, "observa.mjs")), root);
  check("reinstall", "launcher replaced atomically in place (regular file, single link)", lstatSync(launcher).isFile() && lstatSync(launcher).nlink === 1, `ino ${ino} -> ${lstatSync(launcher).ino}`);
  const bin = readdirSync(join(a.prefix, "bin")).sort();
  check("reinstall", "no duplicate wrappers or temporaries", JSON.stringify(bin) === JSON.stringify(["observa", "openclaw"]), bin.join(","));
  check("reinstall", "observa still works", observa(a, ["--version"]).stdout.trim() === "Observa 0.7.4");
}

// D. Uninstall through observa
{
  const stateBefore = existsSync(join(a.state, PLUGIN));
  const refused = observa(a, ["uninstall"]);
  check("uninstall", "non-interactive uninstall without --yes is refused deterministically", refused.status === 1 && /^UNINSTALL_CONFIRMATION_REQUIRED/.test(refused.stderr), refused.stderr.trim());
  const un = observa(a, ["uninstall", "--yes"]);
  check("uninstall", "observa uninstall succeeds", un.status === 0, un.stdout.trim() || un.stderr.trim());
  check("uninstall", "reports its launcher removed", /observa command this plugin created was removed/.test(un.stdout));
  check("uninstall", "launcher gone, openclaw untouched", !existsSync(join(a.prefix, "bin", "observa")) && existsSync(join(a.prefix, "bin", "openclaw")));
  check("uninstall", "plugin no longer installed", !/mcpherson-governance/.test(pluginRow(a)), pluginRow(a));
  check("uninstall", "connector state preserved", stateBefore && existsSync(join(a.state, PLUGIN)));
  const oc = a.run(join(a.prefix, "bin", "openclaw"), ["--version"]);
  check("uninstall", "openclaw still healthy", oc.status === 0 && /2026\.8\.2/.test(oc.stdout), oc.stdout.trim());
}

// C. Upgrade 0.7.3 (public) -> candidate, with paired state and evidence
const c = sandbox("C upgrade");
{
  const base = install(c, BASE_SPEC);
  check("upgrade", `install previous public ${BASE_SPEC}`, base.status === 0 && /0\.7\.3/.test(pluginRow(c)), pluginRow(c));
  const stateDir = seedPairedState(c);
  await withGateway(c, async () => {});
  check("upgrade", "0.7.3 gateway run gives no observa (baseline defect)", c.which() === "", c.which());
  const credential = sha(join(stateDir, "deployment-credential"));
  const evidence = sha(join(stateDir, "receipts", "evidence-history.jsonl"));
  const entry = JSON.stringify(JSON.parse(readFileSync(join(c.state, "openclaw.json"), "utf8")).plugins.entries[PLUGIN]);
  const up = install(c, `npm-pack:${ARTIFACT}`, ["--force"]);
  check("upgrade", "upgrade to candidate", up.status === 0 && /0\.7\.4/.test(pluginRow(c)), pluginRow(c));
  check("upgrade", "credential preserved byte-for-byte", sha(join(stateDir, "deployment-credential")) === credential);
  check("upgrade", "evidence preserved byte-for-byte", sha(join(stateDir, "receipts", "evidence-history.jsonl")) === evidence);
  const entryAfter = JSON.parse(readFileSync(join(c.state, "openclaw.json"), "utf8")).plugins.entries[PLUGIN];
  check("upgrade", "plugin entry/config preserved", JSON.stringify(entryAfter.config) === JSON.stringify(JSON.parse(entry).config), JSON.stringify(entryAfter.config));
  await withGateway(c, async (log) => {
    check("upgrade", "restarted gateway installs observa", /observa command INSTALLED/.test(log));
  });
  check("upgrade", "command -v observa after upgrade", c.which() === join(c.prefix, "bin", "observa"), c.which());
  const st = observa(c, ["status"]);
  check("upgrade", "paired state intact after upgrade", /Paired\s+YES/.test(st.stdout) && /Configured agents\s+3/.test(st.stdout), (st.stdout.match(/Paired[^\n]*/) ?? [""])[0]);
  const hh = observa(c, ["hosted-health", "--json"]);
  const report = JSON.parse(hh.stdout || "{}").hosted_health ?? {};
  check("upgrade", "hosted-health runs (closed test endpoint => UNREACHABLE, no crash)", hh.status === 2 && report.state === "UNREACHABLE", `${report.state} reachable=${report.reachable}`);
}

// E. Local Node collision
const e = sandbox("E local node");
{
  const ln = e.npm(["install", "-g", "--prefix", e.prefix, LOCAL_NODE_SPEC, "--no-audit", "--no-fund"]);
  const link = join(e.prefix, "bin", "observa");
  check("local-node", `Local Node installed (${LOCAL_NODE_SPEC})`, ln.status === 0 && lstatSync(link).isSymbolicLink(), ln.stderr.split("\n").slice(-2).join(" "));
  const target = readlinkSync(link);
  const lnVersion = e.run("observa", ["--version"]).stdout.trim();
  install(e, `npm-pack:${ARTIFACT}`, ["--force"]);
  await withGateway(e, async (log) => {
    check("local-node", "gateway reports COLLISION_LOCAL_NODE", /observa command COLLISION_LOCAL_NODE/.test(log), (log.match(/\[observa-cli\][^\n]*/) ?? [""])[0]);
  });
  check("local-node", "Local Node link untouched", lstatSync(link).isSymbolicLink() && readlinkSync(link) === target, target);
  check("local-node", "observa still runs Local Node", e.run("observa", ["--version"]).stdout.trim() === lnVersion, lnVersion);
  const installed = record(e).plugin_root ?? e.ext;
  const direct = e.run("node", [join(installed, "observa.mjs"), "status"]);
  check("local-node", "direct status explains the conflict and remediation", /COLLISION_LOCAL_NODE/.test(direct.stdout) && /npm uninstall -g @mcpherson-ai\/observa-local-node/.test(direct.stdout), (direct.stdout.match(/CLI entrypoint[^\n]*/) ?? [""])[0]);
  const un = e.run("node", [join(installed, "observa.mjs"), "uninstall", "--yes"]);
  check("local-node", "plugin uninstall leaves Local Node in place", un.status === 0 && lstatSync(link).isSymbolicLink() && readlinkSync(link) === target);
}

const failed = results.filter((r) => !r.ok);
writeFileSync(join(WORK, "e2e-result.json"), `${JSON.stringify({ openclaw: PREFIX, artifact: ARTIFACT, artifact_sha256: sha(ARTIFACT), passed: results.length - failed.length, failed: failed.length, results }, null, 2)}\n`);
process.stdout.write(`\n${results.length - failed.length}/${results.length} checks passed\n`);
process.exitCode = failed.length ? 1 : 0;

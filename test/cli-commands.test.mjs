// The local-first command surface: offline views over a founder-like profile,
// profile selection, and the Hosted access funnel staying first-class.
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";

import { runObserva, CLI_VERSION } from "../cli/cli.mjs";
import { cleanupTemps, makeProfileHome, snapshotTree } from "./cli-fixtures.mjs";
import { TEST_CREDENTIAL } from "./helpers.mjs";

after(cleanupTemps);

const ENV = Object.freeze({ PATH: "/usr/bin:/bin" });
const cli = (argv, { home, env = ENV, dependencies = {}, now } = {}) =>
  runObserva(argv, { env, ...(home ? { home } : {}), dependencies, ...(now ? { now } : {}) });
const json = (result) => JSON.parse(result.stdout);

describe("help and version", () => {
  it("--version and version print the plugin version", async () => {
    for (const argv of [["--version"], ["version"]]) {
      const result = await cli(argv);
      assert.equal(result.code, 0);
      assert.equal(result.stdout, `Observa ${CLI_VERSION}`);
    }
    assert.equal(CLI_VERSION, "0.7.4");
    assert.equal(json(await cli(["--version", "--json"])).version, "0.7.4");
  });

  it("--help groups commands local-first and puts the Hosted funnel up front", async () => {
    const { code, stdout } = await cli(["--help"]);
    assert.equal(code, 0);
    const order = ["Local (offline", "status", "agents", "agent <id>", "activity", "decisions",
      "Hosted access", "request-access", "request-status", "pair",
      "Hosted health / refresh", "hosted-health", "identify", "Controls:", "Lifecycle:"];
    let at = -1;
    for (const marker of order) {
      const next = stdout.indexOf(marker, at + 1);
      assert.ok(next > at, `${marker} out of order in help`);
      at = next;
    }
    assert.match(stdout, /request-access -> request-status -> pair -> hosted-health -> identify/);
    assert.match(stdout, /SHADOW ONLY \/ AUTHORITY NONE \/ ENFORCEMENT OFF \/ ACTIVE OFF/);
    assert.equal((await cli([])).stdout, stdout, "no arguments also prints help");
  });

  it("every command has its own --help", async () => {
    for (const command of ["status", "agents", "agent", "activity", "decisions", "request-access", "request-status",
      "pair", "hosted-health", "identify", "enable", "disable", "killswitch", "lock", "credential", "unpair", "uninstall"]) {
      const result = await cli([command, "--help"]);
      assert.equal(result.code, 0, command);
      assert.ok(result.stdout.startsWith(`Usage: observa ${command}`), command);
    }
  });
});

describe("local commands work with or without Hosted, and never contact it", () => {
  const fetchSpy = [];
  const noNetwork = { accessFetch: async (...args) => { fetchSpy.push(args); throw new Error("network"); } };

  it("status reports paired founder-like state with conservative labels", async () => {
    const { home } = makeProfileHome();
    const result = await cli(["status", "--profile-home", home], { dependencies: noNetwork });
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /^Observa 0\.7\.4/);
    assert.match(result.stdout, /Paired\s+YES/);
    assert.match(result.stdout, /Enabled\s+YES/);
    assert.match(result.stdout, /Observing\s+STALE_LOCAL_EVIDENCE/);
    assert.match(result.stdout, /Posture\s+SHADOW ONLY \/ AUTHORITY NONE \/ ENFORCEMENT OFF \/ ACTIVE OFF/);
    assert.match(result.stdout, /Configured agents\s+3/);
    assert.match(result.stdout, /Heartbeat\s+NOT_AVAILABLE \(no gateway publication journal\)/);
    assert.match(result.stdout, /Hosted connection\s+PAIRED_CONNECTION_NOT_PROBED \(observa hosted-health probes it\)/);
    assert.match(result.stdout, /Local evidence warning: FOREIGN_EVIDENCE_SKIPPED/);
    assert.match(result.stdout, /CLI entrypoint\s+observa not on PATH; gateway record NOT_RECORDED/);
    assert.equal(result.stdout.includes(TEST_CREDENTIAL), false);
    assert.deepEqual(fetchSpy, []);
  });

  it("status shows the gateway's recorded heartbeat when the journal exists", async () => {
    const { home } = makeProfileHome({ journal: { heartbeatAgeSeconds: 30 } });
    const status = json(await cli(["status", "--json", "--profile-home", home])).status;
    assert.equal(status.heartbeat, "FRESH");
    assert.equal(status.heartbeat_source, "GATEWAY_PUBLICATION_JOURNAL");
    assert.equal(status.hosted_connection, "PAIRED_CONNECTION_NOT_PROBED");
  });

  it("agents lists the three configured agents; none is ACTIVE from old evidence", async () => {
    const { home } = makeProfileHome();
    const { agents } = json(await cli(["agents", "--json", "--profile-home", home]));
    assert.deepEqual(agents.map((a) => [a.agent_id, a.state]), [["aegis", "CONFIGURED"], ["main", "QUIET"], ["sterling", "QUIET"]]);
    assert.ok(agents.every((a) => a.configured === true));
    const human = await cli(["agents", "--profile-home", home]);
    assert.match(human.stdout, /aegis\s+YES\s+NO\s+CONFIGURED/);
  });

  it("agent <id> combines roster, activity and decisions; unknown and invalid ids are refused", async () => {
    const { home } = makeProfileHome();
    const main = json(await cli(["agent", "main", "--json", "--profile-home", home]));
    assert.equal(main.agent.agent_id, "main");
    assert.deepEqual(main.activity.map((a) => a.outcome), ["COMPLETED"]);
    assert.deepEqual(main.decisions.map((d) => d.decision).sort(), ["WOULD_ALLOW", "WOULD_DENY"]);
    const missing = await cli(["agent", "nobody", "--profile-home", home]);
    assert.equal(missing.code, 1);
    assert.match(missing.stderr, /^AGENT_NOT_FOUND:/);
    const invalid = await cli(["agent", "../etc", "--profile-home", home]);
    assert.match(invalid.stderr, /^AGENT_ID_INVALID:/);
  });

  it("activity shows COMPLETED receipts only, foreign deployments skipped, and honours --limit", async () => {
    const { home } = makeProfileHome();
    const all = json(await cli(["activity", "--json", "--profile-home", home]));
    assert.deepEqual(all.activity.map((a) => [a.agent_id, a.outcome]), [["sterling", "COMPLETED"], ["main", "COMPLETED"]]);
    assert.ok(all.evidence.problems.includes("FOREIGN_EVIDENCE_SKIPPED"));
    const one = json(await cli(["activity", "--json", "--limit", "1", "--profile-home", home]));
    assert.equal(one.activity.length, 1);
    for (const bad of ["0", "101", "abc", "-1", "1e2"]) {
      assert.equal((await cli(["activity", "--limit", bad, "--profile-home", home])).code, 1, bad);
    }
  });

  it("decisions keeps WOULD_* counterfactuals separate from activity", async () => {
    const { home } = makeProfileHome();
    const { decisions } = json(await cli(["decisions", "--json", "--profile-home", home]));
    assert.deepEqual(decisions.map((d) => d.decision).sort(), ["WOULD_ALLOW", "WOULD_DENY", "WOULD_REQUIRE_APPROVAL"]);
    const human = await cli(["decisions", "--limit", "5", "--profile-home", home]);
    assert.match(human.stdout, /COUNTERFACTUAL DECISION/);
  });

  it("unpaired installations keep every local view", async () => {
    const { home } = makeProfileHome({ paired: false, enabled: false });
    for (const argv of [["status"], ["agents"], ["agent", "main"], ["activity"], ["decisions"]]) {
      const result = await cli([...argv, "--profile-home", home]);
      assert.equal(result.code, 0, `${argv[0]}: ${result.stderr}`);
    }
    assert.match((await cli(["status", "--profile-home", home])).stdout, /Hosted connection\s+UNPAIRED/);
  });

  it("local reads change no file", async () => {
    const { home, root } = makeProfileHome({ journal: {} });
    const before = snapshotTree(root);
    for (const argv of [["status"], ["agents"], ["agent", "main"], ["activity"], ["decisions"], ["status", "--json"]]) {
      await cli([...argv, "--profile-home", home]);
    }
    assert.deepEqual(snapshotTree(root), before);
  });
});

describe("profile selection", () => {
  it("--profile selects a named profile and nothing else", async () => {
    const { home } = makeProfileHome({ profile: "work" });
    const result = await cli(["status", "--json", "--profile", "work", "--profile-home", home]);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(json(result).status.configured_agent_count, 3);
    const other = await cli(["status", "--json", "--profile-home", home]);
    assert.equal(json(other).status.configuration, "MISSING", "the default profile is not substituted");
  });

  it("OPENCLAW_STATE_DIR selects a runtime root; conflicting selectors are refused", async () => {
    const { home, root } = makeProfileHome();
    const viaEnv = await cli(["agents", "--json"], { env: { ...ENV, OPENCLAW_STATE_DIR: root } });
    assert.equal(viaEnv.code, 0, viaEnv.stderr);
    assert.equal(json(viaEnv).agents.length, 3);
    const conflict = await cli(["status", "--profile", "other", "--profile-home", home], { env: { ...ENV, OPENCLAW_STATE_DIR: root } });
    assert.match(conflict.stderr, /^PROFILE_STATE_CONFLICT:/);
    const relative = await cli(["status"], { env: { ...ENV, OPENCLAW_STATE_DIR: "relative/dir" } });
    assert.match(relative.stderr, /^STATE_PATH_INVALID:/);
    const rootDir = await cli(["status"], { env: { ...ENV, OPENCLAW_STATE_DIR: "/" } });
    assert.match(rootDir.stderr, /^STATE_PATH_INVALID:/);
  });

  it("malicious profile names and options are refused without echoing input", async () => {
    for (const profile of ["../etc", "a/b", ".hidden", "x".repeat(80), "$(id)", "a;b"]) {
      const result = await cli(["status", "--profile", profile]);
      assert.equal(result.code, 1, profile);
      assert.match(result.stderr, /^PROFILE_INVALID:/);
      assert.equal(result.stderr.includes(profile), false);
    }
    const unknown = await cli(["status", "--evil=$(id)"]);
    assert.match(unknown.stderr, /^OPTIONS_INVALID:/);
    assert.equal(unknown.stderr.includes("$(id)"), false);
    const duplicate = await cli(["status", "--json", "--json"]);
    assert.match(duplicate.stderr, /OPTIONS_INVALID/);
  });
});

describe("the Hosted access funnel is available before pairing", () => {
  function accessServer() {
    const requests = [];
    let status = "EMAIL_PENDING";
    return {
      requests,
      approve() { status = "APPROVED"; },
      fetch: async (url, init) => {
        const body = JSON.parse(init.body);
        requests.push({ url, auth: init.headers.authorization.slice(0, 7), body });
        const action = url.split("/").at(-1);
        const reply = action === "status" ? { request_id: body.request_id, status } : {};
        return new Response(JSON.stringify(reply), { status: 200 });
      },
    };
  }

  it("request-access submits a verified-email request on an unpaired profile", async () => {
    const { home } = makeProfileHome({ paired: false, enabled: false, evidence: false });
    const server = accessServer();
    const result = await cli(["request-access", "--api-url", "https://observa.example", "--name", "Ada", "--email", "ada@example.com", "--yes", "--json", "--profile-home", home],
      { dependencies: { accessFetch: server.fetch, accessOutput: () => {} } });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(json(result).request.status, "EMAIL_PENDING");
    assert.deepEqual(server.requests.map((r) => r.url.split("/").at(-1)), ["create", "status", "send"]);
    assert.ok(server.requests.every((r) => r.url.startsWith("https://observa.example/access/v1/")));
    // request-status reads the saved receipt and follows the request.
    server.approve();
    const status = await cli(["request-status", "--json", "--profile-home", home], { dependencies: { accessFetch: server.fetch } });
    assert.equal(json(status).request.status, "APPROVED");
    assert.match(json(status).request.next_action, /observa pair/);
  });

  it("request-status without a request gives a deterministic next step", async () => {
    const { home } = makeProfileHome({ paired: false, enabled: false, evidence: false });
    const result = await cli(["request-status", "--api-url", "https://observa.example", "--profile-home", home]);
    assert.equal(result.code, 1);
    assert.equal(result.stderr, "ACCESS_NO_REQUEST: No request receipt exists in this profile. Run observa request-access.");
  });

  it("pair stays available and refuses deterministically without an endpoint", async () => {
    const { home } = makeProfileHome({ paired: false, enabled: false, evidence: false });
    const result = await cli(["pair", "--profile-home", home]);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /^PAIR_API_URL_REQUIRED:/);
    assert.equal(JSON.parse((await cli(["pair", "--json"])).stderr).code, "PAIR_JSON_UNSUPPORTED");
  });
});

describe("uninstall on OpenClaw 2026.8.2 (confirmation required)", () => {
  function runner() {
    const calls = [];
    const fn = (bin, argv, options) => { calls.push({ bin, argv, stdio: options.stdio, env: options.env }); return { status: 0, stdout: "", stderr: "" }; };
    return { calls, fn };
  }

  it("non-interactive without --yes: deterministic refusal, nothing run", async () => {
    const { home } = makeProfileHome();
    const r = runner();
    const result = await cli(["uninstall", "--profile-home", home], { dependencies: { runner: r.fn, interactive: false } });
    assert.equal(result.code, 1);
    assert.match(result.stderr, /^UNINSTALL_CONFIRMATION_REQUIRED:/);
    assert.deepEqual(r.calls, []);
  });

  it("--yes confirms: OpenClaw's uninstaller runs with --force in the selected profile", async () => {
    const { home, root } = makeProfileHome();
    const r = runner();
    const result = await cli(["uninstall", "--yes", "--json", "--profile-home", home], { dependencies: { runner: r.fn, interactive: false } });
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(r.calls.map((c) => [c.bin, c.argv, c.stdio]), [["openclaw", ["plugins", "uninstall", "mcpherson-governance-connector", "--force"], "pipe"]]);
    assert.equal(r.calls[0].env.OPENCLAW_STATE_DIR, root);
    assert.equal(json(result).result.receipts_preserved, true);
    assert.equal(json(result).result.cli_entrypoint_removed, false);
  });

  it("interactive: OpenClaw's own prompt is shown on the terminal", async () => {
    const { home } = makeProfileHome();
    const r = runner();
    const result = await cli(["uninstall", "--profile-home", home], { dependencies: { runner: r.fn, interactive: true } });
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(r.calls.map((c) => [c.argv, c.stdio]), [[["plugins", "uninstall", "mcpherson-governance-connector"], "inherit"]]);
    assert.match(result.stdout, /uninstall completed\. No observa command owned by this plugin was removed/);
  });

  it("a declined or failed uninstall keeps everything", async () => {
    const { home } = makeProfileHome();
    const result = await cli(["uninstall", "--yes", "--profile-home", home], { dependencies: { runner: () => ({ status: 1 }), interactive: false } });
    assert.equal(result.code, 1);
    assert.match(result.stderr, /^UNINSTALL_FAILED:/);
  });
});


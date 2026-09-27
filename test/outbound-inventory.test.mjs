// The outbound inventory, as an executable contract.
//
// Every way this package can reach the network is enumerated here. A new
// network primitive, a new Hosted path, or an ungated publisher makes one of
// these tests fail, which is the point: the inventory cannot silently drift.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

function sources() {
  const found = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      if ([".git", "node_modules", "test"].includes(name)) continue;
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else if (name.endsWith(".mjs")) found.push(relative(ROOT, path));
    }
  };
  walk(ROOT);
  return found;
}

const code = (path) => readFileSync(join(ROOT, path), "utf8")
  .replace(/\/\*[\s\S]*?\*\//g, " ")
  .replace(/^\s*\/\/.*$/gm, " ");

// Exhaustive: the only modules in this package permitted to open a socket.
const NETWORK_OWNERS = Object.freeze({
  "plugins/openclaw-connector/client.mjs": "plugin runtime Hosted client (node:https)",
  "plugins/openclaw-connector/shadow-v070/transport.mjs": "SHADOW evaluation transport (node:https)",
  "observa-pair-legacy.mjs": "operator-invoked pairing redemption (node:https)",
  "cli/access.mjs": "operator-invoked Hosted beta access request (fetch)",
});

describe("no undeclared network primitive exists anywhere in the package", () => {
  it("only the four declared owners import a network primitive", () => {
    const primitive = /\b(node:https|node:http|node:net|node:dgram|node:tls|undici|axios|got|node-fetch)\b|\bfetch\s*\(|XMLHttpRequest|WebSocket/;
    for (const path of sources()) {
      const hit = primitive.exec(code(path));
      if (!hit) continue;
      assert.ok(
        Object.hasOwn(NETWORK_OWNERS, path),
        `${path} uses a network primitive (${hit[0]}) but is not a declared outbound owner`,
      );
    }
  });

  it("every declared owner still exists and still owns its primitive", () => {
    for (const path of Object.keys(NETWORK_OWNERS)) {
      assert.ok(sources().includes(path), `declared owner missing: ${path}`);
    }
  });

  it("ships no alternate, debug, or plaintext endpoint", () => {
    for (const path of sources()) {
      const text = code(path);
      for (const match of text.matchAll(/["'`](https?:\/\/[^"'`\s]+)["'`]/g)) {
        const url = match[1];
        assert.ok(url.startsWith("https://"), `${path} contains a plaintext endpoint: ${url}`);
        // The only literal endpoint in source is the loopback default. Every
        // real endpoint comes from the operator's configuration.
        assert.ok(
          url === "https://127.0.0.1:8443",
          `${path} hard-codes an endpoint: ${url}`,
        );
      }
    }
  });

  it("refuses a non-https endpoint at both transports", async () => {
    const { GovernanceApiClient } = await import("../plugins/openclaw-connector/client.mjs");
    const { createShadowTransport } = await import("../plugins/openclaw-connector/shadow-v070/transport.mjs");
    const { loadConnectorConfig } = await import("../plugins/openclaw-connector/config.mjs");
    for (const bad of ["http://hosted.invalid", "https://user:pw@hosted.invalid", "ftp://hosted.invalid"]) {
      assert.throws(() => new GovernanceApiClient({ baseUrl: bad, connectTimeoutMs: 100 }), undefined, bad);
      assert.throws(() => createShadowTransport({ apiUrl: bad }), undefined, bad);
      assert.throws(() => loadConnectorConfig({ apiUrl: bad }), undefined, bad);
    }
  });

  it("never disables TLS verification", () => {
    for (const path of sources()) {
      const text = code(path);
      assert.equal(/rejectUnauthorized\s*:\s*false/.test(text), false, `${path} disables TLS verification`);
      assert.equal(/NODE_TLS_REJECT_UNAUTHORIZED\s*=/.test(text), false, `${path} sets NODE_TLS_REJECT_UNAUTHORIZED`);
    }
    assert.ok(code("plugins/openclaw-connector/client.mjs").includes("rejectUnauthorized: true"));
    assert.ok(code("plugins/openclaw-connector/shadow-v070/transport.mjs").includes("rejectUnauthorized: true"));
  });
});

describe("every plugin-runtime Hosted path is gated", () => {
  // The four Hosted destinations the plugin runtime can reach on its own, and
  // the module that must consult the outbound controls before each one.
  const GATED = Object.freeze([
    ["/v1/decisions", "plugins/openclaw-connector/pipeline.mjs"],
    ["/v1/observations", "plugins/openclaw-connector/runtime-observer.mjs"],
    ["/v1/openclaw/shadow/evaluate", "plugins/openclaw-connector/shadow-v070/runtime.mjs"],
    ["/v1/runtime/inventory", "plugins/openclaw-connector/runtime-publisher.mjs"],
    ["/v1/runtime/heartbeat", "plugins/openclaw-connector/runtime-publisher.mjs"],
    // Operator-invoked hosted-health / identify: same gate, same contracts.
    ["/v1/health", "plugins/openclaw-connector/hosted-ctl.mjs"],
    ["/v1/credentials/identity", "plugins/openclaw-connector/hosted-ctl.mjs"],
    ["/v1/runtime/inventory", "plugins/openclaw-connector/hosted-ctl.mjs"],
  ]);

  for (const [path, owner] of GATED) {
    it(`${path} is reached only through a control check in ${owner}`, () => {
      const text = code(owner);
      assert.ok(
        /inspectObservationControls|controlInspector|createHostedOutboundGate|#gate\(/.test(text),
        `${owner} must consult the outbound controls`,
      );
    });
  }

  it("the publisher checks the gate before the credential, not after", () => {
    const text = code("plugins/openclaw-connector/runtime-publisher.mjs");
    // The credential can now only be reached through the gate's own run(),
    // which asserts before invoking the credential provider.
    assert.equal(
      /this\.#credential\(config,/.test(text.replace(/credentialProvider: \(run\) => this\.#credential\(config, run\),/, "")),
      false,
      "no publication path may call the credential reader directly any more",
    );
    assert.ok(text.includes('#gate(config, "runtime_inventory").run('));
    assert.ok(text.includes('#gate(config, "runtime_heartbeat").run('));
    assert.ok(text.includes("beforeAttempt"), "each attempt must re-check the gate");
  });

  it("the gate asserts before the credential provider is invoked", () => {
    const text = code("plugins/openclaw-connector/controls.mjs");
    const run = /async run\(send\) \{([\s\S]*?)\n    \},/.exec(text);
    assert.ok(run, "the gate exposes a run helper");
    const body = run[1];
    assert.ok(
      body.indexOf("assert()") < body.indexOf("credentialProvider("),
      "assert() must precede the credential provider call",
    );
    assert.ok(body.includes("beforeAttempt: assert"), "the caller gets a per-attempt re-check");
  });

  it("hosted-health and identify reach the credential and the client only through the gate", () => {
    const text = code("plugins/openclaw-connector/hosted-ctl.mjs");
    // Each command inspects the gate first and sends only inside gate.run().
    for (const [start, end] of [["export async function probeHostedHealth", "export async function identifyRuntimeRoster"], ["export async function identifyRuntimeRoster", "\u0000"]]) {
      const body = text.slice(text.indexOf(start), end === "\u0000" ? undefined : text.indexOf(end));
      assert.ok(body.indexOf("gate.inspect()") > 0, `${start} inspects the gate`);
      assert.ok(body.indexOf("gate.inspect()") < body.indexOf("gate.run("), `${start} inspects before running`);
      assert.equal(/withCredential\(|readSecureFile|deployment-credential/.test(body), false, `${start} reads no credential directly`);
      assert.equal(/owned\.(health|credentialIdentity|publishInventory)\(/.test(body.slice(0, body.indexOf("gate.run("))), false, `${start} sends nothing before the gate`);
    }
    assert.equal(/publishHeartbeat|\/v1\/runtime\/heartbeat|\/v1\/observations|\/v1\/decisions|allocateRuntimeGeneration/.test(text), false,
      "hosted-ctl never heartbeats, observes, decides or claims a runtime generation");
  });

  it("the launcher module is local-only", () => {
    const text = code("plugins/openclaw-connector/cli-entrypoint.mjs");
    assert.equal(/node:child_process|\bspawn(?:Sync)?\(|\bexec(?:File)?(?:Sync)?\(\s*["'`]/.test(text), false);
    assert.equal(/withCredential|deployment-credential/.test(text), false);
  });

  it("no plugin-runtime path swallows a refusal and sends anyway", () => {
    for (const path of [
      "plugins/openclaw-connector/pipeline.mjs",
      "plugins/openclaw-connector/runtime-observer.mjs",
      "plugins/openclaw-connector/runtime-publisher.mjs",
    ]) {
      const text = code(path);
      // A bare `catch {}` around a control check would be fail-open.
      assert.equal(
        /catch\s*\{\s*\}\s*(?:\n\s*)?(?:await\s+)?this\.#client/.test(text),
        false,
        `${path} has a catch-and-send fallback`,
      );
    }
  });

  it("ships no background timer other than the governed cadence and bounded deadlines", () => {
    for (const path of sources()) {
      assert.equal(/setInterval/.test(code(path)), false, `${path} uses setInterval`);
    }
    const publisher = code("plugins/openclaw-connector/runtime-publisher.mjs");
    assert.ok(publisher.includes("unref"), "the cadence timer never holds the process open");
    assert.ok(
      publisher.includes("if (this.#refusedThisRun(config)) return;"),
      "every cadence tick re-checks the gate before doing anything",
    );
  });
});

describe("operator-invoked Hosted paths remain operator-invoked", () => {
  it("unpair disables the connector before it contacts Hosted at all", () => {
    const text = code("plugins/openclaw-connector/operator.mjs");
    const unpair = text.slice(text.indexOf("export async function unpairConnector"));
    assert.ok(
      unpair.indexOf('setControl(config.stateDir, "disabled", true)') < unpair.indexOf("revokeSelf"),
      "revocation is a stop action: the connector is disabled first",
    );
  });

  it("the plugin runtime never starts a pairing or access request by itself", () => {
    for (const path of sources().filter((file) => file.startsWith("plugins/"))) {
      const text = code(path);
      assert.equal(text.includes("/v1/pairing/redeem"), false, `${path} must not redeem pairing codes`);
      assert.equal(text.includes("/access/v1/"), false, `${path} must not make access requests`);
    }
  });

  it("the access request never authenticates with the installation credential", () => {
    const text = code("cli/access.mjs");
    assert.equal(text.includes("withCredential"), false);
    assert.equal(text.includes("deployment-credential"), false);
    assert.ok(text.includes("owner_key"), "it uses its own per-request owner key");
  });
});

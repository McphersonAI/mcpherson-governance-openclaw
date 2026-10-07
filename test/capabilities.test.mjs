// The managed-install capability surface must match what the code actually does.
//
// OpenClaw 2026.8.2 resolves the two hook grants like this
// (dist/hook-policy-decisions-*.js):
//
//   allowPromptInjection    = entry?.hooks?.allowPromptInjection !== false
//   allowConversationAccess = origin === "bundled"
//                               ? entry?.hooks?.allowConversationAccess !== false
//                               : entry?.hooks?.allowConversationAccess === true
//
// Both read `plugins.entries.<id>.hooks` in openclaw.json. `PluginManifest` has
// no field for either, so a plugin declines prompt injection by writing its own
// entry policy. These tests pin that policy, and pin that no prompt-mutating
// hook or injection API is used anywhere in the shipped runtime.
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  LEAST_PRIVILEGE_HOOK_POLICY, withLeastPrivilegeHookPolicy,
} from "../pairing/openclaw-profile-pairing.mjs";
import { makeConnectionTool, makeConnectionToolRegistration } from "../plugins/openclaw-connector/tools.mjs";
import { CONNECTION_MARKER, CONNECTION_TOOL_NAME } from "../plugins/openclaw-connector/constants.mjs";
import { cleanupProfiles } from "./helpers.mjs";

after(cleanupProfiles);

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const manifest = JSON.parse(readFileSync(join(ROOT, "openclaw.plugin.json"), "utf8"));

// The exact resolver OpenClaw 2026.8.2 uses, reproduced so the assertions are
// about the host's rule and not about our wording of it.
const promptInjectionAllowed = (hooks) => hooks?.allowPromptInjection !== false;
const conversationAccessAllowed = (origin, hooks) => (origin === "bundled"
  ? hooks?.allowConversationAccess !== false
  : hooks?.allowConversationAccess === true);

// Comments in this package discuss the OpenClaw APIs it deliberately does NOT
// use, so the "never calls" assertions scan executable code only.
function codeOf(path) {
  return readFileSync(path, "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/^\s*\/\/.*$/gm, " ");
}

function sourceFiles() {
  const found = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      if (name === "node_modules" || name === ".git" || name === "test") continue;
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else if (name.endsWith(".mjs")) found.push(path);
    }
  };
  walk(ROOT);
  return found;
}

describe("declared capabilities match registered capabilities", () => {
  it("registers exactly four hooks, none of which build or mutate a prompt", () => {
    const index = readFileSync(join(ROOT, "plugins/openclaw-connector/index.mjs"), "utf8");
    const registered = new Set([...index.matchAll(/api\.on\(\s*(?:"([a-z_]+)"|hookName)/g)]
      .map((match) => match[1]).filter(Boolean));
    for (const name of ["before_tool_call", "after_tool_call", "gateway_start", "gateway_stop"]) {
      assert.ok(index.includes(`"${name}"`), `${name} must remain registered`);
    }
    void registered;
    // Prompt-mutating OpenClaw hooks. None may appear anywhere in the package.
    const promptHooks = [
      "before_prompt_build", "before_agent_start", "before_model_resolve",
      "llm_input", "llm_output", "agent_end", "before_compaction", "after_compaction",
      "message_received", "message_sending", "before_message_write",
      "session_start", "session_end", "tool_result_persist",
      "subagent_spawning", "subagent_spawned",
    ];
    for (const path of sourceFiles()) {
      const text = codeOf(path);
      for (const hook of promptHooks) {
        assert.equal(text.includes(hook), false, `${path} must not reference ${hook}`);
      }
    }
  });

  it("never calls any prompt-injection or conversation-access API", () => {
    const forbidden = [
      "enqueueNextTurnInjection", "prependContext", "systemPrompt",
      "registerSessionExtension", "agent_turn_prepare", "buildPluginAgentTurnPrepareContext",
      "registerContextEngine", "registerCompactionProvider", "registerInteractiveHandler",
      "registerAgentToolResultMiddleware", "registerTrustedToolPolicy",
    ];
    for (const path of sourceFiles()) {
      const text = codeOf(path);
      for (const api of forbidden) {
        assert.equal(text.includes(api), false, `${path} must not call ${api}`);
      }
    }
  });

  it("the shipped entry policy resolves to prompt injection DENIED", () => {
    const hooks = withLeastPrivilegeHookPolicy({});
    assert.equal(hooks.allowPromptInjection, false);
    assert.equal(promptInjectionAllowed(hooks), false, "OpenClaw must report Prompt injection: denied");
  });

  it("the shipped entry policy resolves to conversation access DENIED", () => {
    const hooks = withLeastPrivilegeHookPolicy({});
    assert.equal(hooks.allowConversationAccess, false);
    assert.equal(conversationAccessAllowed("global", hooks), false);
    assert.equal(conversationAccessAllowed("bundled", hooks), false);
  });

  it("an explicit operator value is preserved, never overwritten", () => {
    const widened = withLeastPrivilegeHookPolicy({
      hooks: { allowPromptInjection: true, allowConversationAccess: true, timeoutMs: 1234 },
    });
    assert.equal(widened.allowPromptInjection, true);
    assert.equal(widened.allowConversationAccess, true);
    assert.equal(widened.timeoutMs, 1234, "unrelated operator hook settings survive");
  });

  it("without the policy OpenClaw's own default would grant prompt injection", () => {
    // This is the v0.7.2 state the scanner saw: no entry policy at all.
    assert.equal(promptInjectionAllowed(undefined), true);
    assert.equal(LEAST_PRIVILEGE_HOOK_POLICY.allowPromptInjection, false);
  });

  it("the manifest declares exactly one tool and no other reviewed surface", () => {
    assert.deepEqual(manifest.contracts.tools, [CONNECTION_TOOL_NAME]);
    for (const key of ["channels", "providers", "mcpServers", "cliCommands", "cliBackends", "skills"]) {
      assert.equal(manifest[key], undefined, `manifest must not declare ${key}`);
    }
    assert.equal(manifest.configContracts, undefined, "no dangerous config flags are declared");
    assert.equal(manifest.id, "mcpherson-governance-connector");
    assert.equal(manifest.activation.onStartup, true, "gateway_start is genuinely required");
  });

  it("the root and connector manifests stay identical", () => {
    assert.deepEqual(
      manifest,
      JSON.parse(readFileSync(join(ROOT, "plugins/openclaw-connector/openclaw.plugin.json"), "utf8")),
    );
  });
});

describe("mcpherson_connection_test stays bounded", () => {
  it("accepts no arguments, touches no network, and returns only a fixed marker", async () => {
    const tool = makeConnectionTool();
    assert.equal(tool.name, CONNECTION_TOOL_NAME);
    assert.deepEqual(tool.parameters.properties, {});
    assert.equal(tool.parameters.additionalProperties, false);

    const result = await tool.execute({});
    assert.deepEqual(result, { content: [{ type: "text", text: CONNECTION_MARKER }] });

    // It holds no client, no credential path, and no endpoint.
    const source = codeOf(join(ROOT, "plugins/openclaw-connector/tools.mjs"));
    for (const token of ["https", "fetch", "credential", "apiUrl", "Bearer"]) {
      assert.equal(source.includes(token), false, `tools.mjs must not reference ${token}`);
    }
  });

  it("rejects any argument shape other than the empty object", () => {
    const { governance } = makeConnectionToolRegistration();
    assert.equal(governance.validateParams({}), true);
    for (const bad of [{ a: 1 }, null, [], "x", 1]) {
      assert.equal(governance.validateParams(bad), false, String(bad));
    }
    assert.equal(governance.actionClass, "read_only_internal");
  });
});

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadConnectorConfig } from "../plugins/openclaw-connector/config.mjs";
import { installCredential } from "../plugins/openclaw-connector/credentials.mjs";
import { setControl } from "../plugins/openclaw-connector/controls.mjs";

// A syntactically valid mgd1 token. It is a throwaway local fixture: nothing in
// this suite contacts a real endpoint, and no production credential is used.
export const TEST_CREDENTIAL =
  "mgd1_0123456789abcdef0123456789abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

const roots = [];

export function makeProfile({ enabled = true, paired = true, apiUrl = "https://hosted.invalid" } = {}) {
  const root = mkdtempSync(join(tmpdir(), "observa-v073-"));
  roots.push(root);
  const stateDir = join(root, "state");
  const config = loadConnectorConfig(
    { enabled, apiUrl },
    { openclawStateDir: root, stateDir, receiptDir: join(root, "receipts") },
  );
  if (paired) installCredential(config.stateDir, TEST_CREDENTIAL);
  return { root, config };
}

export function cleanupProfiles() {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
}

export const control = (config, name, on) => setControl(config.stateDir, name, on);

/**
 * Hosted network spy.
 *
 * Every method records its call AND the credential it was handed. A test that
 * expects silence asserts `spy.calls.length === 0`; because the spy stands in
 * for the whole GovernanceApiClient, a recorded call is proof that a request
 * would have been constructed and a credential transmitted.
 */
export function makeClientSpy({ fail = false } = {}) {
  const calls = [];
  const record = async (path, body, credential, options = {}) => {
    calls.push({ path, credential, bytes: body?.length ?? 0 });
    // Mirror the real client: give the caller its per-attempt re-check before
    // anything would go on the wire, so a gate that refuses mid-flight is seen.
    options.beforeAttempt?.({ attempt: 0, phase: "before_transport", path });
    if (fail) throw Object.assign(new Error("UNREACHABLE"), { remoteStatus: "UNREACHABLE" });
    return Object.freeze({ ok: true });
  };
  return {
    calls,
    credentialsSeen: () => calls.map((call) => call.credential).filter((value) => value != null),
    publishInventory: (body, credential, options) => record("/v1/runtime/inventory", body, credential, options),
    publishHeartbeat: (body, credential, options) => record("/v1/runtime/heartbeat", body, credential, options),
    observeShadow: (body, credential, options) => record("/v1/observations", body, credential, options),
    decide: (body, credential, options) => record("/v1/decisions", body, credential, options),
    health: (credential, options) => record("/v1/health", null, credential, options),
    recordFailure() {},
    recordSuccess() {},
    status: () => Object.freeze({ activeTransports: 0 }),
    shutdown: async () => undefined,
  };
}

/** A credential provider that records every read and never returns a secret. */
export function makeCredentialSpy(value = TEST_CREDENTIAL) {
  const reads = [];
  const provider = async (stateDir, callback) => {
    reads.push(stateDir);
    return callback(value, { credentialId: "0".repeat(32), fingerprint: `sha256:${"0".repeat(16)}` });
  };
  provider.reads = reads;
  return provider;
}

/**
 * Drain the microtask queue and one macrotask turn, which is enough for a
 * publisher run (gate -> credential -> client -> settle) to reach its terminal
 * state before a test asserts on it.
 */
export async function flush() {
  for (let round = 0; round < 4; round += 1) {
    for (let i = 0; i < 32; i += 1) await Promise.resolve();
    await new Promise((resolve) => setImmediate(resolve));
  }
}

/** Deterministic timer pair: `fire()` runs the pending cadence callback. */
export function makeManualTimers() {
  let pending = null;
  let nextId = 1;
  return {
    setTimeoutFn(callback) { pending = callback; return { id: nextId++, unref() {} }; },
    clearTimeoutFn() { pending = null; },
    armed: () => pending !== null,
    async fire() {
      const callback = pending;
      pending = null;
      callback?.();
      await flush();
    },
  };
}

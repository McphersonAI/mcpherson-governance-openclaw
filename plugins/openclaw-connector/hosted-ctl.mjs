// Operator-invoked Hosted checks: `observa hosted-health` and `observa identify`.
//
// Both reuse existing contracts only: GET /v1/health and
// GET /v1/credentials/identity (the v0.6.2 connector health/identity pair) and
// the runtime roster publication POST /v1/runtime/inventory. No new protocol.
//
// Both go through the same Hosted-outbound gate as the plugin runtime, so the
// source `enabled` flag, disable, kill switch and lock refuse them before any
// credential read or socket. Neither writes a receipt, an activity record, a
// decision or a heartbeat, and neither changes controls, mappings or config.
//
// `identify` never claims a runtime generation. Hosted gives roster ownership
// to the highest generation ever claimed on a credential, so a CLI process
// publishing under a new generation would permanently supersede the running
// gateway's heartbeat. Instead it re-publishes the configured roster under the
// running gateway's own runtime identity (from the local publication journal):
// an unchanged roster is an idempotent confirmation on Hosted, and a changed
// roster is left for the gateway to publish on its next start.
import { GovernanceApiClient } from "./client.mjs";
import { createHostedOutboundGate } from "./controls.mjs";
import { withCredential } from "./credentials.mjs";
import {
  buildRuntimeInventoryRequest, rosterRevision, serializeRuntimePublication,
} from "./runtime-publication-contract.mjs";

// A heartbeat older than this many cadences is stale: the gateway is not
// currently publishing (stopped, refused, or unable to reach Hosted).
export const HEARTBEAT_FRESH_CADENCES = 3;
export const FUNNEL = Object.freeze([
  "observa request-access --api-url https://<host>",
  "observa request-status",
  "observa pair --api-url https://<host>",
]);

const age = (at, now) => (at ? Math.max(0, Math.floor((now - Date.parse(at)) / 1000)) : null);

function failure(error) {
  if (error?.name === "HostedOutboundRefused") return { state: "REFUSED_BY_CONTROL", reason: String(error.priority ?? error.remoteStatus ?? "NOT_ATTEMPTED"), reached: false };
  const status = String(error?.remoteStatus ?? error?.code ?? "");
  if (status === "AUTH_REJECTED") return { state: "CREDENTIAL_REFUSED", reason: "HTTP_403", reached: true };
  if (status === "CREDENTIAL_IDENTITY_MISMATCH") return { state: "BINDING_MISMATCH", reason: status, reached: true };
  if (["UNREACHABLE", "TIMEOUT", "TLS_FAILURE", "CIRCUIT_OPEN"].includes(status)) return { state: "UNREACHABLE", reason: status, reached: false };
  if (status === "HTTP_ERROR:503") return { state: "HOSTED_UNAVAILABLE", reason: status, reached: true };
  if (status === "HTTP_ERROR:410") return { state: "RUNTIME_SUPERSEDED", reason: status, reached: true };
  if (status === "HTTP_ERROR:429") return { state: "RATE_LIMITED", reason: status, reached: true };
  if (/^HTTP_ERROR:4\d\d$/.test(status)) return { state: "HOSTED_REFUSED", reason: status, reached: true };
  if (status === "INVALID_RESPONSE") return { state: "HOSTED_CONTRACT_INVALID", reason: status, reached: true };
  if (/^(CREDENTIAL_|INSECURE_|INVALID_SIZE|WRONG_OWNER|NOT_REGULAR_FILE|ENOENT|ELOOP)/.test(status)) {
    return { state: "CREDENTIAL_UNUSABLE", reason: "LOCAL_CREDENTIAL_UNREADABLE", reached: false };
  }
  return { state: "HOSTED_CHECK_FAILED", reason: /^[A-Z][A-Z0-9_:]{0,47}$/.test(status) ? status : "UNKNOWN", reached: false };
}

function gateFor(config, purpose, { credentialProvider, controlInspector }) {
  return createHostedOutboundGate({
    config, purpose,
    ...(controlInspector ? { controlInspector: () => controlInspector(config) } : {}),
    credentialProvider: (run) => credentialProvider(config.stateDir, run),
  });
}

function defaultClient(config) {
  return new GovernanceApiClient({ baseUrl: config.apiUrl, connectTimeoutMs: config.connectTimeoutMs, caFile: config.caFile });
}

/** Heartbeat/roster freshness from the gateway's local publication journal. */
export function assessPublication(publication, { now = Date.now(), rosterRevision: configured = null } = {}) {
  if (publication === null || publication === undefined) {
    return Object.freeze({
      heartbeat: "NOT_AVAILABLE", heartbeat_age_seconds: null, heartbeat_accepted_at: null,
      roster: "NOT_AVAILABLE", roster_published_at: null, roster_agents: null,
      runtime_instance_id: null, runtime_generation: null, last_outcome: null, last_failure: null,
    });
  }
  const heartbeatAge = age(publication.heartbeat_accepted_at, now);
  const limit = publication.cadence_seconds * HEARTBEAT_FRESH_CADENCES;
  let heartbeat;
  if (publication.last_outcome === "STOPPED") heartbeat = "STOPPED";
  else if (publication.last_outcome === "SUPERSEDED") heartbeat = "SUPERSEDED";
  else if (heartbeatAge === null) heartbeat = "NONE_ACCEPTED";
  else heartbeat = heartbeatAge <= limit ? "FRESH" : "STALE";
  let roster;
  if (publication.inventory_accepted_at === null) roster = "NOT_PUBLISHED";
  else if (configured === null) roster = "PUBLISHED";
  else roster = configured === publication.roster_revision ? "CURRENT" : "CHANGED_SINCE_PUBLICATION";
  return Object.freeze({
    heartbeat, heartbeat_age_seconds: heartbeatAge, heartbeat_accepted_at: publication.heartbeat_accepted_at,
    heartbeat_cadence_seconds: publication.cadence_seconds,
    roster, roster_published_at: publication.inventory_accepted_at, roster_agents: publication.agents.length,
    runtime_instance_id: publication.runtime_instance_id, runtime_generation: publication.runtime_generation,
    last_outcome: publication.last_outcome, last_failure: publication.last_failure,
  });
}

/**
 * `observa hosted-health`. A deliberate, networked, read-only probe of the
 * paired Hosted path: reachability, credential acceptance and installation
 * binding, plus the gateway's recorded heartbeat and roster freshness.
 */
export async function probeHostedHealth({
  config, pairing, roster = null, publication = null, configured = true, now = Date.now(),
  client = null, credentialProvider = withCredential, controlInspector = null,
}) {
  const revision = roster ? rosterRevision(roster) : null;
  const report = {
    state: null, healthy: false,
    paired: pairing?.paired === true,
    credential: pairing?.paired ? "PRESENT" : pairing?.error ? "UNUSABLE" : "ABSENT",
    credential_fingerprint: pairing?.fingerprint ?? null,
    connector_configured: configured, connector_enabled: config.enabled === true,
    endpoint: pairing?.paired ? config.apiUrl : null,
    deployment_id: pairing?.paired ? config.deploymentId : null,
    workspace_binding: "SERVER_BOUND",
    reachable: "NOT_PROBED", binding: "UNKNOWN", probed_at: null, last_success_at: null,
    refusal: null,
    publication: assessPublication(publication, { now, rosterRevision: revision }),
    next: [],
  };
  if (!report.paired) {
    report.state = pairing?.error ? "CREDENTIAL_UNUSABLE" : "NOT_PAIRED";
    report.next = pairing?.error ? ["Repair or re-pair: observa pair --api-url https://<host> --replace-existing"] : [...FUNNEL];
    return Object.freeze(report);
  }
  const gate = gateFor(config, "hosted_health", { credentialProvider, controlInspector });
  const controls = gate.inspect();
  if (controls.blocked) {
    report.state = "REFUSED_BY_CONTROL";
    report.refusal = String(controls.priority ?? "NOT_ATTEMPTED");
    report.next = ["Hosted was not contacted and the credential was not read. Clear the control to probe."];
    return Object.freeze(report);
  }
  const owned = client ?? defaultClient(config);
  try {
    await gate.run(async (credential, { beforeAttempt, descriptor }) => {
      await owned.health(credential, { beforeAttempt });
      report.reachable = "YES";
      await owned.credentialIdentity(credential, {
        beforeAttempt, expectedCredentialId: descriptor?.credentialId, expectedDeploymentId: config.deploymentId,
      });
      report.binding = "VALID";
    });
    report.probed_at = new Date(now).toISOString();
    report.last_success_at = report.probed_at;
    const heartbeat = report.publication.heartbeat;
    report.state = heartbeat === "FRESH" ? "HEALTHY"
      : heartbeat === "NOT_AVAILABLE" ? "CONNECTED_HEARTBEAT_UNKNOWN" : "CONNECTED_HEARTBEAT_STALE";
    report.healthy = report.state === "HEALTHY";
    if (!report.healthy) {
      report.next = ["The gateway is not recording accepted heartbeats. Restart the OpenClaw gateway and check again."];
    }
  } catch (error) {
    const mapped = failure(error);
    report.state = mapped.state;
    report.refusal = mapped.reason;
    report.probed_at = new Date(now).toISOString();
    if (mapped.reached) report.reachable = "YES";
    else if (mapped.state === "UNREACHABLE") report.reachable = "NO";
    if (["CREDENTIAL_REFUSED", "BINDING_MISMATCH"].includes(mapped.state)) report.binding = "INVALID";
    report.last_success_at = report.publication.heartbeat_accepted_at ?? report.publication.roster_published_at;
    report.next = mapped.state === "CREDENTIAL_REFUSED" || mapped.state === "BINDING_MISMATCH"
      ? ["Hosted does not accept this installation's credential. Re-pair: observa pair --api-url https://<host> --replace-existing"]
      : mapped.state === "UNREACHABLE" ? ["Check network access to the Hosted endpoint, then retry."]
        : ["Retry shortly. Local inspection (observa status) is unaffected."];
  } finally {
    if (client === null) await owned.shutdown();
  }
  return Object.freeze(report);
}

/**
 * `observa identify`. Identifies the configured agents locally (OpenClaw's
 * configured roster), then, when paired and allowed, confirms that roster on
 * Hosted through the existing runtime roster contract under the running
 * gateway's own runtime identity.
 */
export async function identifyRuntimeRoster({
  config, pairing, roster = null, publication = null, now = Date.now(),
  client = null, credentialProvider = withCredential, controlInspector = null,
}) {
  const revision = roster ? rosterRevision(roster) : null;
  const assessed = assessPublication(publication, { now, rosterRevision: revision });
  const report = {
    local: {
      state: roster ? "IDENTIFIED" : "CONFIG_UNAVAILABLE",
      source: "OPENCLAW_CONFIGURED_ROSTER",
      agents: roster ? roster.map((agent) => agent.agent_id) : [],
      roster_revision: revision,
    },
    hosted: { state: null, reason: null, runtime_instance_id: null, runtime_generation: null, record_id: null, confirmed_at: null },
    publication: assessed,
    // Identity is not activity: nothing below writes a receipt or a decision.
    meaningful_activity_written: false, governance_decisions_written: false, heartbeat_sent: false,
    next: [],
  };
  const hosted = report.hosted;
  const done = (state, reason = null, next = []) => {
    hosted.state = state; hosted.reason = reason; report.next = next;
    return Object.freeze({ ...report, hosted: Object.freeze(hosted) });
  };
  if (!roster) return done("NOT_ATTEMPTED", "LOCAL_ROSTER_UNAVAILABLE", ["Check the selected profile's openclaw.json."]);
  if (pairing?.paired !== true) {
    return done(pairing?.error ? "CREDENTIAL_UNUSABLE" : "NOT_PAIRED", null,
      pairing?.error ? ["Repair or re-pair before publishing the roster to Hosted."] : [...FUNNEL]);
  }
  const gate = gateFor(config, "runtime_inventory", { credentialProvider, controlInspector });
  const controls = gate.inspect();
  if (controls.blocked) {
    return done("REFUSED_BY_CONTROL", String(controls.priority ?? "NOT_ATTEMPTED"),
      ["Hosted was not contacted and the credential was not read. Clear the control to refresh."]);
  }
  if (publication === null || publication === undefined) {
    return done("GATEWAY_PUBLICATION_UNAVAILABLE", "NO_PUBLICATION_JOURNAL",
      ["Restart the OpenClaw gateway. It publishes the configured roster at start."]);
  }
  if (assessed.heartbeat !== "FRESH") {
    return done("GATEWAY_PUBLICATION_STALE", assessed.heartbeat,
      ["The gateway is not currently publishing. Restart the OpenClaw gateway; it publishes the roster at start."]);
  }
  hosted.runtime_instance_id = publication.runtime_instance_id;
  hosted.runtime_generation = publication.runtime_generation;
  if (publication.roster_revision !== revision) {
    return done("ROSTER_CHANGED_RESTART_REQUIRED", "CONFIGURED_ROSTER_DIFFERS_FROM_PUBLISHED",
      ["Restart the OpenClaw gateway to publish the changed roster. Publishing it from here would stop the running gateway's heartbeat."]);
  }
  const request = buildRuntimeInventoryRequest({
    runtimeInstanceId: publication.runtime_instance_id,
    runtimeGeneration: publication.runtime_generation,
    rosterRevision: revision,
    agents: roster,
  });
  const body = serializeRuntimePublication(request);
  const owned = client ?? defaultClient(config);
  try {
    const ack = await gate.run((credential, { beforeAttempt }) => owned.publishInventory(
      body, credential, { expectedRequestHash: request.request_hash, beforeAttempt },
    ));
    hosted.record_id = typeof ack?.record_id === "string" ? ack.record_id : null;
    hosted.confirmed_at = new Date(now).toISOString();
    return done("ROSTER_CONFIRMED");
  } catch (error) {
    const mapped = failure(error);
    return done(mapped.state, mapped.reason, mapped.state === "RUNTIME_SUPERSEDED"
      ? ["Another runtime on this credential owns the Hosted roster. Restart this gateway to publish from it."]
      : ["Retry shortly. Local identification above is unaffected."]);
  } finally {
    body.fill(0);
    if (client === null) await owned.shutdown();
  }
}

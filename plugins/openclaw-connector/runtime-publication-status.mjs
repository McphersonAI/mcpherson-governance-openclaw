// Local, owner-only journal of what the gateway's runtime publisher last had
// accepted by Hosted. It lets `observa hosted-health` report heartbeat and
// roster freshness, and lets `observa identify` confirm the roster under the
// running gateway's OWN runtime identity, without a CLI process ever claiming
// a runtime generation (which would supersede the gateway on Hosted).
//
// It is liveness and identity metadata only: no credential, no tool, no
// capability, no activity, no decision. It is never read as activity.
import { join } from "node:path";
import { atomicWriteSecureFile } from "./secure-files.mjs";

export const PUBLICATION_STATUS_FILE = "runtime-publication-status.json";
export const PUBLICATION_STATUS_SCHEMA = "observa-openclaw-runtime-publication-status/v1";
export const PUBLICATION_OUTCOMES = Object.freeze([
  "INVENTORY_ACCEPTED", "HEARTBEAT_ACCEPTED", "FAILED", "SUPERSEDED", "STOPPED",
]);

const SAFE_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const AGENT_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const STATUS_CODE = /^[A-Z][A-Z_]{0,47}(?::\d{3})?$/;
const FIELDS = Object.freeze([
  "schema", "runtime_instance_id", "runtime_generation", "roster_revision", "agents",
  "cadence_seconds", "inventory_accepted_at", "heartbeat_accepted_at", "heartbeats_accepted",
  "last_outcome", "last_outcome_at", "last_failure", "authority", "enforcement", "active",
]);

const instant = (value) => typeof value === "string" && value.length <= 32
  && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value) && Number.isFinite(Date.parse(value));

/** Strict parse; any deviation yields null (treated as "no journal"). */
export function parsePublicationStatus(text) {
  let value;
  try { value = JSON.parse(text); } catch { return null; }
  if (!value || typeof value !== "object" || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...FIELDS].sort())) return null;
  const ok = value.schema === PUBLICATION_STATUS_SCHEMA
    && typeof value.runtime_instance_id === "string" && SAFE_ID.test(value.runtime_instance_id)
    && Number.isSafeInteger(value.runtime_generation) && value.runtime_generation >= 1
    && typeof value.roster_revision === "string" && SHA256.test(value.roster_revision)
    && Array.isArray(value.agents) && value.agents.length >= 1 && value.agents.length <= 256
    && value.agents.every((id) => typeof id === "string" && AGENT_ID.test(id))
    && Number.isSafeInteger(value.cadence_seconds) && value.cadence_seconds >= 10 && value.cadence_seconds <= 300
    && (value.inventory_accepted_at === null || instant(value.inventory_accepted_at))
    && (value.heartbeat_accepted_at === null || instant(value.heartbeat_accepted_at))
    && Number.isSafeInteger(value.heartbeats_accepted) && value.heartbeats_accepted >= 0
    && PUBLICATION_OUTCOMES.includes(value.last_outcome) && instant(value.last_outcome_at)
    && (value.last_failure === null || (typeof value.last_failure === "string" && STATUS_CODE.test(value.last_failure)))
    && value.authority === "NONE" && value.enforcement === "OFF" && value.active === false;
  return ok ? Object.freeze({ ...value, agents: Object.freeze([...value.agents]) }) : null;
}

/** Bounded status code for the journal; anything unexpected is generic. */
export function publicationFailureCode(error) {
  const code = String(error?.remoteStatus ?? error?.code ?? "");
  return STATUS_CODE.test(code) ? code : "PUBLICATION_FAILED";
}

export function writePublicationStatus(stateDir, status) {
  const value = { schema: PUBLICATION_STATUS_SCHEMA, ...status, authority: "NONE", enforcement: "OFF", active: false };
  if (parsePublicationStatus(JSON.stringify(value)) === null) {
    throw Object.assign(new Error("PUBLICATION_STATUS_INVALID"), { code: "PUBLICATION_STATUS_INVALID" });
  }
  atomicWriteSecureFile(join(stateDir, PUBLICATION_STATUS_FILE), `${JSON.stringify(value)}\n`, {
    temporaryPrefix: ".runtime-publication-status-tmp-",
  });
}

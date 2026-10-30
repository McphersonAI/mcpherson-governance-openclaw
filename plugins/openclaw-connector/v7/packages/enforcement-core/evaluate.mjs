// v0.7 deterministic enforcement evaluator (requirements 1 & 2).
//
// evaluate(envelope, policy_bundle, approvals[], evaluation_context) -> record
//
// A PURE function of its four supplied inputs. It reads NO ambient clock,
// network, filesystem, randomness, model, or executor. `evaluated_at` and
// `engine_version` are supplied in evaluation_context, so replays are exact.
//
// Fail-closed engine-boundary guarantee: decision_permit is true ONLY for (a) an
// affirmative rederivable policy match (an ALLOW rule, incl. an explicit
// catch-all ALLOW), or (b) a REQUIRE_APPROVAL satisfied by a verified, fresh,
// envelope-bound approval. Every uncertainty, error, missing context, budget
// exhaustion, drift, unresolved conflict, ABSTAIN, and unverifiable approval is
// a non-permit. ABSTAIN is NEVER permission.

import { createHash } from "node:crypto";
import { canonicalizeJson, canonicalHash } from "./hashing.mjs";
import {
  EVALUATION_MODE, AUTHORITY_NONE, RUNTIME_ACTIVE, ENFORCEMENT_ELIGIBLE,
  latticeRank, contextMissingReason,
} from "./vocabulary.mjs";
import { toWire, basePermit } from "./decision-model.mjs";
import { validateActionEnvelope, effectsConsistentWithClass } from "./envelope.mjs";
import { validateBundle, engineInRange } from "./policy-registry.mjs";
import { evaluateMatch } from "./policy-match.mjs";
import { verifyApproval } from "./approval-verify.mjs";
import { validateEvaluationContext } from "./evaluation-context.mjs";
import { toEpochSeconds } from "./time.mjs";
import { MAX_EVALUATION_STEPS } from "./bounds.mjs";
import { assertValidArtifact } from "./contracts.mjs";

export const DECISION_SCHEMA_ID = "mcpherson-governance-enforcement-decision/v1";
const REDACTION_NOTE = "no_raw_arguments_credentials_hosts_or_pii";

const WIRE_SAFE_ID_RE = /^[A-Za-z0-9._:-]{1,96}$/;
const SHA256_RE = /^sha256:[a-f0-9]{64}$/;
const VERSION_RE = /^[A-Za-z0-9._+-]{1,32}$/;
const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ULID_RE = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const TS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;
const ZERO_HASH = `sha256:${"0".repeat(64)}`;
const FALLBACK_CONTEXT = Object.freeze({
  schema: "mcpherson-governance-enforcement-evaluation-context/v1",
  context_version: "1",
  evaluated_at: "1970-01-01T00:00:00Z",
  engine_version: "0",
  prev_record_hash: null,
  approval_verifications: Object.freeze([]),
  consumed_approval_ids: Object.freeze([]),
});

function safeCanonicalHash(value, label) {
  try {
    return canonicalHash(value);
  } catch {
    return canonicalHash({ invalid_input: label });
  }
}

function recordContext(context) {
  if (!context || typeof context !== "object" || Array.isArray(context)) {
    return FALLBACK_CONTEXT;
  }
  return Object.freeze({
    ...FALLBACK_CONTEXT,
    evaluated_at: typeof context.evaluated_at === "string"
      && TS_RE.test(context.evaluated_at)
      ? context.evaluated_at
      : FALLBACK_CONTEXT.evaluated_at,
    engine_version: typeof context.engine_version === "string"
      && VERSION_RE.test(context.engine_version)
      ? context.engine_version
      : FALLBACK_CONTEXT.engine_version,
    prev_record_hash: typeof context.prev_record_hash === "string"
      && SHA256_RE.test(context.prev_record_hash)
      ? context.prev_record_hash
      : null,
    approval_verifications: Object.freeze([]),
    consumed_approval_ids: Object.freeze([]),
  });
}

// Deterministic UUIDv4-shaped id derived from the envelope hash, used only when
// an ERROR record must be bound but the envelope's own id is unusable.
function syntheticEnvelopeId(envelopeHash) {
  const hex = createHash("sha256").update(envelopeHash).digest("hex");
  const variant = "89ab"[parseInt(hex[16], 16) % 4];
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-${variant}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

// Safe, schema-valid binding identity, tolerating an invalid envelope so an
// ERROR record can still be produced and bound (fail-closed, never a crash).
function bindIdentity(envelope, envelopeHash, ctx) {
  const idOk = typeof envelope.envelope_id === "string"
    && (UUID_V4_RE.test(envelope.envelope_id) || ULID_RE.test(envelope.envelope_id));
  const wireId = (v) => (typeof v === "string" && WIRE_SAFE_ID_RE.test(v) ? v : "unknown");
  const version = (v) => (typeof v === "string" && VERSION_RE.test(v) ? v : "0");
  const sha = (v) => (typeof v === "string" && SHA256_RE.test(v) ? v : ZERO_HASH);
  const ts = (v) => (typeof v === "string" && TS_RE.test(v) ? v : ctx.evaluated_at);
  return {
    envelope_id: idOk ? envelope.envelope_id : syntheticEnvelopeId(envelopeHash),
    envelope_hash: envelopeHash,
    request_hash: sha(envelope.request_hash),
    tenant_id: wireId(envelope.tenant_id),
    workspace_id: wireId(envelope.workspace_id),
    policy_bundle_id: wireId(envelope.policy_bundle_id),
    policy_bundle_version: version(envelope.policy_bundle_version),
    policy_bundle_hash: sha(envelope.policy_bundle_hash),
    observed_at: ts(envelope.observed_at),
  };
}

function emptyApprovalBinding(state) {
  return {
    required_state: state,
    bound_approval_ref: null,
    verified: false,
    staleness: "MISSING",
    bound_envelope_hash: null,
    bound_bundle_id: null,
    bound_bundle_version: null,
    bound_bundle_hash: null,
    bound_tenant_id: null,
    bound_workspace_id: null,
    approval_issuer: null,
    approval_subject: null,
    approval_scope: null,
    issued_at: null,
    expires_at: null,
    trust_verification_hash: null,
    trust_verified: false,
    consumption_status: state === null ? "NOT_APPLICABLE" : "UNKNOWN",
  };
}

function emptyConflict(strategy) {
  return {
    strategy,
    winning_rule_id: null,
    losing_rule_ids: [],
    same_priority_contradictions: [],
  };
}

function finalizeRecord(body) {
  const evidence_hash = canonicalHash(body);
  const decision_id = `ench-dec-${createHash("sha256")
    .update(new TextEncoder().encode(canonicalizeJson(body)))
    .digest("hex").slice(0, 24)}`;
  return Object.freeze({ decision_id, ...body, evidence_hash });
}

/**
 * The core evaluation. `evaluation_context` is a closed contract supplying
 * `evaluated_at`, `engine_version`, `prev_record_hash`, issuer-verification
 * results, and consumed approval ids. Invalid inputs return a documented,
 * schema-valid ERROR/non-permit record; evaluation never performs or leaks a
 * filesystem operation.
 */
export function evaluate(envelope, bundle, approvals, evaluationContext) {
  const envelopeIsObject = envelope !== null
    && typeof envelope === "object" && !Array.isArray(envelope);
  const bundleIsObject = bundle !== null
    && typeof bundle === "object" && !Array.isArray(bundle);
  const contextIsObject = evaluationContext !== null
    && typeof evaluationContext === "object" && !Array.isArray(evaluationContext);
  const contextResult = contextIsObject
    ? validateEvaluationContext(evaluationContext)
    : { ok: false, reason: "failsafe:invalid:evaluation_context" };
  const ctx = contextResult.ok ? evaluationContext : recordContext(evaluationContext);
  const envelopeHash = safeCanonicalHash(envelope, "envelope");
  const identity = bindIdentity(envelopeIsObject ? envelope : {}, envelopeHash, ctx);
  const evaluationContextHash = safeCanonicalHash(
    evaluationContext,
    "evaluation_context",
  );
  const strategy = (bundle && bundle.conflict_strategy) === "strict" ? "strict" : "lattice";
  const prevRecordHash = typeof ctx.prev_record_hash === "string"
    && SHA256_RE.test(ctx.prev_record_hash)
    ? ctx.prev_record_hash
    : null;

  // Assemble a fail-closed record shell; fill decision-specific fields below.
  const make = ({
    abstract, permit, reason, wire, rules_evaluated = [], default_applied = false,
    conflict_resolution = emptyConflict(strategy), approval_required = false,
    approval_binding = emptyApprovalBinding(null),
  }) => {
    const rationale =
      `decision=${abstract} permit=${permit} reason=${reason} ` +
      `rule=${conflict_resolution.winning_rule_id ?? "none"} mode=${EVALUATION_MODE}`;
    const body = {
      schema: DECISION_SCHEMA_ID,
      contract_version: "1",
      engine_version: ctx.engine_version,
      evaluation_context_hash: evaluationContextHash,
      evaluation_mode: EVALUATION_MODE,
      abstract_decision: abstract,
      wire_decision: wire,
      decision_permit: permit,
      authority: AUTHORITY_NONE,
      runtime_active: RUNTIME_ACTIVE,
      enforcement_eligible: ENFORCEMENT_ELIGIBLE,
      envelope_id: identity.envelope_id,
      envelope_hash: identity.envelope_hash,
      request_hash: identity.request_hash,
      policy_bundle_id: identity.policy_bundle_id,
      policy_bundle_version: identity.policy_bundle_version,
      policy_bundle_hash: identity.policy_bundle_hash,
      tenant_id: identity.tenant_id,
      workspace_id: identity.workspace_id,
      rules_evaluated,
      default_applied,
      conflict_resolution,
      reason_code: reason,
      rationale: rationale.slice(0, 512),
      approval_required,
      approval_binding,
      observed_at: identity.observed_at,
      evaluated_at: ctx.evaluated_at,
      redaction_note: REDACTION_NOTE,
      prev_record_hash: prevRecordHash,
    };
    return assertValidArtifact(DECISION_SCHEMA_ID, finalizeRecord(body));
  };

  const errorRecord = (abstract, reason) => make({
    abstract, permit: false, reason, wire: toWire(abstract),
  });

  // 0) The complete four-input contract is fail-closed, including programmer
  // errors. No invalid input is allowed to escape as an exception.
  if (!envelopeIsObject) {
    return errorRecord("ERROR", "failsafe:invalid:envelope_schema");
  }
  if (!bundleIsObject) {
    return errorRecord("ERROR", "failsafe:invalid:bundle_schema");
  }
  if (!Array.isArray(approvals)) {
    return errorRecord("ERROR", "failsafe:invalid:approval_input");
  }
  if (!contextResult.ok) {
    return errorRecord("ERROR", "failsafe:invalid:evaluation_context");
  }

  // 1) Bundle validity (an invalid bundle can never be evaluated).
  let bundleResult;
  try {
    bundleResult = validateBundle(bundle);
  } catch {
    return errorRecord("ERROR", "failsafe:invalid:bundle_schema");
  }
  if (!bundleResult.ok) return errorRecord("ERROR", bundleResult.reason);

  // 2) Envelope validity (structural / bounds / privacy / model-field / hash).
  let envelopeResult;
  try {
    envelopeResult = validateActionEnvelope(envelope);
  } catch {
    return errorRecord("ERROR", "failsafe:invalid:envelope_schema");
  }
  if (!envelopeResult.ok) return errorRecord("ERROR", envelopeResult.reason);

  // 3) Supplied chronology: an action cannot be evaluated before observation.
  const observedAt = toEpochSeconds(envelope.observed_at);
  const evaluatedAt = toEpochSeconds(ctx.evaluated_at);
  if (observedAt === null || evaluatedAt === null || observedAt > evaluatedAt) {
    return errorRecord("ERROR", "failsafe:invalid:timestamp_order");
  }

  // 4) Engine/bundle version compatibility.
  if (!engineInRange(ctx.engine_version, bundle.engine_range)) {
    return errorRecord("ERROR", "engine_range_unsupported");
  }

  // 5) Policy drift: the caller's expected bundle hash must equal the loaded one.
  if (envelope.policy_bundle_hash !== bundle.bundle_hash
      || envelope.policy_bundle_id !== bundle.bundle_id
      || envelope.policy_bundle_version !== bundle.bundle_version) {
    return make({
      abstract: "INDETERMINATE", permit: false,
      reason: "unexpected_policy_version", wire: toWire("INDETERMINATE"),
    });
  }

  // 6) Modeled safety states (kill switch / system lock / circuit).
  const safetyState = envelope.metadata?.safety_state;
  if (safetyState === "KILL_SWITCH_ACTIVE") return make({ abstract: "INDETERMINATE", permit: false, reason: "kill_switch_active", wire: toWire("INDETERMINATE") });
  if (safetyState === "SYSTEM_LOCK_ACTIVE") return make({ abstract: "INDETERMINATE", permit: false, reason: "system_lock_active", wire: toWire("INDETERMINATE") });
  if (safetyState === "CIRCUIT_OPEN") return make({ abstract: "INDETERMINATE", permit: false, reason: "circuit_open", wire: toWire("INDETERMINATE") });

  // 7) Required context present.
  if (Array.isArray(bundle.required_context)) {
    for (const field of bundle.required_context) {
      if (!Object.prototype.hasOwnProperty.call(envelope, field) || envelope[field] === undefined) {
        return make({
          abstract: "INDETERMINATE", permit: false,
          reason: contextMissingReason(field), wire: toWire("INDETERMINATE"),
        });
      }
    }
  }

  // 8) effects <-> action_class consistency.
  if (!effectsConsistentWithClass(envelope)) {
    return make({
      abstract: "INDETERMINATE", permit: false,
      reason: "effects_action_class_mismatch", wire: toWire("INDETERMINATE"),
    });
  }

  // 9) Rule evaluation in canonical (priority ASC, rule_id ASC) order.
  const ordered = [...bundle.rules].sort((a, b) =>
    (a.priority - b.priority) || (a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0));
  const rules_evaluated = [];
  const contributors = [];
  let steps = 0;
  for (const rule of ordered) {
    if (!rule.enabled) {
      rules_evaluated.push({ rule_id: rule.rule_id, matched: false, contributed_decision: null, precedence_rank: -1, enabled: false });
      continue;
    }
    const { matched, steps: ruleSteps } = evaluateMatch(rule.match, envelope);
    steps += ruleSteps;
    if (steps > MAX_EVALUATION_STEPS) {
      return make({ abstract: "INDETERMINATE", permit: false, reason: "budget_exceeded", wire: toWire("INDETERMINATE") });
    }
    const contributed = matched ? rule.effect.decision : null;
    rules_evaluated.push({
      rule_id: rule.rule_id, matched, contributed_decision: contributed,
      precedence_rank: matched ? latticeRank(rule.effect.decision) : -1, enabled: true,
    });
    if (matched) contributors.push(rule);
  }

  // 10) Same-priority contradictions among matched enabled rules (D3).
  const byPriority = new Map();
  for (const rule of contributors) {
    if (!byPriority.has(rule.priority)) byPriority.set(rule.priority, []);
    byPriority.get(rule.priority).push(rule);
  }
  const contradictions = [];
  for (const [priority, group] of [...byPriority.entries()].sort((a, b) => a[0] - b[0])) {
    const decisions = [...new Set(group.map((r) => r.effect.decision))];
    if (group.length >= 2 && decisions.length >= 2) {
      contradictions.push({
        priority,
        rule_ids: group.map((r) => r.rule_id).sort(),
        decisions: decisions.sort(),
      });
    }
  }

  // 11) strict mode escalates any same-priority contradiction to INDETERMINATE.
  if (strategy === "strict" && contradictions.length > 0) {
    return make({
      abstract: "INDETERMINATE", permit: false, reason: "conflict_unresolved",
      wire: toWire("INDETERMINATE"), rules_evaluated,
      conflict_resolution: {
        strategy, winning_rule_id: null, losing_rule_ids: [],
        same_priority_contradictions: contradictions,
      },
    });
  }

  // 12) Resolve outcome.
  let abstract; let reason; let default_applied = false;
  let winningRule = null; const losing = [];
  if (contributors.length === 0) {
    default_applied = true;
    abstract = bundle.default_decision;
    reason = abstract === "ABSTAIN" ? "no_matching_policy_abstain" : "default_decision";
  } else {
    // Most-restrictive by lattice; tie broken by canonical rule order (already
    // sorted). winningRule = first contributor at the minimum lattice rank.
    let bestRank = Infinity;
    for (const rule of contributors) {
      const rank = latticeRank(rule.effect.decision);
      if (rank < bestRank) { bestRank = rank; winningRule = rule; }
    }
    abstract = winningRule.effect.decision;
    reason = "rule_match";
    for (const rule of contributors) if (rule !== winningRule) losing.push(rule.rule_id);
  }

  const conflict_resolution = {
    strategy,
    winning_rule_id: winningRule ? winningRule.rule_id : null,
    losing_rule_ids: losing.sort(),
    same_priority_contradictions: contradictions,
  };

  // 13) Approval step for REQUIRE_APPROVAL.
  if (abstract === "REQUIRE_APPROVAL") {
    const requirement = {
      requiredSubject: winningRule?.effect?.required_approval_subject ?? null,
      requiredScope: winningRule?.effect?.required_approval_scope ?? null,
    };
    const { binding, reason: approvalReason, verified } =
      verifyApproval(approvals, envelope, bundle, ctx, requirement);
    return make({
      abstract: "REQUIRE_APPROVAL", permit: verified,
      reason: verified ? "approval_satisfied" : approvalReason,
      wire: toWire("REQUIRE_APPROVAL"), rules_evaluated, default_applied,
      conflict_resolution, approval_required: true, approval_binding: binding,
    });
  }

  // 14) Non-approval outcomes. Permit only for ALLOW (basePermit).
  const logObligation = abstract === "ALLOW" && winningRule?.effect?.log_obligation === true;
  const permit = basePermit(abstract);
  return make({
    abstract, permit, reason, wire: toWire(abstract, { logObligation }),
    rules_evaluated, default_applied, conflict_resolution,
  });
}

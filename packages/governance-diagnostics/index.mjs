// v0.6 governance diagnostics: AutoMap (discover/propose only), the
// Governability Governor (diagnose only), and latency instrumentation
// (observe only). Nothing exported from this package can activate a mapping,
// block or alter a tool call, change a policy decision, grant authority,
// modify credentials or connector state, or contact any external network
// service or model. The separate `openclaw-live-observer` package may issue
// only its two hard-coded operator.read calls to an explicitly supplied local
// OpenClaw runtime and may read the existing local connector receipt ledger.
// The v0.5 runtime never imports this package.

export * from "./vocabulary.mjs";
export * from "./sensitive-values.mjs";
export * from "./typed-values.mjs";
export * from "./schema-validate.mjs";
export * from "./contracts.mjs";
export * from "./automap/input-safety.mjs";
export * from "./automap/fingerprint.mjs";
export * from "./automap/classification.mjs";
export * from "./automap/discovery.mjs";
export * from "./automap/pinned-content.mjs";
export * from "./automap/candidate-validate.mjs";
export * from "./automap/confirmation.mjs";
export * from "./automap/live-confirmation.mjs";
export * from "./automap/approval.mjs";
export * from "./automap/drift.mjs";
export * from "./governor/diagnose-evidence.mjs";
export * from "./governor/render.mjs";
export * from "./latency/recorder.mjs";
export * from "./latency/summary.mjs";
export * from "./coverage.mjs";
export * from "./registry.mjs";

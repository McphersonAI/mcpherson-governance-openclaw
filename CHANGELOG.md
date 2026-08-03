# Changelog

All notable changes to the public McPherson Governance OpenClaw connector.

This project adheres to semantic versioning for its public package identity.
The plugin ID (`mcpherson-governance-connector`), package name
(`@mcphersonai/mcpherson-governance-openclaw`), configuration schema, and the
`mcpherson-connector-ctl` command name are stable across 0.5.x and 0.6.0.

---

## [0.6.0] — Account-free V6 local diagnostics

The connector now ships with the **V6 local diagnostics CLI**: account-free
local agent and tool discovery, non-authoritative AutoMap proposals, a
Governability Diagnosis, and private JSON and Markdown reports.

**No change to the shadow-only contract.** `AUTHORITY` remains `NONE`,
`ENFORCEMENT` remains `OFF`, `remote_authority` remains `false`,
`ENFORCEABLE_REMOTE_DECISIONS` remains an empty frozen array, `RECEIPT_MODE`
remains `POST_HOOK`, automatic mapping activation remains off, outbound actions
and registry mutation remain off, and remote decisions remain `SHADOW_ONLY`.
No policy evaluator and no gate were added. Nothing here can block, approve,
deny, delay, or rewrite a tool call.

### Added — V6 local diagnostics

- **Account-free local workflow.** No McPherson account, email verification,
  MFA, organization, workspace, installation pairing, McPherson API key,
  billing, credits, dashboard login, or hosted SaaS availability is required.
- **`scripts/governance-diagnostics.mjs`**, the local diagnostics CLI. The
  documented sequence is `init-profile-binding`, `verify-profile-binding`,
  `observe-live`, `verify-observation`, `discover`, `propose`, `govern`,
  `render-diagnosis`. Supporting commands include
  `preview`, `confirm-classification`,
  `generate-classification-confirmation`, `export-registry-patch`,
  `validate-registry-patch`, `preview-registry-patch`, `shadow-lookup`,
  `drift`, `latency-summarize`, and `coverage`. There is deliberately no
  `apply-registry-patch`.
- **Bounded local observer.** Reads only `agents.list`, `tools.catalog`, and the
  local receipt ledger. Excludes chat content, tool arguments and results,
  session identifiers, request hashes, correlation references, deployment
  identifiers, credentials, runtime paths, and receipt bodies.
- **Private outputs.** Observation directory `0700`, artifacts `0600`, existing
  paths never overwritten.
- **AutoMap proposals** with status `PROPOSED`. They cannot activate themselves,
  and this package has no registry-mutation path.
- **Package manifest binding.** `V6-PACKAGE-MANIFEST.json` binds the observer
  modules by content hash and carries the portable audited OpenClaw target.
- **Strict local profile binding.** A local `0600` manifest, valid for at most
  24 hours, binds the package/source identity and exact explicitly selected
  DEFAULT or NAMED profile, physical home, state, config, and runtime paths.
  It also pins the exact profile-local connector state and receipt-ledger
  paths, and its one canonical byte serialization is enforced on every read.
  Its independently captured `binding_id` is required by every consumer, so a
  rehashed edit still fails closed. NAMED never falls back to DEFAULT, and
  inherited environment variables cannot redirect an approved binding.
- **`PACKAGE-FILES.sha256` and `RELEASE-PROVENANCE.json`** for exact inventory,
  per-file checksums, and build provenance.

### Changed — corrected description of unconfigured tools

Previous public documentation said unmapped tools normally produce remote
registry `404` observations. **That description is withdrawn.** It did not
describe actual behavior.

An unconfigured tool now demonstrably:

- remains local;
- makes **no HTTPS request**;
- records `remote_status: NOT_ATTEMPTED`;
- records `local_disposition: SKIPPED`;
- has **unchanged** execution;
- contributes **no fallback metadata** to the wire or the receipt ledger.

The accurate limitation is retained: a **configured** connected-shadow identity
may still receive a remote `404` when the service cannot resolve the deployment,
agent, tool, or contract. That is a remote contract or registry failure, not an
execution decision, and it cannot block the original tool in V6.

Corrected in `README.md`, `INSTALL.md`, `LIMITATIONS.md`, `SECURITY.md`,
`SUPPORT.md`, and `examples/README.md`.

### Changed — package layout

Packaged files now sit at their exact source-repository-relative paths, so the
connector is at `plugins/openclaw-connector/` rather than `connector/`. This is
required by the V6 runtime's own module and schema resolution and makes the
package a faithful, auditable subset of the source tree.

`main`, `exports`, `bin`, and `openclaw.extensions` were updated accordingly.
**The plugin ID, package name, configuration schema, config storage key, state
directory name, and `mcpherson-connector-ctl` command name are unchanged**, so
existing configuration and state carry over.

### Changed — receipt-ledger version transition is now documented

The observer pins connector lifecycle records to one exact version and validates
every ledger line with no window filter, so a mixed-version ledger fails closed
with `live_receipt_contract_invalid`. The exact rotation procedure — including
the trap that the outgoing connector writes one final `gateway_stop` at the old
version *after* a premature rotation — is documented in `INSTALL.md` §6 and
`LIFECYCLE.md`.

### Changed — runtime `child_process` disclosure

In 0.5.1, `child_process` appeared only in release-engineering scripts and no
runtime module imported it. In 0.6.0 the V6 observer executes the package-bound
OpenClaw runtime for two `operator.read` RPCs and a `--version` probe, under a
fixed safe `PATH` and bounded sanitized environment. It runs only when the
operator invokes the diagnostics CLI — never during activation, never in a hook,
and never as a result of a remote response. The connector runtime compatibility
gate still executes no subprocess.

### Changed — requirements

- **Node.js 22 or newer** (was 20), required by the V6 diagnostics runtime.
- OpenClaw minimum remains **2026.6.5**, still enforced by the connector itself
  at activation via the source-owned `MIN_SUPPORTED_OPENCLAW_VERSION`.

### Removed

- No founder-host paths, internal evidence artifacts, internal programme names,
  audit reports, or private absolute paths are present in the published package.

---

## [0.5.1] — Public install-contract patch

A narrow patch release correcting the public installation and lifecycle
documentation to the actual ClawHub install path, isolating connector state per
OpenClaw profile, enforcing the declared OpenClaw compatibility floor at
runtime, and making the connector's disabled behavior match the documentation.

No change to the shadow-only contract; package name and plugin identity
unchanged.

---

## [0.5.0] — Initial public release

First public release of the shadow-only OpenClaw connector: metadata-minimized
governance observations for configured tools, local attempt and completion
receipts, and no authority over tool execution.

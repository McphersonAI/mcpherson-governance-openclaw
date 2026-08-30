# Changelog

## 0.6.3-beta.6

- Fixes partial live-capture suppression caused by benign duplicate/alias OpenClaw lifecycle dispatch: a supported exact openclaw<tool> + <tool> alias pair canonicalizes to ONE logical observation, and an exact duplicate lifecycle dispatch is treated idempotently.
- Preserves fail-closed behavior for genuine runtime identity ambiguity and adds durable BLOCKED_LOCAL refusal receipts plus AMBIGUOUS_FAIL_CLOSED diagnostics so refusals are never silent.
- Preserves the completion classifier fix for real OpenClaw success events.
- Beta candidate only: adds a profile-bound, metadata-only fresh-pair observation bootstrap for actual supported OpenClaw tool hooks.
- Keeps discovered tools OBSERVED / UNMAPPED; it does not infer semantic toolMetadata, approve or activate mappings, or create execution authority.
- Synchronizes package, plugin, runtime receipt, observer, manifest, and archive identity.
- Preserves SHADOW_ONLY, authority NONE, enforcement OFF, and proposal-only AutoMap.

All notable changes to the public McPherson Governance OpenClaw connector.

This project adheres to semantic versioning for its public package identity.
The plugin ID (`mcpherson-governance-connector`), package name
(`@mcphersonai/mcpherson-governance-openclaw`), configuration schema, and the
`mcpherson-connector-ctl` command name are stable across 0.5.x, 0.6.0, 0.6.1,
and 0.6.2.

---

## [0.6.2] — Release provenance, recursive redaction, and compatibility

A provenance, hardening, and documentation patch. **No runtime governance
behavior changed.** `AUTHORITY` remains `NONE`, `ENFORCEMENT` remains `OFF`,
automatic mapping activation remains off, outbound actions and registry
mutation remain off, and remote decisions remain `SHADOW_ONLY`. No policy
evaluator and no gate were added. No governance decision, AutoMap semantic,
governability diagnosis, or enforcement behavior changed.

### Public release provenance — corrected

Through 0.6.1 the public artifact described the private build that produced
it, in two ways that no downloader could check:

- `RELEASE-PROVENANCE.json` named the **private candidate commit** as the
  public `source_commit`. That commit does not exist in the public repository.
- `V6-PACKAGE-MANIFEST.json` recorded **seventeen source files** under private
  `release/openclaw-public/…` paths that do not resolve inside the package.

Both are corrected. `RELEASE-PROVENANCE.json` moves to schema `…/v2` and binds
to the public release source:

- `source_commit` / `source_tree` are the **public base commit and tree**,
  explicitly labelled `PUBLIC_BASE_COMMIT` and `PUBLIC_BASE_TREE` so neither
  can be misread as a self-reference;
- the three bindings an artifact cannot make about itself — the release
  commit, the release tree, and the archive SHA-256 — are declared under
  `external_bindings`, each with the exact command that resolves it and the
  reason it cannot be stated inline;
- `release_ordering` records the order the three manifests must be written in.

No future commit is hardcoded and no self-referential commit claim is made.
The source inventory now names public package paths only.

`scripts/build-release-manifests.mjs` replaces the manual private step that
produced the defect, and `--check` re-derives all three manifests and fails on
any drift. Because the archive is now built by `npm pack` from the tagged
public tree, **the release is reproducible outside McPherson AI** — see
[VERIFY.md](./VERIFY.md) §6.

### Recursive secret redaction

New `packages/governance-diagnostics/redaction.mjs` removes credential
material from every nested object and array before it reaches an output
boundary. Two independent layers: normalized key matching (case, hyphen, and
underscore variants of token, access/refresh/device token, authorization,
bearer, API key, secret, password, credential, cookie, session, private key,
TOTP seed, recovery code, and state key), and value-shape scrubbing that
catches a credential pasted under a harmless key.

Wired into the live observer's single artifact-serialization choke point and
every diagnostics CLI output path, each followed by a final-output scan that
fails closed. On well-formed artifacts redaction is a no-op, so v0.6.1 output
bytes are unchanged.

Evidence usability is preserved deliberately: booleans, `null`, and
`undefined` are never redacted, only whole or trailing credential key names
match, and value scrubbing replaces just the matched credential rather than
the surrounding text. `authority`, `credential_id`, `credential_material`,
`token_shape`, `private_key_shape`, and `session_identifiers` all keep their
values. Recursion is depth-limited and cycle-safe.

18 regression tests cover nested objects, arrays of objects, mixed casing,
hyphenated and underscored keys, nested device-token transcript shapes,
authorization headers, cookies and sessions, null and primitive values,
harmless similarly named fields, depth limits, and final-output scanning.

### Compatibility and migration

New [COMPATIBILITY.md](./COMPATIBILITY.md) states each target's exact support:

- **`2026.6.33` (`7af0cfc`)** — preferred target; fully lifecycle-proven.
- **`2026.6.5` (`5181e4f`)** — fully lifecycle-proven.
- **`2026.7.1-2` (`0790d9f`)** — exact-target binding validated; install and
  uninstall validated; **live observation unsupported**, because the upstream
  local CLI does not issue the device-bound `operator.read` token the observer
  requires.

It also documents the v0.5.1 → v0.6.2 migration end to end: stop v0.5.1 before
rotating the ledger, archive the historical ledger, create a fresh owner-only
v0.6.x ledger, verify the profile binding and the device-bound
`operator.read` token, run the lifecycle and restart proof, and never mix
historical and fresh version records.

### Other

- The packaged verifier now asserts **all six** fixed safety values against an
  independently declared expectation, rather than two of them.
- Version declarations are synchronized to 0.6.2 across `package.json`,
  `openclaw.plugin.json`, the connector package, `PLUGIN_VERSION`,
  `LIVE_LIFECYCLE_PLUGIN_VERSION`, both release manifests, and the
  documentation set. Historical references to 0.6.0 and 0.6.1 are preserved.
- The packaged test that pinned `plugin_version` to a literal now derives it,
  so it cannot silently go stale on a future release.

Zero runtime dependencies. The lifecycle version pin moves from `0.6.1` to
`0.6.2`, so a v0.6.1 receipt ledger requires the documented rotation — see
[INSTALL.md](./INSTALL.md) §6.

---

## [0.6.1] — Manifest, schema, and disclosure corrections

A metadata, documentation, and disclosure patch. **No runtime behavior
changed.** `AUTHORITY` remains `NONE`, `ENFORCEMENT` remains `OFF`,
automatic mapping activation remains off, outbound actions and registry
mutation remain off, and remote decisions remain `SHADOW_ONLY`. No policy
evaluator and no gate were added. No feature was added.

### Fixed

- **`openclaw.plugin.json` no longer declares package-style fields.**
  `license`, `homepage`, and `repository` were top-level manifest keys that
  the OpenClaw `PluginManifest` type does not define, which the ClawHub
  plugin inspector reports as `manifest-unknown-fields` (P2). They were
  verified as unsupported against the OpenClaw `2026.6.5`, `2026.7.1`, and
  `2026.7.2-beta.7` manifest type surfaces, then removed from the plugin
  manifest. The same values remain in `package.json`, which is where npm and
  ClawHub read them. `id`, `name`, `description`, `version`, `activation`,
  `contracts`, and `configSchema` are each confirmed supported and unchanged,
  so plugin ID, tool registration, and the config schema are preserved.

- **Live observation manifest schema now states its path policy exactly.**
  `mcpherson-governance-live-observation-manifest-v1` described runtime and
  receipt paths as excluded while also requiring a fixed `runtime_identity`
  value, which reads as a contradiction. The schema now states that absolute
  host-specific runtime paths and all receipt paths are excluded, and that
  `runtime_identity` is a fixed portable *relative* identity declared by the
  contract and retained solely to bind an observation to the audited OpenClaw
  target. `runtime_identity` and the `runtime_paths` exclusion each gained a
  direct description. The constant value, every other constant, the required
  field set, and `additionalProperties: false` closure are unchanged, so all
  existing target-binding guarantees hold.

### Documented

- **`child_process.spawnSync` is now disclosed in [SECURITY.md](./SECURITY.md).**
  Static scanners flag the single call in the live observer. It is necessary,
  local, and bounded, so it was documented rather than removed: the executable
  is digest-pinned to the audited runtime, argv is code-built with an
  allowlisted RPC method, `shell: false`, the environment is a frozen
  allowlist, and timeout, `cwd`, and output ceilings are explicit. Removing it
  would have broken live observation for a cosmetic scanner result.

### Added

- **OpenClaw `2026.6.33` extended-stable is an approved live-observation
  target.** The published extended-stable build was pinned to its exact
  identity — full commit `7af0cfc9c5488e03c4e2f528bdc7ac9f7778b35e`, plus the
  SHA-256 of its runtime entrypoint, `package.json`, and
  `dist/build-info.json` — and the complete live lifecycle was run against
  that exact build: device-bound `operator.read` bootstrap, `observe-live`,
  `verify-observation`, `discover`, `propose`, `govern`, and
  `render-diagnosis`, followed by disable, uninstall, and cleanup.
  `2026.6.33` is now the **preferred** baseline for live observation.

  It is a `2026.6` maintenance build produced *after* the `2026.7` line, so
  nothing about it was assumed from `2026.6.5`; its host shape was
  re-reviewed independently. It does not carry the `2026.7`
  `isLocalCliSharedAuth` change, so a local CLI on a loopback Gateway still
  pairs a device identity and still receives an `operator.read` device token.

  Approval is bound to the five exact identity fields, **not** to the
  `extended-stable` dist-tag. That tag is a moving pointer; a build upstream
  later points it at is not covered by this release.

### Compatibility

- `openclaw.compat.pluginApi` remains `>=2026.6.5`. The connector's own
  runtime floor is unchanged and admits the entire `2026.7.x` line. The floor
  was deliberately not raised: `2026.6.5` remains fully supported and
  lifecycle-proven.
- `openclaw.build` now records `openclawVersion 2026.6.33` /
  `openclawCommit 7af0cfc`. That block names the single preferred audited
  build, not the whole approved set.
- The approved target set is now three exact builds: `2026.6.5` (`5181e4f`)
  and `2026.6.33` (`7af0cfc`), both live-lifecycle proven, and `2026.7.1-2`
  (`0790d9f`), which remains target-bound and installable but is **not**
  live-observation supported — OpenClaw does not issue the required
  device-bound operator token there, and the shared Gateway token is still
  refused as a substitute.

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

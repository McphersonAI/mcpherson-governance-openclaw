# Changelog

All notable changes to the McPherson Governance Connector for OpenClaw.

This project uses [Semantic Versioning](https://semver.org/).

## [0.5.1] — Public install-contract patch

A narrow patch release. It corrects the public installation and lifecycle
documentation, isolates connector state per OpenClaw profile, enforces the
declared OpenClaw compatibility floor at runtime, and makes the connector's
disabled behavior match what the documentation claims.

**No change to the shadow-only contract.** `remote_shadow` remains `true`,
`remote_authority` remains `false`, `ENFORCEABLE_REMOTE_DECISIONS` remains
empty, `RECEIPT_MODE` remains `POST_HOOK`, receipts remain metadata-minimized,
the privacy boundary is unchanged, remote failures remain non-blocking, and no
code path acquires enforcement authority. The package name and plugin identity
are unchanged.

### Fixed — public installation and lifecycle documentation

- `INSTALL.md`, `VERIFY.md`, `LIFECYCLE.md`, and `README.md` now describe the
  **actual ClawHub installation path** with the exact commands: `clawhub package
  download`, `clawhub package verify`, then `openclaw plugins install` of the
  verified `mcphersonai-mcpherson-governance-openclaw-0.5.1.tgz`. The previous
  text described a GitHub release tarball
  (`mcpherson-governance-openclaw-v0.5.0.tar.gz`), an extract step, and
  installation of the `connector/` subdirectory — none of which describes what
  ClawHub publishes or how OpenClaw installs it.
- Documented commands for the complete lifecycle a user can actually run:
  install, verify the installed version (`plugins info`), configure
  (`config set plugins.entries.mcpherson-governance-connector.config`), enable,
  check status, disable (`plugins disable`), uninstall
  (`plugins uninstall --dry-run` then `--force`), and verify removal.
- **`connector-ctl` is no longer presented as a `PATH` command.** A ClawHub
  download followed by an OpenClaw archive install copies files into the profile
  and creates no command links, so neither `connector-ctl` nor
  `mcpherson-connector-ctl` was ever on `PATH` for a normal public install. The
  documented public workflow now uses OpenClaw's own commands, and where the
  connector's local control surface is needed (kill switch, system lock, canary,
  unpair, status) it is invoked by explicit path with `OPENCLAW_STATE_DIR` naming
  the profile. The `bin` declarations are retained for consumers who install the
  package with a package manager that does create links.
- Documented the two install-time warnings a normal install produces (manifest
  id vs npm package name; empty `plugins.allow`) and the static-scanner note
  about `child_process` in the shipped release-engineering scripts.

### Fixed — named-profile state isolation

- The connector's default state root previously resolved to
  `~/.openclaw/mcpherson-governance-connector` from the user's home directory,
  **independently of the active OpenClaw profile**. A named profile therefore
  wrote connector state, receipts, controls, and the credential into the default
  profile's location.
- State now resolves inside the **active** profile, in this order: the host's own
  `runtime.state.resolveStateDir`, then `OPENCLAW_STATE_DIR`, then the default
  profile root. Explicit `stateDir`/`receiptDir` configuration and the
  `MCP_GOVERNANCE_STATE_DIR`/`MCP_GOVERNANCE_RECEIPT_DIR` path overrides continue
  to win over all of them.
- A named profile never writes into the default profile, two profiles never share
  connector state, and uninstalling or purging one profile does not touch
  another's. **No automatic legacy-state migration occurs** — a pre-existing
  default-profile state directory is neither read, copied, moved, nor modified.

### Added — OpenClaw compatibility activation gate

- The connector now enforces its declared minimum of OpenClaw **`2026.6.5`** at
  runtime. Package-manager compatibility metadata is not relied upon: OpenClaw
  `2026.3.2` installed and loaded the v0.5.0 package without enforcing or warning
  about the declared `>=2026.6.5` requirement.
- On a host below the minimum the connector **refuses activation**: it logs a
  clear compatibility error, sends no governance request, writes no receipt,
  starts no shadow observation, creates no state or receipt directory, and
  constructs no client, pipeline, or receipt writer. Hook entrypoints are still
  registered so the host's plugin contract is undisturbed, and every handler
  returns immediately — unrelated OpenClaw execution is preserved and nothing
  blocks.
- The version source is the OpenClaw plugin SDK's `runtime.version`. When the
  host declares a version it could not itself resolve — OpenClaw's own fallback
  for that case is the literal string `"unknown"` — the gate falls back to a
  bounded, read-only lookup of the host's installed `package.json`. **No
  subprocess is executed.** A host that declares a version neither source can
  determine is refused rather than assumed supported.

### Changed — disabled behavior and wording now agree

- OpenClaw records the plugin entry as `enabled: true` and registers hook
  entrypoints when it loads the plugin. That is accepted and now documented
  plainly, instead of the previous unqualified "installs disabled".
- **Operationally disabled now means inert.** Previously the pre-call hook still
  derived a tool summary and wrote an `attempt_receipt` with
  `remote_status: NOT_ATTEMPTED`, the post-call hook still wrote a
  `completion_receipt`. A disabled connector therefore produced observation
  receipts. Now, while disabled: both tool-observation hook handlers return
  immediately, no governance request is sent, no ordinary observation receipt is
  written, and no shadow observation is admitted. The guarantee is enforced in
  the observation pipeline as well as the hook, so it holds for every caller,
  including an observation already in flight when the operator disables.
- **Gateway lifecycle records are deliberately unchanged.** `gateway_start` and
  `gateway_stop` still write a `connector_lifecycle` record. That is a separate
  schema recording that the connector was loaded — it is not an ordinary
  observation receipt, it carries no tool, agent, or decision metadata, and
  suppressing it would remove truthful evidence rather than add privacy.
- Explicit enablement activates shadow observation; disabling returns the
  connector to inert behavior immediately, including for a call whose pre-hook
  already ran.
- **Kill switch and system lock are unchanged.** They stop remote contact before
  any network I/O while local receipts continue, exactly as documented.
- The loaded runtime description no longer reads "Private v0.5.0"; the plugin now
  reports its version to OpenClaw, so `plugins info` shows `"version": "0.5.1"`.

### Fixed — documentation accuracy and profile-safe example

- **`LIMITATIONS.md` §9 reported the wrong test accounting.** It carried v0.5.0
  wording claiming 180 applicable upstream tests pass with one exclusion. The
  correct v0.5.1 figures are 179 applicable upstream tests passing with **two**
  exact-name exclusions, inside a complete suite of 250 passed / 0 failed /
  0 skipped. §9 now states the full breakdown, names both excluded tests, says
  why each original assertion no longer applies, records that each is replaced
  by stricter coverage, and states that exclusion is by exact anchored test name
  with no broad pattern.
- **The compatibility gate's `UNKNOWN` case is now publicly documented**
  (`LIMITATIONS.md` §9a, with pointers from `README.md` and `INSTALL.md`). A
  host reporting a version below the floor, or a version that cannot be parsed,
  refuses activation. An environment exposing **no** detectable OpenClaw version
  is reported as `UNKNOWN` and may activate. `UNKNOWN` does not mean verified
  compatible and is not a supported configuration; shadow-only and non-blocking
  guarantees apply in every case. Operators should run OpenClaw `2026.6.5` or
  newer.
- **`examples/connector-config.example.json` no longer hardcodes `stateDir` and
  `receiptDir`.** Copied literally, the previous example pinned state outside
  the active profile and defeated the profile-isolation fix above. The example
  now omits both keys so state resolves inside the active profile. They remain
  supported and are documented separately in `examples/README.md`, together with
  the caveat that setting them opts out of profile-based isolation.

### Packaging

- Version `0.5.1` in `package.json`, `connector/package.json`,
  `openclaw.plugin.json`, and `PLUGIN_VERSION`.
- Release-artifact ordering: `scripts/build-release-artifacts.mjs` packages the
  committed `HEAD`, so the release archive must be generated **after** the
  v0.5.1 commit exists. Its `EVIDENCE_ROOT` is now verified against
  `package.json` by `scripts/verify-package.mjs` so the two cannot drift.
- One new connector module, `connector/host.mjs` (profile state resolution and
  the compatibility gate). The connector tree is now 29 files, 24 of them `.mjs`.
- `SEALED-CONNECTOR-FILES.sha256` continues to record the sealed **v0.5.0**
  reference. `npm test` now verifies that the difference from it is exactly the
  enumerated v0.5.1 set — one added file, five changed runtime modules, two
  changed metadata files, one updated `connector/README.md`, and 20 sealed files
  carried over byte-identical.
- The embedded governance core is unchanged and still verifies against its
  recorded `SOURCE.sha256`.

## [0.5.0] — Initial public release

Initial public release of the connector, licensed under **Apache-2.0**
(copyright 2026 McPherson AI LLC). Independent verification records are
maintained outside the distributed package.

The sealed connector inventory contains 28 files. The public connector matches
27/28; the sole intentional difference is `connector/package.json`. All 23
`.mjs` runtime files remain byte-identical. The package-metadata difference
enables public distribution and does not change runtime logic (see below and
[LIMITATIONS.md](LIMITATIONS.md) §10).

### Added

- Shadow-only OpenClaw connector plugin (`mcpherson-governance-connector`),
  registering on the supported plugin surface via `before_tool_call`,
  `after_tool_call`, `gateway_start`, and `gateway_stop`.
- Observation of configured OpenClaw tool activity with metadata-minimized
  governance requests over outbound TLS.
- Local append-only, owner-only (`0600`) receipts: `attempt_receipt` pre-call
  and `completion_receipt` after a directly observed completion
  (`POST_HOOK` receipt mode).
- Closed outbound metadata allowlist enforced over serialized payload bytes,
  with value-shape rejection (URLs, bearer tokens, PEM private keys, key/password
  assignments, SSN-shaped values) and an 8 KB cap.
- Operator control surface via `connector-ctl`: `status`, `enable`, `disable`,
  `killswitch`, `lock`, `canary`, `rotate`, `recover`, `unpair`, `uninstall`.
- Local control precedence `DISABLED > KILL_SWITCH > SYSTEM_LOCK > CANARY >
  REMOTE_OBSERVATION`, evaluated before credential read and before any network
  I/O.
- Credential handling restricted to a `0600` file in a `0700` state directory,
  with restart-safe rotation, recovery, and idempotent server-confirmed unpair.
- Bounded observation: 150 ms default foreground budget, 2 s connect timeout,
  max 4 in-flight, max 16 queued, 1 retry, circuit break after 5 failures.
- Bounded shutdown with honest residue reporting (`CLEAN`,
  `CLEAN_AFTER_DEADLINE`, `NON_CLEAN_DEADLINE`).
- Embedded governance-core subset (canonicalization, classification, contracts,
  errors, policy validation) with recorded source hashes in `SOURCE.sha256`.
- Public documentation: README, PRIVACY, LIMITATIONS, SECURITY, SUPPORT,
  INSTALL, VERIFY, LIFECYCLE, placeholder-only configuration example, and
  checksum manifests.

### Deliberately not included

- **Enforcement.** `REMOTE_AUTHORITY = false` and
  `ENFORCEABLE_REMOTE_DECISIONS = []` are compiled into source and are not
  operator-configurable. Remote decisions have no execution authority.
- The policy evaluator (`evaluate.mjs`) and gate (`gate.mjs`) modules are **not
  shipped** in the embedded governance core.
- Internal deployment tooling, operations runbooks, gate evidence, receipt
  ledgers, runtime state, and production logs.

### Known limitations

Shadow-only; manual capability mapping required; unmapped tools produce registry
404 observations that do not block execution; receipt truth bounded by
OpenClaw's hook surface; observations dropped under configured bounds, so this
is not a complete audit log; no compliance certification. Full list:
[LIMITATIONS.md](LIMITATIONS.md).

### Packaging

- Licensed under Apache-2.0; `LICENSE` and `NOTICE` added. A provenance review
  of all 28 connector files found no third-party or vendored code and no
  dependencies of any kind, so no third-party notices are required.
- Published as `@mcphersonai/mcpherson-governance-openclaw`, with a root
  distribution manifest carrying the scoped name, license, repository, issues,
  homepage, OpenClaw extension entry, and compatibility metadata.
- `connector/package.json` metadata normalized for public distribution:
  `"private": true` removed, license and repository metadata added, the broken
  test-script path replaced with the self-contained
  `scripts/verify-package.mjs`, and the `bin` path corrected. No runtime source
  was touched.
- Compatibility values are carried over unchanged from the sealed connector:
  plugin API `>=2026.6.5`, built against OpenClaw `2026.6.5` (`5181e4f`).

[0.5.0]: https://semver.org/

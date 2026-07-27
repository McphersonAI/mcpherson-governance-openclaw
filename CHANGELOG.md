# Changelog

All notable changes to the McPherson Governance Connector for OpenClaw.

This project uses [Semantic Versioning](https://semver.org/).

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

# Limitations

**Connector v0.5.1.** Read this before relying on the connector for anything.

## 1. It is shadow-only. It does not enforce.

This release observes and records. It does not block, deny, approve, delay, or
modify any tool call. If you need blocking or approval gating today, **this
release is not that product**, and no configuration setting will make it one.

Remote decisions have **no execution authority**. A governance response of
`DENY`, `REQUIRE_APPROVAL`, or `HOLD` is written into a local receipt and
changes nothing about execution. `ENFORCEABLE_REMOTE_DECISIONS` is empty and
compiled into source.

## 2. There is exactly one local blocking path, and it is not enforcement

The connector's own diagnostic tool `mcpherson_governance_canary` can be blocked
locally when the operator explicitly turns the canary on and the call carries an
exact literal token. It exists to let an operator prove local authority is
retained. It never inspects or blocks any other tool and never reads remote
data. With the canary off — the default — nothing in this release blocks
execution.

## 3. Manual capability mapping is required

The connector cannot describe a tool it has no mapping for. Every tool you want
meaningfully observed needs a `toolMetadata` entry (schema version, schema hash,
action class). This is manual work and it does not happen automatically.

## 4. Unmapped tools produce registry 404 observations

A tool with no mapping — or a deployment/agent the governance registry does not
know — produces a `404`-class observation (`MGP_UNKNOWN_TOOL`,
`MGP_UNKNOWN_AGENT`, `MGP_UNKNOWN_DEPLOYMENT`).

**These observations do not block the original tool.** The tool runs normally.
The 404 is recorded in the receipt as the remote status. Expect a lot of them
until mapping is complete; they are an inventory signal, not an error condition
in your agent.

## 5. Receipt truth is bounded by OpenClaw's hook surface

Receipt mode is `POST_HOOK`. A `completion_receipt` is emitted only after a
directly observed `after_tool_call`. Where OpenClaw does not deliver that event,
you get an `attempt_receipt` saying `UNKNOWN` or `NOT_OBSERVED` — the connector
**does not guess** outcomes. Timeouts, queue drops, shutdown, and missing events
never become tool outcomes.

Consequence: attempt and completion counts will not always match, and that is
correct behavior rather than a defect.

## 6. Observation is bounded and lossy by design

To avoid becoming a latency tax on your agents, the connector caps its own work:

| Bound | Default |
| --- | --- |
| Foreground observation budget | 150 ms (max 500) |
| Connect timeout | 2000 ms |
| Max in-flight observations | 4 |
| Max queued observations | 16 |
| Network retries | 1 |
| Circuit opens after | 5 consecutive failures (60 s) |

When these limits are hit, observations are **dropped**. Dropped observations
are recorded as such locally. **The connector is not a complete audit log** and
must not be relied on as one.

## 7. Classification labels can be wrong

`action_class`, `resource_class`, sensitivity, and reversibility labels come
from your manual mapping and local derivation. They can misclassify. In a
shadow release the consequence is a mislabeled observation — never a wrong
enforcement action.

## 8. Not a certification

This release is **not a safety, security, or compliance certification**. No
regulatory certification is claimed or implied. Independent verification
records are maintained outside the distributed package and do not constitute a
certification or guarantee.

## 9. Scope of testing

The complete v0.5.1 public release suite reports **250 passed, 0 failed, 0
skipped**. Those 250 are not all upstream tests. They are three distinct
groups:

| Group | Count | Shipped in this package |
| --- | ---: | --- |
| Applicable upstream (sealed-reference) connector tests | 179 | No — see §10a |
| Public distribution, runtime, and v0.5.1 regression tests | 51 | Yes |
| Bundled package verification checks | 20 | Yes |
| **Total** | **250** | — |

Only the second and third groups ship in this package; together they are the
71 checks an external auditor can reproduce without the internal build
repository (`npm test`).

The sealed reference suite contains **181** connector tests. **179** are
applicable to v0.5.1 and pass against the public connector. **Two** are
excluded, each by exact test name, because each encodes a v0.5.0 contract that
v0.5.1 deliberately supersedes:

1. `"package is private v0.5.0 and declares only inspected supported hooks at
   runtime"` asserts `package.json.private === true` and version `0.5.0`. The
   private flag is npm's refuse-to-publish flag: correct for the internal
   installer, and deliberately invalid for a public package.
2. `"disabled/kill/lock precedence beats exact canary with a zero-network
   call-order trace"` asserts that an operationally **disabled** connector still
   derives a tool summary and writes a `NOT_ATTEMPTED` attempt receipt. v0.5.1
   deliberately changed that: disabled is now inert and writes no observation
   receipt at all.

Each is replaced by **stricter** public coverage, not dropped. The first is
replaced by `tests/public-distribution.test.mjs`. The second is replaced by
`tests/public-v051-regression.test.mjs`, which runs **all five** of the original
test's scenarios — the three kill-switch/system-lock scenarios keep their
original receipt expectations, and the two disabled scenarios assert the tighter
v0.5.1 contract (no receipt at all, and the tool summary is never derived).

**No broad exclusion pattern is used.** Exclusion is by exact, fully anchored
test name — never by filename, prefix, or wildcard — so every other test in
those two files continues to run, including the 20 safety tests in
`operator-structure.test.mjs`. Running the upstream suite with the exclusions
removed produces exactly two failures, and they are exactly these two tests.
§10a records the full rationale.

Coverage includes hostile-endpoint behavior, privacy-guard assertions over
serialized wire bytes, scheduler saturation, shutdown residue accounting,
named-profile state isolation, the OpenClaw compatibility gate, and
disabled-mode inertness.

Long-run production soak evidence and platforms other than those tested are not
covered by the distributed package. Built and tested against OpenClaw
`2026.6.5` (`5181e4f`), minimum supported OpenClaw `2026.6.5`, on Node 24. **No
end-to-end install on a real OpenClaw `2026.6.5` or newer host has been
performed for this release** — see §9a and §12.

## 9a. OpenClaw version detection, and what UNKNOWN means

**The minimum supported OpenClaw version is `2026.6.5`.** The connector enforces
this itself at activation time rather than relying on package-manager
compatibility metadata, which is not enforced by every installer — OpenClaw
`2026.3.2` installed and loaded the v0.5.0 package without warning.

The gate reads the version the host reports through the OpenClaw plugin SDK. If
the host reports a version it could not itself resolve, the connector makes one
bounded, read-only attempt to read the host's own installed `package.json`. It
runs no subprocess and opens no socket. There are three outcomes:

| What the host reports | Compatibility status | Connector activates |
| --- | --- | --- |
| A version `2026.6.5` or newer | `SUPPORTED` | Yes |
| A version below `2026.6.5` | `UNSUPPORTED` | **No** |
| A version that is supplied but not parseable, and no readable host manifest | `UNSUPPORTED` | **No** |
| **No detectable version at all** — the host exposes no version field | `UNKNOWN` | **Yes** |

The first three rows are the enforcement you should rely on. A known-unsupported
host, and a host that explicitly supplies a version nobody can parse, both
refuse activation: the connector logs a compatibility error and stays inert —
no governance requests, no observation receipts, no shadow observation — while
OpenClaw and your other plugins continue to run normally.

**The fourth row is the honest carve-out, and you should read it carefully.**

An environment that exposes **no** identifiable OpenClaw version is reported as
`UNKNOWN` and is allowed to activate. This covers non-OpenClaw embedders and
test harnesses that load the plugin module directly without implementing the
SDK's version field. The gate refuses only what it can positively identify as
unsupported; it does not invent a refusal for a host that never made a version
claim at all.

The consequence, stated plainly:

- **`UNKNOWN` does not mean verified compatible.** It means no version was
  detectable. Nothing about that environment has been checked against the
  `2026.6.5` floor.
- **An unsupported host that exposes no version is therefore not refused.** The
  floor is enforced against hosts that declare a version, not against hosts that
  are silent.
- **`UNKNOWN` hosts are not officially supported**, are not covered by the
  compatibility statement in §9, and are not a tested configuration.

What still holds in every case, including `UNKNOWN`: the connector remains
shadow-only and non-blocking. `remote_authority` stays `false`,
`ENFORCEABLE_REMOTE_DECISIONS` stays empty, no remote decision acquires
execution authority, and every hook returns without altering tool execution. An
`UNKNOWN` host cannot obtain behavior the shadow-only contract does not already
permit — the carve-out affects *whether observation starts*, not *what
observation is allowed to do*.

**For a supported deployment, run OpenClaw `2026.6.5` or newer** and confirm it
with `openclaw --version` before installing. Do not rely on `UNKNOWN` as a
substitute for a supported host.

## 10. Packaging metadata differs from the sealed internal build

Two kinds of difference from the sealed internal inventory exist. First, the
public packaging changes made in v0.5.0 to make the package publishable and its
test command functional:

| Change | Reason |
| --- | --- |
| Removed `"private": true` | npm's refuse-to-publish flag; it blocks public distribution |
| Description no longer says "Private" | Inaccurate for a public release |
| Added `"license": "Apache-2.0"`, author, homepage, repository, bugs | Required public metadata |
| `scripts.test` now runs `../scripts/verify-package.mjs` | The old path pointed at a test tree not shipped in this package, so `npm test` was broken |
| `bin` path `./connector-ctl.mjs` → `connector-ctl.mjs` | npm rejects and strips the `./` prefix |

Second, the runtime changes made in v0.5.1 for the findings listed in
[CHANGELOG.md](CHANGELOG.md): profile-scoped state, the OpenClaw compatibility
activation gate, and inert disabled behavior.

The sealed v0.5.0 connector inventory contains 28 files. Relative to it, v0.5.1
adds `connector/host.mjs`, changes five runtime modules
(`config.mjs`, `constants.mjs`, `hook.mjs`, `index.mjs`, `pipeline.mjs`),
changes two metadata files (`package.json`, `openclaw.plugin.json`), updates
`connector/README.md`, and carries the remaining 20 sealed files over
byte-identical. The connector tree is 29 files, including 24 `.mjs` runtime
modules. `npm test` verifies that this enumerated set is the
*only* difference. See [CONNECTOR-FILES.sha256](CONNECTOR-FILES.sha256) for
public-package integrity and
[SEALED-CONNECTOR-FILES.sha256](SEALED-CONNECTOR-FILES.sha256) for the sealed
v0.5.0 reference.

The embedded governance core is unchanged by v0.5.1 and still verifies against
its recorded `SOURCE.sha256`.

One item is still **not** changed:

- `connector/runtime/governance-core/policy-validate.mjs` defaults its expected
  policy-document owner to an internal build value and its expected environment
  to `production`. These are defaults of an **optional validation helper** —
  overridable per call and not used by the observation path.

## 10a. What `npm test` covers, and what it does not

`npm test` runs the package's own tests — `tests/public-distribution.test.mjs`,
`tests/public-runtime.test.mjs`, and `tests/public-v051-regression.test.mjs`,
plus the checks in `scripts/verify-package.mjs`. All of it is dependency-free
and makes no network calls, and it works from an installed copy of the package.

It covers: the public packaging contract, checksum manifests, shadow-only
invariants, metadata and manifest parsing, license presence, hook registration,
non-blocking behaviour under hostile remote responses, metadata-only receipts,
outbound-guard rejection, local control precedence, configuration-example
loading, and every v0.5.1 finding — named-profile state isolation, absence of
legacy-state migration, the OpenClaw compatibility activation gate, and inert
disabled behavior.

It is **not** the full upstream connector suite. That suite lives in the
internal build repository and is not shipped here. `npm run test:public` runs
the complete public release suite, but it needs that tree — set
`MCPHERSON_UPSTREAM_REPO` to the internal build repository root. Without it the
runner exits non-zero rather than reporting a partial pass.

Two upstream tests are excluded from the public suite by exact name, and each
is replaced by a public test asserting the contract that supersedes it:

- `"package is private v0.5.0 and declares only inspected supported hooks at
  runtime"` asserts `package.json.private === true` and version `0.5.0`. That is
  correct for the internal installer and deliberately wrong for a public
  package. Replaced by `tests/public-distribution.test.mjs`.
- `"disabled/kill/lock precedence beats exact canary with a zero-network
  call-order trace"` asserts that a *disabled* connector still writes a
  `NOT_ATTEMPTED` attempt receipt. v0.5.1 deliberately changed that: disabled is
  now inert and writes no observation receipt at all. Replaced by
  `tests/public-v051-regression.test.mjs`, which runs all five of that test's
  scenarios — the three kill-switch/system-lock scenarios unchanged, and the two
  disabled scenarios under the stricter v0.5.1 contract.

Both exclusions are by test name rather than by file, so every other safety test
in those files keeps running.

## 11. License scope

Licensed under Apache-2.0 (see [LICENSE](LICENSE), [NOTICE](NOTICE)),
copyright 2026 McPherson AI LLC.

The license covers **this connector only**. It does not license or include the
commercial McPherson Governance wrapper, the hosted Governance API, Observa
commercial services, the Governance Dashboard, v0.6, v0.7 enforcement, private
infrastructure, or internal deployment tooling. Nothing in this package provides
access to those, and none of them is required to run the connector — but the
connector is only useful when pointed at some governance endpoint, which you
must supply or obtain separately.

## 12. Production use is an operator decision

Before production use, review your configuration, your tool naming, your
identifier choices, your receipt retention, and the privacy boundary in
[PRIVACY.md](PRIVACY.md) — including who operates the governance endpoint you
configure.

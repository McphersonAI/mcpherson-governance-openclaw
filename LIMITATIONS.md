# Limitations

**Connector v0.5.0.** Read this before relying on the connector for anything.

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

The sealed reference suite contains 181 connector tests. The applicable 180
tests pass against the public connector; its one internal-only packaging
assertion is replaced by the public distribution tests. Coverage includes
hostile-endpoint behavior, privacy-guard assertions over serialized wire bytes,
scheduler saturation, and shutdown residue accounting.

Long-run production soak evidence and platforms other than those tested are not
covered by the distributed package. Built and tested against OpenClaw
`2026.6.5` (`5181e4f`), plugin API `>=2026.6.5`, on Node 24.

## 10. Packaging metadata differs from the sealed internal build

**One file** in the connector directory differs from the sealed internal
inventory: `connector/package.json`. It was changed deliberately, to make the
package publishable and its test command functional:

| Change | Reason |
| --- | --- |
| Removed `"private": true` | npm's refuse-to-publish flag; it blocks public distribution |
| Description no longer says "Private" | Inaccurate for a public release |
| Added `"license": "Apache-2.0"`, author, homepage, repository, bugs | Required public metadata |
| `scripts.test` now runs `../scripts/verify-package.mjs` | The old path pointed at a test tree not shipped in this package, so `npm test` was broken |
| `bin` path `./connector-ctl.mjs` → `connector-ctl.mjs` | npm rejects and strips the `./` prefix |

The sealed connector inventory contains 28 files. The public connector matches
27/28 sealed files. The sole intentional difference is
`connector/package.json`; all 23 `.mjs` runtime files remain byte-identical.
That package-metadata difference enables public distribution and does not
change runtime logic. See [CONNECTOR-FILES.sha256](CONNECTOR-FILES.sha256) for
public-package integrity and
[SEALED-CONNECTOR-FILES.sha256](SEALED-CONNECTOR-FILES.sha256) for the exact
sealed-reference comparison.

Two cosmetic items were **not** changed, to keep runtime source byte-frozen:

- `connector/openclaw.plugin.json` and `connector/index.mjs` still describe the
  plugin as "Private v0.5.0 …" in their description strings. This is stale
  wording from the internal build, not a statement about licensing — the package
  is Apache-2.0. Correcting it requires a new sealed connector build.
- `connector/runtime/governance-core/policy-validate.mjs` defaults its expected
  policy-document owner to an internal build value and its expected environment
  to `production`. These are defaults of an **optional validation helper** —
  overridable per call and not used by the observation path.

## 10a. What `npm test` covers, and what it does not

`npm test` runs the package's own tests — 27 tests across
`tests/public-distribution.test.mjs` and `tests/public-runtime.test.mjs`, plus
18 checks in `scripts/verify-package.mjs`. All of it is dependency-free and
makes no network calls, and it works from an installed copy of the package.

It covers: the public packaging contract, checksum manifests, shadow-only
invariants, metadata and manifest parsing, license presence, hook registration,
non-blocking behaviour under hostile remote responses, metadata-only receipts,
outbound-guard rejection, local control precedence, and
configuration-example loading.

It is **not** the full upstream connector suite. That suite lives in the
internal build repository and is not shipped here. `npm run test:public` runs
the complete 225-test public release suite, but it needs that tree — set
`MCPHERSON_UPSTREAM_REPO` to the internal build repository root. Without it the
runner exits non-zero rather than reporting a partial pass.

One upstream test is excluded from the public suite by exact name:
`"package is private v0.5.0 and declares only inspected supported hooks at
runtime"`, which asserts `package.json.private === true`. That is correct for
the internal installer and deliberately wrong for a public package, so it is
replaced by `tests/public-distribution.test.mjs`. The exclusion is by test name
rather than by file so the other 20 safety tests in that file keep running.

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

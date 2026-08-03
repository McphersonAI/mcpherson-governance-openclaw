# Limitations — McPherson Governance Connector v0.6.0

Read this before deciding what this package is for. Everything here is a real
limitation, stated plainly.

## 1. This is not enforcement

There is **no active enforcement** in this release. The connector contains no
policy evaluator and no gate. It cannot block, approve, deny, delay, or rewrite
a tool call, and no configuration option turns that on. `AUTHORITY` is `NONE`
and `ENFORCEMENT` is `OFF`, both as source-owned constants that are not derived
from configuration, environment variables, policy documents, or API data.

If you need enforcement, this release does not provide it.

## 2. Remote decisions have no execution authority

When remote shadow is explicitly enabled, the connector may send
metadata-minimized observations and receive responses. Those responses are
recorded. **They cannot change what a tool does.** There is no code path from a
remote response to a modified, delayed, denied, or duplicated tool call. The
list of enforceable remote decisions is an empty frozen array in source.

## 3. AutoMap proposals are proposals

AutoMap output has status `PROPOSED`. It **cannot activate itself**, and this
package has no registry-mutation path (`apply-registry-patch` does not exist).

This package does **not** claim that AutoMap proposals are correct, approved, or
eligible for enforcement. They are machine-generated suggestions derived from
local metadata. A human must review them. Some will be wrong.

## 4. Unconfigured tools — corrected in v0.6.0

**Previous releases of this documentation said unmapped tools normally produce
remote registry `404` observations. That description is withdrawn.** It does not
describe v0.6.0 behavior.

Current behavior for a tool with no complete configured metadata:

- the tool **remains local**;
- **no HTTPS request occurs**;
- the receipt records `remote_status: NOT_ATTEMPTED`;
- the receipt records `local_disposition: SKIPPED`;
- **tool execution is unchanged**;
- **no fallback metadata reaches the wire or the receipt ledger.**

The connector does not manufacture a schema hash or action class for a tool you
have not configured, so it does not send a request that could not be accepted.

### The one case where a 404 can still legitimately appear

A **configured** connected-shadow identity may still receive a remote `404` when
the service cannot resolve the deployment, agent, tool, or contract. That `404`
is a **remote contract or registry failure**, not an execution decision, and it
**cannot block the original tool** in V6. It is recorded as the remote status of
an observation and nothing more.

## 5. Coverage is not universal

- **Not universal tool support.** Only tools your OpenClaw gateway reports, and
  for remote shadow only tools you have configured with complete metadata.
- **Not complete audit-log coverage.** Receipts cover what the post-hook
  observes. Activity outside that path is not receipted. In the default
  shadow posture the connector writes only `gateway_start` / `gateway_stop`
  lifecycle records and no attempt or completion receipts — so zero receipt
  groups is the expected result, not a broken pipeline.
- **Not universal outcome verification.** A completion receipt records the
  outcome the hook observed. It is not an independent verification that the
  tool's real-world effect occurred.

## 6. No certification

This package carries **no security certification and no compliance
certification** of any kind. Nothing here is an attestation of SOC 2, ISO 27001,
HIPAA, GDPR, or any other framework. The safety properties described are
properties of this source code, verified by its own test suite — not third-party
certifications.

## 7. Platform and availability

- **Not multi-platform.** Evidence binds this release to OpenClaw `2026.6.5`
  (commit `5181e4f`) on POSIX hosts, with Node.js 22+. Other OpenClaw versions
  are permitted by the declared `>=` range but are not covered by that evidence.
- **No public dashboard.** The connected dashboard is a separate beta and is not
  publicly available as part of this package.
- **No billing or paid-plan activation.** There is no billing, credits, or
  paid-plan path in this package.
- **No v0.7 enforcement.** It is not included and not available here.

## 8. Local observation constraints

- Live observation requires an explicit, local profile binding. The binding
  pins the exact package/source identity, profile mode and identity, physical
  home, state/config/runtime paths, exact profile-local connector state and
  receipt ledger, and the audited OpenClaw `2026.6.5 (5181e4f)` runtime. Its
  canonical bytes are enforced, it expires after at most 24 hours, and every
  consumer requires the independently captured ID printed at initialization.
- Named mode uses exactly `<profile-home>/.openclaw-<profile>` and never falls
  back to DEFAULT. Default mode is accepted only when both creation and use
  explicitly request DEFAULT, and then selects exactly
  `<profile-home>/.openclaw`.
- OpenClaw's case-insensitive reserved named profile `dev` is refused because
  2026.6.5 assigns it a different gateway port than the audited endpoint.
- The profile home must be an owned physical absolute directory with no
  symlinked component. The state root and config are owned and private; the
  runtime must have the package-bound home-relative identity. Environment
  variables cannot redirect an approved binding.
- Live observation supports the connector's profile-local default `stateDir`
  and `receiptDir` only. Explicit connector path overrides are refused rather
  than guessed or followed; remove them and use the documented profile-local
  layout before creating a binding.
- Binding initialization and verification are local and account-free, but
  they require the exact audited OpenClaw runtime, the documented local
  SecretRef configuration, and the profile identity/operator token created by
  one successful local loopback health call. No remote account is involved.
- It reads only `agents.list`, `tools.catalog`, and the exact bounded receipt
  ledger named by the binding. A ledger from DEFAULT or another named profile
  is refused before RPC or file access.
- It refuses a receipt ledger that is not a private, owned, non-symlink `0600`
  regular file, and it refuses to overwrite an existing output path.
- A ledger containing records from more than one connector version fails closed.
  See [INSTALL.md](./INSTALL.md) §6.
- Malformed or unavailable inputs produce no candidates and no proposals, plus a
  bounded local error record. They never become authority or an action.

## 9. Trust boundary

The connector runs inside your OpenClaw process with your permissions. It is not
a sandbox and does not isolate tools from each other or from your system. It
observes; it does not contain.

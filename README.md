# Observa local CLI — 0.8.0

Observa connects supported OpenClaw runtime events to local evidence and Hosted
Observa. Version 0.8.0 is qualified for **OpenClaw 2026.10.9** within the runtime,
evidence and enforcement limits below; see `CANDIDATE-PROVENANCE.json`.

## Start here

After installing the connector and starting your OpenClaw gateway:

```sh
observa access
observa access status
observa pair
observa doctor
```

`access` guides you through your name, email, workspace/organization, intended
use, confirmation and email verification. It saves a private request receipt so
`access status` can check the same request. Approval, account sign-in and pairing
are separate steps: an access request alone does not pair an installation.
`pair` accepts your pairing code through hidden terminal input; do not put codes
or credentials in command arguments.

You do not normally supply a Hosted server address. The CLI resolves a saved
request's origin, a private trusted access binding, the selected profile's Hosted
configuration, or the verified public onboarding origin recorded in
`cli/trusted-hosted.json`. Explicit `--api-url` remains available for advanced
operators. Saved requests cannot silently change origin. Redirects are refused.
The currently verified beta origin requires connectivity to the Hosted service;
this release does not claim an internet-public ingress independent of that service.

```sh
observa status       # actual local configuration and retained evidence
observa doctor       # local diagnostics and paired Hosted health
observa stop         # safely stop observation and delivery
observa enable       # resume observation; restart gateway if instructed
observa --help
```

`status` is offline. Configured/enabled does not prove that a gateway is running.
`doctor` checks the supported runtime evidence, local proof integrity, delivery
backlog and authenticated Hosted binding; it reports incomplete setup rather
than inventing a healthy installation. `stop` preserves configuration,
credentials, evidence and pending delivery. Other OpenClaw tools continue to
operate. If the isolated synthetic bound tool was explicitly configured, it
refuses new effects while observation controls are stopped.

## Installation and CLI collisions

The existing OpenClaw distribution channel is ClawHub's **code-plugin** package
`@mcphersonai/mcpherson-governance-openclaw`. The established install command is:

```sh
openclaw plugins install clawhub:@mcphersonai/mcpherson-governance-openclaw@0.8.0
```

Use the release's verified version and artifact identity when performing an
upgrade. Restart the selected gateway to register the plugin and
refresh its CLI launchers. Do not reset OpenClaw memory, agents or state.

The stable plugin configuration key is `mcpherson-governance-connector`; it
intentionally differs from the package name. Existing configuration remains
under this key.

When Observa Local Node owns `observa`, use the namespaced OpenClaw command:

```sh
observa-openclaw access
observa-openclaw access status
observa-openclaw pair
observa-openclaw status
observa-openclaw doctor
observa-openclaw stop
```

The connector never overwrites Local Node, unknown commands or package-manager
links. It creates `observa-openclaw` alongside the verified OpenClaw launcher when
that name is available. If either name is occupied or the launcher directory is
unwritable, gateway diagnostics provide the verified installed CLI's direct
`node …/observa.mjs` fallback. Namespace failures are recorded, not hidden.

## Runtime and evidence boundaries

The tested target is the official OpenClaw `v2026.10.9` source commit
`8b18b5578f66eab1501cba4cef2310d88bfb9a41`. Its Node engine requirement is
`>=24.22.1 <25 || >=26.12.1`; qualification uses Node 24.22.1 on macOS arm64.
A declared Node range is not a test claim for every Node version, platform or
OpenClaw release. Plugin APIs remain version-pinned and subject to upstream change.

The exact upstream installation is not free of dependency advisories. The
October 30 audit reports six affected package entries (four high, two moderate),
including OpenClaw's pinned undici 8.11.2 and zod 4.6.5. This connector adds no npm
runtime dependencies and does not patch or certify the host. Compatibility tests
do not establish that untrusted host networking or other OpenClaw features are safe.

The adapter registers supported tool, session and model lifecycle hooks. It does
not read OpenClaw's private agent/session database or infer execution from the
configured agent roster. The connector owns a separate `native-v1/evidence.sqlite`
inside its existing state directory. Signed, chained records and delivery intent
commit together with full SQLite synchronization. Replay indexes and acceptance
indexes are verified against signed evidence in one consistent database snapshot.

Before/after tool evidence uses deployment, agent, run, tool-call and tool
identity. Optional session identities are correlated when present. Missing or
contradictory identity remains unresolved. A missing, asynchronous or unrecognized
result is `UNKNOWN`; a tool return does not prove a business outcome. No prompt,
argument body, result body or raw exception text is stored in the native journal.
Session identifiers and local run/call references are hashes. The existing closed
Hosted v2 envelope retains its bounded, screened native run/tool-call identifiers
for exact execution linkage; those identifiers are part of durable delivery intent.

Supported completed, failed or timed-out observations use the existing Hosted
`/v1/observations` v2 contract. UNKNOWN outcomes, lifecycle metadata and bound-policy
evidence remain local. Current Hosted native-v3 is specific to another adapter;
it does not accept OpenClaw. This connector does not relabel OpenClaw events to
fit it. Existing receipts and their schemas remain intact.

Delivery completes only after authenticated HTTPS acceptance with the exact
request hash and a durable local acceptance record. Requests remain bound to the
capture-time credential, origin and deployment. Re-pairing or credential rotation
does not silently redirect old evidence. Network failures retain pending evidence
for retry/restart. The current Hosted route has a five-minute freshness window
and refuses consumed-nonce/correlation replay: a lost acknowledgement or expired
request remains unresolved, even if a server row might exist. A 409 is never
reported as acceptance. These limits prevent a universal eventual-delivery claim.

## First bound operation

**Customer enforcement is disabled by default.** The optional binding currently
permits isolated synthetic qualification only. It registers one connector-owned
tool, `observa_bound_write`, for exclusive creation of a bounded synthetic text
file beneath the connector's `bound-synthetic` directory.

The actual OpenClaw `before_tool_call` hook invokes the unchanged V7 deterministic
evaluator. The adapter consumes its decision; it does not decide policy itself.
The vocabulary is ALLOW, DENY, REQUIRE_APPROVAL, ABSTAIN, INDETERMINATE and ERROR.
Only a valid permit proceeds. A supported interactive host approval is bound to
the exact request and re-evaluated by V7. `allow-always` is not offered. The tool
also checks the exact parameter digest and unchanged policy at execution, and
persists a single-use claim before creating a file. Uncertain crash-after-effect
claims remain consumed after restart.

Ordinary shell `exec`, file `write`/`edit`/`apply_patch`, other plugin tools, MCP
routes, native harness tools, subagent tools, gateway commands and external
processes are **not governed by this policy binding**. A subagent cannot invoke
this bound tool under an unapproved agent identity, but that does not govern its
other tools. OpenClaw may expose routes that do not run these hooks; direct access
to this bound executor still requires its exact unconsumed permit. Neither this
hook nor its synthetic tests establish comprehensive enforcement or independent
certification.

Production activation requires separate Control Gate C qualification, explicit
customer authorization and a separately accepted activation path. This release
has no production-enforcement switch. V7 evaluator records retain their own
SIMULATION/NONE posture; the synthetic host binding and actual downstream outcome
are recorded separately.

## Advanced compatibility

`request-access` remains an alias for `access`; `request-status` remains an alias
for `access status`. Existing advanced commands remain available: `agents`,
`agent`, `activity`, `decisions`, `hosted-health`, `identify`, `enable`, `disable`,
`killswitch`, `lock`, `credential rotate`, `credential recover`, `unpair` and
`uninstall`. Existing flags and `observa-pair` / `observa-openclaw-ctl` entrypoints
are retained. Use `<command> --help` for exact options.

`activity` and `decisions` retain their existing receipt/counterfactual views;
they are not a complete projection of the new native journal. `status` reports
native evidence integrity and delivery backlog separately. Profile selection and
state-path safety checks apply to all commands.

Preserve the original 0.7.4 artifact, state directory and any configuration
backups before an upgrade. Rolling package code back does not require deleting
native evidence; an older connector simply does not consume the new journal.
Remove a newly configured synthetic binding from the active configuration before
using code whose configuration schema predates that field. Do not delete proof,
credentials, memories, backups or worktrees to repair an installation.

## License

See `LICENSE`, `NOTICE` and `LICENSE-CLARIFICATION-v0.7.4.md` for the existing
plugin's Apache-2.0 grant and service/trademark boundaries. The exact 39-file V7
set in `plugins/openclaw-connector/v7/PROVENANCE.json` is covered by the explicit
Apache-2.0 grant in `LICENSE-V7-v0.8.0.md`. The grant does not extend to separately
distributed private Hosted services, commercial control-plane code or unreleased
SDK software.

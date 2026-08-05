# McPherson Governance Connector for OpenClaw

**Version 0.6.2 — account-free local governance diagnostics.**

This package is the distributed McPherson Governance OpenClaw plugin. It is not
the McPherson Governance monorepo: it contains the connector runtime, the V6
local diagnostics CLI, the runtime modules those two need, the JSON schema
contracts they read, public documentation, and self-verification tooling.

## What it does

Installed into an OpenClaw profile, it gives you a local, private workflow:

- **Account-free local agent and tool discovery** from your own OpenClaw
  gateway metadata.
- **Non-authoritative AutoMap proposals** for the capabilities it discovers.
- **A Governability Diagnosis** of how much of your local surface could be
  governed.
- **Private JSON and Markdown reports** written `0600` under a directory you
  choose.

## What it does not require

No McPherson account. No email verification. No MFA. No organization, no
workspace, no installation pairing. No McPherson API key. No billing, no
credits. No dashboard login. No hosted SaaS availability.

The connected dashboard beta is a **separate** product path and is not required
for, and does not gate, local V6 use.

## Fixed safety boundary

| Property | Value |
| --- | --- |
| `AUTHORITY` | `NONE` |
| `ENFORCEMENT` | `OFF` |
| Automatic mapping activation | `OFF` |
| Outbound actions | `OFF` |
| Registry mutation | `OFF` |
| Billing / enforcement credits | absent or inactive |
| Remote decisions | `SHADOW_ONLY` |

- The connector **does not block, approve, deny, delay, or rewrite** any tool
  call. It has no policy evaluator and no gate.
- **Remote decisions cannot alter tool execution.** There is no code path from
  a remote response to a change in what a tool does.
- **AutoMap proposals cannot activate themselves.** Their status is `PROPOSED`.
  Promoting a proposal is a separate, human, out-of-band decision.
- The single exception to "never blocks" is the operator-enabled, exact-match
  local canary tool, which exists so you can prove the hook is installed. It
  reads no remote data.

## Unconfigured tools make no network request

If a tool has no complete configured metadata in your connector configuration:

- it **remains local**;
- **no HTTPS request occurs**;
- the receipt records `remote_status: NOT_ATTEMPTED`;
- the receipt records `local_disposition: SKIPPED`;
- **tool execution is unchanged**;
- no fallback metadata reaches the wire or the receipt ledger.

Earlier releases described unmapped tools as normally producing remote registry
`404` observations. That is **not** V6 behavior — see
[LIMITATIONS.md](./LIMITATIONS.md) §4 for the corrected description and the one
case where a `404` can still legitimately appear.

## Requirements

- **OpenClaw 2026.6.5 or newer.** This minimum is source-owned and enforced by
  the connector itself at activation time. See [INSTALL.md](./INSTALL.md) for
  the exact provenance of that number.
- **For live observation, one of three exact audited builds.** Support is
  exact-target based, not range-based: `2026.6.5` (`5181e4f`) and `2026.6.33`
  (`7af0cfc`, extended-stable) are both live-lifecycle proven, with
  `2026.6.33` preferred. `2026.7.1-2` (`0790d9f`) is target-bound and
  installable but **not** live-observation supported. Live observation
  refuses every other build. See [LIMITATIONS.md](./LIMITATIONS.md).
- **Node.js 22 or newer** (the V6 diagnostics CLI requires it).
- No third-party dependencies. Every import resolves to a sibling module in this
  package or to a Node.js built-in.

## Quick start

```sh
PROFILE=my-profile
PROFILE_HOME=/absolute/physical/path/to/the/openclaw-home
OPENCLAW="$PROFILE_HOME/.local/bin/openclaw"
PROFILE_STATE="$PROFILE_HOME/.openclaw-$PROFILE"
PACKAGE_ROOT=/absolute/path/to/the/verified/package
clawhub package download @mcphersonai/mcpherson-governance-openclaw \
  --version 0.6.2 --output ./mcpherson-governance-download
clawhub package verify \
  ./mcpherson-governance-download/mcphersonai-mcpherson-governance-openclaw-0.6.2.tgz \
  --package @mcphersonai/mcpherson-governance-openclaw --version 0.6.2
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  "$OPENCLAW" --profile "$PROFILE" plugins install \
  ./mcpherson-governance-download/mcphersonai-mcpherson-governance-openclaw-0.6.2.tgz
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  "$OPENCLAW" --profile "$PROFILE" config set \
  plugins.entries.mcpherson-governance-connector.config \
  '{"enabled":false}' --strict-json
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  "$OPENCLAW" --profile "$PROFILE" config validate
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  "$OPENCLAW" --profile "$PROFILE" plugins inspect mcpherson-governance-connector
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  "$OPENCLAW" --profile "$PROFILE" plugins disable mcpherson-governance-connector
```

Download, verify, then install the verified `.tgz` — the same install contract
as v0.5.1. Full steps and expected install warnings are in
[INSTALL.md](./INSTALL.md).

`enabled: false` is the default and keeps remote shadow off. The local V6
diagnostics workflow runs with the connector disabled.

Then follow the account-free SecretRef and local loopback-health identity
bootstrap in [INSTALL.md](./INSTALL.md) §4.1. It uses the exact named profile,
requires no remote service or account, and must complete before binding. The
binding pins the exact profile-local ledger under
`$PROFILE_STATE/mcpherson-governance-connector/receipts/`.

Run the local workflow using the full commands in [INSTALL.md](./INSTALL.md):

```sh
node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" init-profile-binding ...
node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" verify-profile-binding ...
node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" observe-live ...
node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" verify-observation ...
node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" discover ...
node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" propose ...
node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" govern ...
node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" render-diagnosis ...
```

## Verify what you installed

```sh
npm run verify
```

This checks the packaged file inventory against `PACKAGE-FILES.sha256`, the
declared identities, and the safety constants. See [VERIFY.md](./VERIFY.md).

## Documents

| File | Contents |
| --- | --- |
| [INSTALL.md](./INSTALL.md) | Install, configure, run the V6 workflow, upgrade from v0.5.1 |
| [VERIFY.md](./VERIFY.md) | Independent verification of this package |
| [LIMITATIONS.md](./LIMITATIONS.md) | What this does not do, honestly stated |
| [PRIVACY.md](./PRIVACY.md) | What is read, what is written, what never leaves |
| [SECURITY.md](./SECURITY.md) | Security posture and reporting |
| [SUPPORT.md](./SUPPORT.md) | Getting help, troubleshooting |
| [LIFECYCLE.md](./LIFECYCLE.md) | Enable, disable, rotate, uninstall, version transitions |
| [CHANGELOG.md](./CHANGELOG.md) | Release history |

## Security

To report a suspected vulnerability, email **admin@mcphersonai.com** privately.
Please do not open a public issue for suspected security vulnerabilities. See
[SECURITY.md](./SECURITY.md).

## What this package is not

It does not include, and this license does not grant rights to, the hosted
McPherson Governance API, the McPherson Governance Dashboard, Observa
commercial services, the commercial control plane, or v0.7 enforcement. Those
are separate works and are not distributed here. See [NOTICE](./NOTICE).

## License

Apache License 2.0. Copyright 2026 McPherson AI LLC. See [LICENSE](./LICENSE)
and [NOTICE](./NOTICE).

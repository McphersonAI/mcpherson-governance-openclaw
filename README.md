# McPherson Governance Connector for OpenClaw

**Version: 0.5.0 — initial public release.**

A small OpenClaw plugin that observes configured tool activity, sends
metadata-minimized governance requests, and records local receipts of what was
attempted and what completed.

> Independent verification records are maintained outside the distributed
> package. Read [LIMITATIONS.md](LIMITATIONS.md) before using this release.

---

## What this release is

- v0.5 is **shadow-only**.
- It **observes configured OpenClaw tool activity**.
- It sends **metadata-minimized governance requests** to a governance endpoint
  you configure.
- It records **attempt and completion receipts** locally.
- It **does not block or alter tool execution**.
- **Remote decisions have no execution authority.** A governance response of
  `DENY`, `REQUIRE_APPROVAL`, or `HOLD` is recorded in a local receipt and
  changes nothing about what your agent does.
- **Unmapped tools may produce registry 404 observations.**
- **Registry 404 observations do not block the original tool.**
- **Manual capability mapping is required** — see
  [Configuration](#configuration). A tool with no `toolMetadata` entry cannot be
  described to the governance endpoint.
- This is **not active enforcement**.
- This is **not a safety, security, or compliance certification**.
- **Production use requires the operator to review configuration and privacy
  boundaries** before enabling it. See [PRIVACY.md](PRIVACY.md).

## What this release is not

It does not block, deny, approve, delay, queue, retry, or modify any tool call.
It is not an enforcement product, and it does not become one through
configuration. It makes no guarantee of security and carries no compliance
certification.

## How the shadow-only property is held

Four values are compiled into the connector source as authority ceilings
(`connector/constants.mjs`). They are not read from configuration, environment
variables, policy documents, or API responses:

| Constant | Value |
| --- | --- |
| `remote_shadow` | `true` |
| `remote_authority` | `false` |
| `deny_enforcement` | `false` |
| `approval_enforcement` | `false` |
| `ENFORCEABLE_REMOTE_DECISIONS` | `[]` (empty) |
| `RECEIPT_MODE` | `POST_HOOK` |

The configuration loader **rejects** any configuration containing
`remote_authority`, `deny_enforcement`, `approval_enforcement`, or any other
authority key (`FORBIDDEN_AUTHORITY_CONFIG`), and rejects `remote_shadow` as an
unknown key. There is no supported way for an operator, a policy document, or a
governance response to raise these ceilings.

In the pre-call hook, the remote observation path ends in an unconditional
non-authoritative return: a governance response that is slow, malformed,
hostile, or absent changes only the contents of a local receipt.

### One local, operator-gated exception — the canary

There is exactly one code path in this release that can block a call, and it is
**local, self-contained, and off by default**. The canary blocks *only* the
connector's own diagnostic tool `mcpherson_governance_canary`, and only when
**all** of these hold:

1. the tool name is exactly `mcpherson_governance_canary`;
2. the agent ID matches the configured agent;
3. the operator has explicitly activated the local canary control file
   (`connector-ctl canary --on`); and
4. the call carries the exact literal canary token.

It never inspects or blocks any other tool, and it never reads remote data. It
exists so an operator can prove locally that local authority is retained. With
the canary off — the default — no code path in this release blocks execution.

This is documented rather than omitted because "it cannot block anything at all"
would be inaccurate. See [LIMITATIONS.md](LIMITATIONS.md).

## Architecture

```
┌──────────────────────── your host ────────────────────────┐
│  OpenClaw runtime                                         │
│      │  before_tool_call / after_tool_call (observe only) │
│      ▼                                                    │
│  Governance Connector                                     │
│   ├─ metadata builder (closed allowlist — never content)  │
│   ├─ local receipt writer (append-only, 0600)             │
│   └─ disable / kill switch / lock (local, always win)     │
└─────────────┬─────────────────────────────────────────────┘
              │ outbound TLS, metadata only, when enabled
              ▼
       governance endpoint you configure
```

There are no inbound ports, no webhooks into your host, and no remote control
channel. A local kill-switch file stops all remote contact before any network
I/O.

## Requirements

- OpenClaw with plugin API `>=2026.6.5`. Built and tested against OpenClaw
  `2026.6.5` (commit `5181e4f`).
- Node.js with ES module support (developed and tested on Node 24).
- Outbound HTTPS access to the governance endpoint you configure — only when
  `enabled` is `true`.

## Installation

See **[INSTALL.md](INSTALL.md)** for full steps. In short: verify the package
checksum, install through OpenClaw's supported plugin mechanism, place a
configuration file with `enabled: false`, confirm status, then enable
deliberately.

## Configuration

A complete, placeholder-only example is in
[examples/connector-config.example.json](examples/connector-config.example.json).
Every value there is a placeholder — replace them before use. Do not copy real
credentials into configuration; the deployment credential is read only from a
`0600` file at `<stateDir>/deployment-credential`.

Note `toolMetadata`: the connector cannot describe a tool it has no mapping for.
**Capability mapping is manual.** Tools you do not map are reported to the
governance endpoint as unknown, which typically produces a registry 404
observation. That observation is recorded in the receipt and **does not block
the original tool**.

## Verification

See **[VERIFY.md](VERIFY.md)**. It covers verifying the release archive
checksum, verifying all 28 connector files against
[CONNECTOR-FILES.sha256](CONNECTOR-FILES.sha256), and confirming the shadow-only
constants in the installed source. It also distinguishes the public package's
self-checksum manifest from its sealed provenance boundary: 27 of 28 connector
files match the sealed inventory, and all 23 `.mjs` runtime files match.

## Disable, uninstall, rollback

See **[LIFECYCLE.md](LIFECYCLE.md)**. Every level of "make it stop" is local and
does not depend on the governance endpoint being reachable.

## Privacy

Only fields on a closed allowlist leave your host — identifiers, class labels,
one-way hashes, and timestamps. Prompts, message bodies, tool parameters,
file contents, credentials, and customer records do not. The full field list and
the boundary's limits are in **[PRIVACY.md](PRIVACY.md)**.

## Limitations

Read **[LIMITATIONS.md](LIMITATIONS.md)** before relying on this release. It is
shadow-only, its receipt truth is bounded by OpenClaw's hook surface, its
classification labels can be wrong, and it carries no certification.

## Security

To report a suspected vulnerability, email **admin@mcphersonai.com** privately.
Please do not open a public issue for security reports. Full policy and scope:
**[SECURITY.md](SECURITY.md)**.

## Support

Best-effort community support through
[GitHub Issues](https://github.com/McphersonAI/mcpherson-governance-openclaw/issues)
— no SLA. See **[SUPPORT.md](SUPPORT.md)**.

## License

Licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).

```
Copyright 2026 McPherson AI LLC
```

This license covers the public v0.5 connector in this repository and package
only. It does not license or include the commercial McPherson Governance
wrapper, the hosted Governance API, Observa commercial services, the Governance
Dashboard, v0.6, v0.7 enforcement, private infrastructure, or internal
deployment tooling. Those are separate works and are not distributed here.

## Installation as a package

```
@mcphersonai/mcpherson-governance-openclaw
```

Install through OpenClaw's supported plugin mechanism — see
[INSTALL.md](INSTALL.md). Verify the package before installing
([VERIFY.md](VERIFY.md)); the bundled check runs with `npm test`.

## Links

- Repository: https://github.com/McphersonAI/mcpherson-governance-openclaw
- Issues: https://github.com/McphersonAI/mcpherson-governance-openclaw/issues
- Website: https://mcphersonai.com

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

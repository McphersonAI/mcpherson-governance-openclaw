# Security Policy

**Version: 0.5.1.**

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** to:

**admin@mcphersonai.com**

Do not open a public issue for a security report, and do not include exploit
details in a public channel.

A report is most useful if it includes: affected version, environment (OpenClaw
and Node versions, platform), reproduction steps, observed versus expected
behavior, and impact. Please do not include credentials, real customer data, or
receipt contents in a report.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.5.1 | Yes |
| 0.5.0 | No |
| < 0.5.0 | No |

## Security properties this release intends to hold

These are the properties worth reporting a break in:

- **No remote execution authority.** No governance response can block, approve,
  delay, or modify a tool call. `REMOTE_AUTHORITY` is `false` and
  `ENFORCEABLE_REMOTE_DECISIONS` is empty, both compiled into source.
- **Authority ceilings are not configurable.** Configuration containing
  `remote_authority`, `deny_enforcement`, `approval_enforcement`, or another
  authority key is rejected at load.
- **Closed outbound allowlist.** Only allowlisted metadata fields can be
  serialized outbound; the guard runs over the serialized bytes. Prompts,
  parameters, and content have no path to the network.
- **TLS verification is never disabled**, anywhere in the connector.
- **Local controls always win.** Disable, kill switch, and system lock are
  evaluated before credentials are read and before any network I/O.
- **Credential handling.** The deployment credential is read only from a `0600`
  file inside a `0700` state directory. It is never accepted from an argument,
  environment variable, or ordinary plugin configuration, and never logged.
- **Receipt integrity.** Receipts are append-only, owner-only, and validated
  against a schema before write.
- **Bounded resource ownership.** Shutdown does not report clean while any
  connector-owned socket, timer, request, or promise remains outstanding.

A demonstration that any of the above does not hold is a security issue.

## Privileged-execution surface you should know about

Credential **rotation** and **recovery** can optionally invoke a
caller-supplied trusted callback executable via `sudo`
(`makeCommandRotationOperator` in `connector/operator.mjs`). You should
understand this before using those commands:

- It is **opt-in**. It runs only when you pass `--rotation-operator <path>` to
  the connector control CLI's `rotate` or `recover`. Ordinary observation, install, enable,
  disable, and uninstall never touch it.
- The callback path is canonicalized and revalidated — including every parent
  directory — immediately before *each* execution, so a path swapped after CLI
  startup fails closed.
- The invocation grammar is fixed and carries only a rotation ID and a
  credential ID, both regex-constrained. Arbitrary arguments cannot be passed
  through it.
- It runs `sudo --non-interactive`; it never prompts and never adds a remote
  administration endpoint.
- Callback output is capped at 8 KB and is rejected outright if it contains
  credential-shaped material.

If you do not use credential rotation, this path is never reached. If you do,
the executable you point it at must be root-owned and not writable by the
connector's runtime user — the connector enforces this and fails with
`ROTATION_OPERATOR_PATH_INSECURE` otherwise.

## Known defaults inherited from the internal build

`connector/runtime/governance-core/policy-validate.mjs` carries build-time
default expectations for policy-document validation — an expected owner value
and an expected environment of `production`. These are **defaults for an
optional validation helper**, overridable per call, and they are not used by the
observation path. They are noted here for transparency because they reflect the
internal build's context rather than a neutral public default. See
[LIMITATIONS.md](LIMITATIONS.md) §10.

## Explicitly out of scope

- The connector being unable to block a tool call. That is the intended
  behavior of a shadow-only release, not a vulnerability.
- Registry `404` observations for unmapped tools not blocking execution. Also
  intended.
- Misclassification by manually configured `toolMetadata` labels.
- Dropped observations under configured in-flight/queue bounds.
- Security of any governance endpoint you choose to configure. That endpoint is
  outside this package's boundary.

## Disclosure

Coordinated disclosure. Please allow a reasonable period to investigate and
issue a fix before public disclosure.

## No warranty

This is an early release from a small team. It carries **no compliance
certification and no security guarantee**. Independent verification records are
maintained outside the distributed package. As stated in Sections 7 and 8 of
the [Apache-2.0 License](LICENSE), the software is provided "AS IS", without
warranties or conditions of any kind. See [LIMITATIONS.md](LIMITATIONS.md).

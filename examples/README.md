# Configuration example

[`connector-config.example.json`](connector-config.example.json) is an
illustrative configuration. **Every value in it is a placeholder.** It contains
no credentials, no real endpoints, and no real identifiers.

It ships with `"enabled": false`. Keep it that way until you have completed the
verification steps in [../VERIFY.md](../VERIFY.md).

## Do not put credentials here

The deployment credential is **never** read from configuration, a command
argument, or an environment variable. It is read only from a `0600` file at
`<stateDir>/deployment-credential`, inside a `0700` directory. Configuration
containing credential-shaped values will be rejected.

## Keys the loader rejects

The configuration loader is strict — unknown keys fail the load rather than
being ignored. In particular it rejects any attempt to raise authority:

| Key | Result |
| --- | --- |
| `remote_authority` | `FORBIDDEN_AUTHORITY_CONFIG` |
| `deny_enforcement` | `FORBIDDEN_AUTHORITY_CONFIG` |
| `approval_enforcement` | `FORBIDDEN_AUTHORITY_CONFIG` |
| `remote_shadow` | `CONFIG_UNKNOWN_KEY` |
| any other unlisted key | `CONFIG_UNKNOWN_KEY` |

This includes JSON comment keys such as `_comment` — the loader has no comment
support, so do not add one.

## `toolMetadata` — manual capability mapping

Mapping is manual. A tool with no entry here is reported as unknown and
typically produces a registry 404 observation. That observation is recorded in
the receipt and **does not block the tool**.

Required per tool: `schemaVersion`, `schemaHash` (`sha256:` + 64 lowercase hex),
`actionClass`.

Optional: `resourceClass`, `recipientType`, `recipientCount` (0–100000),
`attachmentIndicator` (boolean), `dataSensitivityLabel`, `reversibilityLabel`.

### Valid `actionClass` values

Exact strings only — similar, suffixed, prefixed, or differently-cased names are
rejected with `CONFIG_ACTION_CLASS_INVALID`:

- `read_only_internal`
- `reversible_internal_write`
- `file_modification`
- `command_execution`
- `configuration_modification`
- `service_gateway_control`
- `external_outbound`
- `credential_secret_access`
- `destructive_irreversible`
- `unknown`

## Remember what these labels are for

Class labels are sent to the governance endpoint verbatim, and so are
`agentId`, `deploymentId`, and tool IDs. Choose identifiers that are not
themselves sensitive — see [../PRIVACY.md](../PRIVACY.md).

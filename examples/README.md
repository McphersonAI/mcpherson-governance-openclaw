# Configuration example

[`connector-config.example.json`](connector-config.example.json) is an
illustrative configuration. **Every value in it is a placeholder.** It contains
no credentials, no real endpoints, and no real identifiers.

It ships with `"enabled": false`. Keep it that way until you have completed the
verification steps in [../VERIFY.md](../VERIFY.md).

## State location — leave it unset

The example **deliberately omits `stateDir` and `receiptDir`.** Do not add them
unless you have a specific reason to.

Left unset, the connector resolves its own state root inside the **active
OpenClaw profile**, in this order:

1. the host's own profile state directory, as OpenClaw reports it;
2. `OPENCLAW_STATE_DIR`, which `openclaw --profile <name>` exports;
3. `~/.openclaw`, reached only when neither names a profile.

So a named profile keeps its connector state, receipts, controls, and
credential with that profile:

```
~/.openclaw-<profile>/mcpherson-governance-connector/            state, controls, credential
~/.openclaw-<profile>/mcpherson-governance-connector/receipts/   receipts
```

With no `--profile`, the same paths apply under `~/.openclaw`. Nothing is
shared between profiles and nothing is migrated between them.

### Optional explicit overrides

`stateDir` and `receiptDir` remain supported for operators who deliberately
want a different location — an encrypted volume, a separate evidence mount, or
a path outside the profile. They are **not** required, and setting them opts out
of profile-based isolation:

```json
{
  "stateDir": "/absolute/path/you/own/mcpherson-governance-connector",
  "receiptDir": "/absolute/path/you/own/mcpherson-governance-connector/receipts"
}
```

If you set them, both must be absolute paths you own, and the connector will
use those exact paths for **every** profile. Two profiles pointed at the same
`stateDir` share state — that is the behavior you are asking for by setting it.
The `MCP_GOVERNANCE_STATE_DIR` and `MCP_GOVERNANCE_RECEIPT_DIR` environment
variables have the same effect and the same caveat.

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

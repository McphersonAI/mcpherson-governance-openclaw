# Examples

Everything in this directory is a **placeholder**. No value here is real, and
none of it points at a real endpoint, deployment, agent, or certificate.
Replace every `REPLACE-...` value before use.

## `connector-config.example.json`

A complete configuration showing every supported key. The config schema is
`additionalProperties: false`, so any key not shown here is rejected.

### You do not need most of this

For the **account-free local V6 workflow**, the entire configuration you need
is:

```json
{ "enabled": false }
```

Everything else in the example file only matters if you deliberately enable
remote shadow against a governance endpoint you control.

### Key notes

| Key | Notes |
| --- | --- |
| `enabled` | Defaults to `false`. Leave it false for local V6 use. |
| `apiUrl` | Must match `^https://`. The example host is `.invalid` on purpose and will never resolve. |
| `deploymentId`, `agentId` | Your identifiers, 1–96 chars from `A-Za-z0-9._:-`. |
| `policyVersion` | Integer ≥ 1. |
| `observationBudgetMs` | 0–500. Foreground wait budget per observation. |
| `connectTimeoutMs` | 1–5000. |
| `maxInFlight` | 1–4. |
| `maxQueue` | 0–16. |
| `stateDir`, `receiptDir` | Optional overrides. Omit to use the profile defaults. |
| `caFile` | Absolute path to your own CA certificate, if you use a private CA. |
| `toolMetadata` | Per-tool metadata. **This is what makes a tool "configured".** |

### `toolMetadata` decides whether a tool talks to the network

A tool is **configured** only if it has an entry here with all three required
fields: `schemaVersion`, `schemaHash`, and `actionClass`.

- **Configured** + `enabled: true` → that tool may use the approved HTTPS shadow
  path.
- **Unconfigured** → the tool **remains local**, **no HTTPS request occurs**, and
  the receipt records `remote_status: NOT_ATTEMPTED` with
  `local_disposition: SKIPPED`. Tool execution is unchanged, and no fallback
  metadata is manufactured or transmitted.

Earlier documentation described unconfigured tools as normally producing remote
registry `404` observations. That is **not** current behavior — nothing is sent
for an unconfigured tool. See [../LIMITATIONS.md](../LIMITATIONS.md) §4.

A **configured** tool can still receive a remote `404` if the service cannot
resolve the deployment, agent, tool, or contract. That is a remote contract or
registry failure, not an execution decision, and it cannot block your tool.

`schemaHash` must be `sha256:` followed by 64 lowercase hex characters. The
zeroed hashes in the example are placeholders and will not match any real tool.

## Applying a configuration

```sh
openclaw config set \
  plugins.entries.mcpherson-governance-connector.config \
  "$(cat connector-config.example.json)" --strict-json
openclaw config validate
```

Review what you are applying first. Do not paste a real configuration
containing deployment or agent identifiers into an issue report.

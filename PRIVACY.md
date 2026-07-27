# Privacy and Metadata Boundary

**Connector v0.5.0.** This document describes exactly what can leave your host,
what cannot, and where the boundary's limits are.

## Summary

When enabled, the connector sends **metadata-minimized governance requests**:
identifiers, class labels, one-way hashes, and timestamps. It does not send
prompts, message bodies, tool parameters, file contents, or credentials.

When not enabled — or when the kill switch, system lock, or disable control is
active — **no network contact occurs at all**.

## The closed outbound allowlist

A governance request may contain only these fields
(`connector/constants.mjs`, `OUTBOUND_FIELDS`). Anything else fails closed.

| Field | What it is |
| --- | --- |
| `api_version` | Wire protocol version (`mgp/1`) |
| `request_id` | Random UUID v4, generated per request |
| `nonce` | 16 random bytes, hex |
| `timestamp` | ISO-8601 time of the request |
| `agent_id` | The agent identifier **you configure** |
| `tool_id` | The tool name as registered in OpenClaw |
| `tool_schema_version` | From your `toolMetadata` mapping |
| `tool_schema_hash` | `sha256:…` from your `toolMetadata` mapping |
| `action_class` | Class label from your mapping (e.g. `read_only_internal`) |
| `resource_class` | Optional class label from your mapping |
| `recipient_type` | Optional class label from your mapping |
| `recipient_count` | Optional non-negative integer from your mapping |
| `attachment_indicator` | Optional boolean from your mapping |
| `data_sensitivity_label` | Optional label from your mapping |
| `reversibility_label` | Optional label from your mapping |
| `request_hash` | One-way SHA-256 over the request fields |
| `policy_version` | Integer you configure |
| `correlation_ref` | One-way reference derived from the tool-call/run ID |

Note that most of these values come from **your own configuration**, not from
the traffic being observed.

## What never leaves your host

- Prompts, completions, and message bodies
- Tool parameters — complete or partial
- File contents, paths from tool arguments, and command output
- Credentials, API keys, bearer tokens, cookies, session values
- Customer records and personal data
- Receipt ledgers (receipts stay on your host)

## How the boundary is held

Four independent layers, in order:

1. **Structural.** The metadata builder `deriveSafeToolSummary()` has *no
   parameter for tool arguments*. A caller cannot pass `event.params` into the
   outbound request builder even by mistake — there is nowhere to put it. Raw
   arguments are read in exactly one place, the local canary, which is local-only
   and never reaches the network path.
2. **Closed allowlist.** `serializeAllowlistedRequest()` rejects the entire
   request (`PRIVACY_GUARD_TRIPPED`) if any key is not on the allowlist above, or
   if any required field is missing.
3. **Value shape enforcement.** Every string must match a safe-label pattern and
   stay within 256 characters. Values containing newlines, `http(s)://` URLs,
   `Bearer` tokens, deployment-credential patterns, `api_key`/`password`/
   `private_key` assignments, PEM private-key headers, or US SSN-shaped digits
   are rejected outright.
4. **Serialized-byte cap.** The canonicalized payload is rejected above 8 KB.

The guard runs on the **serialized bytes actually sent**, not on an
intermediate object, so it cannot be bypassed by a field added later in the
pipeline.

## Limits of the boundary — read this

The guard protects against *content* leaking. It cannot protect against
identifiers you deliberately configure:

- **`agent_id`, `deployment_id`, `tool_id`, and your `toolMetadata` labels are
  sent as-is.** If you name a tool `export_acme_corp_payroll`, that name leaves
  your host. Choose identifiers that are not themselves sensitive.
- **`policy_version` and class labels are your values.** They are transmitted
  verbatim.
- **Traffic metadata still exists.** The governance endpoint learns that *some*
  tool ran, when, and how often, plus the network-level facts of the connection.
- `correlation_ref` and `request_hash` are one-way, but they are stable — the
  endpoint can correlate repeated activity for the same call.

## Local receipts

Receipts are written to `<receiptDir>/connector-receipts.jsonl`:

- Append-only, opened `O_APPEND`, mode `0600` in a `0700` directory, `fsync`ed.
- **Metadata only** — the same class of fields as above, plus outcome and
  timestamps. Receipts contain no prompts, parameters, or content.
- They stay on your host. The connector never uploads them.

Two record types are written per observed call:

- `attempt_receipt` — written pre-call, with outcome `UNKNOWN` or `NOT_OBSERVED`.
- `completion_receipt` — written only after a directly observed
  `after_tool_call`, with outcome `COMPLETED`, `FAILED`, or `TIMED_OUT`.

Receipts are yours. Rotate, archive, or delete them per your own retention
policy — the connector does not manage retention for you.

## Network

- Outbound HTTPS only, to the endpoint you configure. TLS verification is never
  disabled.
- No inbound ports, no webhooks into your host, no remote control channel.
- A local kill-switch file stops all remote contact **before any network I/O**.

## Operator responsibility

Production use requires you to review this boundary against your own privacy
obligations — including your tool naming, your identifier choices, your
retention of receipts, and the jurisdiction and operator of whatever governance
endpoint you point the connector at. This document describes the connector's
behavior; it is not legal advice and not a compliance certification.

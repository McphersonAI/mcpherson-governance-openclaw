# Privacy — McPherson Governance Connector v0.6.0

## Summary

For the local V6 workflow, **nothing leaves your machine**. There is no account,
no telemetry, no analytics, no crash reporting, and no phone-home. The package
has no third-party dependencies that could add any of those.

## Local V6 diagnostics: what is read

The observer collects operational metadata from exactly three sources:

1. `agents.list` from your local OpenClaw gateway;
2. `tools.catalog` from your local OpenClaw gateway;
3. your local connector receipt ledger, through a bounded, descriptor-bound
   reader.

Before collecting it, the observer locally validates the shipped package
manifest, the operator-created profile binding, the bound profile's private
configuration, the bound OpenClaw runtime identity/build metadata, and the
profile's local device identity and operator token. The gateway authentication
SecretRef in configuration is validated structurally but is never resolved,
read, copied, or written to evidence. Device and operator credentials are used
only to authenticate the fixed loopback RPCs and are never included in output.

It executes two `operator.read` gateway RPCs against a package-bound OpenClaw
executable over the fixed loopback endpoint. It has no activation, registration,
hook, session, payload, or action path.

## Local V6 diagnostics: what is deliberately excluded

The observation output **never** contains:

- chat or message content;
- tool arguments or tool results;
- session identifiers;
- request hashes;
- correlation references;
- deployment identifiers;
- credentials or credential material;
- runtime or source filesystem paths;
- receipt bodies;
- command output or descriptions.

## Local V6 diagnostics: what is written

Binding initialization first writes one local `0600` profile-binding JSON file
in the private `0700` directory you name. It contains package/source identity,
the selected profile mode/name, physical home/state/config/runtime paths, exact
connector state and receipt-ledger paths, and creation/expiry timestamps. It
contains no credential value. Treat it as local private operational metadata;
it is not uploaded and is never silently overwritten. Its one canonical byte
serialization is enforced. Initialization also prints its non-secret content
hash as `binding_id`; the operator retains that value separately so later
commands can detect even a binding whose contents and self-hash were both
changed.

Observation then writes only metadata artifacts, in a directory you name,
created `0700`, each file `0600`:

- `capability-snapshot.json`
- `governability-evidence.json`
- `shadow-receipt-summary.json`
- `latency-events.json`
- `observation-manifest.json`

Plus, from the later commands, `discovery.json`, `automap-proposals.json`,
`governability-findings.json`, and `governability-diagnosis.md` — also `0600`.
Existing paths are never overwritten.

These files are yours. Nothing uploads them.

## Remote shadow: only if you explicitly enable it

`enabled` defaults to `false`. The local V6 workflow does not need it.

If you set `enabled: true` and supply an `apiUrl`, `deploymentId`, `agentId`,
and complete per-tool metadata, then **for those configured tools only** the
connector may send a metadata-minimized observation over HTTPS.

### The exact outbound field set

Nothing outside this list is ever sent:

`api_version`, `request_id`, `nonce`, `timestamp`, `agent_id`, `tool_id`,
`tool_schema_version`, `tool_schema_hash`, `action_class`, `resource_class`,
`recipient_type`, `recipient_count`, `attachment_indicator`,
`data_sensitivity_label`, `reversibility_label`, `request_hash`,
`policy_version`, `correlation_ref`.

Tool arguments, tool results, prompts, message content, file contents, and
filesystem paths are **not** in that set and are never transmitted.

`request_hash` is a hash, not recoverable content. `correlation_ref` links an
attempt to its completion locally.

### Unconfigured tools send nothing

A tool without complete configured metadata makes **no HTTPS request at all**.
It is recorded locally with `remote_status: NOT_ATTEMPTED` and
`local_disposition: SKIPPED`. No fallback metadata is manufactured, so nothing
about that tool reaches the wire.

## Receipts

Receipts are written to a local JSONL ledger in your OpenClaw profile state
directory, owner-only. They are not uploaded. Their content is bounded by the
same metadata-only discipline described above.

## Data controller

For the local workflow there is no data controller other than you: no data is
transmitted. If you enable remote shadow against a McPherson-operated endpoint,
that connection is governed by the separate agreement covering that service,
which is not part of this package.

## Contact

See [SUPPORT.md](./SUPPORT.md) and [SECURITY.md](./SECURITY.md).

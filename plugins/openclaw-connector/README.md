# McPherson Governance Connector v0.6.0

This private OpenClaw connector is structurally shadow-only. Remotely sourced data is observed and receipted but cannot block, pause, approve, modify, or duplicate an ordinary tool call. The only blocking path is the exact-match, operator-enabled local harmless canary; it does not read or depend on remote data.

## Account-free V6 local use

Installing this plugin does not require a McPherson Governance account. Leave
its configuration at `{"enabled":false}` and use the package's local
diagnostics CLI to discover local agents, tools, and capabilities, create
non-authoritative AutoMap proposals, and render a Governability Diagnosis.
There is no login redirect or dependency on email verification, MFA,
workspace creation, installation pairing, McPherson API keys, billing,
credits, or the dashboard. See `docs/v6-account-free-local.md` in the V6
package for exact commands and output locations.

Remote shadow is opt-in and independent: only a tool with complete explicit
remote configuration may use HTTPS. An unconfigured tool stays local, makes
no HTTPS request, and records `remote_status: NOT_ATTEMPTED` and
`local_disposition: SKIPPED`. In both cases tool execution is unchanged,
authority is `NONE`, and enforcement is off.

The exact integration target, OpenClaw `2026.6.5 (5181e4f)`, publicly documents and types `before_tool_call`, `after_tool_call`, `gateway_start`, and `gateway_stop`. The connector therefore uses `POST_HOOK` mode. Every pre-call emits an `attempt_receipt` with `UNKNOWN` or `NOT_OBSERVED`; a `completion_receipt` is emitted only after a directly observed `after_tool_call`. HTTP timeouts, queue drops, shutdown, missing events, and elapsed time never become tool outcomes.

The connector requires OpenClaw `2026.6.5` or newer and enforces that minimum at runtime from the host's own reported version. A host that declares an older or unresolvable version is `UNSUPPORTED`: activation is refused and the connector stays inert. A harness or embedder that exposes no runtime-version field is `UNKNOWN` and may load for compatibility with the existing test seam; `UNKNOWN` is not verified or officially supported. The internal canary hard-stops rather than using that seam.

Connector state-root precedence is:

1. an explicit path override or explicit connector `stateDir` configuration, when deliberately supplied;
2. the host runtime state resolver for the active OpenClaw profile;
3. `OPENCLAW_STATE_DIR`; and
4. the true default `~/.openclaw` profile.

An explicit `stateDir` intentionally opts out of the automatic profile-derived connector root. The internal canary forbids a shared or cross-profile override. Without that deliberate override, the active-profile default keeps state, receipts, controls, and the credential isolated below the active OpenClaw profile. No state is automatically copied or migrated between profiles.

While operationally disabled the connector is inert for ordinary observation: both tool-observation hook handlers return immediately and no governance request, shadow observation, or ordinary observation receipt is produced. Gateway lifecycle records, which note only that the connector was loaded, are unaffected.

Operator controls are available through the `connector-ctl.mjs` control CLI. An archive install does not guarantee a `connector-ctl` executable on `PATH`; invoke it by explicit path as `node <install-dir>/connector-ctl.mjs <command>` with `OPENCLAW_STATE_DIR` naming the intended profile:

- `status`
- `enable` (clear the durable disabled control after OpenClaw config has explicitly set `enabled:true`)
- `disable`
- `killswitch --on|--off`
- `lock --on|--off`
- `canary --on|--off`
- `rotate --rotation <32-hex-id> --new-credential-file <0600-file> [--rotation-operator <trusted-path>]`
- `recover --new-credential-file <expected-path> [--rotation-operator <trusted-path>]`
- `unpair --api-url https://... --deployment-id ... --agent-id ...`
- `uninstall`

The credential is read only from `<stateDir>/deployment-credential` (0600 in a 0700 directory). Never pass it in an argument, environment variable, ordinary OpenClaw config, or log. Rotation uses the operator-supplied durable non-secret server rotation ID and a trusted root-owned callback executable whose fixed grammar carries IDs only; it does not add a remote administration endpoint. Rotation first writes and fsyncs a new exclusive 0600 staged file while the old active path remains untouched, preserves the old material in a private retirement file, tests the new credential, and activates with one rename over the existing path followed by directory fsync. It then confirms active connector use, records the server's bounded-overlap activation, obtains exact atomic old-revocation/completion confirmation, and durably removes the retirement file, input delivery file, and secret-free recovery journal. Restart recovery requires the original expected delivery path even when that file is already absent, making explicit delivery retirement idempotent before the journal is removed. It reconciles the journal with complete file IDs and fingerprints; it never restores an old credential after an ambiguous activation or revocation response. If trusted reconciliation instead returns the exact unchanged server `PENDING` state after its deadline, the connector journals that terminal observation, atomically restores and fsyncs the preserved old credential first, and only then invokes exact idempotent server cancellation/output retirement. Each rollback step is restart-safe and a wrong-state or wrong-ID response cannot trigger restoration or report success.

`rotate`, `recover`, and `unpair` share one durable lifecycle interlock. An unfinished rotation blocks unpair and reports the supported connector recovery command; an unfinished unpair blocks a new rotation. `unpair` first creates the durable local disabled control and a secret-free recovery record, confirms idempotent server self-revocation with the exact local credential ID, records that confirmation, and only then deletes the local credential. Ambiguous responses and local-delete failures cannot report success. A restart either retries the idempotent server confirmation or finishes the already-confirmed local deletion without issuing another revocation.

`uninstall` delegates to the supported `openclaw plugins uninstall` command and preserves the state directory and receipts. A gateway reload/restart completes removal of the host-owned hook registry; the public `api.on` contract in the inspected build does not expose an in-process unregister handle. Gateway stop requests abort and bounded drain for every connector-owned operation. `CLEAN` proves zero connector-owned queue, timer, request, response, socket, promise, and correlation residue. A concrete transport that ignores abort remains visibly owned as `NON_CLEAN_DEADLINE`; it is not reported clean or zero until actual close/settlement advances it to `CLEAN_AFTER_DEADLINE`.

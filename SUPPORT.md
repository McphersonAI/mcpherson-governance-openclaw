# Support — McPherson Governance Connector v0.6.2

## Where to go

| Need | Where |
| --- | --- |
| Bug reports, feature requests | https://github.com/McphersonAI/mcpherson-governance-openclaw/issues |
| Security vulnerabilities | **admin@mcphersonai.com** privately — see [SECURITY.md](./SECURITY.md) |
| General questions | https://github.com/McphersonAI/mcpherson-governance-openclaw/issues |

Best-effort, no SLA, no guaranteed response time. This is provided as-is under
the Apache License 2.0.

## Before filing an issue

Please include:

- the output of `openclaw --version`;
- `node --version`;
- the package version (`0.6.2`) and the archive SHA-256 if you have it;
- what you ran and what happened;
- any error code (they are stable identifiers, e.g. `live_receipt_contract_invalid`).

Please do **not** paste receipt ledgers, credentials, or configuration
containing real deployment or agent identifiers.

## Troubleshooting

| Symptom | Explanation |
| --- | --- |
| `remote_status: NOT_ATTEMPTED`, `local_disposition: SKIPPED` on many tools | Expected. Those tools have no complete configured metadata, so no HTTPS request was made and execution was unchanged. Not an error. |
| Zero receipt groups / `latency_events: 0` | Expected in the default shadow posture: the connector writes only `gateway_start` / `gateway_stop` lifecycle records and no attempt or completion receipts. Do not enable the connector to make counts appear. |
| `live_receipt_contract_invalid` after upgrading | The ledger contains records from more than one connector version. Follow the rotation procedure in [INSTALL.md](./INSTALL.md) §6. This is the contract failing closed by design. |
| Connector inert on startup | The host is below OpenClaw 2026.6.5. The connector enforces its own minimum and stays inert rather than activating. |
| CLI exits 0 and prints nothing | The script was invoked through a path containing a symlink, so its entry-point guard did not match. Resolve the real path first (`cd <dir> && pwd -P`) and re-run. On macOS this happens by default under `$TMPDIR`, because `/var` is a symlink to `/private/var`. |
| `live_package_manifest_invalid` | `--package-manifest` must be an absolute path to the `V6-PACKAGE-MANIFEST.json` shipped in this package. |
| `live_package_source_binding_invalid` | The observer modules do not match the manifest. The package has been modified after build; re-verify with `npm run verify`. |
| `live_profile_binding_*` | The local binding is missing, malformed, altered, rehashed, stale, insecure, package-mismatched, has the wrong independently captured ID, or does not match the requested profile/path. Do not edit it. Follow [INSTALL.md](./INSTALL.md) §4 to initialize a new binding at a new private path, capture its exact `binding_id`, and verify it. |
| `live_runtime_*` during binding | The explicit profile home does not contain an audited OpenClaw runtime — `2026.6.5 (5181e4f)`, `2026.6.33 (7af0cfc)`, or `2026.7.1-2 (0790d9f)` — at its bound home-relative path, or the runtime changed. Restore an independently sourced audited runtime and initialize a new binding. |
| `LIVE_PATH_COMPONENT_UNREADABLE` at `identity/device-auth.json` on 2026.7.1-2 | That OpenClaw build does not issue a device-bound operator token to a local CLI using shared-secret auth on a loopback Gateway, so the file is never created. This is expected on `2026.7.1-2`; the observer will not accept the shared Gateway token instead. Run live observation on `2026.6.33` (preferred) or `2026.6.5`. |
| Output path refuses to be written | By design: existing paths are never overwritten. Choose a new output directory or file. |
| A configured tool records a remote `404` | The service could not resolve the deployment, agent, tool, or contract. It is a remote contract or registry failure, not an execution decision, and it cannot block your tool. |

## What support cannot do

We cannot enable enforcement, blocking, approval, denial, delay, rewrite, or
automatic mapping activation in this release. Those do not exist in v0.6.0 and
are not configuration options.

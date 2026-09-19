# Observa local CLI — 0.7.3

Observa provides governance visibility for AI agents. This OpenClaw
package adds one primary executable, `observa`. It adds no execution authority.

```text
observa --help
observa --version
observa status
observa agents
observa agent <id>
observa activity [--limit 20]
observa decisions [--limit 20]
observa pair --api-url https://<host> [--code-file <owner-only-file>]
observa enable
observa disable
observa killswitch on|off
observa lock on|off
observa credential rotate --new-credential-file <file> --rotation <id>
observa credential recover --new-credential-file <file>
observa unpair
observa uninstall
observa request-access
observa request-status
```

Every major command supports `--help`. No arguments also prints help. `--json`
selects the versioned `observa-cli/v1` metadata envelope for inspection, controls,
lifecycle, version and Hosted request commands. Help remains text. Pairing uses
the existing hidden-terminal/owner-only-file flow and explicitly refuses `--json`.
Unknown options and invalid arguments return a bounded error with exit status 1;
empty local views exit 0. Failed admission operations return a bounded error and
retain the private request receipt for a retry.

Use `--profile <name>` and, when needed, `--profile-home <home>` to select an
OpenClaw profile. `OPENCLAW_STATE_DIR` supports a custom runtime root; it must agree
with explicit profile selectors. A conflicting `OPENCLAW_CONFIG_PATH` is refused.
No command searches other profiles. Pair retains the existing named/default
profile model; custom roots cannot be coerced into another profile for pairing.

## Hosted beta access

Run `observa request-access --api-url https://<host>`. Enter name, email and
optional organization/use case, review the exact bounded metadata, and explicitly
confirm. A one-time email code expires in 10 minutes; paste it at the hidden
prompt. The verified request enters the founder's Access Requests queue.

For automation, supply `--name`, `--email`, `--yes` and `--json`. Verify in a
second invocation with `--code-file <0600-file>`; verification codes and private
request credentials never appear in JSON. `--resend` retries email delivery.
The owner-only receipt is in the selected profile's `observa-access/request.json`;
request status never authenticates with a runtime or installation credential.

`observa request-status --json` returns the saved request's state. Approval sends
an existing single-use beta invite to the verified email. Redeem it in Hosted,
sign in, accept the beta documents, and obtain a pairing code. Then run
`observa pair`. Missing invitation mail can be retried with
`observa request-access --resend`. Expired or denied requests can start again
with `--new`. Different emails require new verification.

Approval authorizes beta onboarding only: tenant/workspace and role come from
the staff decision; composition approval and automatic signed-manifest issuance
retain their existing separate server-side authority. No paid entitlement or
installation credential is issued by an access request. Public local use remains
available without approval. Access requests need a Hosted service with
admission routing, durable storage and email delivery configured.
This package includes the root `openclaw.plugin.json` required for managed installation.
Its plugin manifest id is `mcpherson-governance-connector` and the npm package is
`@mcphersonai/mcpherson-governance-openclaw`. OpenClaw notes the difference and uses
the manifest id as the config key; that is intentional and stable. Installed profiles
key `plugins.entries.mcpherson-governance-connector` on it, so the id is not renamed.
Signed component manifests are consumed by the Local Node installer. This
OpenClaw package uses managed plugin installation and credential pairing.

## What the local views prove

`agents` uses the runtime-completeness configured roster function: `agents.entries`
or the supported `agents.list` equivalent. A readable empty host config has
OpenClaw's implicit default roster; missing/corrupt config never invents one.
Configured agents without completion receipts have no observed capabilities.
`agent <id>` combines that roster with locally evidenced activity and decisions.

`activity` reads actual validated completion receipts, including completion/failure/
timeout metadata. Attempt receipts, lifecycle records and heartbeat are not
meaningful activity. `decisions` reads SHADOW decision records and projects only
WOULD_ALLOW, WOULD_DENY, WOULD_REQUIRE_APPROVAL, ABSTAIN, INDETERMINATE and ERROR
when present. It never derives decisions from activity or claims business success.
An agent with decision evidence alone remains `DECISION_ONLY`, not observed.

Each evidence file is read from its final 1 MiB; each record is limited to 16 KiB.
The default result limit is 20 (maximum 100). Agent identity and capability sets
refer to this inspected local window, not all-time history. ACTIVE means meaningful
activity in the last five minutes, not active governance. QUIET means older local
activity; CONFIGURED means no completion in the inspected window. `never` means no
meaningful activity evidenced in this view. Truncation and corrupt/rejected records
are reported; healthy-looking partial output does not hide evidence warnings.

`status` resolves plugin configuration from the selected `openclaw.json`, then
combines it with durable observation controls. It distinguishes plugin installation
metadata, plugin configuration, pairing, enabled configuration intent, observing
evidence and Hosted connection state. Package manifests prove an installed package
where available; they do not prove a loaded gateway. Runtime version comes from
last local SHADOW evidence and is labelled as historical. Credentials are read only
through the existing safe descriptor path; only the existing identifier/fingerprint
can appear, never the credential.

The inherited runtime does not persist heartbeat or current Hosted connection
state locally. Accordingly heartbeat is `NOT_AVAILABLE`, live runtime is
`NOT_PROBED`, and pairing is never called a current Hosted connection. Recent
completion evidence is labelled `RECENT_LOCAL_EVIDENCE`; old evidence is STALE;
a later gateway-stop receipt produces STOPPED. None is a live-process claim.
No inspection starts a gateway, contacts Hosted or changes local files.

Plain JSON is supported, matching the existing pairing configuration reader.
JSON5, includes, environment substitutions and foreign state/receipt paths are
refused explicitly instead of falling back to standalone defaults. This is a
bounded local CLI, not a second OpenClaw configuration engine.

## Controls and compatibility

`enable` enables this plugin's entry and connector configuration when necessary,
preserves other config, and clears its durable disable flag. A gateway reload may
be required after a configuration change; the command says so. It never opens
global plugin gates or enables other plugins.

`disable`, `killswitch on` and `lock on` each stop **all** Observa Hosted outbound
traffic from the plugin runtime: observations, SHADOW evaluations, the startup
runtime roster, and the periodic liveness heartbeat. While any of them is active
the plugin makes zero Hosted requests and never reads the paired credential, on a
fresh gateway start as well as mid-session, and a retry armed before the control
was set still refuses when it fires. Precedence is disable, then kill switch, then
lock; an unreadable or malformed control file fails closed. Clearing the control
resumes ordinary publication without a gateway restart. Ordinary OpenClaw tools
continue unchanged throughout — these controls stop Observa, never your agents.

Two Hosted paths are deliberately outside that stop, because each is an explicit
operator command rather than background traffic: `pair` (which redeems a pairing
code and has no credential to obey a control with yet) and `unpair` (which sets
the durable disable flag first, then confirms server-side revocation before
deleting the local credential). `request-access`/`request-status` use their own
per-request owner key and never touch the installation credential.

Pair, authenticated rotation/recovery and unpair reuse the inherited lifecycle
implementation. Rotation still requires the existing trusted server operator;
there is no new admin backend. Unpair deletes credentials only after revocation
confirmation and retains existing recovery state on failure. Uninstall invokes
the existing OpenClaw plugin uninstaller in the selected profile and preserves
receipts; it does not itself revoke credentials.

`observa-pair` routes to `observa pair` and retains its existing options.
`observa-openclaw-ctl status|enable|disable|unpair|uninstall` routes to the matching
command. `rotate`/`recover` route to `credential rotate`/`credential recover`, and
`killswitch --on|--off`/`lock --on|--off` route to the corresponding subcommands.
The ctl alias retains its legacy JSON result fields and callable `runConnectorCtl`
export. Help works through both aliases. Explicit legacy endpoint/deployment/agent/
state flags must agree with the selected profile; mismatched selectors now fail
safely instead of operating on ambiguous or foreign state. The original lifecycle
implementation is also retained in `connector-ctl-legacy.mjs`.

The existing Local Node installer package (`@mcphersonai/observa-cli`) and its
working entry points are unchanged in this release. This OpenClaw package does
not replace or bundle that installer. The shared command router selects a bounded
runtime provider (`--runtime openclaw`); Local Node/n8n, MCP and custom adapters can
supply the same projected snapshot and bounded controls later. No dynamic plugin
platform, alternate runtime adapter or MCP implementation is included here.

All paths, outputs and status fields describe local metadata. No prompts, messages,
command bodies, tool result bodies, environment values, pairing codes, approval
tokens or credential contents are emitted by the inspection views. Unsafe file
ownership/permissions, symlinks, hardlinks and foreign paths fail safely. The
owner-controlled local evidence files are not a remotely authenticated ledger.

## What leaves this machine

A paired, enabled installation sends exactly four kinds of request, all to the
endpoint bound at pairing, all over verified TLS, all bearing the installation
credential:

| Request | When | Contents |
| --- | --- | --- |
| `POST /v1/runtime/inventory` | once per gateway start | runtime instance id, generation, the configured agent id list, roster revision |
| `POST /v1/runtime/heartbeat` | every 60s | runtime instance id, generation, sequence, cadence |
| `POST /v1/observations`, `POST /v1/decisions` | per observed tool call | bounded identity and classification metadata |
| `POST /v1/openclaw/shadow/evaluate` | per governed tool call | bounded metadata, executable name, correlation reference, digest of tool arguments |

Roster and heartbeat carry no tool identities, no capabilities, no activity and
no business claim; they say this runtime is alive and which agent ids the host
configures. No request ever carries a prompt, message body, command body, tool
result, exception body, environment value, pairing code, approval token or
credential content. All five paths obey `disable`, the kill switch and the lock.

## Capabilities this plugin asks for

The plugin registers four OpenClaw hooks — `before_tool_call`, `after_tool_call`,
`gateway_start`, `gateway_stop` — and one tool, `mcpherson_connection_test`, which
takes no arguments, makes no network call and returns a fixed marker.

It builds no prompt and mutates no conversation, so `pair` and `enable` write
`hooks.allowPromptInjection: false` and `hooks.allowConversationAccess: false`
into this plugin's own `openclaw.json` entry, and OpenClaw's capability review
then reports both as denied. An explicit value you have already set is preserved.
Because OpenClaw grants prompt injection by default to any plugin whose entry is
silent, and because a first-time install has no entry yet, the approval screen on
the very first `openclaw plugins install` shows the host default until `pair` or
`enable` writes the policy; to see it denied at first install, add the entry with
those two keys before installing.

SHADOW ONLY / AUTHORITY NONE / ENFORCEMENT OFF / ACTIVE OFF

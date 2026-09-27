# Observa local CLI — 0.7.4

Observa provides governance visibility for AI agents. This OpenClaw
package adds one primary executable, `observa`. It adds no execution authority.

```text
# Local (offline; never contacts Hosted)
observa --help
observa --version
observa status
observa agents
observa agent <id>
observa activity [--limit 20]
observa decisions [--limit 20]

# Hosted access (start here for the Hosted dashboard)
observa request-access --api-url https://<host>
observa request-status
observa pair --api-url https://<host> [--code-file <owner-only-file>]

# Hosted health / refresh (after pairing; contacts Hosted)
observa hosted-health
observa identify

# Controls
observa enable
observa disable
observa killswitch on|off
observa lock on|off

# Lifecycle
observa credential rotate --new-credential-file <file> --rotation <id>
observa credential recover --new-credential-file <file>
observa unpair
observa uninstall [--yes]
```

## Getting the `observa` command

```sh
openclaw plugins install clawhub:@mcphersonai/mcpherson-governance-openclaw
# restart the OpenClaw gateway (required for any plugin to load), then:
observa --help
```

OpenClaw installs plugins with package scripts disabled and does not link a
plugin's `bin` entries, and its plugin CLI API only adds `openclaw <command>`
subcommands, so the plugin provides the command itself. On every gateway start
it ensures one small launcher named `observa` in the directory that holds the
`openclaw` launcher the gateway was started from — for an npm global install
the npm prefix `bin` directory, such as `~/.local/bin` or `/usr/local/bin`. No
PATH edit, alias, Local Node install or knowledge of the extension directory is
needed: if `openclaw` is on your PATH, so is `observa`.

The launcher contains no product code. It runs the CLI of the installed plugin
directory and passes arguments through unchanged, so an update takes effect
without rewriting it, and a reinstall is idempotent. It is written exclusively
(never over an existing file) and only into a directory, and ancestors, that no
other user can write. If the plugin is later removed, the launcher prints
`OBSERVA_PLUGIN_NOT_INSTALLED` with the reinstall and `rm` commands and runs
nothing else; it never falls back to another Observa package.

An existing `observa` that is not this plugin's launcher is never overwritten
or removed. Observa Local Node (`@mcpherson-ai/observa-local-node`) also ships
an `observa` command; when it holds the name, the plugin records
`COLLISION_LOCAL_NODE`, leaves Local Node untouched, and `observa status` (run
as `node <extension-dir>/observa.mjs status`) prints the remediation: remove
Local Node's global command or keep using the direct path. Any other file gives
`COLLISION_UNKNOWN`. `observa uninstall` removes only this plugin's own
launcher. `openclaw plugins uninstall` alone does not run plugin code, so after
it the leftover launcher explains itself and can be removed with `rm`. With
several OpenClaw profiles, the launcher follows the most recently started
gateway; `--profile` still selects which profile's state every command reads.
Windows is not supported by the launcher; use `node <extension-dir>\observa.mjs`.

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

`status` never contacts Hosted. Its heartbeat line comes from the gateway's local
publication journal (the last heartbeat Hosted accepted) and is `NOT_AVAILABLE`
until a gateway running this version has had one accepted; live runtime stays
`NOT_PROBED`, and pairing is never called a current Hosted connection. Recent
completion evidence is labelled `RECENT_LOCAL_EVIDENCE`; old evidence is STALE;
a later gateway-stop receipt produces STOPPED. None is a live-process claim.
No inspection starts a gateway, contacts Hosted or changes local files.

Plain JSON is supported, matching the existing pairing configuration reader.
JSON5, includes, environment substitutions and foreign state/receipt paths are
refused explicitly instead of falling back to standalone defaults. This is a
bounded local CLI, not a second OpenClaw configuration engine.

## Hosted health and identify

`observa hosted-health` is the deliberate, networked counterpart of `status`.
With the paired credential it calls the existing `GET /v1/health` and
`GET /v1/credentials/identity` contracts and reports: paired, credential
present, Hosted reachable, installation binding (credential id and deployment
accepted by Hosted), the deployment id, workspace binding (resolved by Hosted
from the credential and not disclosed), last successful Hosted contact, and
the runtime heartbeat and roster freshness the gateway recorded. States include
`HEALTHY`, `NOT_PAIRED` (with the request-access → request-status → pair next
steps), `REFUSED_BY_CONTROL`, `UNREACHABLE`, `CREDENTIAL_REFUSED`,
`BINDING_MISMATCH`, `HOSTED_UNAVAILABLE`, `CONNECTED_HEARTBEAT_STALE` and
`CONNECTED_HEARTBEAT_UNKNOWN`. Exit status is 0 only for `HEALTHY`, 2 for a
completed check that is not healthy, 1 when the check could not run.

`observa identify` reports the agents the selected OpenClaw profile configures
(the same configured-roster function the runtime publishes). When paired, it
confirms that roster on Hosted through the existing `POST /v1/runtime/inventory`
contract under the running gateway's own runtime instance and generation, read
from the gateway's local publication journal. Hosted gives roster ownership to
the highest runtime generation, so `identify` never claims one: an unchanged
roster is an idempotent confirmation (`ROSTER_CONFIRMED`), and a roster changed
since the gateway started is reported as `ROSTER_CHANGED_RESTART_REQUIRED` and
left for the gateway to publish on restart. Unpaired, it still identifies the
agents locally and shows the access funnel.

Neither command sends a heartbeat or writes a receipt, activity record or
governance decision, so no agent becomes ACTIVE and the dashboard's activity
stays truthful. Both obey `disable`, the kill switch and the lock: when one is
active they report `REFUSED_BY_CONTROL` without reading the credential or
opening a connection. Neither changes controls, mappings, configuration,
policy or authority.

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

The operator's `hosted-health` and `identify` commands are inside that stop too.
Two Hosted paths are deliberately outside it, because each is an explicit
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
receipts; it does not itself revoke credentials. OpenClaw 2026.8.2 asks to
confirm a plugin removal: in a terminal you answer OpenClaw's own prompt, and
non-interactive callers pass `observa uninstall --yes` (without it they get
`UNINSTALL_CONFIRMATION_REQUIRED` and nothing is removed). Only after OpenClaw
confirms the removal does `uninstall` delete this plugin's own `observa`
launcher.

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

A paired, enabled installation sends exactly four kinds of background request,
all to the endpoint bound at pairing, all over verified TLS, all bearing the
installation credential:

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

Only when you run them, `observa hosted-health` sends `GET /v1/health` and
`GET /v1/credentials/identity` (no body), and `observa identify` sends one
`POST /v1/runtime/inventory` with the same roster fields as the gateway. They
obey the same controls.

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

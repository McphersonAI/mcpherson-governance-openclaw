# Disable, Uninstall, and Rollback

**Connector v0.5.1.** Every control here is **local**. None of them requires the
governance endpoint to be reachable, and none can be overridden remotely.

## Two layers, two meanings of "off"

| Command | Effect |
| --- | --- |
| `openclaw plugins disable <id>` | OpenClaw stops loading the plugin entirely |
| `connector-ctl disable` | The connector stays loaded but becomes **inert** |

Both are valid full stops. Use OpenClaw's when you want the plugin gone from
the host's load path; use the connector's when you want a durable, auditable
local control that survives restarts and reload.

**Operationally disabled means inert**, not merely quiet:

- both tool-observation hook handlers (`before_tool_call`, `after_tool_call`)
  return immediately;
- no governance request is sent;
- no ordinary observation receipt is written;
- no shadow observation is active.

OpenClaw may still list the plugin as `enabled` and may still show registered
hook entrypoints. That reflects the host's load state, not connector activity.
Disabling takes effect immediately, including for a call whose pre-hook already
ran.

The gateway lifecycle hooks still write a `connector_lifecycle` record noting
that the connector was loaded. It carries no tool, agent, or decision metadata
and is not an observation receipt.

## Paths and the control CLI

The connector's control CLI is **not on your `PATH`** after a ClawHub download
plus an OpenClaw archive install — that install method copies files into the
profile and creates no command links. Invoke it by explicit path:

```sh
PROFILE=my-profile
INSTALL_DIR="$HOME/.openclaw-$PROFILE/extensions/mcpherson-governance-connector"
STATE_DIR="$HOME/.openclaw-$PROFILE/mcpherson-governance-connector"

export OPENCLAW_STATE_DIR="$HOME/.openclaw-$PROFILE"
CTL="node $INSTALL_DIR/connector/connector-ctl.mjs"
```

`OPENCLAW_STATE_DIR` is what binds the CLI to the right profile. Every
`$CTL` invocation below assumes it is exported. For the default profile, use
`$HOME/.openclaw` and drop `--profile` from the OpenClaw commands.

## Control precedence

Local controls are evaluated before credentials are read and before any network
I/O, in this order:

```
DISABLED  >  KILL_SWITCH  >  SYSTEM_LOCK  >  CANARY  >  REMOTE_OBSERVATION
```

A higher control short-circuits everything below it. When any of the first three
is active, **zero network calls occur** — no credential read, no request built,
no socket opened.

## Level 1 — Kill switch (stop remote contact, keep observing locally)

Stops all remote contact before any network I/O. Local receipts continue —
this is the difference between the kill switch and a full disable.

```sh
$CTL killswitch --on
$CTL status            # confirm KILL_SWITCH_ACTIVE
```

Undo:

```sh
$CTL killswitch --off
```

## Level 2 — System lock

A separate durable local control with the same before-any-network guarantee.
Local receipts continue, as with the kill switch. Useful for maintenance
windows where you want a distinct, independently auditable reason recorded.

```sh
$CTL lock --on
$CTL lock --off
```

## Level 3 — Disable (make the connector inert, keep it installed)

The full stop. The plugin stays installed and loaded; it stops observing, stops
all remote contact, and stops writing observation receipts.

```sh
$CTL disable
$CTL status            # confirm disabled
```

This writes a **durable** local disabled control that survives restarts.

Re-enable — deliberately, and note it takes both:

```sh
openclaw --profile "$PROFILE" config set \
  'plugins.entries.mcpherson-governance-connector.config.enabled' true --strict-json
$CTL enable
```

`enable` only clears the durable control. It does not override plugin
configuration, and configuration alone does not clear the durable control.
Both must agree.

To stop the host from loading the plugin at all:

```sh
openclaw --profile "$PROFILE" plugins disable mcpherson-governance-connector
openclaw --profile "$PROFILE" plugins info mcpherson-governance-connector --json
```

Expect `"enabled": false` and no registered tools or hooks.

## Level 4 — Unpair (revoke the credential)

Revokes the deployment credential server-side **first**, then deletes it
locally.

```sh
$CTL unpair \
  --api-url https://YOUR-GOVERNANCE-ENDPOINT \
  --deployment-id YOUR-DEPLOYMENT-ID \
  --agent-id YOUR-AGENT-ID
```

Behavior worth knowing:

- Unpair creates the durable disabled control **before** it does anything else,
  so the connector is already inert while unpair proceeds.
- It confirms idempotent server-side revocation against the exact local
  credential ID, records that confirmation, and only then deletes the local
  credential.
- An ambiguous server response or a failed local delete **cannot report
  success**.
- An interrupted unpair is restart-safe: it either retries the idempotent
  server confirmation or completes the already-confirmed local deletion.
- **Your receipts stay with you.** Unpair does not touch them.

If unpair cannot reach the endpoint and you need an immediate local stop:

```sh
$CTL disable
rm -f "$STATE_DIR/deployment-credential"
```

Then complete the server-side revocation when you can.

## Level 5 — Uninstall

Uninstall through OpenClaw, in the same profile you installed into. Preview
first:

```sh
openclaw --profile "$PROFILE" plugins uninstall \
  mcpherson-governance-connector --dry-run

openclaw --profile "$PROFILE" plugins uninstall \
  mcpherson-governance-connector --force
```

The dry run lists exactly what will be removed: the plugin config entry, the
install record, and the installed directory under that profile's `extensions/`.

- **The state directory and receipts are preserved.** Uninstall removes the
  installed plugin files; it does not delete your evidence.
- **Only the named profile is touched.** Another profile's installation and
  state are unaffected.
- A gateway reload or restart completes removal of the host-owned hook registry.
- Gateway stop aborts and bounded-drains every connector-owned operation.

Verify removal:

```sh
openclaw --profile "$PROFILE" plugins info mcpherson-governance-connector --json
# expect: Plugin not found
openclaw --profile "$PROFILE" plugins list --json
```

Recommended order:

```sh
$CTL disable                          # make it inert first
$CTL unpair --api-url ...             # if paired
openclaw --profile "$PROFILE" plugins uninstall \
  mcpherson-governance-connector --force
# restart or reload the OpenClaw gateway
```

To remove your local data as well — this is irreversible, and affects only this
profile:

```sh
rm -rf "$STATE_DIR"
```

Archive your receipts first if you need them for evidence.

## Level 6 — Rollback

The connector is shadow-only, so **there is no enforcement state to unwind**. It
never blocked, approved, or modified anything, so removing it cannot leave your
agents in a changed decision state.

Rollback is therefore simply removal:

1. `$CTL disable`
2. `$CTL unpair ...` if paired
3. `openclaw --profile "$PROFILE" plugins uninstall mcpherson-governance-connector --force`
4. Reload or restart the OpenClaw gateway
5. Confirm OpenClaw no longer lists `mcpherson-governance-connector`
6. Optionally restore your previous plugin set through OpenClaw's supported
   mechanism

Your receipts remain valid records of what was observed while it ran. Nothing
about rollback invalidates them.

## Verifying a clean stop

```sh
$CTL status
```

Shutdown reports:

| State | Meaning |
| --- | --- |
| `CLEAN` | Zero connector-owned queue, timer, request, response, socket, promise, and correlation residue |
| `CLEAN_AFTER_DEADLINE` | Settled cleanly, but after the shutdown deadline |
| `NON_CLEAN_DEADLINE` | A transport ignored abort and is still genuinely owned |

`NON_CLEAN_DEADLINE` is reported honestly rather than being rounded up to
"clean" — the connector does not claim zero residue until residue is actually
zero. If you see it persist, capture the `status` output for a support report.

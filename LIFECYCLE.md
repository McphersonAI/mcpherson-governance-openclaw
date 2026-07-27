# Disable, Uninstall, and Rollback

**Connector v0.5.0.** Every control here is **local**. None of them requires the
governance endpoint to be reachable, and none can be overridden remotely.

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

Stops all remote contact before any network I/O. Local receipts continue.

```sh
connector-ctl killswitch --on
connector-ctl status            # confirm KILL_SWITCH_ACTIVE
```

Undo:

```sh
connector-ctl killswitch --off
```

Use this when you want observation to continue but all outbound traffic to stop
immediately.

## Level 2 — System lock

A separate durable local control with the same before-any-network guarantee.
Useful for maintenance windows where you want a distinct, independently
auditable reason recorded.

```sh
connector-ctl lock --on
connector-ctl lock --off
```

## Level 3 — Disable (stop all connector activity, keep it installed)

The full stop. The plugin stays installed; it stops observing and stops all
remote contact.

```sh
connector-ctl disable
connector-ctl status            # confirm disabled
```

This writes a **durable** local disabled control that survives restarts.

Re-enable — deliberately, and note it takes both:

```sh
# 1. set "enabled": true in plugin configuration, then
connector-ctl enable
```

`connector-ctl enable` only clears the durable control. It does not override
plugin configuration, and configuration alone does not clear the durable
control. Both must agree.

## Level 4 — Unpair (revoke the credential)

Revokes the deployment credential server-side **first**, then deletes it
locally.

```sh
connector-ctl unpair \
  --api-url https://YOUR-GOVERNANCE-ENDPOINT \
  --deployment-id YOUR-DEPLOYMENT-ID \
  --agent-id YOUR-AGENT-ID
```

Behavior worth knowing:

- Unpair creates the durable disabled control **before** it does anything else,
  so the connector is already stopped while unpair proceeds.
- It confirms idempotent server-side revocation against the exact local
  credential ID, records that confirmation, and only then deletes the local
  credential.
- An ambiguous server response or a failed local delete **cannot report
  success**.
- An interrupted unpair is restart-safe: it either retries the idempotent
  server confirmation or completes the already-confirmed local deletion.
- **Your receipts stay with you.** Unpair does not touch them.

If unpair cannot reach the endpoint and you need an immediate local stop, use
`connector-ctl disable` and delete the credential file yourself:

```sh
connector-ctl disable
rm -f ~/.openclaw/mcpherson-governance-connector/deployment-credential
```

Then complete the server-side revocation when you can.

## Level 5 — Uninstall

Delegates to OpenClaw's supported uninstall command:

```sh
connector-ctl uninstall
```

- **The state directory and receipts are preserved by default.** Uninstall does
  not delete your evidence.
- A gateway reload or restart completes removal of the host-owned hook registry.
  The plugin API in the inspected OpenClaw build exposes no in-process
  unregister handle, so the hook entry clears on reload rather than instantly.
- Gateway stop aborts and bounded-drains every connector-owned operation.

Recommended order:

```sh
connector-ctl disable                 # stop activity first
connector-ctl unpair --api-url ...    # if paired
connector-ctl uninstall               # then remove
# restart or reload the OpenClaw gateway
```

To remove your local data as well — this is irreversible:

```sh
rm -rf ~/.openclaw/mcpherson-governance-connector
```

Archive your receipts first if you need them for evidence.

## Level 6 — Rollback

The connector is shadow-only, so **there is no enforcement state to unwind**. It
never blocked, approved, or modified anything, so removing it cannot leave your
agents in a changed decision state.

Rollback is therefore simply removal:

1. `connector-ctl disable`
2. `connector-ctl unpair ...` if paired
3. `connector-ctl uninstall`
4. Reload or restart the OpenClaw gateway
5. Confirm OpenClaw no longer lists `mcpherson-governance-connector`
6. Optionally restore your previous plugin set through OpenClaw's supported
   mechanism

Your receipts remain valid records of what was observed while it ran. Nothing
about rollback invalidates them.

## Verifying a clean stop

```sh
connector-ctl status
```

Shutdown reports:

| State | Meaning |
| --- | --- |
| `CLEAN` | Zero connector-owned queue, timer, request, response, socket, promise, and correlation residue |
| `CLEAN_AFTER_DEADLINE` | Settled cleanly, but after the shutdown deadline |
| `NON_CLEAN_DEADLINE` | A transport ignored abort and is still genuinely owned |

`NON_CLEAN_DEADLINE` is reported honestly rather than being rounded up to
"clean" — the connector does not claim zero residue until residue is actually
zero. If you see it persist, capture `connector-ctl status` output for a
support report.

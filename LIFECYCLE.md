# Lifecycle — McPherson Governance Connector v0.6.3-beta.6

How to enable, disable, stop, rotate, upgrade, and remove the connector, and
what each action does and does not touch.

## State layout

Connector state lives in a fixed directory name inside the **active** OpenClaw
profile state directory:

```
<OPENCLAW_PROFILE_STATE_DIR>/mcpherson-governance-connector/
  receipts/
    connector-receipts.jsonl   receipt ledger (owner-only, 0600)
  deployment-credential        remote shadow credential, only if paired
  governance-killswitch.on     kill switch marker
  system.lock                  system lock marker
  connector-disabled.on        operational disable marker
  canary-control.json          canary tool control
```

Named profiles do not share controls, receipts, or state with the default
profile or with each other.

## Control CLI

The package installs the `mcpherson-connector-ctl` command. It can also be run
directly:

```sh
node <PACKAGE_ROOT>/plugins/openclaw-connector/connector-ctl.mjs status
```

| Command | Effect |
| --- | --- |
| `status` | Report non-authoritative status as JSON |
| `enable` | Clear the operational disable marker |
| `disable` | Write the operational disable marker |
| `rotate --rotation <id>` | Rotate the deployment credential |
| `recover` | Recover credential state |
| `unpair` | Remove the deployment credential |
| `uninstall` | Remove connector state, preserving receipts |

`status` is informational only. Nothing in this CLI grants authority.

## The three stop controls

| Control | Remote contact | Local receipt | Notes |
| --- | --- | --- | --- |
| **Operational disable** (`connector-disabled.on`) | stopped | **none** | Fully inert for ordinary observations. Takes effect immediately, including for a call whose pre-hook ran while still enabled. |
| **Kill switch** (`governance-killswitch.on`) | stopped | still written | Records `remote_status` reflecting the control and `local_disposition: SKIPPED`. |
| **System lock** (`system.lock`) | stopped | still written | Same shape as the kill switch. |

Disabling is the strongest: no completion receipt is written while
operationally disabled.

## Default posture

`enabled` defaults to `false`. In that shadow posture the connector emits
**only** `gateway_start` and `gateway_stop` lifecycle records — no attempt or
completion receipts. A local observation will therefore report zero receipt
groups and zero latency events. **That is the correct, expected result.** Do not
enable the connector merely to make those counts non-zero: enabling changes
observation behavior and is a deliberate operator decision.

## Receipt ledger

- JSONL, one record per line, owner-only `0600`.
- Every line is validated. There is no window filter and no partial-parse mode.
- Lifecycle records are pinned to **one exact connector version**.
- An empty `0600` ledger is a valid state.

## Version transitions — the ledger rotation contract

**This is required when upgrading between connector versions, including
v0.5.1 → v0.6.3-beta.6.**

Because every line is validated against one exact version, a ledger holding
records from two connector versions fails closed with
`live_receipt_contract_invalid`. That is deliberate: mixed-version records must
never be parsed as one current-version ledger.

Two traps, both learned from the previous version transition:

1. **Upgrading the connector alone is not enough.** The ledger path is unchanged
   across versions, so historical records keep failing forever until the ledger
   is rotated.
2. **Rotating before the restart is not enough.** The still-loaded old connector
   writes one final `gateway_stop` at the **old** version during shutdown. The
   true boundary is *after the old process exits*.

The correct order:

1. Stop or restart the old connector so it writes its final old-version
   `gateway_stop`.
2. Wait for the old process to exit. Do not proceed while it is running.
3. Rotate the ledger, moving it into an `0700` `archive/` directory with a
   timestamped, version-labelled name.
4. Start the new version.
5. Initialize a fresh ledger as owner-only `0600` (empty is valid).
6. Preserve the old ledger as evidence. Do not delete it and do not merge it.
7. Never parse mixed-version records as one current-version ledger.

Exact commands are in [INSTALL.md](./INSTALL.md) §6.

## Upgrading the package

Set `PROFILE_HOME` to the same physical home and `PROFILE` to the exact named
profile you intend to change. For an explicitly selected default profile, omit
`--profile "$PROFILE"`.

```sh
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  "$PROFILE_HOME/.local/bin/openclaw" --profile "$PROFILE" plugins update \
  mcpherson-governance-connector
```

Your configuration is keyed by **plugin ID**
(`plugins.entries.mcpherson-governance-connector.config`) and the state
directory name is a source-owned constant, so both survive the upgrade. The
plugin ID, package name, config schema, and the `mcpherson-connector-ctl`
command name are unchanged from v0.5.1.

Perform the ledger rotation above as part of the upgrade.

## Uninstall

Dry run first:

```sh
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  "$PROFILE_HOME/.local/bin/openclaw" --profile "$PROFILE" plugins uninstall \
  mcpherson-governance-connector --dry-run
```

Then:

```sh
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  "$PROFILE_HOME/.local/bin/openclaw" --profile "$PROFILE" plugins uninstall \
  mcpherson-governance-connector
```

`connector-ctl uninstall` removes connector state while **preserving the receipt
ledger** as evidence. If you want the receipts gone, remove them yourself,
deliberately, after confirming you no longer need them.

Uninstalling removes the plugin from the profile you targeted. It does not
modify other profiles.

## What is never done automatically

The connector never rotates, truncates, deletes, or merges your receipt ledger
on its own, never modifies another profile, never activates a mapping, and never
changes tool execution.

# Installation

**Connector v0.5.0.** Every step ends in something you can check locally, and
every step has an undo in [LIFECYCLE.md](LIFECYCLE.md).

The connector installs **disabled**. Nothing is observed and no network contact
occurs until you deliberately enable it.

## Prerequisites

- OpenClaw with plugin API `>=2026.6.5` (built and tested against `2026.6.5`,
  commit `5181e4f`).
- Node.js with ES module support (tested on Node 24).
- A user account that owns the OpenClaw runtime.
- Outbound HTTPS to your governance endpoint — only if you intend to enable it.

## Step 1 — Verify the package before you unpack it

Never install an archive you have not checksummed. Compare against the value in
the release manifest:

```sh
shasum -a 256 mcpherson-governance-openclaw-v0.5.0.tar.gz
```

Then verify the full file manifest after extraction — see [VERIFY.md](VERIFY.md).
Do not proceed if any file fails.

## Step 2 — Extract

```sh
tar -xzf mcpherson-governance-openclaw-v0.5.0.tar.gz
cd mcpherson-governance-openclaw-v0.5.0
```

## Step 3 — Verify the 28 connector files

```sh
shasum -a 256 -c CONNECTOR-FILES.sha256
```

All 28 lines must report `OK`. A single `FAILED` means the connector you are
about to install is not the verified one. Stop.

## Step 4 — Install through OpenClaw's supported plugin mechanism

Install the `connector/` directory using your OpenClaw build's supported plugin
install command. Use the supported mechanism — do not hand-copy files into
OpenClaw internals, and do not patch OpenClaw.

Confirm OpenClaw lists the plugin `mcpherson-governance-connector` as installed
before continuing.

## Step 5 — Create the state and receipt directories

The connector requires a private state directory. Ownership and modes matter —
the connector refuses to use directories that are not owner-only.

```sh
mkdir -p ~/.openclaw/mcpherson-governance-connector/receipts
chmod 700 ~/.openclaw/mcpherson-governance-connector
chmod 700 ~/.openclaw/mcpherson-governance-connector/receipts
```

## Step 6 — Configure, with `enabled: false`

Copy [examples/connector-config.example.json](examples/connector-config.example.json)
into your OpenClaw plugin configuration and replace **every** placeholder.

Keep `"enabled": false` for now.

Notes:

- `apiUrl` must be `https://`.
- `stateDir` and `receiptDir` must be absolute paths you own.
- `toolMetadata` is **manual capability mapping**. Tools you do not map produce
  registry 404 observations, which do not block execution but carry no useful
  classification. Map the tools you actually care about.
- Do **not** put a credential in this file. See Step 7.

## Step 7 — Place the deployment credential (only if using a governance endpoint)

The credential is read only from a `0600` file inside the `0700` state
directory. It is never accepted from a command argument, an environment
variable, or plugin configuration.

```sh
install -m 600 /path/to/issued-credential \
  ~/.openclaw/mcpherson-governance-connector/deployment-credential
```

If you are not pairing with a governance endpoint, skip this step and leave
`enabled` false — the connector will not attempt remote contact.

## Step 8 — Check status before enabling

```sh
connector-ctl status
```

Confirm: version `0.5.0`, shadow mode, and your expected disable/kill-switch/lock
state. Resolve anything unexpected here rather than after enabling.

## Step 9 — Enable deliberately

Set `"enabled": true` in the plugin configuration, then clear the durable
disabled control:

```sh
connector-ctl enable
```

`enable` only clears the local durable control — it does not override plugin
configuration. Both must agree before observation begins.

## Step 10 — Confirm it is working

```sh
connector-ctl status
```

Receipts should begin appearing in
`<receiptDir>/connector-receipts.jsonl` as tools run:

```sh
wc -l ~/.openclaw/mcpherson-governance-connector/receipts/connector-receipts.jsonl
```

Expect `attempt_receipt` records for observed calls, `completion_receipt`
records after observed completions, and — until mapping is complete — a number
of `404` remote statuses for unmapped tools. **None of this blocks your tools.**

## Step 11 — Optional: prove local authority is retained

If you want to confirm for yourself that local control beats everything:

```sh
connector-ctl canary --on
# invoke the connector's own mcpherson_governance_canary tool with the exact token
connector-ctl canary --off
```

The canary blocks only the connector's own diagnostic tool, never your tools.
Turn it off when finished.

## If something goes wrong

Every step above is reversible. Go to [LIFECYCLE.md](LIFECYCLE.md) for disable,
uninstall, and rollback. The fastest full stop is:

```sh
connector-ctl disable
```

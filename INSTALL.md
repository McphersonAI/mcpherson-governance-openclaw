# Installation

**Connector v0.5.1.** Every step ends in something you can check locally, and
every step has an undo in [LIFECYCLE.md](LIFECYCLE.md).

This is the **ClawHub installation path**, written against the commands ClawHub
and OpenClaw actually expose. ClawHub's package workflow provides `inspect`,
`download`, and `verify`; installation itself is performed by OpenClaw.

## What "installs disabled" means precisely

Read this before Step 1, because two different layers each have an "enabled"
flag and they do not mean the same thing.

| Layer | After a normal install | What it controls |
| --- | --- | --- |
| OpenClaw plugin entry | `enabled: true` | Whether OpenClaw **loads** the plugin and registers its hook entrypoints |
| Connector configuration | `enabled: false` | Whether the connector **observes anything** |

So OpenClaw does load the plugin and does register hook entrypoints
immediately. That is normal and expected. What matters is that while the
connector is **operationally disabled**:

- both tool-observation hook handlers (`before_tool_call`, `after_tool_call`)
  return immediately;
- no governance request is sent;
- no ordinary observation receipt is written;
- no shadow observation is active.

The gateway lifecycle hooks still record a `connector_lifecycle` entry noting
that the connector was loaded. That record contains no tool, agent, or decision
metadata and is not an observation receipt.

Shadow observation begins only when you explicitly enable it in Step 7.

## Prerequisites

- **OpenClaw `2026.6.5` or newer.** This is enforced by the connector at
  runtime, not merely declared in package metadata. On a host reporting an older
  version — or a version that cannot be parsed — the connector refuses to
  activate, logs a compatibility error, and stays inert; OpenClaw and your other
  plugins keep running normally. An environment exposing no detectable OpenClaw
  version is reported as `UNKNOWN` and may activate; that is not a supported
  configuration. See [LIMITATIONS.md](LIMITATIONS.md) §9a.
- ClawHub CLI (tested with `0.23.1`).
- Node.js with ES module support (tested on Node 24).
- A user account that owns the OpenClaw runtime.
- Outbound HTTPS to your governance endpoint — only if you intend to enable it.

Check your OpenClaw version first:

```sh
openclaw --version
```

## A note on profiles

Every command below uses `--profile <name>`. A named profile isolates OpenClaw
under `~/.openclaw-<profile>`, and **the connector keeps its state, receipts,
controls, and credential inside that same profile**:

```
~/.openclaw-<profile>/extensions/mcpherson-governance-connector/   installed files
~/.openclaw-<profile>/mcpherson-governance-connector/              connector state
~/.openclaw-<profile>/mcpherson-governance-connector/receipts/     receipts
```

To use the default profile instead, drop `--profile <name>` from every command;
the paths become `~/.openclaw/...`. Nothing is ever copied or migrated between
profiles.

For brevity the rest of this document uses:

```sh
PROFILE=my-profile
INSTALL_DIR="$HOME/.openclaw-$PROFILE/extensions/mcpherson-governance-connector"
STATE_DIR="$HOME/.openclaw-$PROFILE/mcpherson-governance-connector"
```

## Step 1 — Download the package from ClawHub

```sh
clawhub package download @mcphersonai/mcpherson-governance-openclaw \
  --version 0.5.1 \
  --output ./mcpherson-governance-download
```

This writes `mcphersonai-mcpherson-governance-openclaw-0.5.1.tgz`. That single
`.tgz` is the artifact you install — do not extract it and do not install the
`connector/` subdirectory on its own.

## Step 2 — Verify the artifact before installing it

Never install an artifact you have not verified. Verify against ClawHub's
published digests:

```sh
clawhub package verify \
  ./mcpherson-governance-download/mcphersonai-mcpherson-governance-openclaw-0.5.1.tgz \
  --package @mcphersonai/mcpherson-governance-openclaw \
  --version 0.5.1
```

It must report `verified: true`. You can also check the SHA-256 yourself against
the value published with the release:

```sh
shasum -a 256 \
  ./mcpherson-governance-download/mcphersonai-mcpherson-governance-openclaw-0.5.1.tgz
```

Do not proceed on any mismatch.

## Step 3 — Install through OpenClaw

```sh
openclaw --profile "$PROFILE" plugins install \
  ./mcpherson-governance-download/mcphersonai-mcpherson-governance-openclaw-0.5.1.tgz
```

Expect two warnings on a normal install. Both are benign:

- **Manifest ID vs npm package name.** The plugin id is
  `mcpherson-governance-connector`; the npm package is
  `mcpherson-governance-openclaw`. OpenClaw uses the manifest id as the config
  key. This is the intended identity and does not change between versions.
- **`plugins.allow` is empty.** This is OpenClaw's advice to pin an explicit
  trusted plugin list. See Step 4.

OpenClaw's static scanner may also flag `child_process` usage in the shipped
release-engineering scripts (`scripts/build-release-artifacts.mjs`,
`scripts/run-public-tests.mjs`). Those scripts are build and test tooling; no
connector runtime module imports them, and the runtime compatibility gate
executes no subprocess.

## Step 4 — Verify the installed version

```sh
openclaw --profile "$PROFILE" plugins info mcpherson-governance-connector --json
```

Confirm:

- `"id": "mcpherson-governance-connector"`
- `"version": "0.5.1"`
- `"status": "loaded"`

Optionally pin the trusted plugin list:

```sh
openclaw --profile "$PROFILE" config set \
  plugins.allow '["mcpherson-governance-connector"]' --strict-json
```

## Step 5 — Configure, with `enabled: false`

Connector configuration lives under
`plugins.entries.mcpherson-governance-connector.config`. Use
[examples/connector-config.example.json](examples/connector-config.example.json)
as the template and replace every `REPLACE-WITH-…` placeholder in it.

That example deliberately omits `stateDir` and `receiptDir` so the connector
keeps its state inside the active profile. Do not add them back unless you
intend to opt out of profile-based isolation.

```sh
openclaw --profile "$PROFILE" config set \
  'plugins.entries.mcpherson-governance-connector.config' \
  '{
     "enabled": false,
     "apiUrl": "https://YOUR-GOVERNANCE-ENDPOINT",
     "deploymentId": "YOUR-DEPLOYMENT-ID",
     "agentId": "YOUR-AGENT-ID",
     "policyVersion": 3,
     "toolMetadata": {}
   }' --strict-json
```

Read it back:

```sh
openclaw --profile "$PROFILE" config get \
  'plugins.entries.mcpherson-governance-connector.config' --json
```

Notes:

- Keep `"enabled": false` for now.
- `apiUrl` must be `https://`.
- You do **not** need to set `stateDir` or `receiptDir`, and the shipped
  example omits them. Left unset, they resolve inside the active profile as
  shown above. Set them only if you deliberately want a different location — an
  encrypted volume or a separate evidence mount. If you do, they must be
  absolute paths you own, and they apply to **every** profile, which opts you
  out of profile-based isolation. See
  [examples/README.md](examples/README.md).
- `toolMetadata` is **manual capability mapping**. Tools you do not map produce
  registry 404 observations, which do not block execution but carry no useful
  classification. Map the tools you actually care about.
- Do **not** put a credential in this file. See Step 6.

## Step 6 — Place the deployment credential (only if using a governance endpoint)

The credential is read only from a `0600` file inside the `0700` state
directory. It is never accepted from a command argument, an environment
variable, or plugin configuration.

```sh
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
install -m 600 /path/to/issued-credential "$STATE_DIR/deployment-credential"
```

If you are not pairing with a governance endpoint, skip this step and leave
`enabled` false — the connector will not attempt remote contact.

## Step 7 — Check status, then enable deliberately

The connector's own control CLI is **not placed on your `PATH`** by a ClawHub
download plus an OpenClaw archive install — that install method copies files
into the profile and does not create command links. Invoke it by explicit path,
with `OPENCLAW_STATE_DIR` naming the profile:

```sh
OPENCLAW_STATE_DIR="$HOME/.openclaw-$PROFILE" \
  node "$INSTALL_DIR/connector/connector-ctl.mjs" status
```

Confirm shadow mode and your expected disable/kill-switch/lock state before
enabling. Resolve anything unexpected here rather than after enabling.

Enabling takes **both** steps — configuration and the durable local control:

```sh
# 1. turn on observation in configuration
openclaw --profile "$PROFILE" config set \
  'plugins.entries.mcpherson-governance-connector.config.enabled' true --strict-json

# 2. clear the durable local disabled control
OPENCLAW_STATE_DIR="$HOME/.openclaw-$PROFILE" \
  node "$INSTALL_DIR/connector/connector-ctl.mjs" enable
```

`enable` only clears the local durable control — it does not override plugin
configuration. Both must agree before observation begins.

Restart or reload the OpenClaw gateway so the new configuration is loaded.

## Step 8 — Confirm it is working

```sh
OPENCLAW_STATE_DIR="$HOME/.openclaw-$PROFILE" \
  node "$INSTALL_DIR/connector/connector-ctl.mjs" status

wc -l "$STATE_DIR/receipts/connector-receipts.jsonl"
```

Expect `attempt_receipt` records for observed calls, `completion_receipt`
records after observed completions, and — until mapping is complete — a number
of `404` remote statuses for unmapped tools. **None of this blocks your tools.**

## Step 9 — Optional: prove local authority is retained

If you want to confirm for yourself that local control beats everything:

```sh
CTL="node $INSTALL_DIR/connector/connector-ctl.mjs"
export OPENCLAW_STATE_DIR="$HOME/.openclaw-$PROFILE"

$CTL canary --on
# invoke the connector's own mcpherson_governance_canary tool with the exact token
$CTL canary --off
```

The canary blocks only the connector's own diagnostic tool, never your tools.
Turn it off when finished.

## If something goes wrong

Every step above is reversible. Go to [LIFECYCLE.md](LIFECYCLE.md) for disable,
uninstall, and rollback. The fastest full stop is:

```sh
openclaw --profile "$PROFILE" plugins disable mcpherson-governance-connector
```

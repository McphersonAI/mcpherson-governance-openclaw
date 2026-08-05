# Install and run — McPherson Governance Connector v0.6.2

## 1. Requirements

| Requirement | Value |
| --- | --- |
| OpenClaw | **2026.6.5 or newer** |
| Node.js | **22 or newer** |
| Account | none |
| Network | none required for the local V6 workflow |
| Dependencies | none (no third-party packages) |

### Provenance of the 2026.6.5 minimum

This number is not a guess and not merely package metadata:

- It is a **source-owned constant**, `MIN_SUPPORTED_OPENCLAW_VERSION`, in
  `plugins/openclaw-connector/constants.mjs`, and the connector enforces it
  itself at activation time. It is deliberately not delegated to
  package-manager or host-side compatibility metadata, because those are not
  enforced by every installer.
- It is *also* declared as `openclaw.compat.pluginApi: ">=2026.6.5"` in
  `package.json`, for installers that do check.
- The build metadata in `package.json` records the preferred audited runtime
  for this release — the build the full lifecycle is run against first:
  `openclawVersion 2026.6.33`, `openclawCommit 7af0cfc`,
  `receiptMode POST_HOOK`. It names one preferred build, not the whole
  approved set; `2026.6.5` remains fully supported and separately proven.

**Caveat, stated exactly:** the approved live-observation target set is three
exact OpenClaw builds — `2026.6.5` at commit `5181e4f`, `2026.6.33` at commit
`7af0cfc`, and `2026.7.1-2` at commit `0790d9f`. It does **not** establish
behavior on any other OpenClaw version. Other releases in the `>=` range may
load the connector but are not covered by that evidence, and live observation
refuses them outright. On a host below 2026.6.5 the connector stays inert
rather than activating.

Support is **exact-target based**. A build is approved only when its semantic
version, full commit, runtime-entry SHA-256, `package.json` SHA-256, and
`dist/build-info.json` SHA-256 all match one approved entry. Being in the
`2026.6` line, or carrying the `extended-stable` dist-tag, approves nothing on
its own — that tag is a moving pointer and upstream may repoint it at a build
this release has never audited.

| OpenClaw build | Target binding | Live lifecycle |
| --- | --- | --- |
| `2026.6.5` (`5181e4f`) | exact, supported | **proven** |
| `2026.6.33` (`7af0cfc`) extended-stable | exact, supported | **proven** — preferred baseline |
| `2026.7.1-2` (`0790d9f`) | exact, supported | **not supported** — blocked upstream |

**The full local V6 workflow in section 4 is proven on `2026.6.5` and on
`2026.6.33`.** Prefer `2026.6.33`, the published extended-stable build. The
connector installs and runs on `2026.7.1-2`, but that build does not issue the
device-bound operator token the observer requires — see
[LIMITATIONS.md](./LIMITATIONS.md).

## 2. Install the plugin

The install contract is unchanged from v0.5.1: download the published `.tgz`
from ClawHub, verify it, then install that single archive through OpenClaw.

```sh
PROFILE=my-profile
PROFILE_HOME=/absolute/physical/path/to/the/openclaw-home
OPENCLAW="$PROFILE_HOME/.local/bin/openclaw"
PROFILE_STATE="$PROFILE_HOME/.openclaw-$PROFILE"
PACKAGE_ROOT=/absolute/path/to/the/verified/package
```

`PROFILE_HOME` is explicit: the diagnostics do not consult the calling
account's passwd entry and do not infer it from `$HOME`. For a named profile,
OpenClaw state must be at `$PROFILE_HOME/.openclaw-$PROFILE`, its config must be
`openclaw.json` there, and the independently installed OpenClaw runtime must be
at `$PROFILE_HOME/.local/lib/node_modules/openclaw/openclaw.mjs`. Use a physical
absolute path with no symlinked component.

`PROFILE` must match `[A-Za-z0-9][A-Za-z0-9_-]{0,63}` and must not be
`default` or `dev` in any letter case. OpenClaw 2026.6.5 reserves `dev` and
changes its gateway port; the V6 binding deliberately refuses that alias.

### Step 1 — Download from ClawHub

```sh
clawhub package download @mcphersonai/mcpherson-governance-openclaw \
  --version 0.6.2 \
  --output ./mcpherson-governance-download
```

This writes `mcphersonai-mcpherson-governance-openclaw-0.6.2.tgz`. That single
`.tgz` is the artifact you install — do not extract it and do not install a
subdirectory on its own.

### Step 2 — Verify before installing

Never install an artifact you have not verified.

```sh
clawhub package verify \
  ./mcpherson-governance-download/mcphersonai-mcpherson-governance-openclaw-0.6.2.tgz \
  --package @mcphersonai/mcpherson-governance-openclaw \
  --version 0.6.2

shasum -a 256 \
  ./mcpherson-governance-download/mcphersonai-mcpherson-governance-openclaw-0.6.2.tgz
```

It must report `verified: true`, and the SHA-256 must match the value published
with the release. Do not proceed on any mismatch.

### Step 3 — Install through OpenClaw

```sh
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  "$OPENCLAW" --profile "$PROFILE" plugins install \
  ./mcpherson-governance-download/mcphersonai-mcpherson-governance-openclaw-0.6.2.tgz
```

Expect these warnings on a normal install. All are benign:

- **Manifest ID vs npm package name.** The plugin id is
  `mcpherson-governance-connector`; the npm package is
  `mcpherson-governance-openclaw`. OpenClaw uses the manifest id as the config
  key. This is the intended identity and does not change between versions.
- **`plugins.allow` is empty.** This is OpenClaw's advice to pin an explicit
  trusted plugin list.

**Static-scanner note on `child_process` — changed in v0.6.0.** In v0.5.1,
`child_process` appeared only in shipped release-engineering scripts and no
runtime module imported it. That is **no longer true.** The V6 local observer
(`packages/openclaw-live-observer/index.mjs`) executes your package-bound
OpenClaw executable to perform exactly two `operator.read` gateway RPCs
(`agents.list`, `tools.catalog`) and a `--version` probe. This is runtime
subprocess use, disclosed here rather than buried:

- it runs only when **you** invoke the local diagnostics CLI;
- it executes only the OpenClaw runtime bound by the package manifest, with a
  fixed safe `PATH` and a bounded, sanitized environment;
- it never runs during connector activation, during a hook, or as a result of
  any remote response;
- the connector runtime compatibility gate still executes no subprocess.

## 3. Configure it (stays disabled)

```sh
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  "$OPENCLAW" --profile "$PROFILE" config set \
  plugins.entries.mcpherson-governance-connector.config \
  '{"enabled":false}' --strict-json
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  "$OPENCLAW" --profile "$PROFILE" config validate
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  "$OPENCLAW" --profile "$PROFILE" plugins inspect \
  mcpherson-governance-connector
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  "$OPENCLAW" --profile "$PROFILE" plugins disable \
  mcpherson-governance-connector
```

`enabled` defaults to `false`. Leave it there for the local V6 workflow.
Installing does not open a login page, provision an account, or create a
deployment credential or receipt ledger.

The host plugin entry must remain disabled during the local identity bootstrap
below. `config.enabled: false` and the disabled host entry are distinct
controls; verify both.

A placeholder configuration showing every supported key is in
[`examples/connector-config.example.json`](./examples/connector-config.example.json).
Every value in it is a placeholder and must be replaced before use.

## 4. Initialize the named profile and run the local V6 workflow

Create private output and binding locations first. The observer accepts only
private, owned, non-symlink paths. A binding directory must be `0700`:

```sh
install -d -m 0700 /absolute/path/to/V6_LOCAL_RESULTS
install -d -m 0700 /absolute/path/to/V6_LOCAL_BINDING
```

Use calendar-valid UTC timestamps and the package manifest shipped in this
package. Repeat `--agent` to select more local agents; at least one explicit
agent is required.

`PACKAGE_ROOT` is the physical absolute directory containing this `INSTALL.md`.

### 4.1 Configure and bootstrap the account-free local gateway identity

Create a private local gateway token without placing it in shell history, then
configure the exact loopback endpoint and an OpenClaw single-value file
SecretRef. These are local OpenClaw credentials, not a McPherson account or API
key:

```sh
install -d -m 0700 "$PROFILE_STATE"
openssl rand -hex -out "$PROFILE_STATE/gateway-token" 32
chmod 0600 "$PROFILE_STATE/gateway-token"

env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  OPENCLAW_STATE_DIR="$PROFILE_STATE" \
  OPENCLAW_CONFIG_PATH="$PROFILE_STATE/openclaw.json" \
  "$OPENCLAW" --profile "$PROFILE" config set gateway.mode local
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  OPENCLAW_STATE_DIR="$PROFILE_STATE" \
  OPENCLAW_CONFIG_PATH="$PROFILE_STATE/openclaw.json" \
  "$OPENCLAW" --profile "$PROFILE" config set gateway.bind loopback
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  OPENCLAW_STATE_DIR="$PROFILE_STATE" \
  OPENCLAW_CONFIG_PATH="$PROFILE_STATE/openclaw.json" \
  "$OPENCLAW" --profile "$PROFILE" config set gateway.port 18789 --strict-json
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  OPENCLAW_STATE_DIR="$PROFILE_STATE" \
  OPENCLAW_CONFIG_PATH="$PROFILE_STATE/openclaw.json" \
  "$OPENCLAW" --profile "$PROFILE" config set gateway.auth.mode token
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  OPENCLAW_STATE_DIR="$PROFILE_STATE" \
  OPENCLAW_CONFIG_PATH="$PROFILE_STATE/openclaw.json" \
  "$OPENCLAW" --profile "$PROFILE" config set \
  gateway.auth.allowTailscale false --strict-json
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  OPENCLAW_STATE_DIR="$PROFILE_STATE" \
  OPENCLAW_CONFIG_PATH="$PROFILE_STATE/openclaw.json" \
  "$OPENCLAW" --profile "$PROFILE" config set gateway.tailscale.mode off
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  OPENCLAW_STATE_DIR="$PROFILE_STATE" \
  OPENCLAW_CONFIG_PATH="$PROFILE_STATE/openclaw.json" \
  "$OPENCLAW" --profile "$PROFILE" config set \
  gateway.tailscale.resetOnExit false --strict-json
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  OPENCLAW_STATE_DIR="$PROFILE_STATE" \
  OPENCLAW_CONFIG_PATH="$PROFILE_STATE/openclaw.json" \
  "$OPENCLAW" --profile "$PROFILE" config set secrets.providers.default \
  --provider-source file --provider-path "$PROFILE_STATE/gateway-token" \
  --provider-mode singleValue
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  OPENCLAW_STATE_DIR="$PROFILE_STATE" \
  OPENCLAW_CONFIG_PATH="$PROFILE_STATE/openclaw.json" \
  "$OPENCLAW" --profile "$PROFILE" config set gateway.auth.token \
  --ref-provider default --ref-source file --ref-id value
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  OPENCLAW_STATE_DIR="$PROFILE_STATE" \
  OPENCLAW_CONFIG_PATH="$PROFILE_STATE/openclaw.json" \
  "$OPENCLAW" --profile "$PROFILE" config validate
```

With the package host entry still disabled, run the gateway in terminal 1:

```sh
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  OPENCLAW_STATE_DIR="$PROFILE_STATE" \
  OPENCLAW_CONFIG_PATH="$PROFILE_STATE/openclaw.json" \
  MCP_GOVERNANCE_STATE_DIR= MCP_GOVERNANCE_RECEIPT_DIR= \
  "$OPENCLAW" --profile "$PROFILE" gateway run
```

In terminal 2, perform one local health call. OpenClaw uses the configured
SecretRef, creates the named profile's device identity, and caches its local
operator token:

```sh
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  OPENCLAW_STATE_DIR="$PROFILE_STATE" \
  OPENCLAW_CONFIG_PATH="$PROFILE_STATE/openclaw.json" \
  MCP_GOVERNANCE_STATE_DIR= MCP_GOVERNANCE_RECEIPT_DIR= \
  "$OPENCLAW" --profile "$PROFILE" gateway call health --json
```

Require a successful health result, then stop terminal 1 with Ctrl-C. Confirm
`$PROFILE_STATE/identity/device.json` and `device-auth.json` are private files.
This bootstrap is local loopback only and requires no email, login, remote
service, pairing UI, billing, or credits.

#### Two different credentials — do not confuse them

This step establishes **two** separate things, and live observation needs both:

1. **The shared Gateway token** (`gateway.auth.token`, the SecretRef above).
   It authenticates the *connection* to your local Gateway. It is not an
   operator identity.
2. **The device-bound operator token**, which OpenClaw issues to this
   profile's persistent device identity during the health call and persists at
   `$PROFILE_STATE/identity/device-auth.json` with role `operator` and scope
   `operator.read`.

**The shared Gateway token does not replace the device-bound token.** The
observer requires the device-bound token specifically, and will not fall back
to the shared Gateway token, `gateway.remote.token`, a token from another
profile, or a token from another device. Verify the file exists and carries the
operator role before continuing:

```sh
stat -f '%Lp' "$PROFILE_STATE/identity/device-auth.json"   # require 600
```

`device-auth.json` is sensitive owner-only state. Treat it like a credential:
never copy it between profiles or machines, never commit it, and never paste
its contents. Each named profile keeps its own device identity and its own
token; profile separation is what keeps one profile's observation from reading
another's.

> **On OpenClaw `2026.7.1-2` this file is not created.** That build omits the
> device identity from the connect handshake for a local CLI using
> shared-secret auth on a loopback Gateway, so OpenClaw never opens a
> device-pairing request and never issues the token. `observe-live` therefore
> fails closed with `LIVE_PATH_COMPONENT_UNREADABLE`. Run the section 4
> workflow on `2026.6.33` or `2026.6.5` until this is resolved upstream.
> `2026.6.33` does not carry that change: a local CLI still pairs and still
> receives an `operator.read` device token there.

OpenClaw's first-run state initialization leaves the profile state directory
group- and world-readable (`0755`). Restore owner-only access before continuing;
the binding refuses a state root that is not private:

```sh
chmod 0700 "$PROFILE_STATE"
stat -f '%Lp' "$PROFILE_STATE" 2>/dev/null || stat -c '%a' "$PROFILE_STATE"
```

Require `700`. Skipping this step makes the next command fail closed with
`LIVE_STATE_ROOT_INVALID_PERMISSIONS_INSECURE`. This is a one-time correction
for a new profile; later gateway restarts and health calls preserve `0700`.

### 4.2 Initialize the exact named-profile binding

The observer will not accept a profile merely because its name is syntactically
valid. Create a short-lived local binding that pins this package and source,
the exact named profile, physical home, state and config paths, and one audited
OpenClaw runtime — `2026.6.5 (5181e4f)`, `2026.6.33 (7af0cfc)`, or
`2026.7.1-2 (0790d9f)`. The binding
records the single build that host actually runs. Initialization validates all
of those
inputs before writing the binding, never overwrites an existing file, and does
not read or copy a gateway secret value.

The command also binds the exact connector state directory and receipt ledger:
`$PROFILE_STATE/mcpherson-governance-connector/receipts/connector-receipts.jsonl`.
The observed profile must not configure connector `stateDir` or `receiptDir`
overrides; this release refuses those overrides instead of following a path
outside the bound profile.

```sh
node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" init-profile-binding \
  --package-manifest "$PACKAGE_ROOT/V6-PACKAGE-MANIFEST.json" \
  --profile-mode NAMED \
  --profile "$PROFILE" \
  --profile-home "$PROFILE_HOME" \
  --profile-binding /absolute/path/to/V6_LOCAL_BINDING/profile-binding.json
```

Copy the exact 64-character `binding_id` printed by initialization into a
separate shell variable. It is the operator's commitment to the original
binding bytes and makes even a rehashed edit fail closed:

```sh
BINDING_ID=<exact-binding_id-printed-by-init-profile-binding>
```

The file has one exact canonical serialization. Reformatting, reordering,
altering, or rehashing it fails closed. The binding expires after at most 24
hours. When it expires, preserve it as
bounded evidence if required and initialize a new binding at a new private
path; the command never silently refreshes or replaces one.

### 4.3 Verify the binding immediately before observation

```sh
node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" verify-profile-binding \
  --package-manifest "$PACKAGE_ROOT/V6-PACKAGE-MANIFEST.json" \
  --profile-mode NAMED \
  --profile "$PROFILE" \
  --profile-home "$PROFILE_HOME" \
  --profile-binding /absolute/path/to/V6_LOCAL_BINDING/profile-binding.json \
  --profile-binding-id "$BINDING_ID"
```

Do not proceed unless this reports `"ok": true`. A changed profile name or
mode, state/config/runtime path, runtime build, package/source identity,
binding content, or expired binding fails closed.

### 4.4 Enable the installed plugin only in the named profile

```sh
env HOME="$PROFILE_HOME" OPENCLAW_HOME="$PROFILE_HOME" \
  "$OPENCLAW" --profile "$PROFILE" plugins enable \
  mcpherson-governance-connector
```

This enables the host plugin entry only for the named profile. Keep connector
`config.enabled` set to `false`; remote shadow remains off. Restart the exact
terminal-1 gateway command from §4.1. The connector creates its private ledger
at the binding's exact `receipt_path`; do not supply a ledger from another
profile or an override path.

### 4.5 `observe-live` — one bounded local observation

```sh
node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" observe-live \
  --package-manifest "$PACKAGE_ROOT/V6-PACKAGE-MANIFEST.json" \
  --profile-mode NAMED \
  --profile "$PROFILE" \
  --profile-home "$PROFILE_HOME" \
  --profile-binding /absolute/path/to/V6_LOCAL_BINDING/profile-binding.json \
  --profile-binding-id "$BINDING_ID" \
  --receipts "$PROFILE_STATE/mcpherson-governance-connector/receipts/connector-receipts.jsonl" \
  --agent local-main \
  --start 2026-08-02T05:00:00Z \
  --end 2026-08-02T05:05:00Z \
  --now 2026-08-02T05:05:01Z \
  --out-dir /absolute/path/to/V6_LOCAL_RESULTS/observation
```

Named mode never falls back to the default profile. The observer reconstructs
the child environment from the approved binding and clears inherited OpenClaw
path/profile variables, so caller environment variables cannot redirect it.

### 4.6 `verify-observation` — independently re-verify the observation

```sh
node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" verify-observation \
  --observation-dir /absolute/path/to/V6_LOCAL_RESULTS/observation \
  --package-manifest "$PACKAGE_ROOT/V6-PACKAGE-MANIFEST.json" \
  --profile-binding /absolute/path/to/V6_LOCAL_BINDING/profile-binding.json \
  --profile-binding-id "$BINDING_ID"
```

### 4.7 `discover` — local capability candidates

```sh
node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" discover \
  --method openclaw_live_gateway_v1 \
  --source /absolute/path/to/V6_LOCAL_RESULTS/observation/capability-snapshot.json \
  --observation-dir /absolute/path/to/V6_LOCAL_RESULTS/observation \
  --package-manifest "$PACKAGE_ROOT/V6-PACKAGE-MANIFEST.json" \
  --profile-binding /absolute/path/to/V6_LOCAL_BINDING/profile-binding.json \
  --profile-binding-id "$BINDING_ID" \
  --now 2026-08-02T05:05:01Z \
  --out /absolute/path/to/V6_LOCAL_RESULTS/discovery.json
```

### 4.8 `propose` — non-authoritative AutoMap proposals

```sh
node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" propose \
  --candidates /absolute/path/to/V6_LOCAL_RESULTS/discovery.json \
  --observation-dir /absolute/path/to/V6_LOCAL_RESULTS/observation \
  --package-manifest "$PACKAGE_ROOT/V6-PACKAGE-MANIFEST.json" \
  --profile-binding /absolute/path/to/V6_LOCAL_BINDING/profile-binding.json \
  --profile-binding-id "$BINDING_ID" \
  --now 2026-08-02T05:05:01Z \
  --out /absolute/path/to/V6_LOCAL_RESULTS/automap-proposals.json
```

Output status is `PROPOSED`. Nothing here activates a mapping.

### 4.9 `govern` — governability findings

```sh
node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" govern \
  --evidence /absolute/path/to/V6_LOCAL_RESULTS/observation/governability-evidence.json \
  --observation-dir /absolute/path/to/V6_LOCAL_RESULTS/observation \
  --package-manifest "$PACKAGE_ROOT/V6-PACKAGE-MANIFEST.json" \
  --profile-binding /absolute/path/to/V6_LOCAL_BINDING/profile-binding.json \
  --profile-binding-id "$BINDING_ID" \
  --now 2026-08-02T05:05:01Z \
  --out /absolute/path/to/V6_LOCAL_RESULTS/governability-findings.json
```

### 4.10 `render-diagnosis` — readable Governability Diagnosis

```sh
node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" render-diagnosis \
  --findings /absolute/path/to/V6_LOCAL_RESULTS/governability-findings.json \
  --evidence /absolute/path/to/V6_LOCAL_RESULTS/observation/governability-evidence.json \
  --observation-dir /absolute/path/to/V6_LOCAL_RESULTS/observation \
  --package-manifest "$PACKAGE_ROOT/V6-PACKAGE-MANIFEST.json" \
  --profile-binding /absolute/path/to/V6_LOCAL_BINDING/profile-binding.json \
  --profile-binding-id "$BINDING_ID" \
  --format md \
  --out /absolute/path/to/V6_LOCAL_RESULTS/governability-diagnosis.md
```

`render-diagnosis --format md` requires `--out`. For a preview without writing
another file, omit `--out` from `discover`, `propose`, or `govern` and JSON is
printed to standard output.

### 4.11 Explicit default-profile alternative

Default mode remains available only through a binding created and invoked with
`--profile-mode DEFAULT`; omit `--profile` in both commands. It binds exactly
`$PROFILE_HOME/.openclaw/openclaw.json` and never accepts a named binding.
Because that is the selected home's default OpenClaw state, use it only when
you deliberately intend to observe that exact state. For disposable testing,
use the named-profile flow above. The observer never silently substitutes
DEFAULT for NAMED.

### Supporting commands

`node "$PACKAGE_ROOT/scripts/governance-diagnostics.mjs" help` lists the full
command set, which also includes `preview`, `confirm-classification`,
`generate-classification-confirmation`, `export-registry-patch`,
`validate-registry-patch`, `preview-registry-patch`, `shadow-lookup`, `drift`,
`latency-summarize`, and `coverage`. There is no `apply-registry-patch`: this
package cannot mutate a registry.

## 5. Outputs and permissions

`V6_LOCAL_RESULTS/observation` is created `0700` and contains only these `0600`
metadata artifacts:

- `capability-snapshot.json`
- `governability-evidence.json`
- `shadow-receipt-summary.json`
- `latency-events.json`
- `observation-manifest.json`

The derived files `discovery.json`, `automap-proposals.json`,
`governability-findings.json`, and `governability-diagnosis.md` are also `0600`.
**Existing paths are never overwritten.**

## 6. Upgrading from an earlier version — receipt-ledger transition

**Read this before starting v0.6.2 against a ledger written by any earlier
connector version, including v0.5.1, v0.6.0, and v0.6.1.** v0.6.2 moves the
lifecycle version pin from `0.6.1` to `0.6.2`, so a v0.6.1 ledger needs this
same rotation — upgrading the connector alone is not sufficient. For the
v0.5.1 path specifically, see [COMPATIBILITY.md](./COMPATIBILITY.md) §2.

The observer pins connector lifecycle records to one exact version, and
`parseReceiptLedger` validates **every** line of the ledger with no window
filter. A single record from a previous connector version therefore invalidates
the whole ledger with `live_receipt_contract_invalid`. This is deliberate: a
mixed-version ledger must never be parsed as one current-version ledger.

There is a second trap. Rotating the ledger *before* the restart is not enough,
because the still-loaded old connector writes one final `gateway_stop` record at
the **old** version while shutting down. The real version boundary is **after
the old process has exited.**

Perform the transition in exactly this order:

1. **Stop or restart the old connector** so it writes its final
   `gateway_stop` record at its own version.
2. **Confirm the old process has exited.** Do not proceed while it is running.
3. **Rotate the receipt ledger**, preserving the old file as evidence. Replace
   `<old-version>` with the version you are leaving, for example `v0.5.1`,
   `v0.6.0`, or `v0.6.1`:

   ```sh
   mv ~/.openclaw/mcpherson-governance-connector/receipts/connector-receipts.jsonl \
      ~/.openclaw/mcpherson-governance-connector/archive/connector-receipts-<old-version>-$(date -u +%Y%m%dT%H%M%SZ).jsonl
   ```

   Create the `archive/` directory `0700` first if it does not exist.
4. **Start v0.6.2.**
5. **Initialize the new ledger as owner-only `0600`:**

   ```sh
   install -m 0600 /dev/null \
     ~/.openclaw/mcpherson-governance-connector/receipts/connector-receipts.jsonl
   ```

   An empty `0600` ledger is a valid starting state.
6. **Keep the old ledger.** It remains readable evidence of the previous
   version's activity. Do not delete it and do not merge it into the new one.
7. **Never parse mixed-version records as one current-version ledger.** If you
   need to read historical records, read the archived file separately with the
   connector version that wrote it.
8. **Re-initialize and verify the profile binding, then complete one full
   lifecycle.** A binding captured before the upgrade pins the previous plugin
   version and will not verify against v0.6.2. Run `init-profile-binding`,
   record the new binding ID, run `verify-profile-binding`, then run
   `observe-live` and `verify-observation` as in section 4. Confirm the
   binding reports `plugin_version 0.6.2` and the exact runtime you intend —
   `2026.6.33 (7af0cfc)` or `2026.6.5 (5181e4f)`.

If you skip the rotation, `observe-live` fails closed with
`live_receipt_contract_invalid` rather than silently mixing versions. That
failure is the contract working, not a defect.

This transition is independent of which approved OpenClaw build you run: the
ledger boundary is a *connector* version boundary, and it applies identically
on `2026.6.5` and `2026.6.33`.

## 7. Uninstall

See [LIFECYCLE.md](./LIFECYCLE.md) for disable, kill switch, rotation, and
uninstall, including what is and is not removed.

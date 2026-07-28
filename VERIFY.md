# Verification

**Connector v0.5.1.** How to confirm that what you have is what was released,
and that it behaves as claimed. Everything here runs locally.

## 1. Verify the ClawHub artifact

The public artifact is the ClawHub `.tgz`, not a GitHub release tarball:

```sh
clawhub package verify \
  ./mcphersonai-mcpherson-governance-openclaw-0.5.1.tgz \
  --package @mcphersonai/mcpherson-governance-openclaw \
  --version 0.5.1
```

It must report `verified: true`. To check the digest yourself:

```sh
shasum -a 256 mcphersonai-mcpherson-governance-openclaw-0.5.1.tgz
```

Compare against the published release manifest value. Do not install on a
mismatch.

The remaining checks run against the installed package. With a profile install,
that is:

```sh
cd "$HOME/.openclaw-<profile>/extensions/mcpherson-governance-connector"
```

## 2. Verify every file in the package

```sh
shasum -a 256 -c RELEASE-CHECKSUMS.sha256
```

Every line must report `OK`.

## 3. Verify the 29 connector files specifically

This is the important one. `CONNECTOR-FILES.sha256` covers exactly the 29
connector files and nothing else:

```sh
shasum -a 256 -c CONNECTOR-FILES.sha256
wc -l < CONNECTOR-FILES.sha256      # must print 29
```

All 29 must report `OK`. This is a self-consistency check against the
public-package checksum manifest; it is not a claim that all 29 files match the
v0.5.0 sealed inventory. Any `FAILED` line means your copy has been modified.

The provenance comparison is deliberately separate:

- Sealed v0.5.0 connector inventory: **28 files**
- Files v0.5.1 adds: **1** (`connector/host.mjs`)
- Files v0.5.1 changes: **5** (`connector/config.mjs`, `connector/constants.mjs`,
  `connector/hook.mjs`, `connector/index.mjs`, `connector/pipeline.mjs`)
- Metadata files that differ from sealed: **2**
  (`connector/package.json`, `connector/openclaw.plugin.json`)
- Documentation files that differ from sealed: **1** (`connector/README.md`)
- Sealed files carried over byte-identical: **20/28**
- Runtime modules (`.mjs`): **24**

The connector tree holds 24 `.mjs` runtime modules in total.

`SEALED-CONNECTOR-FILES.sha256` records the sealed v0.5.0 reference hashes.
`npm test` verifies that the difference from that sealed inventory is **exactly**
the enumerated set above and nothing else — an unexpected change to any other
connector file fails the check.

Every changed runtime module is changed for a stated v0.5.1 finding; see
[CHANGELOG.md](CHANGELOG.md).

To confirm no extra runtime file was added to the connector tree:

```sh
find connector -type f | wc -l      # must print 29
```

## 4. Verify the embedded governance core

The connector embeds a subset of the governance core and records its own source
hashes. **v0.5.1 does not change it:**

```sh
cd connector/runtime/governance-core
shasum -a 256 -c SOURCE.sha256
cd -
```

Five files must report `OK`. Note the embedded core deliberately **excludes** the
policy evaluator and gate modules — the enforcement code is not shipped in a
shadow-only release. Confirm they are absent:

```sh
ls connector/runtime/governance-core/evaluate.mjs 2>/dev/null && echo UNEXPECTED
ls connector/runtime/governance-core/gate.mjs 2>/dev/null && echo UNEXPECTED
```

Neither should exist.

## 5. Verify the shadow-only constants in your installed copy

Do not take the README's word for it — read the constants:

```sh
grep -nE 'REMOTE_AUTHORITY|ENFORCEABLE_REMOTE_DECISIONS|remote_shadow|remote_authority|deny_enforcement|approval_enforcement|RECEIPT_MODE|PLUGIN_VERSION|MIN_SUPPORTED_OPENCLAW_VERSION' \
  connector/constants.mjs
```

Expected:

| Constant | Required value |
| --- | --- |
| `PLUGIN_VERSION` | `"0.5.1"` |
| `MIN_SUPPORTED_OPENCLAW_VERSION` | `"2026.6.5"` |
| `REMOTE_AUTHORITY` | `false` |
| `ENFORCEABLE_REMOTE_DECISIONS` | `[]` |
| `remote_shadow` | `true` |
| `remote_authority` | `false` |
| `deny_enforcement` | `false` |
| `approval_enforcement` | `false` |
| `RECEIPT_MODE` | `"POST_HOOK"` |

Machine-checkable version:

```sh
node --input-type=module -e '
import * as c from "./connector/constants.mjs";
const ok =
  c.PLUGIN_VERSION === "0.5.1" &&
  c.MIN_SUPPORTED_OPENCLAW_VERSION === "2026.6.5" &&
  c.REMOTE_AUTHORITY === false &&
  c.ENFORCEABLE_REMOTE_DECISIONS.length === 0 &&
  c.DEFAULT_MODES.remote_shadow === true &&
  c.DEFAULT_MODES.remote_authority === false &&
  c.DEFAULT_MODES.deny_enforcement === false &&
  c.DEFAULT_MODES.approval_enforcement === false &&
  c.RECEIPT_MODE === "POST_HOOK";
console.log(ok ? "SHADOW-ONLY INVARIANTS OK" : "INVARIANT VIOLATION");
process.exit(ok ? 0 : 1);
'
```

## 6. Verify the metadata parses

```sh
node -e 'JSON.parse(require("fs").readFileSync("connector/openclaw.plugin.json","utf8")); console.log("plugin metadata OK")'
node -e 'const p=JSON.parse(require("fs").readFileSync("connector/package.json","utf8")); console.log("package metadata OK, version", p.version)'
```

Version must be `0.5.1`. The version OpenClaw itself reports must agree:

```sh
openclaw --profile <profile> plugins info mcpherson-governance-connector --json
```

## 7. Verify no remote decision can block

The structural claim is that the pre-call hook's remote path ends in an
unconditional non-authoritative return. Read it directly:

```sh
grep -n -A4 'The remote observation path always rejoins here' connector/hook.mjs
```

The remote path returns `undefined` — it constructs no hook result. The only
`hookResult` in the package is in `connector/canary.mjs`, gated on the
connector's own diagnostic tool plus an operator-activated local control file:

```sh
grep -rn 'hookResult\|block: true' connector/
```

You should find these only in `canary.mjs` and in `hook.mjs` where the canary
result is returned. Nothing in `client.mjs` or `pipeline.mjs` — the remote path
— can produce one.

## 8. Verify configuration cannot raise authority

```sh
grep -n -A16 'FORBIDDEN_AUTHORITY_CONFIG_KEYS' connector/constants.mjs
```

Confirm the rejected key list includes `remote_authority`, `deny_enforcement`,
`approval_enforcement`, and `ENFORCEABLE_REMOTE_DECISIONS`.

## 9. Verify the outbound allowlist

```sh
grep -n -A22 'OUTBOUND_FIELDS' connector/constants.mjs
```

Confirm the list matches [PRIVACY.md](PRIVACY.md) and contains no field capable
of carrying prompts, parameters, or content.

## 10. Verify the compatibility gate reads the host, not a subprocess

```sh
grep -n 'runtime?.version\|readHostManifestVersion\|MIN_SUPPORTED_OPENCLAW_VERSION' \
  connector/host.mjs
grep -c 'child_process\|spawnSync\|execSync' connector/host.mjs   # must print 0
```

The gate reads the OpenClaw plugin SDK's `runtime.version`. When the host
declares a version it could not itself resolve, the gate falls back to a
bounded, read-only lookup of the host's own installed `package.json`. It
executes no subprocess and opens no socket. A host below the minimum refuses
activation and stays inert.

## 11. Verify state resolves inside the active profile

```sh
grep -n -A12 'resolveOpenClawStateDir' connector/host.mjs
```

Confirm the order: the host's own `resolveStateDir`, then `OPENCLAW_STATE_DIR`,
then the default profile root. No branch reads, copies, or migrates state from
another profile.

Check it against a live profile:

```sh
OPENCLAW_STATE_DIR="$HOME/.openclaw-<profile>" \
  node connector/connector-ctl.mjs status
```

## 12. Check runtime state

The connector's control CLI is not placed on your `PATH` by a ClawHub download
plus an OpenClaw archive install. Invoke it by explicit path, with
`OPENCLAW_STATE_DIR` naming the profile:

```sh
OPENCLAW_STATE_DIR="$HOME/.openclaw-<profile>" \
  node connector/connector-ctl.mjs status
```

Reports mode, enabled state, disable/kill-switch/lock state, and receipt counts.

## 13. Run the bundled verification

The package ships a self-contained check with no dependencies and no network
calls:

```sh
npm test
# or equivalently
node scripts/verify-package.mjs
```

It verifies the public connector checksum manifest; the exact enumerated
difference from the sealed v0.5.0 inventory; documentation truth; the embedded
governance-core hashes; absence of the enforcement modules; plugin and package
metadata; LICENSE and NOTICE presence; compatibility metadata consistency; the
shadow-only invariants; rejection of authority configuration; that only the
canary constructs a block; and that the bundled configuration example still
loads.

## What this package does not let you re-run

The upstream connector suite runs against the internal build repository's test
tree, which is **not** shipped here (see [LIMITATIONS.md](LIMITATIONS.md) §10a).
The checks above plus `npm test` are the supported local verification path for
this release.

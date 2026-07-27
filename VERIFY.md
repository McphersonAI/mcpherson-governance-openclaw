# Verification

**Connector v0.5.0.** How to confirm that what you have is what was released,
and that it behaves as claimed. Everything here runs locally.

## 1. Verify the release archive

```sh
shasum -a 256 mcpherson-governance-openclaw-v0.5.0.tar.gz
```

Compare against the published release manifest value. Do not install on a
mismatch.

## 2. Verify every file in the package

```sh
shasum -a 256 -c RELEASE-CHECKSUMS.sha256
```

Every line must report `OK`.

## 3. Verify the 28 connector files specifically

This is the important one. `CONNECTOR-FILES.sha256` covers exactly the 28
connector files and nothing else:

```sh
shasum -a 256 -c CONNECTOR-FILES.sha256
wc -l < CONNECTOR-FILES.sha256      # must print 28
```

All 28 must report `OK`. This is a self-consistency check against the
public-package checksum manifest; it is not a claim that all 28 files match the
sealed inventory. Any `FAILED` line means your copy has been modified.

The provenance comparison is deliberately separate:

- Sealed connector inventory: **28 files**
- Public connector identity: **27/28 sealed files**
- Sole intentional difference: **`connector/package.json`**
- Runtime modules (`.mjs`): **23**
- Runtime-module identity: **23/23 byte-identical**

The package-metadata difference enables public distribution and does not change
runtime logic. `SEALED-CONNECTOR-FILES.sha256` records the sealed-reference
hashes; `npm test` verifies that the changed-file set is exactly
`connector/package.json` and that no `.mjs` file differs.

To confirm no extra runtime file was added to the connector tree:

```sh
find connector -type f | wc -l      # must print 28
```

## 4. Verify the embedded governance core

The connector embeds a subset of the governance core and records its own source
hashes:

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
grep -nE 'REMOTE_AUTHORITY|ENFORCEABLE_REMOTE_DECISIONS|remote_shadow|remote_authority|deny_enforcement|approval_enforcement|RECEIPT_MODE|PLUGIN_VERSION' \
  connector/constants.mjs
```

Expected:

| Constant | Required value |
| --- | --- |
| `PLUGIN_VERSION` | `"0.5.0"` |
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
  c.PLUGIN_VERSION === "0.5.0" &&
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

Version must be `0.5.0`.

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

## 10. Check runtime state

```sh
connector-ctl status
```

Reports mode, enabled state, disable/kill-switch/lock state, and receipt counts.

## 11. Run the bundled verification

The package ships a self-contained check with no dependencies and no network
calls:

```sh
npm test
# or equivalently
node scripts/verify-package.mjs
```

It verifies the public connector checksum manifest; 27/28 sealed identity with
only `connector/package.json` changed; 23/23 `.mjs` runtime identity;
documentation truth; the embedded governance-core hashes; absence of the
enforcement modules; plugin and package metadata; LICENSE and NOTICE presence;
compatibility metadata consistency; the shadow-only invariants; rejection of
authority configuration; that only the canary constructs a block; and that the
bundled configuration example still loads.

## What this package does not let you re-run

The 181-test connector suite runs against the internal build repository's test
tree, which is **not** shipped here (see [LIMITATIONS.md](LIMITATIONS.md) §10a).
The checks above plus `npm test` are the supported local verification path for
this release.

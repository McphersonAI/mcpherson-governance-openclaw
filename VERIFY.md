# Verify this package — v0.6.3-beta.6

Do not take the documentation's word for the safety posture. Check it.

## 1. Verify the archive you downloaded

```sh
shasum -a 256 mcphersonai-mcpherson-governance-openclaw-0.6.3-beta.6.tgz
```

Compare against the published release checksum. The archive is a standard npm
tarball with a single `package/` root.

List its contents without installing:

```sh
tar -tzf mcphersonai-mcpherson-governance-openclaw-0.6.3-beta.6.tgz | sort
```

## 2. Run the packaged verifier

From the installed or extracted package root:

```sh
npm run verify
```

This checks, and fails closed on any mismatch:

- every packaged file against `PACKAGE-FILES.sha256`;
- no unexpected and no missing files;
- package name `@mcphersonai/mcpherson-governance-openclaw` and version `0.6.3-beta.6`;
- plugin ID `mcpherson-governance-connector`;
- `package.json` and `openclaw.plugin.json` versions agree;
- `openclaw.compat.pluginApi` is `>=2026.6.5`;
- the config schema default `enabled: false`;
- the package manifest's exact package, plugin, version, source commit/tree,
  and immutable OpenClaw target identity;
- the requirement for a separate exact local profile binding supporting only
  explicit `DEFAULT` or `NAMED` modes;
- the source-owned safety constants;
- absence of any policy evaluator or gate module;
- absence of absolute home-directory paths and credential-shaped material;
- every import resolves to a sibling module or a `node:` built-in.

> If it prints nothing and exits 0, check for a symlinked path component — see
> [SUPPORT.md](./SUPPORT.md). Resolve the real path with `cd <dir> && pwd -P`
> and re-run.

## 3. Check provenance

`RELEASE-PROVENANCE.json` (schema `…/v2`, corrected in 0.6.3-beta.6) binds this
archive to the **public** release source. `V6-PACKAGE-MANIFEST.json`
additionally binds every source file by content hash and carries the immutable
audited OpenClaw target. The target deliberately contains only portable,
home-relative path identities. An operator-created local profile binding
separately pins the exact physical home, profile, state, config, and runtime
paths.

```sh
cat RELEASE-PROVENANCE.json
```

**What changed in 0.6.3-beta.6, and why.** Through 0.6.1 this record named the
private build commit as `source_commit`, and the package manifest listed
seventeen source files under private `release/openclaw-public/…` paths. Both
described a repository you cannot fetch, so neither claim could be checked by
anyone holding the artifact. They are corrected here.

Three bindings genuinely cannot be written into the artifact that they
describe: the release commit SHA (a commit's identifier covers its own
content), the release tree SHA (writing it into a tracked file changes that
tree), and the archive SHA-256 (the archive contains this file). Rather than
guess a future commit or stay silent, each is declared under
`external_bindings` with the exact command that resolves it:

```sh
git rev-parse refs/tags/v0.6.3-beta.6^{commit}
git rev-parse refs/tags/v0.6.3-beta.6^{tree}
shasum -a 256 mcphersonai-mcpherson-governance-openclaw-0.6.3-beta.6.tgz
```

Everything that *can* be stated truthfully at write time is stated as a value:
`source_commit` and `source_tree` are the public base commit and tree this
release was built from — both already published, both labelled
`PUBLIC_BASE_COMMIT` / `PUBLIC_BASE_TREE` so neither can be misread as a
self-reference — along with the release tag, the package version, and the
complete internal checksum coverage. `release_ordering` records the order the
manifests must be written in; `scripts/build-release-manifests.mjs --check`
re-derives all three and fails on any drift.

## 4. Verify the safety claims yourself

These are the checks worth doing by hand.

**No policy evaluator or gate is packaged:**

```sh
find . \( -name 'evaluate.mjs' -o -name 'gate.mjs' \)
# expect: no output
```

Governability Diagnosis uses a diagnostic evidence-assessment module. Its
findings do not grant execution authority, and it has no call path to tool
execution.

**Authority ceilings are source constants, not settings:**

```sh
grep -n 'REMOTE_AUTHORITY\|ENFORCEABLE_REMOTE_DECISIONS' \
  plugins/openclaw-connector/constants.mjs
```

Expect `REMOTE_AUTHORITY = false` and a frozen empty
`ENFORCEABLE_REMOTE_DECISIONS`.

**Configuration cannot introduce authority:**

```sh
grep -n 'FORBIDDEN_AUTHORITY_CONFIG_KEYS' -A 16 \
  plugins/openclaw-connector/constants.mjs
grep -n 'additionalProperties' openclaw.plugin.json
```

**Unconfigured tools make no request:**

```sh
grep -n 'hasOwn(this.#config.toolMetadata' -B 6 -A 4 \
  plugins/openclaw-connector/hook.mjs
```

Expect the unconfigured branch to call `recordLocal(summary, "NOT_ATTEMPTED",
"SKIPPED")` and return without submitting to the network pipeline.

**The outbound field allowlist is fixed:**

```sh
grep -n 'OUTBOUND_FIELDS' -A 22 plugins/openclaw-connector/constants.mjs
```

**No dependencies:**

```sh
node -e 'const p=require("./package.json");console.log(p.dependencies,p.devDependencies,p.peerDependencies,p.bundledDependencies)'
# expect: undefined undefined undefined undefined
```

## 5. Verify it stays inert before you trust it

Install into a throwaway named profile, not your working one. Use an isolated
physical home containing the independently installed audited OpenClaw runtime:

```sh
VERIFY_HOME=/absolute/path/to/disposable-home
VERIFY_PROFILE=verify-mcpherson-v062
env HOME="$VERIFY_HOME" OPENCLAW_HOME="$VERIFY_HOME" \
  "$VERIFY_HOME/.local/bin/openclaw" --profile "$VERIFY_PROFILE" plugins install \
  /absolute/path/to/mcphersonai-mcpherson-governance-openclaw-0.6.3-beta.6.tgz
env HOME="$VERIFY_HOME" OPENCLAW_HOME="$VERIFY_HOME" \
  "$VERIFY_HOME/.local/bin/openclaw" --profile "$VERIFY_PROFILE" plugins inspect \
  mcpherson-governance-connector
```

Confirm connector `config.enabled` is `false`, that no deployment credential and
no receipt ledger were created by installation alone, and that no login page or
account flow appeared. Then remove the profile.

Before live observation, follow [INSTALL.md](./INSTALL.md) §4 exactly: run
the local SecretRef and loopback-health identity bootstrap, stop the bootstrap
gateway, restore the profile state directory to `0700` as §4.1 requires, then
run `init-profile-binding` and `verify-profile-binding`, with the
same explicit NAMED profile and physical home. Capture initialization's exact
`binding_id` separately and supply it as `--profile-binding-id`. Confirm both
commands report `"ok": true`. Every live consumer must receive the same private
binding file and independently captured ID; a wrong, changed, rehashed, stale,
reformatted, package-mismatched, or other-profile receipt binding must fail
closed.

## 6. Check the contents against the published source

The archive is built only from a clean, committed source tree, with normalized
entry ordering, zeroed timestamps, fixed uid/gid, and fixed modes. From 0.6.3-beta.6
you can check both the **contents** and the **archive envelope** yourself:

1. `scripts/verify-package.mjs` recomputes the SHA-256 of every packaged file
   and compares it with `PACKAGE-FILES.sha256`, which covers every file in the
   package except itself. Any single changed byte fails.
2. The identical file tree is published at
   `https://github.com/McphersonAI/mcpherson-governance-openclaw` under tag
   `v0.6.3-beta.6`. Diff your extracted package against that tag; it should be empty.

**You can now rebuild the archive yourself.** From 0.6.3-beta.6 the release is built
by `npm pack` from the tagged public tree — no private tooling is involved, so
the byte-identical archive is reproducible outside McPherson AI:

```sh
git clone https://github.com/McphersonAI/mcpherson-governance-openclaw
cd mcpherson-governance-openclaw && git checkout v0.6.3-beta.6
npm pack
shasum -a 256 mcphersonai-mcpherson-governance-openclaw-0.6.3-beta.6.tgz
```

That digest must equal the one published on the GitHub release and on
ClawHub. You can also re-derive the three release manifests and confirm they
match what shipped:

```sh
node scripts/build-release-manifests.mjs --check
```

Through 0.6.1 neither check was possible: the build ran in a private
repository with private tooling, and the recorded provenance pointed there.
That is the defect 0.6.3-beta.6 removes.

## What verification cannot tell you

It cannot certify the package against any compliance framework, prove the
absence of every possible defect, or establish behavior on OpenClaw versions
outside the approved target set — `2026.6.5` (commit `5181e4f`), `2026.6.33`
(commit `7af0cfc`), and `2026.7.1-2` (commit `0790d9f`). See
[LIMITATIONS.md](./LIMITATIONS.md).

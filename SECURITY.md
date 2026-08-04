# Security — McPherson Governance Connector v0.6.1

## Reporting a vulnerability

To report a suspected vulnerability, email **admin@mcphersonai.com** privately.
Please do not open a public issue for suspected security vulnerabilities.

Please include a description, the affected version, and reproduction steps.

## Security posture

### Structural, not configurable

The safety ceilings are source-owned constants, not settings:

- `REMOTE_AUTHORITY = false`
- `ENFORCEABLE_REMOTE_DECISIONS = []` (frozen, empty)
- `AUTHORITY = NONE`, `ENFORCEMENT = OFF`

They are deliberately not derived from configuration, environment variables,
policy documents, or API data. The configuration schema is
`additionalProperties: false`, and a set of authority-shaped configuration keys
is explicitly refused, so configuration cannot introduce authority.

There is **no policy evaluator and no gate** in this package.

### No third-party dependencies

The package has zero runtime, development, peer, or bundled dependencies. Every
import resolves to a sibling module in this package or to a Node.js built-in
(`node:crypto`, `node:fs`, `node:https`, `node:path`, `node:os`, `node:url`,
`node:util`, `node:child_process`). This removes the third-party supply-chain
surface entirely.

### Local subprocess execution

Static scanners flag the single `child_process.spawnSync` call in
`packages/openclaw-live-observer/index.mjs`. It is disclosed here rather than
removed, because it is how live observation reads the local OpenClaw runtime
without modifying it. Its full boundary:

- **Executable.** Only the OpenClaw runtime entrypoint named by a verified
  local profile binding. Before any spawn, every path component is checked for
  symlinks; the file must be a non-symlink regular file, owned by the invoking
  account, with `realpath` equal to itself; and the SHA-256 of the runtime
  entry, the OpenClaw `package.json`, and `dist/build-info.json` must each
  equal the pinned target digests. Package name, version, `bin.openclaw`, and
  the full build commit must also match. A substituted or modified runtime
  fails closed before execution.
- **Arguments.** Fixed argv arrays built in code — never string concatenation.
  The version probe is exactly `["--version"]`. Gateway calls are
  `[...profilePrefix, "gateway", "call", <method>, "--url", <loopback>,
  "--token", <token>, ("--params", <canonical JSON>), "--json", "--timeout",
  "5000"]`, where `<method>` must be in a frozen RPC allowlist and the profile
  prefix derives from a name matching `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`.
- **No shell.** `shell: false`, with `windowsHide: true`. There is no shell
  interpretation, expansion, or metacharacter handling on any platform.
- **Environment.** The ambient environment is never inherited. A frozen,
  allowlisted environment is constructed per call — `HOME`, a constant `PATH`
  of `/usr/local/bin:/usr/bin:/bin`, a read-only auth-store marker, and the
  explicit profile, home, state, and config values — plus a fixed list of
  redirect-capable variables deliberately set empty.
- **Timeout, cwd, output.** Every call sets an explicit timeout (5s version
  probe, 7.5s gateway call), a `cwd` of the bound account home, and a
  `maxBuffer` ceiling (64 KiB probe, 2 MiB gateway). Oversized output fails as
  `live_rpc_response_too_large` rather than being truncated and parsed.
- **Failure behavior.** Fails closed. Any spawn error, signal, or non-zero exit
  raises a typed `live_*` error. There is no retry with relaxed constraints and
  no fallback path.
- **Untrusted input.** None reaches the executable or the argv. The runtime is
  digest-pinned, methods are allowlisted, and the profile name is pattern-
  validated. The command runner is injectable **only** for deterministic
  adversarial tests; the shipped CLI exposes no injection point.
- **Locality.** Gateway calls address the loopback endpoint only.

This is local, bounded, non-shell, and covered by the adversarial trust-boundary
tests. It is disclosed, not hidden — verify it yourself at
`packages/openclaw-live-observer/index.mjs`.

### Bounded outbound behavior

- Outbound requests occur only when `enabled: true` **and** the tool has
  complete configured metadata.
- `apiUrl` must match `^https://`.
- The outbound field set is a fixed allowlist (see [PRIVACY.md](./PRIVACY.md)).
- Requests are bounded: max outbound bytes, max response bytes, max in-flight,
  max queue, connect timeout, observation budget, bounded retries, and a
  circuit breaker.
- An **unconfigured tool makes no HTTPS request at all** and is recorded
  `remote_status: NOT_ATTEMPTED`, `local_disposition: SKIPPED`. Fallback
  metadata is never manufactured and never reaches the wire.

### Local file discipline

- Connector state lives in a fixed directory name inside the active OpenClaw
  profile state directory.
- Live observation requires a private local profile binding that pins the
  package/source identity and exact explicit profile, home, state, config, and
  runtime paths, plus the exact connector state and receipt-ledger paths.
  NAMED never falls back to DEFAULT, the binding's canonical bytes are
  enforced, it expires after at most 24 hours, every consumer requires its
  independently captured `binding_id`, and inherited path/profile environment
  variables cannot redirect it.
- Credentials, receipts, and outputs are owner-only.
- The observer first requires the binding's exact profile-local receipt path,
  then refuses ledgers that are not private, owned, non-symlink, regular `0600`
  files. A default/founder or other-profile path is never read.
- Path components are checked for symlinks; descriptor-bound reads are used
  where the platform allows.

### Operator controls

A kill switch, a system lock, and an operational disable file each stop remote
contact. Operationally disabled is fully inert for ordinary observations. See
[LIFECYCLE.md](./LIFECYCLE.md).

## Known and accepted limitations

These are stated so they are not mistaken for defects:

- **No certification.** This package carries no security or compliance
  certification of any kind.
- **Not a sandbox.** The connector runs in your OpenClaw process with your
  permissions. It observes; it does not isolate or contain tools.
- **Receipt truth is bounded by the post-hook.** Receipts record what the hook
  observed, not independent verification of a tool's real-world effect.
- **A configured connected-shadow identity may receive a remote `404`** when the
  service cannot resolve the deployment, agent, tool, or contract. That is a
  remote contract or registry failure, not an execution decision, and it cannot
  block the original tool.
- **Node does not expose portable `openat`/`renameat`.** Component checks,
  descriptor-bound reads, and identity rechecks substantially narrow namespace
  races but cannot eliminate a malicious concurrent process rewriting path
  components between syscalls.
- **Version-pinned evidence.** Live observation refuses any build outside the
  approved target set — OpenClaw `2026.6.5` (commit `5181e4f`), `2026.6.33`
  (commit `7af0cfc`), and `2026.7.1-2` (commit `0790d9f`) — including the
  `2026.7.2` prerelease line. Approval requires all five identity fields of one
  approved entry; the `extended-stable` dist-tag grants nothing by itself.
  **The complete live-observation lifecycle is proven on `2026.6.5` and
  `2026.6.33`**, with `2026.6.33` the preferred extended-stable baseline. On
  `2026.7.1-2` the connector installs and the target binding resolves, but
  OpenClaw does not issue the device-bound operator token the observer
  requires; see [LIMITATIONS.md](./LIMITATIONS.md).

## Verifying this package

Run `npm run verify` and follow [VERIFY.md](./VERIFY.md) to check the file
inventory, checksums, declared identities, and safety constants yourself. Do not
take this document's word for the posture — the verification is the point.

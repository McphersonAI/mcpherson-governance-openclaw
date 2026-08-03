# Security — McPherson Governance Connector v0.6.0

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
- **Version-pinned evidence.** Behavior is evidenced against OpenClaw
  `2026.6.5` (commit `5181e4f`) only.

## Verifying this package

Run `npm run verify` and follow [VERIFY.md](./VERIFY.md) to check the file
inventory, checksums, declared identities, and safety constants yourself. Do not
take this document's word for the posture — the verification is the point.

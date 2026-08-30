# Compatibility and migration — v0.6.3-beta.6

Support in this package is **exact-target based, never label-based**. A build
is approved only when its semantic version, full commit, runtime-entry
SHA-256, `package.json` SHA-256, and `dist/build-info.json` SHA-256 all match
one approved entry in `scripts/verify-package.mjs`. Membership in the
`2026.6` line approves nothing on its own, and neither does the
`extended-stable` dist-tag: that tag is a moving pointer, and a future build
it comes to point at is not covered by anything here.

## 1. OpenClaw target support

### `2026.6.33` — commit `7af0cfc9c5488e03c4e2f528bdc7ac9f7778b35e`

- **Preferred target.** This is the extended-stable build to install against.
- **Fully lifecycle-proven.** Install, checksum verification, registration,
  profile binding, device-bound `operator.read`, discovery, AutoMap proposal,
  governability diagnosis, local evidence output, restart with continued
  operation, disable, uninstall, and cleanup all complete against this exact
  build.

### `2026.6.5` — commit `5181e4f7c82bd373cb215a5619b0fa03c13862b7`

- **Fully lifecycle-proven.** The same complete lifecycle completes against
  this exact build. It remains supported; `2026.6.33` is preferred.

### `2026.7.1-2` — commit `0790d9f593ad30c940ed93b5872a8cf6d6f3cf8c`

- **Exact-target binding validated.** The build matches its approved entry on
  all five identity hashes and resolves to a valid target binding.
- **Install and uninstall validated.** The connector installs, loads,
  registers, disables, uninstalls, and cleans up.
- **Live observation is not supported.** The upstream local CLI does not issue
  the device-bound `operator.read` token this observer requires. On a loopback
  Gateway using shared-secret auth it omits its device identity from the
  connect handshake, so OpenClaw never creates a device-pairing request and
  never mints a device-bound token. The observer refuses to accept the shared
  Gateway token in its place rather than weaken the binding, so the
  live-observation lifecycle cannot complete. This is an upstream limitation,
  not a configuration error. Use `2026.6.33` or `2026.6.5` for live
  observation.

Every other OpenClaw version is permitted by the connector's declared
`>=2026.6.5` plugin-API range but is not covered by this evidence, and live
observation refuses it.

## 2. Migrating from v0.5.1 to v0.6.3-beta.6

v0.6.x writes a different receipt-record shape than v0.5.1. A ledger holding
records from more than one connector version **fails closed** — this is
deliberate, and it is why the ledger is rotated rather than reused. Do not
attempt to merge, convert, or interleave the two.

Perform the steps in this order.

### 1. Stop v0.5.1 before rotating the ledger

Disable the v0.5.1 connector and confirm the OpenClaw process is no longer
running with it loaded. Rotating a ledger while the old version can still
append to it is what produces a mixed-version ledger.

```bash
openclaw plugins disable mcpherson-governance-connector
```

### 2. Archive the historical v0.5.1 ledger

Move it aside; do not delete it, and do not leave it in place.

```bash
mv "$PROFILE_STATE/mcpherson-governance-connector/receipts/connector-receipts.jsonl" \
   "$PROFILE_STATE/mcpherson-governance-connector/receipts/connector-receipts.v0.5.1.jsonl.archived"
```

The archived file is historical evidence. It stays readable on its own terms
and is never an input to a v0.6.x observation.

### 3. Create a fresh owner-only v0.6.x ledger

The new ledger must be a private, owned, non-symlink regular file with mode
`0600`, inside a `0700` state directory. Live observation refuses anything
else.

```bash
chmod 0700 "$PROFILE_STATE"
install -m 0600 /dev/null \
  "$PROFILE_STATE/mcpherson-governance-connector/receipts/connector-receipts.jsonl"
```

### 4. Verify the profile binding

Initialize the binding and capture the printed binding ID independently — every
later command requires it.

```bash
node scripts/governance-diagnostics.mjs init-profile-binding \
  --profile-mode NAMED --profile <name> --out ./binding.json
node scripts/governance-diagnostics.mjs verify-profile-binding \
  --binding ./binding.json --profile-binding-id <captured-id>
```

### 5. Verify the device-bound `operator.read` token

One successful local loopback health call creates the profile identity and the
device-bound operator token. Confirm it before observing.

```bash
openclaw gateway call health --json
```

If this does not yield a device-bound token, stop: on `2026.7.1-2` it will not
(see §1), and live observation cannot proceed on that build.

### 6. Run the lifecycle and restart proof

Run one full observation, restart OpenClaw, and run a second observation.
Continued operation across restart is part of the proof, not an optional
extra.

```bash
node scripts/governance-diagnostics.mjs observe-live \
  --binding ./binding.json --profile-binding-id <id> --out-dir ./obs-1
# restart OpenClaw, then:
node scripts/governance-diagnostics.mjs observe-live \
  --binding ./binding.json --profile-binding-id <id> --out-dir ./obs-2
```

### 7. Do not mix historical and fresh version records

Keep the archived v0.5.1 ledger and the fresh v0.6.x ledger permanently
separate. Never point an observation at the archive, never append v0.6.x
records to it, and never restore it over the fresh ledger. A mixed ledger
fails closed, and a mixed *evidence set* is worse: it reads as continuous
history when it is not.

## 3. What this package still does not do

Migration changes none of the fixed safety values. They are asserted by the
packaged verifier on every run:

```
AUTHORITY                     NONE
ENFORCEMENT                   OFF
AUTOMATIC_MAPPING_ACTIVATION  OFF
OUTBOUND_ACTIONS              OFF
REGISTRY_MUTATION             OFF
REMOTE_DECISIONS              SHADOW_ONLY
```

See [LIMITATIONS.md](./LIMITATIONS.md) for the full boundary and
[INSTALL.md](./INSTALL.md) for first-time installation.

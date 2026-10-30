# Observa OpenClaw first bound node — qualification record

Owner: Codex. Mission authority: founder prompt, SOP-03 v1.5 (2026-10-30).
Candidate worktree starts at a4038550796dbcaf51894ae1646d78d9da9553d9.
Engineering candidate: 0.8.0. Public release is held for the exact frozen V7
source disclosure/license decision. No production activation or certification is claimed.

Target: OpenClaw 2026.10.9, source 8b18b5578f66eab1501cba4cef2310d88bfb9a41.
Node constraint from official package: >=24.22.1 <25 || >=26.12.1.
Isolated lab: /Users/bmcpherson/observa-qualification/openclaw-v080.
Existing customer installations, credentials, memories, receipts and worktrees are protected.
All test profiles and processes belong to the isolated lab. No customer gateway restart is authorized by these tests.

## Verified scope

Official target source and npm distribution: OpenClaw 2026.10.9 at the commit
above. Actual clean installation, native gateway registration, startup, tool
events and operator approval used Node 24.22.1 on macOS arm64. Other releases,
Node versions and platforms are unqualified. The plugin uses public hooks and
documented installation reports; it does not read a private OpenClaw database.

The exact original ClawHub 0.7.4 archive is preserved with SHA-256
`084ae9e93dead73e59554b3315c47e11dc06e6f13e9d0dca073961755507de69`.
Actual original → candidate → original installations each loaded a real gateway.
Memory, credential, historical proof and selected profile settings stayed
byte-identical; the new native journal survived rollback.

The source suite passes 231/231 tests. The independent reviewer additionally
ran 27 integrity, replay, tenant-binding, approval and namespace tests, plus two
current Hosted tenant-isolation tests. The reviewed extended gateway run produced
103 valid signed records and 13 exact Hosted request-hash/observation-ID ACK
pairs, with zero forbidden downstream files. The subsequent pairing-hardened
candidate passed a new real gateway run and healthy packaged `doctor` check.

The Hosted qualification uses current source
`fbe815cbeb4e602c357ba313ec73db09700e08c0`, disk persistence and enabled
provenance verification behind local verified TLS. Only the external control
plane entitlement/admission and notification service is a synthetic fixture.
This is not a production Hosted or actual email-delivery qualification.

Actual network outage and replay used distinct connector processes. Exact
acceptance/readback survived a Hosted app restart. Lost ACK after server
acceptance remained pending on nonce refusal; no acceptance was invented.
Disable preserved pending proof, and resume delivered eligible evidence.

The packaged CLI passed 24 cases, including a real terminal-guided `access`
without `--api-url`, hidden verification, request status and old aliases,
pairing through actual Hosted credential issuance/health/identity, truthful
pre-gateway health, stop and help. Eight hostile pairing responses were refused
without activation or configuration changes: oversized body, secret echo,
wrong deployment, credential-ID mismatch, fingerprint mismatch, redirect,
non-boolean success and stalled transport. The real Local Node 0.1.9 command
remained unchanged while `observa-openclaw` worked, including paths with spaces.

## Bound operation and exclusions

The only governed operation is `observa_bound_write`: bounded exclusive creation
inside the connector-owned synthetic directory. The unchanged frozen V7
evaluator supplies all policy decisions. ALLOW produced the authorized file;
DENY prevented it; actual device-authenticated OpenClaw operator approval
allowed only the exact operation once. Deny, allow-always, real approval expiry,
late resolution, changed policy, missing/contradictory identity, altered request,
repeat/restart claims and an alternate direct route did not produce forbidden
effects. The default Tool Search wrapper and direct tool schema were exercised.

Ordinary exec/filesystem tools, other plugin tools, MCP routes, native harness
operations, gateway commands, external processes and subagent operations using
other tools are uncovered. A successful tool return does not prove a business
outcome. An allowed decision does not prove execution.

Customer enforcement remains OFF by default. The available opt-in is restricted
to isolated synthetic mode; no production activation switch is supplied.
Control Gate C must qualify real operations, identities, approval authority,
all relevant routes, failure/recovery behavior and customer authorization before
any separately accepted production activation.

## Evidence contract boundaries
- Hosted native-v3 is n8n-specific; generic acquisition explicitly rejects OpenClaw. No relabeling is permitted.
- Existing /v1/observations accepts COMPLETED/FAILED/TIMED_OUT only. UNKNOWN stays explicit in the signed native ledger.
- Existing Hosted request freshness is 300 seconds; replay of consumed nonce returns 409, which is not proof of acceptance. Lost ACK remains unresolved without a supporting readback contract.
- OpenClaw ordinary ALLOW hooks do not freeze parameters. The bound connector-owned synthetic tool checks and consumes the exact request at execution as well as returning the V7 decision at the host prehook.
- Released customer enforcement stays disabled. Isolated synthetic binding does not confer production authorization; Control Gate C remains required.

The new journal contains no prompts or tool argument/result bodies. Local
session/run/call references are hashed; the existing v2 delivery envelope keeps
its bounded screened run/call identifiers for exact Hosted linkage. Delivery
intent is signed and bound to its capture-time origin/deployment/credential.
Changing pairing does not retarget old evidence. Local signatures establish
local chain integrity, not third-party certification or business success.

## Retained failures and release condition

Original FAIL/HOLD evidence remains preserved. Candidate3's gateway harness
failed on SQLite null-prototype versus plain-object comparison after successful
runtime behavior; corrected comparisons were rerun. The first upgrade harness
assumed the old installation directory, corrected using official `plugins info`
generation reporting. The first final CLI harness expected a published roster
before gateway startup; the correct incomplete-state exit was retained and a
fresh corrected run passed. Earlier reviewer security findings were repaired
and independently retested, rather than relabeled as passes.

The reviewer also reproduced a hidden-input terminal race in candidate5: echo
was disabled after displaying the prompt. Both verification and pairing now
disable echo before displaying the secret prompt. Final terminal tests must send
input immediately; the earlier driver delay masked the defect and was removed.

The upstream dependency audit reports six affected package entries (four high,
two moderate), including pinned undici 8.11.2 and zod 4.6.5. See
`DEPENDENCIES.md` for scope and source references. This is not a clean audit or
host-wide security acceptance. No automatic dependency update or downgrade was
applied to the exact official target.

The exact V7 closure is the 39 immutable files in
`plugins/openclaw-connector/v7/PROVENANCE.json`, frozen source
`b20c39b45f3f80693e38726e456164feae90c272`. The existing public connector license
does not itself establish a grant for this previously private closure.
SOP-03 v1.5 §3's legal-commitment gate is the reason for the narrow pending
owner decision. No public code push, tag, GitHub release or ClawHub upload has
occurred. Public fresh-install verification necessarily follows publication.

Detailed lab logs and original failures are retained under
`/Users/bmcpherson/observa-qualification/openclaw-v080/evidence`; independent
read-only findings are under `/tmp/observa-openclaw-independent-review-20261030`.

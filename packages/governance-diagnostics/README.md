# governance-diagnostics (v0.6)

Diagnostic-only library for the three v0.6 capabilities:

1. **AutoMap** — read-only capability discovery and deterministic mapping
   proposals from static, sanitized, repository-local sources. AutoMap may
   discover and propose; it may not activate.
2. **Governability Governor** — deterministic diagnosis of whether connectors
   and capabilities are visible, attributable, scoped, and independently
   revocable. The Governor may diagnose; it may not block.
3. **Latency instrumentation and summaries** — offline prototype
   governance-path timing over synthetic fixtures, plus separate summaries of
   live tool-execution durations produced by the isolated
   `openclaw-live-observer` package. The offline recorder is not live runtime
   instrumentation.
4. **Approved shadow mapping export** — generated live classification
   confirmation, documentation-only approval binding, deterministic inert
   registry-patch export, exact preview, and in-memory shadow lookup. There is
   no registry application or activation function.

This directory is a plain ES-module library, not an npm workspace, and is not
part of the API release source map. The v0.5 runtime (`packages/
governance-core`, `services/governance-api`, `plugins/openclaw-connector`)
never imports it; the dependency direction is one-way (diagnostics reads the
frozen v0.5 modules read-only, for canonical JSON, wire-safety patterns, and
the outbound privacy guard).

Trust and contract discipline (post-Sol repair, updated for the final-repair
cycle):

- `contracts.mjs` is the versioned diagnostic contract inventory. The current
  CLI artifact inputs and the named AutoMap, Governor, diagnosis, coverage,
  latency-import, recorder, and summarizer paths call
  `validateArtifact()` / `validateEnvelope()` or an equivalent producer guard
  explicitly. `schema-validate.mjs` is a dependency-free strict subset
  validator: it rejects rather than coerces, treats an unsupported schema
  keyword (or a property-bearing object schema with no
  `additionalProperties` policy) as a load-time error, and calendar-validates
  `date-time-utc` timestamps. This is a claim about the presently wired
  boundaries, not an automatic guarantee for arbitrary future callers or
  hand-forged terminal artifacts.
- `governor/diagnose-evidence.mjs` evidence-assessment module `0.6.3` and
  `typed-values.mjs` define the Governor's typed positive-evidence vocabulary.
  The assessment is diagnostic and non-authoritative. Strict identifiers,
  per-field positive-assertion enums, and explicit boolean relevance facts
  drive results with an `asserts` signal. Conditional proof is required only
  when its relevance flag is a usable explicit `true`; `false` establishes
  non-applicability, and omission is missing evidence. Capture chronology is
  enforced (`observed_at` cannot follow `captured_at`, and `captured_at` cannot
  follow evaluation). Findings are canonical derived records, including the
  exact `confirmed_absent_fields` and `independence_conflict_fields` proof
  state; caller-authored reasons, owner lists, or all-PASS partitions cannot
  be substituted. Evidence PASSes only by being a typed positive assertion —
  not by avoiding a finite list of negative phrases.
- Every finding set and diagnosis carries a deterministic finding-set ID plus
  the evidence-document ID, canonical sorted-key JSON SHA-256, evidence
  schema/version, evaluator/version, diagnosed units, and criterion-local
  evidence references. Shape validation alone is not acceptance:
  `validateFindingSet()`, diagnosis construction/validation/rendering, and
  both CLI export paths require the exact separately supplied evidence
  document and rederive the complete findings before returning or writing.
  Changing the evidence, subject, status, or references invalidates the
  composition; genuinely absent evidence still produces UNKNOWN rather than
  a fabricated failure.
- `sensitive-values.mjs` is the semantic sensitive-value policy: values are
  rejected by shape (secret prefixes, token shapes, URLs, hosts, emails, long
  digit runs, and sensitive keyword markers), not only by key name. The same
  policy screens recorded AND imported latency identifier tags, so a value the
  policy recognizes as sensitive-shaped is rejected on the import path. The
  policy is conservative and may both over-reject and miss shapes outside its
  rules; it is not universal secret detection.
- `automap/pinned-content.mjs` binds the code-owned registry to
  **pinned-content** provenance: a trusted root, a contained repository-
  relative path, an exact content-hash pin, a declared source kind, and
  symlink/regular-file/size safety, plus per-entry cross-checks against the
  code-owned classifier. This is content-integrity binding, honestly named —
  the caller selects the trusted root, and it is not a Git-index,
  commit-identity, repository-authenticity, authorship, or signature proof. A
  byte-exact copy at the trusted relative path under a supplied root is
  accepted as pinned content. Its path/type/hash checks do not claim immunity
  to malicious concurrent namespace replacement.
- `automap/candidate-validate.mjs` reconstructs and re-verifies every
  candidate-derived field (identity, semantic content hash, risk proposal,
  outbound preview, effects/classification consistency, duplicate exclusion)
  wherever `validateCandidateSet()` is called. For
  `committed_registry_v1`—a historical method token, not a Git claim—the
  validator derives every static member field from the exact built-in pinned
  registry and classifier and requires complete candidate-set membership and
  canonical ordering. This full derivation is specific to the built-in pinned
  fixture and does not prove Git identity, repository authenticity,
  authorship, or signature provenance. The current CLI candidate-set inputs
  and the proposal/coverage paths call it; a caller that bypasses the
  validator receives no stronger guarantee merely by importing a data object.
- `automap/approval.mjs` binds both sides of a documentation-only lifecycle
  transition: `candidate_content_hash` is the reviewed `PROPOSED` state and
  `approved_candidate_content_hash` is the exact
  `APPROVED_DOCUMENTATION_ONLY` state. Semantic candidate consumers require a
  matching approval record for an approved member. Coverage has no approval
  input and therefore rejects approved candidate sets; drift accepts explicit
  bound artifacts and validates them before using their post-transition hash.
  Approval rationale is screened before creation and again on imported-record
  validation, and the CLI repeats semantic validation before stdout or file
  export. The bounded screen rejects recognized credential assignments and
  weak-value forms; secret, token, private-key, and long-hex shapes; URL
  markers and selected unsafe URI schemes; hosts, network addresses, email,
  long-digit and formatted-phone forms, and common PII/sensitive keyword
  labels; plus absolute, home-relative, dot-relative, drive-qualified, and UNC
  paths. Ordinary slash prose such as `read/write` is not treated as a path.
  Rejected content is not reflected in the public error. This is conservative
  shape screening, not universal secret or PII detection, and it may both
  over-reject safe prose and miss novel forms.
- `automap/drift.mjs` validates each drift record and its event-set envelope,
  recomputes the drift ID, requires normalized mutually disjoint
  `fields_added`/`fields_removed`/`fields_changed`, and enforces the
  change-kind, fingerprints, content hashes, severity, review, and staleness
  relationships. `UNKNOWN` remains wire vocabulary but is not an emittable
  result after both candidate sets pass semantic validation.
- `coverage.mjs` validates receipt identity as well as counts: one receipt ID
  has one exact granularity/identity/count/mode signature, one native-tool or
  operation identity cannot acquire multiple receipt IDs, and tool-level
  context never becomes operation observation. `observing_receipt_mode`,
  observation state, completion counts, classification totals, and the
  sorted `coverage_gaps` list are recomputed. With no supplied confirmation
  artifact, embedded `CONFIRMED_HUMAN` is conservatively unconfirmed.
- `automap/live-confirmation.mjs` is the sole producer for generated live
  classification confirmations. It derives proposal, candidate, schema,
  version, snapshot, manifest, and observation bindings; operator input is
  limited to the effect enum, reviewer ID, time, and bounded rationale.
- `registry.mjs` exports only explicitly approved, classification-confirmed
  shadow records. Patch and record schemas fix authority to `NONE` and every
  enforcement, activation, outbound-action, runtime-active, and applied flag
  to false. Validation re-derives the full chain, rejects stale evidence and
  duplicate/conflicting mappings, and preview/lookup never mutate a registry.
- `latency/summary.mjs` exposes semantic validators for canonical event sets
  and summaries. The declared measurement context is validated before member
  iteration. Direct sequence and summary calls must supply
  `measurementKind` explicitly—even for an empty stream—and omission, an
  undefined/null context, `PRODUCTION`, or any other unsupported context is
  rejected rather than defaulted to `FIXTURE`. `LIVE_SHADOW` summary
  generation additionally requires and re-verifies the exact observation
  directory, including for an empty stream. A
  nonempty event stream must also use one supported instrumentation version
  and ordered contiguous sequence numbers from 1; imported events get the
  same contract and sensitive-value checks as recorded events. Summary
  validation checks event partitions, canonical unique groups, percentile
  ordering, tail-floor/null/note relationships, and exact provenance/empty
  caveats. An accepted empty fixture stream retains its explicit measurement
  kind and carries both no-events and fixture caveats; live output cannot be
  manufactured from context alone. The summary has no wired
  downstream v0.6 consumer; the producer invokes the validator and direct
  callers must do the same.
- `automap/input-safety.mjs` is used for the CLI's filesystem artifact inputs
  and AutoMap file reads. It applies bounded, terminal-symlink-refusing
  `O_NOFOLLOW` + `fstat` reads. Directory discovery resolves and binds the
  selected directory once before enumeration; because Node exposes no
  `openat()` primitive here, this narrows but does not eliminate an
  intermediate directory-swap race.
- Every direct consumer of an observer artifact invokes the observation
  directory verifier. The verifier fixes the inventory, file identities,
  hashes, contracts, source/observation IDs, package source commit, explicit
  `DEFAULT` or `NAMED` profile mode and identity, runtime semantic/build
  identity, and immutable false authority/action fields. `DEFAULT` emits no
  `--profile`; `NAMED` emits the validated name and still rejects `default`.
  There is no automatic discovery or fallback. Redirect-capable environment
  controls derived from OpenClaw 2026.6.5 are neutralized in the child
  process, including dotenv reintroduction. Evidence roots are restricted to
  physical temporary roots and
  component-by-component checks reject traversal, symlinks, repository,
  profile, agent, credential, configuration, plugin, service, runtime, and
  source overlap.

The separate sealed-prerequisite restore helper is a preflight/stage/apply
transaction with atomic-per-file installs, reverse-order verified rollback,
and final inventory verification. It still requires another local workspace
that already holds the pinned material, does not establish secret absence
inside opaque gzip archives, cannot provide whole-transaction atomicity, and
cannot eliminate concurrent path-component replacement without portable
`openat()`/`renameat()` APIs. Rollback failure is surfaced rather than hidden.

Within the current repository wiring, the package has no production consumer
or activation command, and the v0.5 runtime does not import it. Its outputs are
eyes-only diagnostic artifacts, not execution authority. All
repository-supplied example latency and coverage evidence is synthetic
`FIXTURE` data. The live observer and its contracts are implemented and
synthetically tested, but no real live-shadow measurement was collected by
this implementation pass. See `docs/v0.6-diagnostics.md` for the full
boundary, vocabulary-conformance, and limitation statements.

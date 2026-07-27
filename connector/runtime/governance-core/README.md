# Packaged governance-core wire artifact

This directory is the standalone connector's sealed runtime artifact of the exact shared-core sources needed for canonical request hashing and `mgp/1` wire-contract validation. `canonical.mjs`, `classify.mjs`, `contracts.mjs`, `errors.mjs`, and `policy-validate.mjs` are byte-identical to the corresponding files in `packages/governance-core/`; connector tests fail on drift.

The package-local index exposes only the canonical/hash/correlation helpers, `ACTION_CLASSES`, and the four request/decision/receipt validators consumed by the connector. Policy-loader APIs are not re-exported. The policy evaluator and enforcement gate are intentionally absent. This artifact gives a copied OpenClaw plugin a complete runtime without a repository-relative parent and cannot add remote enforcement authority.

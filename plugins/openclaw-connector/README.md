# Observa OpenClaw plugin v0.8.0

Thin native adapter qualified for the exact OpenClaw 2026.10.9 plugin contract.
See the distribution's root README for onboarding,
CLI commands, runtime qualification, continuity limitations and coverage.

The stable plugin id remains `mcpherson-governance-connector`. Ordinary operation
is metadata-only SHADOW observation with enforcement OFF. Configured identity and
roster publication are not evidence of activity. Supported native hooks supply
actual attempts, outcomes and lifecycle metadata; incomplete outcomes remain
UNKNOWN and business outcomes remain UNRESOLVED.

The existing state directory gains connector-owned `native-v1` state: an Ed25519
key, its public key and a signed SQLite evidence/delivery journal. No OpenClaw
runtime database is read or modified. Previous receipts, configuration and
credentials are retained. Pending deliveries are bound to their original
credential, deployment and Hosted origin and require a validated HTTPS
acknowledgement before acceptance is recorded.

An optional `boundNode` configuration is accepted only with `enabled: true`,
`mode: "SYNTHETIC"`, and `customerAuthorization: false`. It registers the single
`observa_bound_write` tool and reads an owner-controlled, expiring
`bound-policy.json` from the connector state directory. The V7 policy bundle must
match deployment, agent, tenant and workspace identity. V7 remains the sole
decision authority. Host approval permits only one exact operation, which the
executor checks again before a durable single-use claim and exclusive create.
This facility is for isolated qualification. It has no production activation
mode; Control Gate C and customer authorization remain separate requirements.

No policy enforcement is claimed for generic OpenClaw tools, commands, other
plugins, MCP operations, native harness work, subagents' other tools or external
effects. Default customer installations do not register this synthetic tool.

The new native and bound-policy evidence lanes are separate from legacy SHADOW
counterfactuals. A permit is authority for a defined synthetic operation; a
successful tool return is an observed tool outcome; neither is proof of the
intended business outcome.

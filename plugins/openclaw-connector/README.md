# Observa OpenClaw plugin v0.7.2

`@mcphersonai/mcpherson-governance-openclaw` records what Observa would have decided at OpenClaw's native synchronous `before_tool_call` seam. Its release posture is fixed in source:

- mode: `SHADOW`
- authority: `NONE`
- enforcement: `OFF`
- active: `false`

`SHADOW_WOULD_ALLOW`, `SHADOW_WOULD_DENY`, and `SHADOW_WOULD_REQUIRE_APPROVAL` are evidence labels. They do not grant, block, delay, approve, modify, retry, or execute a tool. `REQUIRE_APPROVAL` records `shadow_mode_no_approval`; it creates no approval and holds no invocation. Transport, protocol, identity, evidence, and verifier failures remain observational. Every `before_tool_call` handler result is `undefined`, so OpenClaw remains the execution authority.

The supported host floor is OpenClaw `2026.8.2` with Node.js 22 or newer. OAuth-mode OpenAI models can route through another harness unless the selected model is explicitly bound to `agentRuntime.id = "openclaw"`. The plugin reports the observed compatibility state when the host exposes it and never edits model configuration. A Codex runtime or Codex plugin is neither shipped nor required.

The v0.7 SHADOW bridge authenticates to `POST /v1/openclaw/shadow/evaluate` with the installation credential already used by the 0.6 connector. Requests contain bounded identity and classification metadata, the executable name, a correlation reference, and a digest of tool arguments. They do not contain the command body, prompt, message body, tool result, exception body, credential, or approval token. Responses must echo the exact installation, principal, request, and tool binding and must declare `authority=NONE`, `enforcement=OFF`, and `active=false`.

## Upgrade from 0.6.3-beta.6

Install the exact v0.7 package over the existing package and retain the existing OpenClaw plugin entry, connector state directory, endpoint, deployment ID, agent ID, and `deployment-credential` file. A package upgrade does not require re-pairing or credential rotation. The plugin does not alter org, workspace, installation, model, runtime, allowlist, or Alpha state. If the configured service does not support the v0.7 evaluation route, governed calls record `INDETERMINATE` and still execute according to OpenClaw.

Rollback replaces the package with the previously pinned `0.6.3-beta.6` artifact, preserves the connector state directory and credential, and restarts only the affected OpenClaw service when the operator's change procedure requires it. Do not run the pairing command for a version-only rollback.

## Pairing

`observa-pair` is the OpenClaw-native pairing client. It reads a single-use pairing code from a hidden terminal prompt or an owner-only `--code-file`, redeems it through `/v1/pairing/redeem`, binds the returned installation to the selected OpenClaw profile, installs the credential through the connector's secure credential writer, and verifies it. It never accepts the code in argv and never prints the credential. Pairing fixes the posture at SHADOW / NONE / OFF / OFF.

Pair a new profile only:

```console
observa-pair --api-url https://dashboard.example --profile default
```

An existing installation does not need this command for a package upgrade.

## Configuration

The existing 0.6 keys remain supported: `enabled`, `apiUrl`, `deploymentId`, `agentId`, `policyVersion`, observation budgets, state paths, `toolMetadata`, and the profile-bound `runtimeObservation` bootstrap. Mode, authority, enforcement, ACTIVE, approval authority, and operator-token keys are rejected. The default state root remains inside the active OpenClaw profile.

The operator CLI exposes status, enable/disable, observation kill/lock controls, credential lifecycle recovery, unpair, and uninstall. Kill and lock controls stop remote observation and record an observational state; they never produce a tool hook result. No local blocking canary ships in v0.7.

## Evidence

One accepted governed correlation produces one terminal SHADOW decision record. Trusted OpenClaw diagnostic events add deduplicated execution evidence, and `after_tool_call` adds deduplicated result-presence evidence without copying the result. Legacy 0.6 observational receipts remain available for compatibility. Evidence write failures cannot change execution.

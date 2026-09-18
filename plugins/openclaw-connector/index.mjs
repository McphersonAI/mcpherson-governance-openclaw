import { randomUUID } from "node:crypto";
import {
  DEFAULT_MODES,
  ENFORCEABLE_REMOTE_DECISIONS,
  PLUGIN_ID,
  PLUGIN_NAME,
  PLUGIN_VERSION,
  RECEIPT_MODE,
  REMOTE_AUTHORITY,
} from "./constants.mjs";
import { loadConnectorConfig } from "./config.mjs";
import {
  evaluateHostCompatibility,
  resolveHostOpenClawVersion,
  resolveOpenClawStateDir,
} from "./host.mjs";
import { ensureSecureDir } from "./secure-files.mjs";
import { HardenedReceiptWriter, makeLifecycleReceipt } from "./receipts.mjs";
import { GovernanceApiClient } from "./client.mjs";
import { ObservationPipeline } from "./pipeline.mjs";
import { ConnectorHookController } from "./hook.mjs";
import { RuntimeShadowObserver } from "./runtime-observer.mjs";
import { RuntimePublisher } from "./runtime-publisher.mjs";
import {
  makeConnectionTool,
  makeConnectionToolRegistration,
} from "./tools.mjs";
import { buildCodeOwnedToolCatalog } from "./hook-adapter.mjs";
import { connectorStatus, unpairConnector, uninstallConnector } from "./operator.mjs";
import { setControl } from "./controls.mjs";
import {
  createInertShadowRuntime,
  createShadowRuntime,
  SHADOW_HOOK_TIMEOUT_MS,
} from "./shadow-v070/index.mjs";

const CAPABILITY_PROFILES = Object.freeze({
  POST_HOOK: Object.freeze({ receiptMode: "POST_HOOK", postHookName: "after_tool_call" }),
  ATTEMPT_ONLY: Object.freeze({ receiptMode: "ATTEMPT_ONLY", postHookName: null }),
});

// Refusal path for an OpenClaw host below the supported minimum.
//
// OpenClaw registers plugin hook entrypoints when it loads the plugin, so the
// same surface is registered here to leave the host's plugin contract intact.
// Every handler returns immediately. No configuration is loaded, no state or
// receipt directory is created, and no client, pipeline, or receipt writer is
// constructed, so no governance request and no receipt of any kind can occur.
function registerIncompatibleConnector(api, compatibility, receiptMode) {
  api.logger?.error?.(compatibility.message);
  const inert = () => undefined;
  api.registerTool(makeConnectionTool(), { name: "mcpherson_connection_test" });
  const cleanup = [];
  for (const hookName of ["before_tool_call", "after_tool_call", "gateway_start", "gateway_stop"]) {
    const unregister = api.on(hookName, inert);
    if (typeof unregister === "function") cleanup.push(unregister);
  }
  const status = () => Object.freeze({
    pluginId: PLUGIN_ID,
    pluginVersion: PLUGIN_VERSION,
    activated: false,
    enabled: false,
    mode: "SHADOW",
    authority: "NONE",
    enforcement: "OFF",
    active: false,
    remoteAuthority: false,
    receiptMode,
    compatibility,
    pairing: null,
    pipeline: null,
    receipts: null,
  });
  return Object.freeze({
    config: null,
    controller: null,
    pipeline: null,
    client: null,
    receiptWriter: null,
    compatibility,
    activated: false,
    status,
    terminalStatus: () => Object.freeze({
      terminal: true,
      reason: "openclaw_incompatible",
      registeredHooks: cleanup.length,
      pipeline: null,
      client: null,
      controller: null,
      receipts: null,
    }),
    disable: async () => status(),
    unpair: async () => {
      throw Object.assign(
        new Error("OPENCLAW_VERSION_UNSUPPORTED"),
        { code: "OPENCLAW_VERSION_UNSUPPORTED" },
      );
    },
    uninstall: async (operatorOptions = {}) => uninstallConnector(operatorOptions),
    shutdown: async () => {
      for (const unregister of cleanup.splice(0)) unregister();
      return status();
    },
  });
}

function buildGovernanceConnector(options, capabilityProfile) {
  const { receiptMode, postHookName } = capabilityProfile;
  return {
    id: PLUGIN_ID,
    name: PLUGIN_NAME,
    version: PLUGIN_VERSION,
    description: "Shadow-only metadata-minimized OpenClaw governance connector. It observes configured semantic activity and eligible actual runtime tool activity, records local attempt and completion receipts, and keeps runtime-only identities unmapped; it does not block or alter ordinary tool execution, and remote decisions carry no execution authority.",
    register(api) {
      // Runtime compatibility is decided before anything else, from the host's
      // own reported version. Package-manager compatibility metadata is not
      // relied upon: it is not enforced by every installer.
      const compatibility = evaluateHostCompatibility(resolveHostOpenClawVersion(api));
      if (!compatibility.activate) {
        return registerIncompatibleConnector(api, compatibility, receiptMode);
      }

      const config = loadConnectorConfig(options.config || api.pluginConfig || {}, {
        // Explicit overrides win; otherwise the connector's default state root
        // resolves inside the ACTIVE OpenClaw profile.
        openclawStateDir: resolveOpenClawStateDir({ runtime: api?.runtime }),
        ...(options.pathOverrides || {}),
      });
      const connectionRegistration = makeConnectionToolRegistration();
      const codeOwnedTools = buildCodeOwnedToolCatalog([connectionRegistration]);
      ensureSecureDir(config.stateDir);
      ensureSecureDir(config.receiptDir);
      const receiptWriter = options.receiptWriter || new HardenedReceiptWriter(config.receiptDir, api.logger);
      const client = options.client || new GovernanceApiClient({
        baseUrl: config.apiUrl,
        connectTimeoutMs: config.connectTimeoutMs,
        caFile: config.caFile,
        transport: options.transport,
        absoluteTimeoutMs: options.absoluteTimeoutMs,
        random: options.random,
      });
      const runtimeInstanceId = options.runtimeInstanceId || randomUUID();
      const pipeline = options.pipeline || new ObservationPipeline({
        config,
        client,
        receiptWriter,
        credentialProvider: options.credentialProvider,
        controlInspector: options.controlInspector,
        requestBuilder: options.requestBuilder,
        requestSerializer: options.requestSerializer,
      });
      const runtimeObserver = options.runtimeObserver || new RuntimeShadowObserver({
        config,
        client,
        receiptWriter,
        runtimeInstanceId,
        credentialProvider: options.credentialProvider,
        controlInspector: options.controlInspector,
      });
      let runtimePublisher = options.runtimePublisher;
      if (!runtimePublisher) {
        try {
          runtimePublisher = new RuntimePublisher({
            client, hostConfig: api.config, runtimeInstanceId,
            credentialProvider: options.credentialProvider,
          });
        } catch (error) {
          const reason = String(error?.message ?? "RUNTIME_ROSTER_INVALID");
          runtimePublisher = Object.freeze({
            start: () => false, stop: async () => undefined,
            status: () => Object.freeze({ started: false, stopped: true,
              reason, authority: "NONE", enforcement: "OFF", active: false }),
          });
          api.logger?.error?.(`[observa-runtime] inventory publication refused: ${reason}`);
        }
      }
      let shadowRuntime = options.shadowRuntime;
      if (!shadowRuntime) {
        try {
          shadowRuntime = createShadowRuntime({
            config,
            runtimeVersion: compatibility.hostVersion,
            runtimeInstanceId,
            agentRuntime: options.agentRuntime ?? api?.runtime?.agentRuntime ?? api?.agentRuntime ?? null,
            transport: options.shadowTransport,
            evidenceWriter: options.shadowEvidenceWriter,
            credentialProvider: options.shadowCredentialProvider,
            controlInspector: options.shadowControlInspector,
            nowIso: options.shadowNowIso,
            makeRequestId: options.shadowMakeRequestId,
          });
        } catch (error) {
          shadowRuntime = createInertShadowRuntime(error);
          api.logger?.error?.(`[observa-shadow] initialization ${shadowRuntime.status().reason}`);
        }
      }
      const controller = new ConnectorHookController({
        config,
        pipeline,
        receiptWriter,
        receiptMode,
        controlInspector: options.controlInspector,
        summaryBuilder: options.summaryBuilder,
        normalizer: options.normalizer,
        attributionResolver: options.attributionResolver,
        runtimeEligibilityResolver: options.runtimeEligibilityResolver,
        runtimeObserver,
        codeOwnedTools: options.codeOwnedTools || codeOwnedTools,
      });
      const cleanup = [];
      if (typeof options.subscribeDiagnostics === "function") {
        const unsubscribe = options.subscribeDiagnostics((event, metadata) => {
          shadowRuntime.onDiagnosticEvent(event, metadata);
        });
        if (typeof unsubscribe === "function") cleanup.push(unsubscribe);
      }
      let terminalPromise = null;
      let terminalReason = null;

      const terminalStatus = () => Object.freeze({
        terminal: terminalPromise !== null,
        reason: terminalReason,
        registeredHooks: cleanup.length,
        pipeline: pipeline.status(),
        client: client.status(),
        controller: controller.status(),
        receipts: receiptWriter.status?.() || null,
      });

      // Disable, unpair, uninstall, gateway stop, and ordinary shutdown all
      // enter this one idempotent terminal contract. It stops admission,
      // aborts/drains owned work, unregisters hooks, and closes the writer.
      const terminate = ({ reason, lifecycleEvent = null } = {}) => {
        if (terminalPromise !== null) return terminalPromise;
        terminalReason = reason || "shutdown";
        pipeline.stopAdmission();
        terminalPromise = (async () => {
          try {
            await runtimePublisher.stop();
            await controller.shutdown(5_000);
            if (lifecycleEvent !== null) {
              receiptWriter.write(makeLifecycleReceipt({ event: lifecycleEvent, receiptMode }));
            }
          } finally {
            await shadowRuntime.close();
            for (const unregister of cleanup.splice(0)) unregister();
            receiptWriter.close?.();
          }
          return terminalStatus();
        })();
        terminalPromise.catch(() => {});
        return terminalPromise;
      };

      api.registerTool(connectionRegistration.tool, { name: "mcpherson_connection_test" });

      const hookRegistrations = [
        ["before_tool_call", async (event, ctx) => {
          await shadowRuntime.beforeToolCall(event, ctx);
          return controller.beforeToolCall(event, ctx);
        }, { priority: 100, timeoutMs: SHADOW_HOOK_TIMEOUT_MS }],
        // Gateway lifecycle records that the connector was loaded. They are
        // not ordinary observation receipts and are unaffected by the
        // operational disable, which governs tool observation.
        ["gateway_start", async () => {
          shadowRuntime.onGatewayStart();
          runtimePublisher.start(config);
          receiptWriter.write(makeLifecycleReceipt({ event: "gateway_start", receiptMode }));
        }],
        ["gateway_stop", async () => {
          await terminate({ reason: "gateway_stop", lifecycleEvent: "gateway_stop" });
        }],
      ];
      if (postHookName !== null) {
        hookRegistrations.splice(1, 0, [
          postHookName, (event, ctx) => {
            shadowRuntime.afterToolCall(event, ctx);
            return controller.afterToolCall(event, ctx, shadowRuntime.linkageFor(event, ctx));
          },
        ]);
      }
      for (const [hookName, handler, hookOptions] of hookRegistrations) {
        const unregister = api.on(hookName, handler, hookOptions);
        // Current OpenClaw's supported api.on contract returns void. A host test
        // adapter may return an unregister callback; use it when available.
        if (typeof unregister === "function") cleanup.push(unregister);
      }

      return Object.freeze({
        config,
        controller,
        pipeline,
        runtimeObserver,
        runtimePublisher,
        shadowRuntime,
        client,
        receiptWriter,
        compatibility,
        activated: true,
        status: () => Object.freeze({
          ...connectorStatus(config, pipeline.status(), receiptWriter.status?.() || null, receiptMode),
          pluginVersion: PLUGIN_VERSION,
          activated: true,
          compatibility,
          shadow: shadowRuntime.status(),
          runtimePublication: runtimePublisher.status(),
          lifecycle: Object.freeze({
            terminal: terminalPromise !== null,
            reason: terminalReason,
            registeredHooks: cleanup.length,
          }),
        }),
        terminalStatus,
        disable: async () => {
          setControl(config.stateDir, "disabled", true);
          await terminate({ reason: "disable" });
          return connectorStatus(config, pipeline.status(), receiptWriter.status?.() || null, receiptMode);
        },
        unpair: async () => {
          await terminate({ reason: "unpair" });
          // Narrow operator exception: after ordinary observation resources are
          // terminal, server-revocation-first unpair may use this dedicated
          // client solely to confirm self-revocation before local deletion.
          const revocationClient = new GovernanceApiClient({
            baseUrl: config.apiUrl,
            connectTimeoutMs: config.connectTimeoutMs,
            caFile: config.caFile,
            transport: options.transport,
            absoluteTimeoutMs: options.absoluteTimeoutMs,
            random: options.random,
          });
          try {
            return await unpairConnector(config, { client: revocationClient });
          } finally { await revocationClient.shutdown(); }
        },
        uninstall: async (operatorOptions = {}) => {
          await terminate({ reason: "uninstall" });
          return uninstallConnector(operatorOptions);
        },
        shutdown: async () => terminate({ reason: "shutdown" }),
      });
    },
  };
}

// The shipped plugin always takes this source-owned POST_HOOK profile. Neither
// plugin config nor environment can select receipt semantics.
export function createGovernanceConnector(options = {}) {
  return buildGovernanceConnector(options, CAPABILITY_PROFILES.POST_HOOK);
}

// Narrow source-level seam for the required isolated ATTEMPT_ONLY capability
// proof. It is not referenced by plugin.mjs and accepts no operator-supplied
// mode or post-hook name.
export function createAttemptOnlyConnectorForCapabilityTest(options = {}) {
  return buildGovernanceConnector(options, CAPABILITY_PROFILES.ATTEMPT_ONLY);
}

export {
  DEFAULT_MODES,
  ENFORCEABLE_REMOTE_DECISIONS,
  PLUGIN_ID,
  PLUGIN_VERSION,
  RECEIPT_MODE,
  REMOTE_AUTHORITY,
};
export * from "./allowlist.mjs";
export * from "./host.mjs";
export * from "./client.mjs";
export * from "./config.mjs";
export * from "./constants.mjs";
export * from "./controls.mjs";
export * from "./credentials.mjs";
export * from "./hook.mjs";
export * from "./operator.mjs";
export * from "./pipeline.mjs";
export * from "./receipts.mjs";
export * from "./runtime-observation-contract.mjs";
export * from "./runtime-observer.mjs";
export * from "./runtime-generation.mjs";
export * from "./runtime-publication-contract.mjs";
export * from "./runtime-publisher.mjs";
export * from "./shadow-v070/index.mjs";
export * from "./verify.mjs";

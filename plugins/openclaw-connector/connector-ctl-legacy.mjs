#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { loadConnectorConfig } from "./config.mjs";
import {
  connectorStatus,
  disableConnector,
  enableConnector,
  makeCommandRotationOperator,
  recoverConnectorCredentialRotation,
  rotateConnectorCredential,
  unpairConnector,
  uninstallConnector,
} from "./operator.mjs";
import { setControl } from "./controls.mjs";

function required(values, name) {
  const value = values[name];
  if (typeof value !== "string" || value.length === 0) {
    throw Object.assign(new Error(`Missing --${name}`), { code: "OPTION_REQUIRED" });
  }
  return value;
}

function publicError(error) {
  const code = error && typeof error === "object" && "code" in error
    ? String(error.code)
    : "CONNECTOR_CTL_FAILED";
  return Object.freeze({
    ok: false,
    code: /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? code : "CONNECTOR_CTL_FAILED",
    ...(error?.recovery ? { recovery: error.recovery } : {}),
  });
}

export async function runConnectorCtl(argv, dependencies = {}) {
  const command = argv[0] || "status";
  const { values } = parseArgs({
    args: argv.slice(1),
    options: {
      "state-dir": { type: "string" },
      "api-url": { type: "string" },
      "deployment-id": { type: "string" },
      "agent-id": { type: "string" },
      "new-credential-file": { type: "string" },
      rotation: { type: "string" },
      "rotation-operator": { type: "string" },
      on: { type: "boolean" },
      off: { type: "boolean" },
    },
    strict: true,
  });
  const config = (dependencies.loadConfig || loadConnectorConfig)({
    ...(values["api-url"] ? { apiUrl: values["api-url"] } : {}),
    ...(values["deployment-id"] ? { deploymentId: values["deployment-id"] } : {}),
    ...(values["agent-id"] ? { agentId: values["agent-id"] } : {}),
  }, values["state-dir"] ? { stateDir: values["state-dir"] } : {});

  let result;
  if (command === "status") result = connectorStatus(config);
  else if (command === "disable") result = disableConnector(config);
  else if (command === "enable") result = enableConnector(config);
  else if (["killswitch", "lock"].includes(command)) {
    if (values.on === values.off) throw new Error("Specify exactly one of --on or --off");
    result = setControl(config.stateDir, command, values.on === true);
  } else if (command === "rotate" || command === "recover") {
    const newCredentialFile = required(values, "new-credential-file");
    const rotationId = command === "rotate" ? required(values, "rotation") : null;
    const serverOperator = dependencies.rotationOperator
      || makeCommandRotationOperator(
        values["rotation-operator"] || "/usr/local/sbin/mcpherson-govadmin",
        dependencies.commandOptions,
      );
    if (command === "rotate") {
      result = await rotateConnectorCredential(
        config,
        newCredentialFile,
        {
          rotationId,
          serverOperator,
          client: dependencies.rotationClient,
          now: dependencies.now,
        },
      );
    } else {
      result = await recoverConnectorCredentialRotation(config, {
        newCredentialFile,
        serverOperator,
        client: dependencies.rotationClient,
        now: dependencies.now,
      });
    }
  } else if (command === "unpair") {
    result = await unpairConnector(config, {
      ...(dependencies.unpairClient ? { client: dependencies.unpairClient } : {}),
      ...(dependencies.unpairClientFactory
        ? { clientFactory: dependencies.unpairClientFactory }
        : {}),
    });
  } else if (command === "uninstall") result = uninstallConnector();
  else {
    throw new Error("Usage: connector-ctl status|enable|disable|rotate|recover|unpair|uninstall|killswitch|lock [options]");
  }
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await runConnectorCtl(process.argv.slice(2));
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify(publicError(error))}\n`);
    process.exitCode = 1;
  }
}

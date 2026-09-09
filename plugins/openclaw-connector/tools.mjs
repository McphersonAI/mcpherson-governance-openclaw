import {
  CONNECTION_MARKER,
  CONNECTION_TOOL_NAME,
} from "./constants.mjs";

function markerResult(marker) {
  return Object.freeze({ content: Object.freeze([{ type: "text", text: marker }]) });
}

function acceptsNoArguments(params) {
  return params !== null
    && typeof params === "object"
    && !Array.isArray(params)
    && Object.getOwnPropertySymbols(params).length === 0
    && Object.keys(params).length === 0;
}

export function makeConnectionTool() {
  return {
    name: CONNECTION_TOOL_NAME,
    label: "McPherson Governance Connection Test",
    description: "Deterministic marker-only governance health and synthetic decision probe. It accepts no arguments and never exposes response content.",
    parameters: Object.freeze({ type: "object", additionalProperties: false, properties: Object.freeze({}) }),
    execute: async () => markerResult(CONNECTION_MARKER),
  };
}

export function makeConnectionToolRegistration() {
  return Object.freeze({
    tool: makeConnectionTool(),
    governance: Object.freeze({
      schemaVersion: "1.0.0",
      actionClass: "read_only_internal",
      validateParams: acceptsNoArguments,
    }),
  });
}

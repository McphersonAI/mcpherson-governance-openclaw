import {
  CANARY_MARKER,
  CANARY_TOOL_NAME,
  CONNECTION_MARKER,
  CONNECTION_TOOL_NAME,
} from "./constants.mjs";

function markerResult(marker) {
  return Object.freeze({ content: Object.freeze([{ type: "text", text: marker }]) });
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

export function makeCanaryTool() {
  return {
    name: CANARY_TOOL_NAME,
    label: "McPherson Governance Local Canary",
    description: "Harmless operator-directed exact-match local canary. Remote data has no influence on its disposition.",
    parameters: Object.freeze({
      type: "object",
      additionalProperties: false,
      required: Object.freeze(["token"]),
      properties: Object.freeze({ token: Object.freeze({ type: "string" }) }),
    }),
    execute: async () => markerResult(CANARY_MARKER),
  };
}

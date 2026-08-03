import { CANARY_TOKEN, CANARY_TOOL_NAME } from "./constants.mjs";
import { inspectControl } from "./controls.mjs";

export function evaluateLocalCanary(event, ctx, config) {
  const toolName = ctx?.toolName || event?.toolName || null;
  const agentId = ctx?.agentId || config.agentId;
  if (toolName !== CANARY_TOOL_NAME || agentId !== config.agentId) return Object.freeze({ blocked: false, inScope: false });
  const control = inspectControl(config.stateDir, "canary");
  if (!control.active) return Object.freeze({ blocked: false, inScope: true, control });
  // Raw arguments are examined only inside this local canary function. They are
  // never passed to the metadata derivation or network request path.
  const params = event && event.params && typeof event.params === "object" ? event.params : null;
  const tokenMatch = params !== null && params.token === CANARY_TOKEN;
  if (!tokenMatch) return Object.freeze({ blocked: false, inScope: true, control, tokenMatch: false });
  return Object.freeze({
    blocked: true,
    inScope: true,
    control,
    tokenMatch: true,
    hookResult: Object.freeze({
      block: true,
      blockReason: "McPherson local governance canary blocked before execution",
    }),
  });
}


// Exact-string, own-property classification semantics extracted from the
// frozen v0.4.1 oracle. Similar, suffixed, prefixed, or differently-cased names
// never inherit a class.

export const ACTION_CLASS_VALUES = Object.freeze([
  "read_only_internal",
  "reversible_internal_write",
  "file_modification",
  "command_execution",
  "configuration_modification",
  "service_gateway_control",
  "external_outbound",
  "credential_secret_access",
  "destructive_irreversible",
  "unknown",
]);

export const ACTION_CLASSES = new Set(ACTION_CLASS_VALUES);

export const DEFAULT_TOOL_CLASS = Object.freeze({
  mcpherson_readonly_probe: "read_only_internal",
  apply_patch: "file_modification",
  exec: "command_execution",
  message: "external_outbound",
});

export function classifyTool(toolName, toolClass = DEFAULT_TOOL_CLASS) {
  return typeof toolName === "string"
    && toolClass !== null
    && typeof toolClass === "object"
    && Object.prototype.hasOwnProperty.call(toolClass, toolName)
    ? toolClass[toolName]
    : "unknown";
}

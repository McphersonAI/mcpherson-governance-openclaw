/**
 * Deterministic protocol error vocabulary. Serialized errors deliberately omit
 * stack traces, causes, host data, and free-form exception messages.
 */
export const ERROR_HTTP_STATUS = Object.freeze({
  MGP_AUTH_INVALID: 401,
  MGP_AUTH_REVOKED: 401,
  MGP_AUTH_EXPIRED: 401,
  MGP_VERSION_UNSUPPORTED: 400,
  MGP_MALFORMED: 400,
  MGP_OVERSIZE: 413,
  MGP_RATE_LIMITED: 429,
  MGP_CLASS_MISMATCH: 409,
  MGP_POLICY_VERSION_MISMATCH: 409,
  MGP_UNKNOWN_DEPLOYMENT: 404,
  MGP_UNKNOWN_AGENT: 404,
  MGP_UNKNOWN_TOOL: 404,
  MGP_SCHEMA_MISMATCH: 409,
  MGP_HASH_MISMATCH: 400,
  MGP_REPLAY: 409,
  MGP_POLICY_UNAVAILABLE: 503,
  MGP_INTERNAL: 500,
});

export const ERROR_CODES = Object.freeze(Object.keys(ERROR_HTTP_STATUS));

export class GovernanceError extends Error {
  constructor(code, options = {}) {
    const normalizedCode = ERROR_CODES.includes(code) ? code : "MGP_INTERNAL";
    super(normalizedCode);
    this.name = "GovernanceError";
    this.code = normalizedCode;
    this.httpStatus = ERROR_HTTP_STATUS[normalizedCode];
    this.requestId = typeof options.requestId === "string"
      ? options.requestId
      : null;
  }

  toJSON() {
    return { code: this.code, request_id: this.requestId };
  }
}

export class PolicyValidationError extends Error {
  constructor(code) {
    super(code);
    this.name = "PolicyValidationError";
    this.policyValidationCode = code;
  }

  toJSON() {
    return { code: this.policyValidationCode };
  }
}

export function errorResponse(code, requestId = null) {
  const error = new GovernanceError(code, { requestId });
  return Object.freeze({
    status: error.httpStatus,
    body: Object.freeze(error.toJSON()),
  });
}

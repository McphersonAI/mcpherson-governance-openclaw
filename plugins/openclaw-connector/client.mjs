import https from "node:https";
import { readFileSync } from "node:fs";
import {
  ABSOLUTE_OBSERVATION_CAP_MS,
  CIRCUIT_FAILURE_THRESHOLD,
  CIRCUIT_OPEN_MS,
  MAX_NETWORK_RETRIES,
  MAX_OBSERVATIONS_IN_FLIGHT,
  MAX_RESPONSE_BYTES,
} from "./constants.mjs";
import { validateShadowObservationAck } from "./runtime-observation-contract.mjs";

const TLS_CODES = new Set([
  "CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID", "DEPTH_ZERO_SELF_SIGNED_CERT",
  "ERR_TLS_CERT_ALTNAME_INVALID", "SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "ERR_SSL_WRONG_VERSION_NUMBER",
]);
const RETRYABLE_NETWORK_CODES = new Set([
  "ECONNRESET", "ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH", "ENETDOWN",
  "EPIPE", "EAI_AGAIN", "ENOTFOUND", "ETIMEDOUT",
]);
const NON_FAILURE_STATUSES = new Set([
  "ABORTED_SHUTDOWN", "CIRCUIT_OPEN", "KILL_SWITCH_ACTIVE",
  "SYSTEM_LOCK_ACTIVE", "NOT_ATTEMPTED",
]);
const RESOURCE_KINDS = Object.freeze([
  "controllers", "timers", "transports", "requests", "responses", "sockets",
]);

export class ConnectorClientError extends Error {
  constructor(remoteStatus, { retryable = false, cause = undefined } = {}) {
    super(remoteStatus, cause ? { cause } : undefined);
    this.code = remoteStatus;
    this.remoteStatus = remoteStatus;
    this.retryable = retryable;
  }
}

function mapTransportError(error, signal) {
  if (signal?.aborted) {
    const status = signal.reason === "ABORTED_SHUTDOWN" ? "ABORTED_SHUTDOWN" : "TIMEOUT";
    return new ConnectorClientError(status, { cause: error });
  }
  const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
  if (code === "RESPONSE_OVERSIZE") return new ConnectorClientError("INVALID_RESPONSE", { cause: error });
  if (TLS_CODES.has(code) || /^ERR_TLS_/.test(code)) return new ConnectorClientError("TLS_FAILURE", { cause: error });
  if (code === "ETIMEDOUT") return new ConnectorClientError("TIMEOUT", { retryable: true, cause: error });
  if (RETRYABLE_NETWORK_CODES.has(code)) return new ConnectorClientError("UNREACHABLE", { retryable: true, cause: error });
  return new ConnectorClientError("UNREACHABLE", { retryable: true, cause: error });
}

function boundedDeadline(value) {
  return Math.max(1, Math.min(
    Number.isFinite(value) ? Math.floor(value) : ABSOLUTE_OBSERVATION_CAP_MS,
    ABSOLUTE_OBSERVATION_CAP_MS,
  ));
}

function scrubResponse(response) {
  if (Buffer.isBuffer(response?.body)) response.body.fill(0);
}

// The tracker is deliberately supplied by GovernanceApiClient. This keeps the
// HTTPS implementation independently inspectable without exposing request,
// response, socket, or timer objects outside the client.
export function createHttpsTransport(agent, tracker = () => {}) {
  return ({ url, method, body, credential, ca, connectTimeoutMs, signal }) => new Promise((resolve, reject) => {
    let settled = false;
    let received = 0;
    let response = null;
    let socket = null;
    let connectTimer = null;
    let requestClosed = false;
    let responseClosed = true;
    let socketClosed = true;
    let outcome = null;
    const chunks = [];
    const headers = {
      Accept: "application/json",
      Connection: "close",
      Authorization: `Bearer ${credential}`,
    };
    if (body && body.length > 0) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = String(body.length);
    }

    const clearConnectTimer = () => {
      if (connectTimer === null) return;
      clearTimeout(connectTimer);
      tracker("timers", connectTimer, false);
      connectTimer = null;
    };
    const settleIfClosed = () => {
      if (settled || outcome === null
          || !requestClosed || !responseClosed || !socketClosed) return;
      settled = true;
      clearConnectTimer();
      if (outcome.error) reject(outcome.error);
      else resolve(outcome.value);
    };
    const finish = (error, value = null) => {
      if (outcome !== null) {
        scrubResponse(value);
        return;
      }
      for (const chunk of chunks) chunk.fill(0);
      chunks.length = 0;
      outcome = Object.freeze({ error, value });
      settleIfClosed();
    };

    const req = https.request(url, {
      method,
      headers,
      agent,
      ca: ca || undefined,
      rejectUnauthorized: true,
      signal,
    }, (res) => {
      response = res;
      responseClosed = false;
      tracker("responses", res, true);
      res.on("data", (chunk) => {
        received += chunk.length;
        if (received > MAX_RESPONSE_BYTES) {
          req.destroy(Object.assign(new Error("response_oversize"), { code: "RESPONSE_OVERSIZE" }));
          return;
        }
        chunks.push(Buffer.from(chunk));
      });
      res.once("end", () => {
        const value = { statusCode: res.statusCode || 0, body: Buffer.concat(chunks) };
        finish(null, value);
      });
      res.once("error", (error) => finish(error));
      res.once("aborted", () => finish(Object.assign(new Error("response_aborted"), { code: "ECONNRESET" })));
      res.once("close", () => {
        tracker("responses", res, false);
        responseClosed = true;
        if (outcome === null) {
          finish(Object.assign(new Error("response_closed"), { code: "ECONNRESET" }));
        }
        settleIfClosed();
      });
    });
    tracker("requests", req, true);
    req.once("socket", (value) => {
      socket = value;
      socketClosed = false;
      tracker("sockets", socket, true);
      connectTimer = setTimeout(() => {
        req.destroy(Object.assign(new Error("connect_timeout"), { code: "ETIMEDOUT" }));
      }, connectTimeoutMs);
      tracker("timers", connectTimer, true);
      connectTimer.unref?.();
      socket.once("secureConnect", clearConnectTimer);
      socket.once("close", () => {
        clearConnectTimer();
        tracker("sockets", socket, false);
        socketClosed = true;
        settleIfClosed();
      });
    });
    req.once("error", (error) => finish(error));
    req.once("close", () => {
      clearConnectTimer();
      tracker("requests", req, false);
      requestClosed = true;
      if (outcome === null) {
        finish(Object.assign(new Error("request_closed"), { code: "ECONNRESET" }));
      }
      settleIfClosed();
    });
    if (body && body.length > 0) req.write(body);
    req.end();
  });
}

export class GovernanceApiClient {
  #baseUrl;
  #connectTimeoutMs;
  #absoluteTimeoutMs;
  #caFile;
  #ca = null;
  #agent = null;
  #customTransport;
  #now;
  #random;
  #failures = 0;
  #openUntil = 0;
  #closed = false;
  #shutdownPromise = null;
  #shutdownState = "OPEN";
  #shutdownDeadlineExceeded = false;
  #operations = new Set();
  #resources = Object.fromEntries(RESOURCE_KINDS.map((kind) => [kind, new Set()]));
  #peaks = Object.fromEntries(["operations", ...RESOURCE_KINDS].map((kind) => [kind, 0]));

  constructor({
    baseUrl,
    connectTimeoutMs,
    caFile = null,
    transport = null,
    absoluteTimeoutMs = ABSOLUTE_OBSERVATION_CAP_MS,
    now = () => Date.now(),
    random = Math.random,
  }) {
    const parsed = new URL(baseUrl);
    if (parsed.protocol !== "https:" || parsed.username || parsed.password) throw new ConnectorClientError("CONFIG_API_URL_NOT_VERIFIED_HTTPS");
    this.#baseUrl = parsed.origin;
    this.#connectTimeoutMs = connectTimeoutMs;
    this.#absoluteTimeoutMs = boundedDeadline(absoluteTimeoutMs);
    this.#caFile = caFile;
    this.#customTransport = transport;
    this.#now = now;
    this.#random = random;
  }

  #assertAvailable() {
    if (this.#closed) throw new ConnectorClientError("ABORTED_SHUTDOWN");
    if (this.#now() < this.#openUntil) throw new ConnectorClientError("CIRCUIT_OPEN");
    if (this.#openUntil && this.#now() >= this.#openUntil) {
      this.#openUntil = 0;
      this.#failures = 0;
    }
  }

  #trackPeak(kind, size) {
    this.#peaks[kind] = Math.max(this.#peaks[kind], size);
  }

  #track(operation, kind, resource, active) {
    if (!RESOURCE_KINDS.includes(kind) || resource === null || resource === undefined) return;
    const global = this.#resources[kind];
    const local = operation?.resources?.[kind];
    if (active) {
      global.add(resource);
      local?.add(resource);
      this.#trackPeak(kind, global.size);
    } else {
      global.delete(resource);
      local?.delete(resource);
    }
  }

  #ensureNetworkResources() {
    if (this.#customTransport !== null) return;
    if (this.#caFile !== null && this.#ca === null) this.#ca = readFileSync(this.#caFile);
    if (this.#agent === null) {
      this.#agent = new https.Agent({
        keepAlive: false,
        maxSockets: MAX_OBSERVATIONS_IN_FLIGHT,
        maxFreeSockets: 0,
      });
    }
  }

  #checkAttempt(operation, attempt, phase) {
    this.#assertAvailable();
    if (typeof operation.beforeAttempt === "function") operation.beforeAttempt({ attempt, phase, path: operation.path });
    this.#assertAvailable();
  }

  #makeOperation(path, options) {
    const controller = new AbortController();
    const operation = {
      path,
      method: options.method,
      credential: options.credential,
      retryNetwork: options.retryNetwork,
      beforeAttempt: options.beforeAttempt,
      controller,
      immutableBody: Buffer.from(options.body),
      resources: Object.fromEntries(RESOURCE_KINDS.map((kind) => [kind, new Set()])),
      promise: null,
      cleaned: false,
    };
    this.#track(operation, "controllers", controller, true);
    const timer = setTimeout(() => controller.abort("ABSOLUTE_TIMEOUT"), this.#absoluteTimeoutMs);
    this.#track(operation, "timers", timer, true);
    return operation;
  }

  #delay(operation, ms) {
    if (ms <= 0) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const signal = operation.controller.signal;
      let timer = null;
      const cleanup = () => {
        signal.removeEventListener("abort", abort);
        if (timer !== null) {
          clearTimeout(timer);
          this.#track(operation, "timers", timer, false);
          timer = null;
        }
      };
      const done = () => { cleanup(); resolve(); };
      const abort = () => {
        cleanup();
        reject(new ConnectorClientError(signal.reason === "ABORTED_SHUTDOWN" ? "ABORTED_SHUTDOWN" : "TIMEOUT"));
      };
      if (signal.aborted) return abort();
      signal.addEventListener("abort", abort, { once: true });
      timer = setTimeout(done, ms);
      this.#track(operation, "timers", timer, true);
    });
  }

  async #runTransport(operation, attempt) {
    this.#ensureNetworkResources();
    const signal = operation.controller.signal;
    const url = new URL(operation.path, this.#baseUrl);
    const transport = this.#customTransport || createHttpsTransport(
      this.#agent,
      (kind, resource, active) => this.#track(operation, kind, resource, active),
    );
    const transportToken = Object.freeze({ operation, attempt });
    this.#track(operation, "transports", transportToken, true);
    let raw;
    try {
      raw = Promise.resolve(transport({
        url,
        method: operation.method,
        body: operation.immutableBody,
        credential: operation.credential,
        ca: this.#ca,
        connectTimeoutMs: this.#connectTimeoutMs,
        signal,
        attempt,
      }));
    } catch (error) {
      raw = Promise.reject(error);
    }
    // Convert both terminal outcomes to fulfillment so a hostile custom
    // transport can never create an unhandled rejection. Ownership remains
    // with this operation until this settlement wrapper actually completes.
    const settled = raw.then(
      (value) => Object.freeze({ kind: "fulfilled", value }),
      (error) => Object.freeze({ kind: "rejected", error }),
    );
    let removeAbort = () => {};
    const aborted = new Promise((resolve) => {
      const abort = () => resolve(Object.freeze({
        kind: "aborted",
        error: new ConnectorClientError(
          signal.reason === "ABORTED_SHUTDOWN" ? "ABORTED_SHUTDOWN" : "TIMEOUT",
        ),
      }));
      if (signal.aborted) abort();
      else {
        signal.addEventListener("abort", abort, { once: true });
        removeAbort = () => signal.removeEventListener("abort", abort);
      }
    });
    try {
      const first = await Promise.race([settled, aborted]);
      if (first.kind === "aborted") {
        // Abort is a logical result, not permission to detach an unknown task.
        // Wait for the real transport boundary before releasing ownership.
        const terminal = await settled;
        if (terminal.kind === "fulfilled") scrubResponse(terminal.value);
        throw first.error;
      }
      if (signal.aborted) {
        if (first.kind === "fulfilled") scrubResponse(first.value);
        throw new ConnectorClientError(
          signal.reason === "ABORTED_SHUTDOWN" ? "ABORTED_SHUTDOWN" : "TIMEOUT",
        );
      }
      if (first.kind === "rejected") throw first.error;
      return first.value;
    } finally {
      removeAbort();
      this.#track(operation, "transports", transportToken, false);
    }
  }

  async #runLogicalRequest(operation) {
    let attempt = 0;
    for (;;) {
      this.#checkAttempt(operation, attempt, "before_transport");
      let response = null;
      try {
        response = await this.#runTransport(operation, attempt);
        if (!Number.isInteger(response?.statusCode) || response.statusCode < 100 || response.statusCode > 599) {
          throw new ConnectorClientError("INVALID_RESPONSE");
        }
        if (response.statusCode < 200 || response.statusCode >= 300) {
          const status = response.statusCode === 401 || response.statusCode === 403
            ? "AUTH_REJECTED"
            : `HTTP_ERROR:${response.statusCode}`;
          this.recordFailure();
          throw new ConnectorClientError(status);
        }
        let value;
        try { value = JSON.parse(Buffer.from(response.body || Buffer.alloc(0)).toString("utf8")); }
        catch { throw new ConnectorClientError("INVALID_RESPONSE"); }
        this.recordSuccess();
        return value;
      } catch (rawError) {
        const error = rawError instanceof ConnectorClientError
          ? rawError
          : mapTransportError(rawError, operation.controller.signal);
        if (error.retryable && operation.retryNetwork && attempt < MAX_NETWORK_RETRIES
          && !operation.controller.signal.aborted) {
          this.#checkAttempt(operation, attempt + 1, "before_retry_backoff");
          await this.#delay(operation, 5 + Math.floor(this.#random() * 21));
          attempt += 1;
          continue;
        }
        if (!NON_FAILURE_STATUSES.has(error.remoteStatus)
          && !/^HTTP_ERROR:/.test(error.remoteStatus)
          && error.remoteStatus !== "AUTH_REJECTED") this.recordFailure();
        throw error;
      } finally {
        scrubResponse(response);
      }
    }
  }

  #cleanupOperation(operation, { abort = false } = {}) {
    if (operation.cleaned) return;
    operation.cleaned = true;
    if (abort && !operation.controller.signal.aborted) operation.controller.abort("ABORTED_SHUTDOWN");
    for (const timer of operation.resources.timers) clearTimeout(timer);
    for (const request of operation.resources.requests) request.destroy?.();
    for (const response of operation.resources.responses) response.destroy?.();
    for (const socket of operation.resources.sockets) socket.destroy?.();
    for (const kind of RESOURCE_KINDS) {
      for (const resource of operation.resources[kind]) this.#track(operation, kind, resource, false);
      operation.resources[kind].clear();
    }
    operation.immutableBody.fill(0);
    operation.credential = null;
    operation.beforeAttempt = null;
    this.#operations.delete(operation);
    this.#refreshShutdownState();
  }

  #abortOperation(operation) {
    if (operation.cleaned) return;
    if (!operation.controller.signal.aborted) operation.controller.abort("ABORTED_SHUTDOWN");
    for (const timer of [...operation.resources.timers]) {
      clearTimeout(timer);
      this.#track(operation, "timers", timer, false);
    }
    // Destruction requests termination, but ownership is deliberately retained
    // until the tracked transport promise and its concrete resources settle.
    for (const request of operation.resources.requests) request.destroy?.();
    for (const response of operation.resources.responses) response.destroy?.();
    for (const socket of operation.resources.sockets) socket.destroy?.();
  }

  #refreshShutdownState() {
    if (!this.#closed) return;
    const clean = this.#operations.size === 0
      && RESOURCE_KINDS.every((kind) => this.#resources[kind].size === 0);
    if (clean) {
      this.#shutdownState = this.#shutdownDeadlineExceeded
        ? "CLEAN_AFTER_DEADLINE"
        : "CLEAN";
    }
  }

  #logicalRequest(path, {
    method = "POST",
    body = Buffer.alloc(0),
    credential,
    retryNetwork = true,
    beforeAttempt = null,
  } = {}) {
    try {
      this.#assertAvailable();
      if (typeof beforeAttempt === "function") beforeAttempt({ attempt: 0, phase: "before_operation", path });
      this.#assertAvailable();
    } catch (error) {
      return Promise.reject(error);
    }
    const operation = this.#makeOperation(path, {
      method, body, credential, retryNetwork, beforeAttempt,
    });
    this.#operations.add(operation);
    this.#trackPeak("operations", this.#operations.size);
    const promise = this.#runLogicalRequest(operation)
      .finally(() => this.#cleanupOperation(operation));
    operation.promise = promise;
    promise.catch(() => {});
    return promise;
  }

  recordFailure() {
    this.#failures += 1;
    if (this.#failures >= CIRCUIT_FAILURE_THRESHOLD) this.#openUntil = this.#now() + CIRCUIT_OPEN_MS;
  }

  recordSuccess() {
    this.#failures = 0;
    this.#openUntil = 0;
  }

  decide(body, credential, options = {}) {
    return this.#logicalRequest("/v1/decisions", {
      body, credential, retryNetwork: true, beforeAttempt: options.beforeAttempt,
    });
  }

  async observeShadow(body, credential, options = {}) {
    const value = await this.#logicalRequest("/v1/observations", {
      body, credential, retryNetwork: true, beforeAttempt: options.beforeAttempt,
    });
    if (!validateShadowObservationAck(value, options.expectedRequestHash)) {
      this.recordFailure();
      throw new ConnectorClientError("INVALID_RESPONSE");
    }
    return Object.freeze(value);
  }

  async health(credential, options = {}) {
    const value = await this.#logicalRequest("/v1/health", {
      method: "GET", credential, retryNetwork: true, beforeAttempt: options.beforeAttempt,
    });
    if (!value || value.ok !== true || value.api_version !== "mgp/1") throw new ConnectorClientError("INVALID_RESPONSE");
    return true;
  }

  async credentialIdentity(credential, options = {}) {
    const value = await this.#logicalRequest("/v1/credentials/identity", {
      method: "GET", credential, retryNetwork: true, beforeAttempt: options.beforeAttempt,
    });
    const expectedKeys = ["credential_id", "deployment_id", "fingerprint"];
    if (!value || typeof value !== "object" || Array.isArray(value)
        || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(expectedKeys)
        || !/^[a-f0-9]{32}$/.test(value.credential_id)
        || !/^sha256:[a-f0-9]{16}$/.test(value.fingerprint)
        || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$/.test(value.deployment_id)) {
      throw new ConnectorClientError("INVALID_RESPONSE");
    }
    const identity = Object.freeze({
      credentialId: value.credential_id,
      fingerprint: value.fingerprint,
      deploymentId: value.deployment_id,
    });
    if (options.expectedCredentialId !== undefined
        && identity.credentialId !== options.expectedCredentialId) {
      throw new ConnectorClientError("CREDENTIAL_IDENTITY_MISMATCH");
    }
    if (options.expectedDeploymentId !== undefined
        && identity.deploymentId !== options.expectedDeploymentId) {
      throw new ConnectorClientError("CREDENTIAL_IDENTITY_MISMATCH");
    }
    return identity;
  }

  async revokeSelf(credential, options = {}) {
    const value = await this.#logicalRequest("/v1/credentials/revoke-self", {
      body: Buffer.from("{}"), credential, retryNetwork: true, beforeAttempt: options.beforeAttempt,
    });
    if (!value || value.status !== "REVOKED" || typeof value.credential_id !== "string") throw new ConnectorClientError("INVALID_RESPONSE");
    return Object.freeze({ credentialId: value.credential_id, status: "REVOKED" });
  }

  status() {
    const activeOperations = this.#operations.size;
    const controllers = this.#resources.controllers.size;
    return Object.freeze({
      admission: !this.#closed,
      closed: this.#closed,
      failures: this.#failures,
      circuitOpen: this.#now() < this.#openUntil,
      activeOperations,
      activeRequests: controllers,
      activeTransports: this.#resources.transports.size,
      controllers,
      timers: this.#resources.timers.size,
      requests: this.#resources.requests.size,
      responses: this.#resources.responses.size,
      sockets: this.#resources.sockets.size,
      pendingCompletions: activeOperations,
      shutdown: Object.freeze({
        state: this.#shutdownState,
        clean: this.#shutdownState === "CLEAN"
          || this.#shutdownState === "CLEAN_AFTER_DEADLINE",
        deadlineExceeded: this.#shutdownDeadlineExceeded,
      }),
      agentActive: this.#agent !== null,
      caLoaded: this.#ca !== null,
      peaks: Object.freeze({
        activeOperations: this.#peaks.operations,
        activeTransports: this.#peaks.transports,
        controllers: this.#peaks.controllers,
        timers: this.#peaks.timers,
        requests: this.#peaks.requests,
        responses: this.#peaks.responses,
        sockets: this.#peaks.sockets,
      }),
    });
  }

  shutdown(deadlineMs = ABSOLUTE_OBSERVATION_CAP_MS) {
    if (this.#shutdownPromise !== null) return this.#shutdownPromise;
    this.#closed = true;
    this.#shutdownState = "DRAINING";
    const deadline = boundedDeadline(deadlineMs);
    const pending = [...this.#operations].map((operation) => operation.promise).filter(Boolean);
    for (const operation of [...this.#operations]) this.#abortOperation(operation);
    this.#agent?.destroy();
    this.#agent = null;
    if (this.#ca !== null) this.#ca.fill(0);
    this.#ca = null;

    this.#shutdownPromise = (async () => {
      let outcome = "DRAINED";
      if (pending.length > 0) {
        let timer = null;
        const drained = Promise.allSettled(pending);
        outcome = await Promise.race([
          drained.then(() => "DRAINED"),
          new Promise((resolve) => {
            timer = setTimeout(() => resolve("DEADLINE"), deadline);
          }),
        ]);
        if (timer !== null) clearTimeout(timer);
        // Keep a handled observer on the actual drain after a deadline result;
        // operation cleanup will advance status to CLEAN_AFTER_DEADLINE.
        drained.then(() => this.#refreshShutdownState()).catch(() => {});
      }
      if (outcome === "DEADLINE") {
        this.#shutdownDeadlineExceeded = true;
        this.#shutdownState = "NON_CLEAN_DEADLINE";
      }
      this.#refreshShutdownState();
      return this.status();
    })();
    this.#shutdownPromise.catch(() => {});
    return this.#shutdownPromise;
  }
}

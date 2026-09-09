import https from "node:https";
import { readFileSync } from "node:fs";
import {
  SHADOW_DECISION_TIMEOUT_MS,
  SHADOW_EVALUATION_PATH,
  SHADOW_MAX_RESPONSE_BYTES,
} from "./constants.mjs";

export class ShadowTransportError extends Error {
  constructor(code) {
    super(code);
    this.name = "ShadowTransportError";
    this.code = code;
  }
}

function defaultRequest({ url, body, credential, ca, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let received = 0;
    const chunks = [];
    const req = https.request(url, {
      method: "POST",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${credential}`,
        connection: "close",
        "content-type": "application/json",
        "content-length": String(body.length),
        "x-observa-shadow-mode": "SHADOW",
      },
      ca: ca ?? undefined,
      rejectUnauthorized: true,
      signal: controller.signal,
    }, (res) => {
      res.on("data", (chunk) => {
        received += chunk.length;
        if (received > SHADOW_MAX_RESPONSE_BYTES) {
          req.destroy(new ShadowTransportError("RESPONSE_OVERSIZE"));
          return;
        }
        chunks.push(Buffer.from(chunk));
      });
      res.once("error", reject);
      res.once("end", () => resolve({
        statusCode: res.statusCode ?? 0,
        body: Buffer.concat(chunks),
      }));
    });
    req.once("error", reject);
    req.once("close", () => clearTimeout(timer));
    req.end(body);
  });
}

export function createShadowTransport({
  apiUrl,
  caFile = null,
  requestImpl = defaultRequest,
  timeoutMs = SHADOW_DECISION_TIMEOUT_MS,
} = {}) {
  const base = new URL(apiUrl);
  if (base.protocol !== "https:" || base.username || base.password || base.hash) {
    throw new ShadowTransportError("API_URL_NOT_VERIFIED_HTTPS");
  }
  const url = new URL(SHADOW_EVALUATION_PATH, base);
  const ca = caFile ? readFileSync(caFile) : null;

  return Object.freeze({
    async evaluate(body, credential) {
      let response;
      try {
        response = await requestImpl({ url, body, credential, ca, timeoutMs });
      } catch (error) {
        if (error?.name === "AbortError" || error?.name === "TimeoutError") {
          throw new ShadowTransportError("TIMEOUT");
        }
        if (error instanceof ShadowTransportError) throw error;
        throw new ShadowTransportError("UNAVAILABLE");
      }
      if (!Number.isInteger(response?.statusCode)) {
        throw new ShadowTransportError("INVALID_RESPONSE");
      }
      if (response.statusCode === 401 || response.statusCode === 403) {
        throw new ShadowTransportError("AUTH_REJECTED");
      }
      if (response.statusCode < 200 || response.statusCode >= 300) {
        throw new ShadowTransportError(`HTTP_${response.statusCode}`);
      }
      const bytes = Buffer.from(response.body ?? Buffer.alloc(0));
      try {
        if (bytes.length > SHADOW_MAX_RESPONSE_BYTES) {
          throw new ShadowTransportError("RESPONSE_OVERSIZE");
        }
        return JSON.parse(bytes.toString("utf8"));
      } catch (error) {
        if (error instanceof ShadowTransportError) throw error;
        throw new ShadowTransportError("MALFORMED_RESPONSE");
      } finally {
        bytes.fill(0);
      }
    },
    close() {
      if (Buffer.isBuffer(ca)) ca.fill(0);
    },
  });
}

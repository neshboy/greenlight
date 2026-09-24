import http from "node:http";
import https from "node:https";

export interface SimpleResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  protocol: "http" | "https";
}

export interface GetOptions {
  timeoutMs: number;
  /** Cap on response body bytes read, to avoid unbounded memory use. */
  maxBodyBytes?: number;
  headers?: Record<string, string>;
}

/**
 * Performs a single, read-only GET request. No retries, no redirect
 * following (callers that care about redirects inspect statusCode/headers
 * themselves) — this keeps the tool's network footprint per-check minimal
 * and predictable.
 */
export function simpleGet(
  targetUrl: string,
  opts: GetOptions
): Promise<SimpleResponse> {
  return new Promise((resolve, reject) => {
    let url: URL;
    try {
      url = new URL(targetUrl);
    } catch (err) {
      reject(new Error(`invalid URL: ${targetUrl}`));
      return;
    }
    const isHttps = url.protocol === "https:";
    const lib = isHttps ? https : http;
    const maxBodyBytes = opts.maxBodyBytes ?? 1_000_000;

    const req = lib.request(
      {
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        method: "GET",
        headers: {
          "User-Agent": "Greenlight-Scanner/0.1 (+authorized-recon)",
          ...opts.headers,
        },
        timeout: opts.timeoutMs,
        // Recon only: we don't validate cert chains here because expired/
        // self-signed/misconfigured certs are exactly what we want to be
        // able to report on (see the dedicated TLS module for details).
        ...(isHttps ? { rejectUnauthorized: false } : {}),
      },
      (res) => {
        let received = 0;
        let body = "";
        let truncated = false;
        res.on("data", (chunk: Buffer) => {
          received += chunk.length;
          if (received > maxBodyBytes) {
            if (!truncated) {
              body += chunk.toString("utf8").slice(0, Math.max(0, maxBodyBytes - (received - chunk.length)));
              truncated = true;
            }
            return;
          }
          body += chunk.toString("utf8");
        });
        res.on("end", () => {
          resolve({
            statusCode: res.statusCode ?? 0,
            headers: res.headers,
            body,
            protocol: isHttps ? "https" : "http",
          });
        });
      }
    );

    req.on("timeout", () => {
      req.destroy(new Error(`request to ${targetUrl} timed out after ${opts.timeoutMs}ms`));
    });
    req.on("error", (err) => reject(err));
    req.end();
  });
}

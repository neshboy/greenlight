import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { runScan, AuthorizationError, summarizeSeverities } from "../src/scan.js";
import { exitCodeFor } from "../src/report.js";
import { startHttpServer, RunningHttpServer } from "./fixtures/testServer.js";

let tmpHome: string;
let originalHome: string | undefined;

beforeEach(() => {
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "greenlight-scan-test-"));
  originalHome = process.env.GREENLIGHT_HOME;
  process.env.GREENLIGHT_HOME = tmpHome;
});

afterEach(() => {
  process.env.GREENLIGHT_HOME = originalHome;
  fs.rmSync(tmpHome, { recursive: true, force: true });
});

describe("runScan orchestration", () => {
  it("refuses to run any module against an unauthorized public-looking target", async () => {
    await expect(
      runScan("192.0.2.77", { modules: ["headers", "exposure"] })
    ).rejects.toThrow(AuthorizationError);
  });

  it("runs the requested modules against an authorized loopback target and aggregates findings", async () => {
    let running: RunningHttpServer | undefined;
    try {
      running = await startHttpServer((req, res) => {
        if (req.url === "/.env") {
          res.writeHead(200);
          res.end("SECRET=1\nAPI_KEY=abc\n");
          return;
        }
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end("hello");
      });

      const result = await runScan(`http://127.0.0.1:${running.port}`, {
        modules: ["headers", "exposure"],
        scheme: "http",
        httpTimeoutMs: 2000,
      });

      expect(result.authorized).toBe(true);
      expect(result.results.map((r) => r.module).sort()).toEqual(["exposure", "headers"]);

      const counts = summarizeSeverities(result.results);
      expect(counts.high).toBeGreaterThanOrEqual(1); // the exposed .env
      expect(exitCodeFor(result)).toBe(1); // high severity => non-zero exit for CI gating
    } finally {
      if (running) await running.close();
    }
  });

  it("produces exit code 0 when there are no high-severity findings", async () => {
    let running: RunningHttpServer | undefined;
    try {
      running = await startHttpServer((_req, res) => {
        res.writeHead(200, {
          "Content-Security-Policy": "default-src 'self'",
          "X-Frame-Options": "DENY",
          "X-Content-Type-Options": "nosniff",
          "Referrer-Policy": "no-referrer",
          "Permissions-Policy": "geolocation=()",
        });
        res.end("ok");
      });

      const result = await runScan(`http://127.0.0.1:${running.port}`, {
        modules: ["headers"],
        scheme: "http",
        httpTimeoutMs: 2000,
      });
      expect(exitCodeFor(result)).toBe(0);
    } finally {
      if (running) await running.close();
    }
  });

  it("skips the DNS module for literal IP / loopback targets", async () => {
    const result = await runScan("127.0.0.1", { modules: ["dns"] });
    expect(result.results).toHaveLength(0);
  });
});

import { describe, it, expect, afterEach } from "vitest";
import { runHeaderCheck } from "../src/modules/headers.js";
import { startHttpServer, RunningHttpServer } from "./fixtures/testServer.js";

let running: RunningHttpServer | undefined;

afterEach(async () => {
  if (running) {
    await running.close();
    running = undefined;
  }
});

describe("headers module", () => {
  it("flags missing security headers on a bare response", async () => {
    running = await startHttpServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("hello");
    });

    const result = await runHeaderCheck(running.url, { timeoutMs: 2000 });
    expect(result.error).toBeUndefined();

    const titles = result.findings.map((f) => f.title);
    expect(titles).toContain("Missing Content-Security-Policy header");
    expect(titles).toContain("Missing X-Frame-Options header");
    expect(titles).toContain("Missing X-Content-Type-Options header");
    expect(titles).toContain("Missing Referrer-Policy header");

    // Plain-English explanation must actually be present, not just a title.
    const csp = result.findings.find((f) => f.title === "Missing Content-Security-Policy header");
    expect(csp?.detail.length).toBeGreaterThan(20);
  });

  it("does not flag headers that are present, and does not require HSTS over plain HTTP", async () => {
    running = await startHttpServer((_req, res) => {
      res.writeHead(200, {
        "Content-Type": "text/plain",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
      });
      res.end("hello");
    });

    const result = await runHeaderCheck(running.url, { timeoutMs: 2000 });
    const missingHeaderFindings = result.findings.filter((f) => f.title.startsWith("Missing"));
    expect(missingHeaderFindings).toHaveLength(0);
  });

  it("flags a disclosed Server banner", async () => {
    running = await startHttpServer((_req, res) => {
      res.writeHead(200, { Server: "TotallyRealServer/1.0" });
      res.end("hi");
    });
    const result = await runHeaderCheck(running.url, { timeoutMs: 2000 });
    const banner = result.findings.find((f) => f.title.includes("banner disclosed"));
    expect(banner).toBeDefined();
    expect(banner?.detail).toContain("TotallyRealServer/1.0");
  });

  it("reports an error (not a crash) when the target is unreachable", async () => {
    const result = await runHeaderCheck("http://127.0.0.1:1", { timeoutMs: 500 });
    expect(result.error).toBeDefined();
    expect(result.findings).toHaveLength(0);
  });
});

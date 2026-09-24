import { describe, it, expect, afterEach } from "vitest";
import { runExposureCheck } from "../src/modules/exposure.js";
import { startHttpServer, RunningHttpServer } from "./fixtures/testServer.js";

let running: RunningHttpServer | undefined;

afterEach(async () => {
  if (running) {
    await running.close();
    running = undefined;
  }
});

describe("exposure module", () => {
  it("flags an exposed .git/config", async () => {
    running = await startHttpServer((req, res) => {
      if (req.url === "/.git/config") {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end('[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://example.com/repo.git\n');
        return;
      }
      res.writeHead(404);
      res.end();
    });

    const result = await runExposureCheck(running.url, { timeoutMs: 2000, concurrency: 5 });
    const finding = result.findings.find((f) => f.title.includes(".git/config"));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  it("flags an exposed .env file", async () => {
    running = await startHttpServer((req, res) => {
      if (req.url === "/.env") {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end("DATABASE_URL=postgres://user:pass@localhost/db\nSECRET_KEY=abc123\n");
        return;
      }
      res.writeHead(404);
      res.end();
    });

    const result = await runExposureCheck(running.url, { timeoutMs: 2000, concurrency: 5 });
    const finding = result.findings.find((f) => f.title.includes(".env"));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  it("flags directory listing responses", async () => {
    running = await startHttpServer((req, res) => {
      if (req.url === "/") {
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end("<html><head><title>Index of /</title></head><body>...</body></html>");
        return;
      }
      res.writeHead(404);
      res.end();
    });

    const result = await runExposureCheck(running.url, { timeoutMs: 2000, concurrency: 5 });
    const finding = result.findings.find((f) => f.title.includes("Directory listing"));
    expect(finding).toBeDefined();
  });

  it("produces no high-severity findings when none of the sensitive paths are exposed", async () => {
    running = await startHttpServer((_req, res) => {
      res.writeHead(404);
      res.end("not found");
    });

    const result = await runExposureCheck(running.url, { timeoutMs: 2000, concurrency: 5 });
    const highFindings = result.findings.filter((f) => f.severity === "high" || f.severity === "medium");
    expect(highFindings).toHaveLength(0);
  });
});

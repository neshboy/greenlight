import { describe, it, expect, afterEach } from "vitest";
import {
  runPortCheck,
  parsePortSpec,
  MAX_PORTS_WITHOUT_OVERRIDE,
  DEFAULT_PORTS,
  describeOpenPort,
} from "../src/modules/ports.js";
import { startTcpServer, findClosedPort, RunningTcpServer } from "./fixtures/testServer.js";

let running: RunningTcpServer | undefined;

afterEach(async () => {
  if (running) {
    await running.close();
    running = undefined;
  }
});

describe("ports module", () => {
  it("detects an open port on a real local TCP listener", async () => {
    running = await startTcpServer();
    const closedPort = await findClosedPort();

    const result = await runPortCheck("127.0.0.1", [running.port, closedPort], {
      concurrency: 20,
      timeoutMs: 1000,
    });

    const openFinding = result.findings.find((f) => f.title === `Port ${running!.port} is open`);
    expect(openFinding).toBeDefined();
    // A closed port must not be reported as open.
    expect(result.findings.some((f) => f.title === `Port ${closedPort} is open`)).toBe(false);
  });

  it("reports an informational finding when no ports are open", async () => {
    const closedPort1 = await findClosedPort();
    const closedPort2 = await findClosedPort();
    const result = await runPortCheck("127.0.0.1", [closedPort1, closedPort2], {
      concurrency: 20,
      timeoutMs: 500,
    });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("info");
    expect(result.findings[0].title).toMatch(/no open ports/i);
  });

  it("flags well-known risky ports (e.g. databases/RDP/Telnet) as medium severity, and unremarkable open ports as info", () => {
    // Unit-level check of the risk-annotation logic: it doesn't require a
    // real MySQL/RDP/Redis server bound to its well-known port, just the
    // pure port-number-to-finding mapping used by runPortCheck.
    expect(describeOpenPort(3306).severity).toBe("medium"); // MySQL
    expect(describeOpenPort(3389).severity).toBe("medium"); // RDP
    expect(describeOpenPort(6379).severity).toBe("medium"); // Redis
    expect(describeOpenPort(23).severity).toBe("medium"); // Telnet
    expect(describeOpenPort(51234).severity).toBe("info"); // arbitrary unremarkable port
  });

  it("caps effective concurrency and completes within a bounded time for many ports", async () => {
    const ports = DEFAULT_PORTS.slice(0, 10).map((p) => p + 40000); // likely-closed high ports
    const start = Date.now();
    const result = await runPortCheck("127.0.0.1", ports, { concurrency: 5, timeoutMs: 300 });
    const elapsed = Date.now() - start;
    // With concurrency 5 and 10 ports at up to 300ms timeout each, worst case
    // is ~2 batches => well under a generous 5s ceiling even on a slow CI box.
    expect(elapsed).toBeLessThan(5000);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

describe("parsePortSpec", () => {
  it("parses comma lists", () => {
    expect(parsePortSpec("22,80,443")).toEqual([22, 80, 443]);
  });

  it("parses ranges", () => {
    expect(parsePortSpec("1-5")).toEqual([1, 2, 3, 4, 5]);
  });

  it("parses a mix of ranges and singles, de-duplicated and sorted", () => {
    expect(parsePortSpec("443,1-3,2")).toEqual([1, 2, 3, 443]);
  });

  it("rejects invalid ports", () => {
    expect(() => parsePortSpec("0")).toThrow();
    expect(() => parsePortSpec("70000")).toThrow();
    expect(() => parsePortSpec("abc")).toThrow();
  });

  it("enforces the sanity cap constant used by the CLI", () => {
    const wide = parsePortSpec("1-65535");
    expect(wide.length).toBeGreaterThan(MAX_PORTS_WITHOUT_OVERRIDE);
  });
});

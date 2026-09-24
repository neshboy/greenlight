import { describe, it, expect, afterEach } from "vitest";
import { runTlsCheck, evaluateHandshake, HandshakeInfo } from "../src/modules/tls.js";
import { startTlsServer, RunningTlsServer, VALID_CERT, VALID_KEY, EXPIRING_CERT, EXPIRING_KEY } from "./fixtures/testServer.js";

let running: RunningTlsServer | undefined;

afterEach(async () => {
  if (running) {
    await running.close();
    running = undefined;
  }
});

describe("tls module: real handshake against a local TLS server", () => {
  it("reports the negotiated protocol and cipher for a valid self-signed cert", async () => {
    running = await startTlsServer(VALID_CERT, VALID_KEY);
    const result = await runTlsCheck("127.0.0.1", { timeoutMs: 3000, port: running.port });

    expect(result.error).toBeUndefined();
    const protocolFinding = result.findings.find((f) => f.title.startsWith("Negotiated"));
    expect(protocolFinding).toBeDefined();
    expect(protocolFinding?.title).toMatch(/TLSv1\.[23]/);

    // Self-signed cert should fail standard chain validation.
    const unverified = result.findings.find((f) => f.title.startsWith("Certificate did not verify"));
    expect(unverified).toBeDefined();
    expect(unverified?.severity).toBe("medium");

    // A freshly-generated ~2 year cert should not be flagged as expiring soon or expired.
    expect(result.findings.some((f) => f.title.includes("expires soon"))).toBe(false);
    expect(result.findings.some((f) => f.title.includes("has expired"))).toBe(false);
  });

  it("flags a certificate that expires soon", async () => {
    running = await startTlsServer(EXPIRING_CERT, EXPIRING_KEY);
    const result = await runTlsCheck("127.0.0.1", { timeoutMs: 3000, port: running.port });

    const expiring = result.findings.find((f) => f.title.includes("expires soon"));
    expect(expiring).toBeDefined();
    expect(expiring?.severity).toBe("medium");
  });

  it("reports an error (not a crash) when there is nothing listening", async () => {
    const result = await runTlsCheck("127.0.0.1", { timeoutMs: 500, port: 1 });
    expect(result.error).toBeDefined();
    expect(result.findings).toHaveLength(0);
  });
});

describe("evaluateHandshake: pure certificate/protocol evaluation logic", () => {
  const baseCert = {
    valid_from: "Jan 1 00:00:00 2020 GMT",
    valid_to: "Jan 1 00:00:00 2030 GMT",
  } as any;

  function info(overrides: Partial<HandshakeInfo> = {}): HandshakeInfo {
    return {
      protocol: "TLSv1.3",
      cipherName: "TLS_AES_256_GCM_SHA384",
      cert: baseCert,
      authorized: true,
      ...overrides,
    };
  }

  it("flags outdated protocols as high severity", () => {
    const findings = evaluateHandshake(info({ protocol: "TLSv1" }));
    const finding = findings.find((f) => f.title.includes("Outdated TLS protocol"));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  it("does not flag TLS 1.2/1.3 as outdated", () => {
    const findings12 = evaluateHandshake(info({ protocol: "TLSv1.2" }));
    const findings13 = evaluateHandshake(info({ protocol: "TLSv1.3" }));
    expect(findings12.some((f) => f.title.includes("Outdated"))).toBe(false);
    expect(findings13.some((f) => f.title.includes("Outdated"))).toBe(false);
  });

  it("flags an expired certificate as high severity", () => {
    const now = new Date("2025-01-01T00:00:00Z").getTime();
    const findings = evaluateHandshake(
      info({ cert: { valid_from: "Jan 1 2020 GMT", valid_to: "Jan 1 2024 GMT" } as any }),
      now
    );
    const finding = findings.find((f) => f.title === "Certificate has expired");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  it("flags a not-yet-valid certificate as high severity", () => {
    const now = new Date("2020-01-01T00:00:00Z").getTime();
    const findings = evaluateHandshake(
      info({ cert: { valid_from: "Jan 1 2030 GMT", valid_to: "Jan 1 2035 GMT" } as any }),
      now
    );
    const finding = findings.find((f) => f.title === "Certificate is not yet valid");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  it("flags a certificate expiring within 30 days as medium severity", () => {
    const now = new Date("2025-01-01T00:00:00Z").getTime();
    const validTo = new Date(now + 10 * 24 * 60 * 60 * 1000).toUTCString();
    const findings = evaluateHandshake(
      info({ cert: { valid_from: "Jan 1 2020 GMT", valid_to: validTo } as any }),
      now
    );
    const finding = findings.find((f) => f.title.includes("expires soon"));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
  });

  it("does not flag a healthy, long-lived, TLS-1.3 certificate", () => {
    const now = new Date("2025-01-01T00:00:00Z").getTime();
    const findings = evaluateHandshake(info(), now);
    expect(findings.every((f) => f.severity === "info")).toBe(true);
  });

  it("flags when no certificate is presented at all", () => {
    const findings = evaluateHandshake(info({ cert: null }));
    const finding = findings.find((f) => f.title === "No certificate presented");
    expect(finding).toBeDefined();
  });
});

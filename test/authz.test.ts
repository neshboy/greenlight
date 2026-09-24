import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ensureAuthorized, addAuthorization, revokeAuthorization, listAuthorizations } from "../src/authz.js";
import { runScan, AuthorizationError } from "../src/scan.js";
import { readAuditLog } from "../src/audit.js";

let tmpHome: string;
let originalHome: string | undefined;

beforeEach(() => {
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "greenlight-test-"));
  originalHome = process.env.GREENLIGHT_HOME;
  process.env.GREENLIGHT_HOME = tmpHome;
});

afterEach(() => {
  process.env.GREENLIGHT_HOME = originalHome;
  fs.rmSync(tmpHome, { recursive: true, force: true });
});

// Note: these tests deliberately use only literal IP addresses (never
// hostnames) for "external-looking" targets. RFC 5737 reserves
// 192.0.2.0/24, 198.51.100.0/24, and 203.0.113.0/24 for documentation and
// testing — they are guaranteed to never be assigned to a real host, so
// using them here means the authorization gate's classification logic is
// exercised with zero DNS lookups and zero real network traffic.
const DOC_IP_1 = "192.0.2.10";
const DOC_IP_2 = "198.51.100.20";
const DOC_IP_3 = "203.0.113.30";
const DOC_IP_4 = "192.0.2.40";
const DOC_IP_5 = "198.51.100.50";

describe("authorization gate: ensureAuthorized", () => {
  it("refuses an unauthorized external-looking target", async () => {
    const decision = await ensureAuthorized(DOC_IP_1);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/no current authorization/i);
  });

  it("allows a loopback target with no authorization needed", async () => {
    const decision = await ensureAuthorized("127.0.0.1");
    expect(decision.allowed).toBe(true);
    expect(decision.method).toBe("loopback-exempt");
  });

  it("allows the literal hostname 'localhost' with no authorization needed", async () => {
    const decision = await ensureAuthorized("localhost:8080");
    expect(decision.allowed).toBe(true);
    expect(decision.method).toBe("loopback-exempt");
  });

  it("allows an RFC1918 private address with no authorization needed", async () => {
    const decision = await ensureAuthorized("192.168.1.50");
    expect(decision.allowed).toBe(true);
    expect(decision.method).toBe("loopback-exempt");
  });

  it("refuses a public IP address with no authorization record", async () => {
    const decision = await ensureAuthorized(DOC_IP_2);
    expect(decision.allowed).toBe(false);
  });

  it("allows an authorized external-looking target after authz add", async () => {
    addAuthorization(DOC_IP_3, "Written permission from system owner, contract #42");
    const decision = await ensureAuthorized(DOC_IP_3);
    expect(decision.allowed).toBe(true);
    expect(decision.method).toBe("authorization-file");
    expect(decision.record?.target).toBe(DOC_IP_3);
  });

  it("refuses again once the authorization has been revoked", async () => {
    addAuthorization(DOC_IP_4, "temporary engagement");
    let decision = await ensureAuthorized(DOC_IP_4);
    expect(decision.allowed).toBe(true);

    const revokedCount = revokeAuthorization(DOC_IP_4);
    expect(revokedCount).toBe(1);

    decision = await ensureAuthorized(DOC_IP_4);
    expect(decision.allowed).toBe(false);
  });

  it("refuses to add an authorization without a justification note", () => {
    expect(() => addAuthorization(DOC_IP_5, "")).toThrow(/note/i);
  });

  it("accepts interactive --authorize confirmation when the operator types the target back correctly", async () => {
    const decision = await ensureAuthorized(DOC_IP_1, {
      authorizeFlag: true,
      promptFn: async (host) => host === DOC_IP_1,
    });
    expect(decision.allowed).toBe(true);
    expect(decision.method).toBe("interactive-prompt");
  });

  it("refuses interactive --authorize confirmation when the operator types the wrong value", async () => {
    const decision = await ensureAuthorized(DOC_IP_2, {
      authorizeFlag: true,
      promptFn: async () => false,
    });
    expect(decision.allowed).toBe(false);
  });

  it("lists authorization records including revoked ones", () => {
    addAuthorization(DOC_IP_5, "note");
    revokeAuthorization(DOC_IP_5);
    const records = listAuthorizations();
    expect(records).toHaveLength(1);
    expect(records[0].revoked).toBe(true);
  });
});

describe("audit logging", () => {
  it("logs a denied scan attempt to the audit log without running any modules", async () => {
    await expect(runScan(DOC_IP_1, { modules: [] })).rejects.toThrow(AuthorizationError);
    const entries = readAuditLog();
    expect(entries).toHaveLength(1);
    expect(entries[0].result).toBe("denied");
    expect(entries[0].target).toBe(DOC_IP_1);
  });

  it("logs a successful scan with the modules that ran and the authorization method used", async () => {
    const result = await runScan("127.0.0.1", { modules: [] });
    expect(result.authorized).toBe(true);
    const entries = readAuditLog();
    expect(entries).toHaveLength(1);
    expect(entries[0].result).toBe("scanned");
    expect(entries[0].authorizationMethod).toBe("loopback-exempt");
    expect(entries[0].modules).toEqual([]);
  });
});

import { describe, it, expect } from "vitest";
import {
  isPrivateOrLoopbackIPv4,
  isPrivateOrLoopbackIPv6,
  isPrivateOrLoopbackLiteral,
  extractHost,
  checkPrivacyExemption,
} from "../src/utils/network.js";

describe("isPrivateOrLoopbackIPv4", () => {
  it("recognizes loopback", () => {
    expect(isPrivateOrLoopbackIPv4("127.0.0.1")).toBe(true);
    expect(isPrivateOrLoopbackIPv4("127.55.1.2")).toBe(true);
  });

  it("recognizes RFC1918 ranges", () => {
    expect(isPrivateOrLoopbackIPv4("10.0.0.5")).toBe(true);
    expect(isPrivateOrLoopbackIPv4("172.16.0.1")).toBe(true);
    expect(isPrivateOrLoopbackIPv4("172.31.255.255")).toBe(true);
    expect(isPrivateOrLoopbackIPv4("192.168.0.1")).toBe(true);
  });

  it("rejects addresses just outside RFC1918 ranges", () => {
    expect(isPrivateOrLoopbackIPv4("172.15.255.255")).toBe(false);
    expect(isPrivateOrLoopbackIPv4("172.32.0.0")).toBe(false);
    expect(isPrivateOrLoopbackIPv4("192.167.255.255")).toBe(false);
    expect(isPrivateOrLoopbackIPv4("11.0.0.1")).toBe(false);
  });

  it("rejects public addresses", () => {
    expect(isPrivateOrLoopbackIPv4("8.8.8.8")).toBe(false);
    expect(isPrivateOrLoopbackIPv4("1.1.1.1")).toBe(false);
    expect(isPrivateOrLoopbackIPv4("192.0.2.10")).toBe(false); // RFC5737 doc range, not private
  });
});

describe("isPrivateOrLoopbackIPv6", () => {
  it("recognizes ::1 loopback", () => {
    expect(isPrivateOrLoopbackIPv6("::1")).toBe(true);
  });

  it("recognizes unique local (fc00::/7) and link-local (fe80::/10)", () => {
    expect(isPrivateOrLoopbackIPv6("fd12:3456:789a::1")).toBe(true);
    expect(isPrivateOrLoopbackIPv6("fe80::1")).toBe(true);
  });

  it("rejects a public IPv6 address", () => {
    expect(isPrivateOrLoopbackIPv6("2001:4860:4860::8888")).toBe(false);
  });

  it("handles IPv4-mapped IPv6 addresses", () => {
    expect(isPrivateOrLoopbackIPv6("::ffff:127.0.0.1")).toBe(true);
    expect(isPrivateOrLoopbackIPv6("::ffff:8.8.8.8")).toBe(false);
  });
});

describe("isPrivateOrLoopbackLiteral", () => {
  it("dispatches to the correct family", () => {
    expect(isPrivateOrLoopbackLiteral("10.1.2.3")).toBe(true);
    expect(isPrivateOrLoopbackLiteral("::1")).toBe(true);
    expect(isPrivateOrLoopbackLiteral("8.8.8.8")).toBe(false);
  });

  it("returns false for non-IP strings", () => {
    expect(isPrivateOrLoopbackLiteral("not-an-ip")).toBe(false);
  });
});

describe("extractHost", () => {
  it("strips scheme, path, and port", () => {
    expect(extractHost("https://example.com:8443/path?x=1")).toBe("example.com");
    expect(extractHost("http://127.0.0.1:8080/")).toBe("127.0.0.1");
    expect(extractHost("example.com")).toBe("example.com");
  });

  it("handles bracketed IPv6 literals", () => {
    expect(extractHost("http://[::1]:8080/")).toBe("::1");
  });
});

describe("checkPrivacyExemption", () => {
  it("exempts literal loopback/private IPs without any lookup", async () => {
    const result = await checkPrivacyExemption("127.0.0.1");
    expect(result.isExempt).toBe(true);
  });

  it("does not exempt literal public IPs", async () => {
    const result = await checkPrivacyExemption("192.0.2.55");
    expect(result.isExempt).toBe(false);
  });

  it("fails closed (not exempt) when hostname resolution throws", async () => {
    const result = await checkPrivacyExemption("some-hostname.example", async () => {
      throw new Error("ENOTFOUND some-hostname.example");
    });
    expect(result.isExempt).toBe(false);
    expect(result.reason).toMatch(/could not be resolved/i);
  });

  it("fails closed (not exempt) when hostname resolution returns no addresses", async () => {
    const result = await checkPrivacyExemption("empty-hostname.example", async () => []);
    expect(result.isExempt).toBe(false);
  });

  it("exempts a hostname that resolves only to private addresses", async () => {
    const result = await checkPrivacyExemption("private-lab.example", async () => [{ address: "10.0.0.5" }]);
    expect(result.isExempt).toBe(true);
  });

  it("does not exempt a hostname that resolves to a public address", async () => {
    const result = await checkPrivacyExemption("public-host.example", async () => [{ address: "203.0.113.5" }]);
    expect(result.isExempt).toBe(false);
  });
});

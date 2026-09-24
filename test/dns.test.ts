import { describe, it, expect } from "vitest";
import { runDnsCheck } from "../src/modules/dns.js";

/**
 * These tests inject a fake resolver so DNS record lookups and the
 * subdomain-wordlist enumeration logic can be exercised deterministically
 * without making any real network/DNS calls. The production code path
 * (module default) uses node:dns/promises for real lookups; that's
 * exercised implicitly by the CLI smoke tests, but a live external DNS
 * dependency in the automated suite would be flaky and would mean the
 * tests reach out to the real internet, which we deliberately avoid.
 */
function makeFakeResolver(opts: {
  domain?: string;
  a?: string[];
  aaaa?: string[];
  mx?: { priority: number; exchange: string }[];
  txt?: string[][];
  ns?: string[];
  resolvableSubdomains?: Set<string>;
}) {
  const domain = opts.domain ?? "example.test";
  return {
    // Backs both the apex A-record lookup (host === domain) and the
    // per-subdomain wordlist lookups (host === "<word>.<domain>"): these
    // are two different concerns in real DNS but the same resolver method,
    // so the fake needs to distinguish them the same way.
    resolve4: async (host: string) => {
      if (host === domain && opts.a) return opts.a;
      if (opts.resolvableSubdomains?.has(host)) return ["10.0.0.1"];
      throw Object.assign(new Error(`ENOTFOUND ${host}`), { code: "ENOTFOUND" });
    },
    resolve6: async () => {
      if (opts.aaaa) return opts.aaaa;
      throw Object.assign(new Error("no AAAA"), { code: "ENOTFOUND" });
    },
    resolveMx: async () => {
      if (opts.mx) return opts.mx;
      throw Object.assign(new Error("no MX"), { code: "ENOTFOUND" });
    },
    resolveTxt: async () => {
      if (opts.txt) return opts.txt;
      throw Object.assign(new Error("no TXT"), { code: "ENOTFOUND" });
    },
    resolveNs: async () => {
      if (opts.ns) return opts.ns;
      throw Object.assign(new Error("no NS"), { code: "ENOTFOUND" });
    },
  };
}

describe("dns module", () => {
  it("reports A/MX/NS/TXT records found for the domain", async () => {
    const resolver = makeFakeResolver({
      a: ["203.0.113.9"],
      mx: [{ priority: 10, exchange: "mail.example.test" }],
      ns: ["ns1.example.test"],
      txt: [["v=spf1 include:_spf.example.test ~all"]],
      resolvableSubdomains: new Set(),
    });

    const result = await runDnsCheck("example.test", { concurrency: 20, paceMs: 0, wordlist: [], resolver });
    expect(result.error).toBeUndefined();
    const summary = result.findings.find((f) => f.title.startsWith("DNS records found"));
    expect(summary?.detail).toContain("203.0.113.9");
    expect(summary?.detail).toContain("mail.example.test");
  });

  it("flags a missing SPF record", async () => {
    const resolver = makeFakeResolver({ a: ["203.0.113.9"], resolvableSubdomains: new Set() });
    const result = await runDnsCheck("example.test", { concurrency: 20, wordlist: [], resolver });
    const spfFinding = result.findings.find((f) => f.title.includes("SPF"));
    expect(spfFinding).toBeDefined();
    expect(spfFinding?.severity).toBe("low");
  });

  it("does not flag a missing SPF record when one is present", async () => {
    const resolver = makeFakeResolver({
      a: ["203.0.113.9"],
      txt: [["v=spf1 -all"]],
      resolvableSubdomains: new Set(),
    });
    const result = await runDnsCheck("example.test", { concurrency: 20, wordlist: [], resolver });
    expect(result.findings.some((f) => f.title.includes("SPF"))).toBe(false);
  });

  it("discovers resolvable subdomains from the wordlist, rate-limited by the concurrency pool", async () => {
    const resolver = makeFakeResolver({
      a: ["203.0.113.9"],
      resolvableSubdomains: new Set(["www.example.test", "api.example.test"]),
    });
    const result = await runDnsCheck("example.test", {
      concurrency: 20,
      wordlist: ["www", "api", "doesnotexist1", "doesnotexist2"],
      resolver,
    });
    const found = result.findings.find((f) => f.title.includes("subdomain(s) discovered"));
    expect(found).toBeDefined();
    expect(found?.detail).toContain("www.example.test");
    expect(found?.detail).toContain("api.example.test");
  });

  it("flags publicly resolvable dev/admin/staging subdomains as medium severity", async () => {
    const resolver = makeFakeResolver({
      a: ["203.0.113.9"],
      resolvableSubdomains: new Set(["admin.example.test", "staging.example.test"]),
    });
    const result = await runDnsCheck("example.test", {
      concurrency: 20,
      wordlist: ["admin", "staging", "www"],
      resolver,
    });
    const sensitive = result.findings.find((f) => f.title.includes("Development/administrative"));
    expect(sensitive).toBeDefined();
    expect(sensitive?.severity).toBe("medium");
    expect(sensitive?.detail).toContain("admin.example.test");
    expect(sensitive?.detail).toContain("staging.example.test");
  });

  it("never issues more than the configured concurrency of simultaneous lookups", async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const resolver = {
      // resolve4 backs both the apex A-record lookup and every subdomain
      // lookup in the wordlist enumeration; track concurrent in-flight calls.
      resolve4: async (_host: string) => {
        inFlight++;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise((r) => setTimeout(r, 15));
        inFlight--;
        throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
      },
      resolve6: async () => { throw new Error("no AAAA"); },
      resolveMx: async () => { throw new Error("no MX"); },
      resolveTxt: async () => { throw new Error("no TXT"); },
      // NS succeeds so the overall lookup doesn't short-circuit as
      // "nothing resolved" before subdomain enumeration gets a chance to run.
      resolveNs: async () => ["ns1.example.test"],
    };

    const wordlist = Array.from({ length: 25 }, (_, i) => `sub${i}`);
    const result = await runDnsCheck("example.test", { concurrency: 5, paceMs: 0, wordlist, resolver: resolver as any });
    expect(result.error).toBeUndefined();
    expect(maxInFlight).toBeLessThanOrEqual(5);
    expect(maxInFlight).toBeGreaterThan(1); // sanity: the pool did run multiple lookups concurrently
  });

  it("returns an error result when no DNS records resolve at all", async () => {
    const resolver = makeFakeResolver({});
    const result = await runDnsCheck("totally-unresolvable.test", { concurrency: 20, wordlist: [], resolver });
    expect(result.error).toBeDefined();
  });
});

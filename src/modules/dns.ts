import dnsPromises from "node:dns/promises";
import { Finding, ModuleResult } from "../types.js";
import { runWithConcurrency } from "../utils/concurrency.js";

/** ~70 common subdomain names, checked via real DNS resolution, rate-limited. */
export const SUBDOMAIN_WORDLIST: string[] = [
  "www", "api", "staging", "stage", "dev", "development", "test", "qa", "admin", "administrator",
  "portal", "app", "apps", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp",
  "vpn", "remote", "rdp", "ssh", "git", "gitlab", "github", "jenkins", "ci", "cd",
  "build", "docs", "documentation", "wiki", "confluence", "jira", "support", "help", "helpdesk", "status",
  "monitor", "monitoring", "grafana", "kibana", "elastic", "logs", "log", "metrics", "db", "database",
  "mysql", "postgres", "redis", "mongo", "cache", "cdn", "static", "assets", "media", "images",
  "img", "video", "download", "downloads", "upload", "uploads", "files", "backup", "backups", "old",
  "beta", "demo", "sandbox", "internal", "intranet", "secure", "login", "auth", "sso", "id",
  "billing", "pay", "payments", "shop", "store", "blog", "news", "m", "mobile", "api-staging",
];

export interface DnsRecoResult {
  records: {
    A?: string[];
    AAAA?: string[];
    MX?: string[];
    TXT?: string[];
    NS?: string[];
  };
  subdomainsFound: string[];
}

export interface DnsCheckOptions {
  concurrency: number;
  /** Delay in ms between successive subdomain lookups dispatched, for pacing. */
  paceMs?: number;
  wordlist?: string[];
  /** Injectable resolver, primarily for tests. Defaults to node:dns/promises. */
  resolver?: Pick<typeof dnsPromises, "resolve4" | "resolve6" | "resolveMx" | "resolveTxt" | "resolveNs">;
}

const DEFAULT_CONCURRENCY = 20;

export async function runDnsCheck(domain: string, opts: DnsCheckOptions): Promise<ModuleResult> {
  const start = Date.now();
  const resolver = opts.resolver ?? dnsPromises;
  const concurrency = Math.min(opts.concurrency ?? DEFAULT_CONCURRENCY, 20);
  const wordlist = opts.wordlist ?? SUBDOMAIN_WORDLIST;
  const findings: Finding[] = [];

  const records: DnsRecoResult["records"] = {};

  const recordLookups: Array<[string, () => Promise<void>]> = [
    ["A", async () => { records.A = await resolver.resolve4(domain); }],
    ["AAAA", async () => { records.AAAA = await resolver.resolve6(domain); }],
    ["MX", async () => { records.MX = (await resolver.resolveMx(domain)).map((m) => `${m.priority} ${m.exchange}`); }],
    ["TXT", async () => { records.TXT = (await resolver.resolveTxt(domain)).map((t) => t.join("")); }],
    ["NS", async () => { records.NS = await resolver.resolveNs(domain); }],
  ];

  let anySucceeded = false;
  for (const [name, lookup] of recordLookups) {
    try {
      await lookup();
      anySucceeded = true;
    } catch {
      // Absence of a record type (e.g. no AAAA) is normal and not a finding.
    }
  }

  if (!anySucceeded) {
    return {
      module: "dns",
      findings: [],
      error: `Could not resolve any DNS records for ${domain}`,
      durationMs: Date.now() - start,
    };
  }

  const recordSummaryParts: string[] = [];
  if (records.A?.length) recordSummaryParts.push(`A: ${records.A.join(", ")}`);
  if (records.AAAA?.length) recordSummaryParts.push(`AAAA: ${records.AAAA.join(", ")}`);
  if (records.MX?.length) recordSummaryParts.push(`MX: ${records.MX.join(", ")}`);
  if (records.NS?.length) recordSummaryParts.push(`NS: ${records.NS.join(", ")}`);
  if (records.TXT?.length) recordSummaryParts.push(`TXT records: ${records.TXT.length}`);

  findings.push({
    module: "dns",
    severity: "info",
    title: `DNS records found for ${domain}`,
    detail: recordSummaryParts.length > 0 ? recordSummaryParts.join(" | ") : "No standard record types resolved.",
  });

  const hasSpf = records.TXT?.some((t) => /spf1/i.test(t)) ?? false;
  if (!hasSpf) {
    findings.push({
      module: "dns",
      severity: "low",
      title: "No SPF record found",
      detail: "No TXT record containing an SPF policy (v=spf1) was found. Without SPF, it's easier for third parties to send email that spoofs this domain.",
    });
  }

  // Rate-limited subdomain enumeration: hard concurrency cap + optional pacing.
  const subdomainsFound: string[] = [];
  const sensitiveHits: string[] = [];
  const sensitiveNames = new Set(["admin", "administrator", "staging", "stage", "dev", "development", "internal", "intranet", "backup", "backups", "test", "qa", "sandbox"]);

  await runWithConcurrency(
    wordlist,
    { concurrency, paceMs: opts.paceMs ?? 25 },
    async (word) => {
      const fqdn = `${word}.${domain}`;
      try {
        const addrs = await resolver.resolve4(fqdn);
        if (addrs && addrs.length > 0) {
          subdomainsFound.push(fqdn);
          if (sensitiveNames.has(word)) sensitiveHits.push(fqdn);
        }
      } catch {
        // NXDOMAIN / no record: expected for the vast majority of wordlist entries.
      }
    }
  );

  if (subdomainsFound.length > 0) {
    findings.push({
      module: "dns",
      severity: "info",
      title: `${subdomainsFound.length} subdomain(s) discovered via wordlist`,
      detail: `Publicly resolvable subdomains: ${subdomainsFound.sort().join(", ")}.`,
    });
  }

  if (sensitiveHits.length > 0) {
    findings.push({
      module: "dns",
      severity: "medium",
      title: "Development/administrative subdomains are publicly resolvable",
      detail: `${sensitiveHits.sort().join(", ")} resolve publicly. Staging/admin/dev environments are frequently less hardened than production and are a common initial foothold; confirm these are intended to be internet-facing and are otherwise access-controlled.`,
    });
  }

  return { module: "dns", findings, durationMs: Date.now() - start };
}

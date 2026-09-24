import { AuditEntry, ModuleResult, ScanOptions, Severity } from "./types.js";
import { ensureAuthorized, EnsureAuthorizedOptions } from "./authz.js";
import { appendAuditEntry } from "./audit.js";
import { extractHost, extractPort } from "./utils/network.js";
import { runHeaderCheck } from "./modules/headers.js";
import { runTlsCheck } from "./modules/tls.js";
import { runExposureCheck } from "./modules/exposure.js";
import { runPortCheck, DEFAULT_PORTS } from "./modules/ports.js";
import { runDnsCheck } from "./modules/dns.js";

export const ALL_MODULES = ["dns", "headers", "tls", "exposure", "ports"] as const;
export type ModuleName = (typeof ALL_MODULES)[number];

export interface ScanRunOptions extends Partial<ScanOptions> {
  authorizeFlag?: boolean;
  promptFn?: EnsureAuthorizedOptions["promptFn"];
  /** Base URL scheme to use for HTTP-based checks (headers/exposure). Defaults to https. */
  scheme?: "http" | "https";
  /** Explicit port for HTTPS/TLS checks; defaults to 443. */
  httpsPort?: number;
}

export interface ScanRunResult {
  target: string;
  host: string;
  authorized: boolean;
  authorizationReason?: string;
  results: ModuleResult[];
}

export class AuthorizationError extends Error {}

const DEFAULTS: ScanOptions = {
  modules: [...ALL_MODULES],
  portTimeoutMs: 1000,
  portConcurrency: 20,
  httpTimeoutMs: 5000,
  dnsConcurrency: 20,
  forceWideScan: false,
};

/**
 * Runs a full (or module-subset) scan against a single target, but only
 * after passing the authorization gate. This function is the one and only
 * entry point modules should be invoked through, specifically so the gate
 * can never accidentally be bypassed by a caller that forgets to check it.
 */
export async function runScan(target: string, userOpts: ScanRunOptions = {}): Promise<ScanRunResult> {
  const opts: ScanOptions = { ...DEFAULTS, ...userOpts, modules: userOpts.modules ?? DEFAULTS.modules };
  const host = extractHost(target);

  const decision = await ensureAuthorized(target, {
    authorizeFlag: userOpts.authorizeFlag,
    promptFn: userOpts.promptFn,
  });

  if (!decision.allowed) {
    appendAuditEntry({
      timestamp: new Date().toISOString(),
      target: host,
      result: "denied",
      modules: opts.modules,
      reason: decision.reason,
    });
    throw new AuthorizationError(
      decision.reason ?? `Authorization refused for target "${host}".`
    );
  }

  const scheme = userOpts.scheme ?? "https";
  // Preserve any explicit port from the target (e.g. "host:8443") so
  // header/exposure/TLS checks hit the right port instead of silently
  // falling back to 80/443 and reporting a spurious connection error.
  const explicitPort = extractPort(target);
  const httpPort = explicitPort;
  const baseUrl = httpPort ? `${scheme}://${host}:${httpPort}` : `${scheme}://${host}`;
  const tlsPort = userOpts.httpsPort ?? explicitPort ?? 443;
  const results: ModuleResult[] = [];

  for (const moduleName of opts.modules) {
    switch (moduleName) {
      case "dns":
        if (!isLikelyDomainName(host)) break;
        results.push(await runDnsCheck(host, { concurrency: opts.dnsConcurrency }));
        break;
      case "headers":
        results.push(await runHeaderCheck(baseUrl, { timeoutMs: opts.httpTimeoutMs }));
        break;
      case "tls":
        results.push(await runTlsCheck(host, { timeoutMs: opts.httpTimeoutMs, port: tlsPort }));
        break;
      case "exposure":
        results.push(await runExposureCheck(baseUrl, { timeoutMs: opts.httpTimeoutMs, concurrency: 5 }));
        break;
      case "ports": {
        const ports = opts.ports ?? DEFAULT_PORTS;
        results.push(await runPortCheck(host, ports, { concurrency: opts.portConcurrency, timeoutMs: opts.portTimeoutMs }));
        break;
      }
    }
  }

  const findingCounts = summarizeSeverities(results);
  appendAuditEntry({
    timestamp: new Date().toISOString(),
    target: host,
    result: "scanned",
    authorizationMethod: decision.method,
    modules: opts.modules,
    findingCounts,
  });

  return {
    target,
    host,
    authorized: true,
    authorizationReason: decision.reason,
    results,
  };
}

function isLikelyDomainName(host: string): boolean {
  // Skip DNS module for literal IPs and "localhost" — subdomain enumeration
  // and record lookups don't make sense against a bare IP address.
  if (host === "localhost") return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false;
  if (host.includes(":")) return false; // IPv6 literal
  return true;
}

export function summarizeSeverities(results: ModuleResult[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0 };
  for (const r of results) {
    for (const f of r.findings) {
      counts[f.severity]++;
    }
  }
  return counts;
}

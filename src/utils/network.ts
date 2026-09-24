import dns from "node:dns/promises";
import net from "node:net";

/**
 * Returns true if the given literal IPv4 address is loopback (127.0.0.0/8)
 * or within an RFC1918 private range (10.0.0.0/8, 172.16.0.0/12,
 * 192.168.0.0/16), or the "link local" 169.254.0.0/16 range used for
 * autoconfiguration.
 */
export function isPrivateOrLoopbackIPv4(ip: string): boolean {
  const parts = ip.split(".").map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return false;
  }
  const [a, b] = parts;
  if (a === 127) return true; // loopback
  if (a === 10) return true; // RFC1918
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
  if (a === 192 && b === 168) return true; // RFC1918
  if (a === 169 && b === 254) return true; // link-local
  return false;
}

/** Returns true if the given literal IPv6 address is loopback or ULA/link-local. */
export function isPrivateOrLoopbackIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  if (normalized === "::1") return true; // loopback
  // Unique local addresses fc00::/7
  if (/^f[cd][0-9a-f]{2}:/.test(normalized)) return true;
  // Link-local fe80::/10
  if (/^fe[89ab][0-9a-f]:/.test(normalized)) return true;
  // IPv4-mapped IPv6 addresses, e.g. ::ffff:127.0.0.1
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateOrLoopbackIPv4(mapped[1]);
  return false;
}

/**
 * Determines whether a literal IP address (v4 or v6) is private/loopback.
 * Returns false for anything that isn't a valid literal IP address.
 */
export function isPrivateOrLoopbackLiteral(ip: string): boolean {
  if (net.isIPv4(ip)) return isPrivateOrLoopbackIPv4(ip);
  if (net.isIPv6(ip)) return isPrivateOrLoopbackIPv6(ip);
  return false;
}

/** Strips a leading protocol, trailing path, and port from a target string, returning just the host. */
export function extractHost(target: string): string {
  let t = target.trim();
  t = t.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, ""); // strip scheme
  t = t.split("/")[0]; // strip path
  // Strip a trailing :port, but be careful with IPv6 literals in brackets.
  if (t.startsWith("[")) {
    const closeBracket = t.indexOf("]");
    if (closeBracket !== -1) {
      return t.slice(1, closeBracket);
    }
    return t;
  }
  const lastColon = t.lastIndexOf(":");
  if (lastColon !== -1 && /^\d+$/.test(t.slice(lastColon + 1))) {
    t = t.slice(0, lastColon);
  }
  return t;
}

/**
 * Extracts an explicit port from a target string, if one was given (e.g.
 * "https://example.com:8443/" -> 8443, "127.0.0.1:9200" -> 9200).
 * Returns undefined when no explicit port is present, so callers can fall
 * back to a sensible per-module default (443 for TLS, etc).
 */
export function extractPort(target: string): number | undefined {
  let t = target.trim();
  t = t.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "");
  t = t.split("/")[0];
  if (t.startsWith("[")) {
    const closeBracket = t.indexOf("]");
    if (closeBracket === -1) return undefined;
    const rest = t.slice(closeBracket + 1);
    const m = rest.match(/^:(\d+)$/);
    return m ? Number(m[1]) : undefined;
  }
  const lastColon = t.lastIndexOf(":");
  if (lastColon !== -1 && /^\d+$/.test(t.slice(lastColon + 1))) {
    return Number(t.slice(lastColon + 1));
  }
  return undefined;
}

export interface PrivacyCheckResult {
  isExempt: boolean;
  reason: string;
}

/**
 * Determines whether a target is exempt from the authorization gate because
 * it is a loopback / RFC1918 private address (or "localhost"). This is a
 * fail-closed check: hostnames that cannot be confidently classified as
 * private are treated as NOT exempt, requiring explicit authorization.
 *
 * For hostnames (not literal IPs), we also resolve the name and check
 * whether it points at a private/loopback address, so that a DNS name a
 * user has pointed at their own private lab (e.g. "router.home.arpa") is
 * still recognized as private. Resolution failures are treated as "not
 * exempt" (fail closed) rather than silently allowed.
 */
export type LookupFn = (host: string) => Promise<{ address: string }[]>;

const defaultLookup: LookupFn = (host) => dns.lookup(host, { all: true, verbatim: true });

export async function checkPrivacyExemption(
  target: string,
  lookupFn: LookupFn = defaultLookup
): Promise<PrivacyCheckResult> {
  const host = extractHost(target).toLowerCase();

  if (host === "localhost") {
    return { isExempt: true, reason: "hostname is 'localhost'" };
  }

  if (net.isIP(host)) {
    if (isPrivateOrLoopbackLiteral(host)) {
      return { isExempt: true, reason: `literal IP ${host} is in a private/loopback range` };
    }
    return { isExempt: false, reason: `literal IP ${host} is a public address` };
  }

  // Hostname: resolve and check. Fail closed on any error.
  try {
    const results = await lookupFn(host);
    if (results.length === 0) {
      return { isExempt: false, reason: `hostname ${host} did not resolve to any address` };
    }
    const allPrivate = results.every((r) => isPrivateOrLoopbackLiteral(r.address));
    if (allPrivate) {
      return {
        isExempt: true,
        reason: `hostname ${host} resolves only to private/loopback addresses`,
      };
    }
    return { isExempt: false, reason: `hostname ${host} resolves to a public address` };
  } catch (err) {
    return {
      isExempt: false,
      reason: `hostname ${host} could not be resolved (${(err as Error).message}); treating as non-private`,
    };
  }
}

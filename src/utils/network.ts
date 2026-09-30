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
  // A bare (unbracketed) IPv6 literal has no port to strip: a naive
  // trailing ":port" strip can't be distinguished from the address's own
  // hextets (e.g. "::1", "fe80::1", "2001:4860:4860::8888" all end in a
  // colon followed by digits). Require bracket notation (e.g.
  // "[::1]:8080") to pair an IPv6 host with an explicit port, matching the
  // bracketed branch above.
  if (net.isIPv6(t)) {
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
  // See the matching check in extractHost(): a bare IPv6 literal never has
  // a parseable trailing port, and its own hextets can look like one.
  if (net.isIPv6(t)) return undefined;
  const lastColon = t.lastIndexOf(":");
  if (lastColon !== -1 && /^\d+$/.test(t.slice(lastColon + 1))) {
    return Number(t.slice(lastColon + 1));
  }
  return undefined;
}

export interface PrivacyCheckResult {
  isExempt: boolean;
  reason: string;
  /**
   * Present when `target` was a hostname (not a literal IP or "localhost")
   * that this check actually resolved via DNS. Callers that proceed with a
   * scan should pin subsequent connections to this exact address (see
   * `pinnedLookup`) instead of letting each module re-resolve DNS
   * independently, so a target can't answer privately for this check (to
   * pass the authorization gate) and publicly for the real probes
   * (DNS rebinding).
   */
  resolvedAddress?: string;
  resolvedFamily?: number;
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
export type LookupFn = (host: string) => Promise<{ address: string; family?: number }[]>;

/**
 * A `lookup`-option-compatible function, accepted by `http.request`,
 * `https.request`, `tls.connect`, and `net.Socket#connect`, that always
 * resolves to a single pinned address/family regardless of the hostname
 * passed in. Used to pin every connection made during a single scan to the
 * exact address that was checked by the authorization gate (see
 * `PrivacyCheckResult.resolvedAddress`), instead of letting each module
 * (headers/exposure via http(s), tls, raw TCP port checks) perform its own
 * fresh DNS resolution after the gate has already made its decision.
 */
export function pinnedLookup(address: string, family: number): net.LookupFunction {
  return (_hostname, options, callback) => {
    // Modern Node (Happy Eyeballs / autoSelectFamily) calls custom `lookup`
    // functions with `{ all: true }` and expects the callback to receive an
    // *array* of addresses (err, addresses[]), not the single
    // (err, address, family) form @types/node's LookupFunction type
    // describes. Handle both shapes so pinning works regardless of Node
    // version / autoSelectFamily setting.
    const wantsAll = typeof options === "object" && options !== null && (options as { all?: boolean }).all === true;
    if (wantsAll) {
      (callback as unknown as (err: null, addresses: { address: string; family: number }[]) => void)(null, [
        { address, family },
      ]);
    } else {
      callback(null, address, family);
    }
  };
}

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
    const resolvedAddress = results[0].address;
    const resolvedFamily = results[0].family ?? (net.isIPv6(resolvedAddress) ? 6 : 4);
    if (allPrivate) {
      return {
        isExempt: true,
        reason: `hostname ${host} resolves only to private/loopback addresses`,
        resolvedAddress,
        resolvedFamily,
      };
    }
    return {
      isExempt: false,
      reason: `hostname ${host} resolves to a public address`,
      resolvedAddress,
      resolvedFamily,
    };
  } catch (err) {
    return {
      isExempt: false,
      reason: `hostname ${host} could not be resolved (${(err as Error).message}); treating as non-private`,
    };
  }
}

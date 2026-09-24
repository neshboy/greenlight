import { Finding, ModuleResult, Severity } from "../types.js";
import { simpleGet } from "../utils/httpClient.js";

export interface HeaderCheckOptions {
  timeoutMs: number;
}

interface HeaderRule {
  header: string;
  severityIfMissing: Severity;
  onlyIfHttps?: boolean;
  explain: string;
  /** Optional extra validation of a present header's value. Returns a finding if misconfigured. */
  validate?: (value: string) => Finding | null;
}

const RULES: HeaderRule[] = [
  {
    header: "strict-transport-security",
    severityIfMissing: "high",
    onlyIfHttps: true,
    explain:
      "HSTS (Strict-Transport-Security) tells browsers to only ever connect over HTTPS. Without it, users " +
      "who type the bare domain (or follow an old http:// link) can be silently downgraded to plaintext HTTP " +
      "and are exposed to man-in-the-middle interception/downgrade attacks.",
  },
  {
    header: "content-security-policy",
    severityIfMissing: "medium",
    explain:
      "Content-Security-Policy restricts which sources of scripts/styles/frames the browser will execute or " +
      "render. Without it, a single injected-HTML bug (e.g. reflected/stored XSS) can run arbitrary attacker " +
      "script with no defense-in-depth backstop.",
  },
  {
    header: "x-frame-options",
    severityIfMissing: "medium",
    explain:
      "X-Frame-Options (or a frame-ancestors CSP directive) prevents the page from being embedded in a hidden " +
      "iframe on an attacker's site, which is the basis of clickjacking attacks.",
  },
  {
    header: "x-content-type-options",
    severityIfMissing: "low",
    explain:
      "X-Content-Type-Options: nosniff stops browsers from MIME-sniffing a response into a different content " +
      "type than declared, which can turn an innocuous upload/response into executable script in some legacy " +
      "browser behaviors.",
  },
  {
    header: "referrer-policy",
    severityIfMissing: "low",
    explain:
      "Referrer-Policy controls how much of the current URL (which may contain tokens or sensitive paths) is " +
      "leaked to third parties via the Referer header on outbound navigation/requests.",
  },
  {
    header: "permissions-policy",
    severityIfMissing: "info",
    explain:
      "Permissions-Policy lets a site explicitly disable powerful browser features (camera, geolocation, etc.) " +
      "it doesn't use, shrinking the attack surface available to injected or third-party script.",
  },
];

/**
 * Fetches the target once and evaluates the response's security headers.
 * Read-only: a single GET request, no state changes.
 */
export async function runHeaderCheck(targetUrl: string, opts: HeaderCheckOptions): Promise<ModuleResult> {
  const start = Date.now();
  const findings: Finding[] = [];
  try {
    const res = await simpleGet(targetUrl, { timeoutMs: opts.timeoutMs });
    const isHttps = res.protocol === "https";

    for (const rule of RULES) {
      if (rule.onlyIfHttps && !isHttps) continue;
      const value = res.headers[rule.header];
      if (value === undefined) {
        findings.push({
          module: "headers",
          severity: rule.severityIfMissing,
          title: `Missing ${headerDisplayName(rule.header)} header`,
          detail: rule.explain,
        });
      } else if (rule.validate) {
        const finding = rule.validate(Array.isArray(value) ? value.join(", ") : value);
        if (finding) findings.push(finding);
      }
    }

    if (res.headers["server"] || res.headers["x-powered-by"]) {
      const disclosed = [res.headers["server"], res.headers["x-powered-by"]].filter(Boolean).join(", ");
      findings.push({
        module: "headers",
        severity: "info",
        title: "Server/technology banner disclosed",
        detail: `Response advertises: ${disclosed}. This makes fingerprinting the software stack (and its known CVEs) easier for an attacker; consider suppressing these headers.`,
      });
    }

    if (findings.length === 0) {
      findings.push({
        module: "headers",
        severity: "info",
        title: "All checked security headers present",
        detail: "Content-Security-Policy, HSTS (if HTTPS), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy were all present on the response.",
      });
    }

    return { module: "headers", findings, durationMs: Date.now() - start };
  } catch (err) {
    return {
      module: "headers",
      findings: [],
      error: `Could not complete HTTP header check: ${(err as Error).message}`,
      durationMs: Date.now() - start,
    };
  }
}

function headerDisplayName(lowerName: string): string {
  return lowerName
    .split("-")
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join("-");
}

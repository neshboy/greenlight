/**
 * Shared types used across Greenlight's scan modules, authorization gate,
 * and audit logging.
 */

export type Severity = "info" | "low" | "medium" | "high";

/** A single observation produced by a scan module. */
export interface Finding {
  /** Name of the module that produced this finding, e.g. "headers". */
  module: string;
  severity: Severity;
  title: string;
  /** Plain-English explanation of what was found and why it matters. */
  detail: string;
}

/** The result of running a single scan module against a target. */
export interface ModuleResult {
  module: string;
  findings: Finding[];
  /** Set if the module could not complete (network error, timeout, etc). */
  error?: string;
  /** Wall-clock duration of the module run, in milliseconds. */
  durationMs: number;
}

export const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high"];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/** How a scan came to be authorized (or why it was exempt from the gate). */
export type AuthorizationMethod =
  | "loopback-exempt"
  | "private-range-exempt"
  | "authorization-file"
  | "interactive-prompt";

export interface AuthorizationDecision {
  allowed: boolean;
  method?: AuthorizationMethod;
  reason?: string;
  /** Present when method === "authorization-file". */
  record?: AuthorizationRecord;
}

/** A recorded authorization for scanning a specific target. */
export interface AuthorizationRecord {
  target: string;
  createdAt: string; // ISO timestamp
  expiresAt: string; // ISO timestamp
  note: string;
  revoked: boolean;
  revokedAt?: string;
}

export interface ScanOptions {
  modules: string[];
  ports?: number[];
  portTimeoutMs: number;
  portConcurrency: number;
  httpTimeoutMs: number;
  dnsConcurrency: number;
  forceWideScan: boolean;
}

export interface AuditEntry {
  timestamp: string;
  target: string;
  result: "scanned" | "denied";
  authorizationMethod?: AuthorizationMethod;
  modules: string[];
  findingCounts?: Record<Severity, number>;
  reason?: string;
}

import { ModuleResult, Severity } from "./types.js";
import { ScanRunResult, summarizeSeverities } from "./scan.js";

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const COLORS: Record<Severity, string> = {
  high: "\x1b[31m", // red
  medium: "\x1b[33m", // yellow
  low: "\x1b[36m", // cyan
  info: "\x1b[90m", // grey
};

const noColor = process.env.NO_COLOR !== undefined || !process.stdout.isTTY;

function color(text: string, code: string): string {
  if (noColor) return text;
  return `${code}${text}${RESET}`;
}

export const AUTHORIZED_USE_BANNER = [
  "==================================================================",
  " GREENLIGHT — Authorized-use reconnaissance scanner",
  " Only scan systems you own or have explicit written permission to test.",
  " Unauthorized scanning of systems you do not control may be illegal.",
  "==================================================================",
].join("\n");

export function printBanner(): void {
  console.log(noColor ? AUTHORIZED_USE_BANNER : color(AUTHORIZED_USE_BANNER, BOLD));
}

const SEVERITY_ORDER: Severity[] = ["high", "medium", "low", "info"];
const SEVERITY_LABEL: Record<Severity, string> = {
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

export function printScanReport(result: ScanRunResult): void {
  console.log(`\nTarget: ${result.host}`);
  console.log(`Authorization: ${result.authorizationReason ?? "(exempt)"}\n`);

  for (const moduleResult of result.results) {
    printModuleResult(moduleResult);
  }

  const counts = summarizeSeverities(result.results);
  console.log(`\n${color("Summary:", BOLD)}`);
  for (const sev of SEVERITY_ORDER) {
    if (counts[sev] > 0) {
      console.log(`  ${color(SEVERITY_LABEL[sev], COLORS[sev])}: ${counts[sev]}`);
    }
  }
  if (SEVERITY_ORDER.every((s) => counts[s] === 0)) {
    console.log("  No findings.");
  }
}

function printModuleResult(result: ModuleResult): void {
  console.log(color(`--- ${result.module} ---`, BOLD));
  if (result.error) {
    console.log(`  ${color("ERROR", COLORS.medium)}: ${result.error}`);
    return;
  }
  const sorted = [...result.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
  if (sorted.length === 0) {
    console.log("  (no findings)");
  }
  for (const finding of sorted) {
    console.log(`  [${color(SEVERITY_LABEL[finding.severity], COLORS[finding.severity])}] ${finding.title}`);
    console.log(`      ${finding.detail}`);
  }
}

/** Exit code convention: non-zero (1) if any high-severity finding exists, so this is usable as a CI gate. */
export function exitCodeFor(result: ScanRunResult): number {
  const counts = summarizeSeverities(result.results);
  return counts.high > 0 ? 1 : 0;
}

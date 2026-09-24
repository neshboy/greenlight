import net from "node:net";
import { Finding, ModuleResult } from "../types.js";
import { runWithConcurrency } from "../utils/concurrency.js";

/** Small, sane default port list: common services only, not all 65535. */
export const DEFAULT_PORTS: number[] = [
  21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443,
];

/** Ports wider than this require an explicit --force-wide-scan override. */
export const MAX_PORTS_WITHOUT_OVERRIDE = 1000;

export type PortState = "open" | "closed" | "filtered";

export interface PortCheckOptions {
  concurrency: number;
  timeoutMs: number;
}

interface PortResult {
  port: number;
  state: PortState;
}

export const RISKY_PORT_NOTES: Record<number, string> = {
  21: "FTP is unencrypted by default; credentials and data are sent in plaintext.",
  23: "Telnet is unencrypted and its use for remote administration is considered obsolete/insecure.",
  3306: "MySQL should generally not be reachable directly from the internet; restrict to internal networks/VPN.",
  3389: "RDP exposed to the internet is a frequent target for automated attacks; restrict to VPN and enforce MFA/NLA.",
  5432: "PostgreSQL should generally not be reachable directly from the internet; restrict to internal networks/VPN.",
  6379: "Redis has historically shipped with no authentication by default; exposing it to the internet is high risk.",
  445: "SMB exposed to the internet has been the vector for major worm outbreaks (e.g. WannaCry); it should never face the public internet.",
  139: "NetBIOS exposed to the internet leaks host/share information and should not face the public internet.",
};

/**
 * A rate-limited, concurrency-capped, timeout-bounded TCP connect scan.
 * This is a pure connectivity probe (TCP handshake only) — no payloads are
 * sent, so it cannot be used to exploit a service, only to observe whether
 * a port accepts connections.
 */
export async function runPortCheck(host: string, ports: number[], opts: PortCheckOptions): Promise<ModuleResult> {
  const start = Date.now();
  const results = await runWithConcurrency(ports, { concurrency: opts.concurrency }, (port) =>
    checkPort(host, port, opts.timeoutMs)
  );

  const findings: Finding[] = [];
  const open = results.filter((r) => r.state === "open");

  if (open.length === 0) {
    findings.push({
      module: "ports",
      severity: "info",
      title: `No open ports found among ${ports.length} checked`,
      detail: `Checked ports: ${ports.join(", ")}. All were closed or filtered within the ${opts.timeoutMs}ms per-connection timeout.`,
    });
  }

  for (const r of open) {
    findings.push(describeOpenPort(r.port));
  }

  return { module: "ports", findings, durationMs: Date.now() - start };
}

/**
 * Pure mapping from an observed-open port number to a finding. Exported
 * separately from runPortCheck so the well-known-risky-port annotations
 * (e.g. flagging 3306/3389/6379 as medium severity) can be unit tested
 * directly by port number, without needing to actually stand up a real
 * MySQL/RDP/Redis server bound to its well-known port for a test.
 */
export function describeOpenPort(port: number): Finding {
  const note = RISKY_PORT_NOTES[port];
  return {
    module: "ports",
    severity: note ? "medium" : "info",
    title: `Port ${port} is open`,
    detail: note ?? `TCP port ${port} accepted a connection. Confirm this service is intended to be reachable from this network.`,
  };
}

function checkPort(host: string, port: number, timeoutMs: number): Promise<PortResult> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;

    const finish = (state: PortState) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ port, state });
    };

    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish("open"));
    socket.once("timeout", () => finish("filtered"));
    socket.once("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "ECONNREFUSED") finish("closed");
      else finish("filtered");
    });

    socket.connect(port, host);
  });
}

/**
 * Parses a user-supplied port spec like "22,80,443" or "1-1024" or a mix
 * "22,80,1000-1010" into a de-duplicated, sorted list of valid ports.
 */
export function parsePortSpec(spec: string): number[] {
  const ports = new Set<number>();
  for (const part of spec.split(",").map((p) => p.trim()).filter(Boolean)) {
    const rangeMatch = part.match(/^(\d+)-(\d+)$/);
    if (rangeMatch) {
      const lo = Number(rangeMatch[1]);
      const hi = Number(rangeMatch[2]);
      if (lo < 1 || hi > 65535 || lo > hi) {
        throw new Error(`invalid port range: ${part}`);
      }
      for (let p = lo; p <= hi; p++) ports.add(p);
    } else if (/^\d+$/.test(part)) {
      const p = Number(part);
      if (p < 1 || p > 65535) throw new Error(`invalid port: ${part}`);
      ports.add(p);
    } else {
      throw new Error(`invalid port spec segment: ${part}`);
    }
  }
  return [...ports].sort((a, b) => a - b);
}

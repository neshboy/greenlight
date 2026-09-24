import net from "node:net";
import tls from "node:tls";
import { Finding, ModuleResult } from "../types.js";

export interface TlsCheckOptions {
  timeoutMs: number;
  port?: number;
}

const OUTDATED_PROTOCOLS = new Set(["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]);
const NEAR_EXPIRY_DAYS = 30;

/**
 * Performs a single real TLS handshake against host:port and inspects the
 * negotiated protocol version, cipher, and peer certificate validity. This
 * is a read-only handshake (no application data / HTTP request is sent) —
 * it identifies configuration weaknesses, it does not exploit them.
 */
export async function runTlsCheck(host: string, opts: TlsCheckOptions): Promise<ModuleResult> {
  const start = Date.now();
  const port = opts.port ?? 443;

  try {
    const info = await handshake(host, port, opts.timeoutMs);
    const findings = evaluateHandshake(info);
    return { module: "tls", findings, durationMs: Date.now() - start };
  } catch (err) {
    return {
      module: "tls",
      findings: [],
      error: `Could not complete TLS check: ${(err as Error).message}`,
      durationMs: Date.now() - start,
    };
  }
}

export interface HandshakeInfo {
  protocol: string;
  cipherName: string;
  cert: tls.PeerCertificate | null;
  authorized: boolean;
  authorizationError?: string;
}

/**
 * Pure evaluation of a completed handshake's details into findings. Kept
 * separate from the network I/O in handshake() so the date-arithmetic and
 * protocol-version logic (expired/near-expiry/not-yet-valid/outdated
 * protocol) can be exercised directly in tests with synthetic handshake
 * results, without needing to stand up a non-default-configuration TLS
 * server (e.g. one forced down to TLS 1.0) for every edge case.
 */
export function evaluateHandshake(info: HandshakeInfo, now: number = Date.now()): Finding[] {
  const findings: Finding[] = [];

  findings.push({
    module: "tls",
    severity: "info",
    title: `Negotiated ${info.protocol} with cipher ${info.cipherName}`,
    detail: `The server negotiated TLS protocol ${info.protocol} using cipher suite ${info.cipherName}.`,
  });

  if (OUTDATED_PROTOCOLS.has(info.protocol)) {
    findings.push({
      module: "tls",
      severity: "high",
      title: `Outdated TLS protocol negotiated: ${info.protocol}`,
      detail: `${info.protocol} has known cryptographic weaknesses and is deprecated by all major browsers/CAs. Disable it server-side and require TLS 1.2 or 1.3.`,
    });
  }

  if (info.cert) {
    const validTo = new Date(info.cert.valid_to).getTime();
    const validFrom = new Date(info.cert.valid_from).getTime();
    const daysToExpiry = Math.floor((validTo - now) / (24 * 60 * 60 * 1000));

    if (Number.isFinite(validFrom) && now < validFrom) {
      findings.push({
        module: "tls",
        severity: "high",
        title: "Certificate is not yet valid",
        detail: `Certificate's valid_from (${info.cert.valid_from}) is in the future. Clients will reject this certificate.`,
      });
    }

    if (Number.isFinite(validTo) && now > validTo) {
      findings.push({
        module: "tls",
        severity: "high",
        title: "Certificate has expired",
        detail: `Certificate expired on ${info.cert.valid_to}. Browsers will show hard TLS errors to every visitor until it is renewed.`,
      });
    } else if (Number.isFinite(validTo) && daysToExpiry <= NEAR_EXPIRY_DAYS) {
      findings.push({
        module: "tls",
        severity: "medium",
        title: `Certificate expires soon (${daysToExpiry} day${daysToExpiry === 1 ? "" : "s"})`,
        detail: `Certificate expires on ${info.cert.valid_to}. Renew it before expiry to avoid a hard outage/TLS error for users.`,
      });
    }

    if (!info.authorized && info.authorizationError) {
      findings.push({
        module: "tls",
        severity: "medium",
        title: `Certificate did not verify: ${info.authorizationError}`,
        detail: "The certificate chain failed standard validation (e.g. self-signed, untrusted CA, hostname mismatch, or expired). Browsers will warn or block users.",
      });
    }
  } else {
    findings.push({
      module: "tls",
      severity: "medium",
      title: "No certificate presented",
      detail: "The server completed a TLS handshake but presented no peer certificate details that could be inspected.",
    });
  }

  return findings;
}

function handshake(host: string, port: number, timeoutMs: number): Promise<HandshakeInfo> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host,
        port,
        // SNI (servername) is only meaningful for hostnames, not IP
        // literals (RFC 6066); omit it for IPs to avoid a Node warning and
        // to match how a real client would behave.
        ...(net.isIP(host) ? {} : { servername: host }),
        rejectUnauthorized: false, // we want to report on invalid certs, not throw on them
        timeout: timeoutMs,
      },
      () => {
        const cert = socket.getPeerCertificate(false);
        const info: HandshakeInfo = {
          protocol: socket.getProtocol() ?? "unknown",
          cipherName: socket.getCipher()?.name ?? "unknown",
          cert: cert && Object.keys(cert).length > 0 ? cert : null,
          authorized: socket.authorized,
          authorizationError: socket.authorized ? undefined : String(socket.authorizationError ?? "unknown"),
        };
        socket.end();
        resolve(info);
      }
    );
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error(`TLS handshake to ${host}:${port} timed out after ${timeoutMs}ms`));
    });
    socket.on("error", (err) => reject(err));
  });
}

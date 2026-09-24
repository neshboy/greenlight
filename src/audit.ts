import fs from "node:fs";
import { AuditEntry } from "./types.js";
import { auditLogFilePath, ensureGreenlightHome } from "./utils/storage.js";

/** Appends one JSON-lines record to the local audit log. Never throws on write failure (best-effort). */
export function appendAuditEntry(entry: AuditEntry): void {
  try {
    ensureGreenlightHome();
    fs.appendFileSync(auditLogFilePath(), JSON.stringify(entry) + "\n", "utf8");
  } catch (err) {
    // Auditing must never crash a scan; surface a warning instead.
    // eslint-disable-next-line no-console
    console.error(`Warning: failed to write audit log entry: ${(err as Error).message}`);
  }
}

/** Reads and parses every entry in the audit log. Returns [] if the log doesn't exist. */
export function readAuditLog(): AuditEntry[] {
  const file = auditLogFilePath();
  if (!fs.existsSync(file)) return [];
  const raw = fs.readFileSync(file, "utf8");
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => {
      try {
        return JSON.parse(line) as AuditEntry;
      } catch {
        return null;
      }
    })
    .filter((e): e is AuditEntry => e !== null);
}

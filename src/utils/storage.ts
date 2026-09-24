import fs from "node:fs";
import path from "node:path";

/**
 * Resolves the directory Greenlight uses for local state: authorization
 * records and the audit log. Defaults to ".greenlight" in the current
 * working directory, but can be overridden with the GREENLIGHT_HOME
 * environment variable (used by the test suite to avoid touching real
 * user state).
 */
export function greenlightHome(): string {
  return process.env.GREENLIGHT_HOME ?? path.join(process.cwd(), ".greenlight");
}

export function authorizationsFilePath(): string {
  return path.join(greenlightHome(), "authorizations.json");
}

export function auditLogFilePath(): string {
  return path.join(greenlightHome(), "audit.log.jsonl");
}

export function ensureGreenlightHome(): void {
  const dir = greenlightHome();
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

import fs from "node:fs";
import readline from "node:readline";
import { AuthorizationDecision, AuthorizationRecord } from "./types.js";
import { authorizationsFilePath, ensureGreenlightHome } from "./utils/storage.js";
import { checkPrivacyExemption, extractHost } from "./utils/network.js";

const DEFAULT_VALIDITY_DAYS = 30;

/** Loads all authorization records from disk. Returns [] if the file doesn't exist. */
export function loadAuthorizations(): AuthorizationRecord[] {
  const file = authorizationsFilePath();
  if (!fs.existsSync(file)) return [];
  try {
    const raw = fs.readFileSync(file, "utf8");
    if (!raw.trim()) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed as AuthorizationRecord[];
  } catch {
    // Corrupt or unreadable file: fail closed by treating as "no authorizations".
    return [];
  }
}

function saveAuthorizations(records: AuthorizationRecord[]): void {
  ensureGreenlightHome();
  fs.writeFileSync(authorizationsFilePath(), JSON.stringify(records, null, 2) + "\n", "utf8");
}

/** Normalizes a target/host for comparison (lowercase, strip scheme/path/port). */
function normalize(target: string): string {
  return extractHost(target).toLowerCase();
}

export function addAuthorization(
  target: string,
  note: string,
  days: number = DEFAULT_VALIDITY_DAYS
): AuthorizationRecord {
  if (!note || !note.trim()) {
    throw new Error(
      "An authorization record requires a --note explaining the basis for authorization (e.g. contract reference, written permission from the owner)."
    );
  }
  const now = new Date();
  const expires = new Date(now.getTime() + days * 24 * 60 * 60 * 1000);
  const record: AuthorizationRecord = {
    target: normalize(target),
    createdAt: now.toISOString(),
    expiresAt: expires.toISOString(),
    note: note.trim(),
    revoked: false,
  };
  const records = loadAuthorizations();
  records.push(record);
  saveAuthorizations(records);
  return record;
}

export function listAuthorizations(): AuthorizationRecord[] {
  return loadAuthorizations();
}

export function revokeAuthorization(target: string): number {
  const norm = normalize(target);
  const records = loadAuthorizations();
  let count = 0;
  for (const r of records) {
    if (r.target === norm && !r.revoked) {
      r.revoked = true;
      r.revokedAt = new Date().toISOString();
      count++;
    }
  }
  if (count > 0) saveAuthorizations(records);
  return count;
}

/** Finds a current (not revoked, not expired) authorization record for a target, if any. */
export function findCurrentAuthorization(target: string): AuthorizationRecord | undefined {
  const norm = normalize(target);
  const now = Date.now();
  return loadAuthorizations().find(
    (r) => r.target === norm && !r.revoked && new Date(r.expiresAt).getTime() > now
  );
}

export interface PromptFn {
  (targetHost: string): Promise<boolean>;
}

/**
 * Default interactive confirmation: asks the operator to type the exact
 * target hostname back, mirroring "type DELETE to confirm" patterns used
 * for other irreversible/high-stakes actions. This is the human-in-the-loop
 * half of the authorization gate; it is intentionally strict (exact match,
 * case-sensitive-insensitive compare) to avoid accidental confirmation.
 */
export function createReadlinePrompt(
  input: NodeJS.ReadableStream = process.stdin,
  output: NodeJS.WritableStream = process.stdout
): PromptFn {
  return async (targetHost: string): Promise<boolean> => {
    const rl = readline.createInterface({ input, output });
    output.write(
      `\nYou are about to scan "${targetHost}", which is not a private/loopback address.\n` +
        `Greenlight only scans systems you own or are explicitly authorized to test.\n` +
        `Type the target hostname exactly ("${targetHost}") to confirm you have authorization: `
    );
    const answer: string = await new Promise((resolve) => {
      rl.question("", (a) => resolve(a));
    });
    rl.close();
    return answer.trim().toLowerCase() === targetHost.trim().toLowerCase();
  };
}

export interface EnsureAuthorizedOptions {
  /** Set when the user passed --authorize on the scan command. */
  authorizeFlag?: boolean;
  /** Injectable for testing / non-interactive use; defaults to a real readline prompt. */
  promptFn?: PromptFn;
}

/**
 * THE AUTHORIZATION GATE.
 *
 * This is the single function every scan MUST pass through before any
 * network probing happens. It fails closed: any target that is not
 * confidently private/loopback, and for which no current authorization
 * record exists, and for which interactive confirmation was not both
 * requested and correctly answered, is REFUSED.
 */
export async function ensureAuthorized(
  target: string,
  options: EnsureAuthorizedOptions = {}
): Promise<AuthorizationDecision> {
  const host = extractHost(target);

  const privacy = await checkPrivacyExemption(target);
  if (privacy.isExempt) {
    return { allowed: true, method: "loopback-exempt", reason: privacy.reason };
  }

  const record = findCurrentAuthorization(target);
  if (record) {
    return { allowed: true, method: "authorization-file", record, reason: "current authorization record found" };
  }

  if (options.authorizeFlag) {
    const prompt = options.promptFn ?? createReadlinePrompt();
    const confirmed = await prompt(host);
    if (confirmed) {
      return {
        allowed: true,
        method: "interactive-prompt",
        reason: "operator interactively confirmed authorization for this run",
      };
    }
    return {
      allowed: false,
      reason: "interactive confirmation failed: typed value did not match the target hostname",
    };
  }

  return {
    allowed: false,
    reason:
      `No current authorization record found for "${host}" and it is not a private/loopback address. ` +
      `Run "greenlight authz add ${host} --note \\"<justification>\\"" first, or re-run with --authorize ` +
      `to confirm interactively.`,
  };
}

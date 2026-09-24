import { Finding, ModuleResult } from "../types.js";
import { simpleGet } from "../utils/httpClient.js";
import { runWithConcurrency } from "../utils/concurrency.js";

export interface ExposureCheckOptions {
  timeoutMs: number;
  concurrency: number;
}

interface ExposurePath {
  path: string;
  describe: (statusCode: number, body: string) => Finding | null;
}

/**
 * Purely read-only GET probes against well-known paths. Every check here
 * only inspects the status code / response body of a normal GET request —
 * nothing is uploaded, modified, or brute-forced.
 */
const PATHS: ExposurePath[] = [
  {
    path: "/.git/config",
    describe: (status, body) => {
      if (status === 200 && /\[core\]/i.test(body)) {
        return {
          module: "exposure",
          severity: "high",
          title: "Exposed .git/config",
          detail:
            "The web root appears to contain an accessible .git directory. This can leak source code, " +
            "commit history, and sometimes credentials/API keys. Remove .git from the deployed web root or " +
            "block access to dotfiles at the web server level.",
        };
      }
      return null;
    },
  },
  {
    path: "/.env",
    describe: (status, body) => {
      if (status === 200 && /[A-Z0-9_]+\s*=\s*.+/.test(body) && body.length < 20_000) {
        return {
          module: "exposure",
          severity: "high",
          title: "Exposed .env file",
          detail:
            "A .env-style file is publicly accessible and looks like KEY=VALUE configuration. These files " +
            "commonly contain database credentials, API keys, and secrets. Move it outside the web root and " +
            "block dotfile access.",
        };
      }
      return null;
    },
  },
  {
    path: "/.well-known/security.txt",
    describe: (status) => {
      if (status === 200) {
        return {
          module: "exposure",
          severity: "info",
          title: "security.txt present",
          detail: "A security.txt file was found, which helps researchers report vulnerabilities responsibly. This is informational, not a finding of risk.",
        };
      }
      return null;
    },
  },
  {
    path: "/",
    describe: (status, body) => {
      if (
        status === 200 &&
        (/<title>\s*index of\s*\//i.test(body) || /<h1>\s*index of\s*\//i.test(body))
      ) {
        return {
          module: "exposure",
          severity: "medium",
          title: "Directory listing enabled",
          detail:
            "The web server returned an auto-generated directory listing instead of an application response, " +
            "which can expose file names/structure that aid an attacker. Disable directory indexing on the web server.",
        };
      }
      return null;
    },
  },
];

export async function runExposureCheck(baseUrl: string, opts: ExposureCheckOptions): Promise<ModuleResult> {
  const start = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  await runWithConcurrency(PATHS, { concurrency: opts.concurrency }, async (entry) => {
    const url = new URL(entry.path, baseUrl).toString();
    try {
      const res = await simpleGet(url, { timeoutMs: opts.timeoutMs, maxBodyBytes: 50_000 });
      const finding = entry.describe(res.statusCode, res.body);
      if (finding) findings.push(finding);
    } catch (err) {
      errors.push(`${entry.path}: ${(err as Error).message}`);
    }
  });

  if (findings.length === 0 && errors.length === PATHS.length) {
    return {
      module: "exposure",
      findings: [],
      error: `Could not complete exposure checks: ${errors[0]}`,
      durationMs: Date.now() - start,
    };
  }

  return { module: "exposure", findings, durationMs: Date.now() - start };
}

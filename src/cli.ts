import { Command } from "commander";
import { runScan, AuthorizationError, ALL_MODULES } from "./scan.js";
import { addAuthorization, listAuthorizations, revokeAuthorization } from "./authz.js";
import { printBanner, printScanReport, exitCodeFor } from "./report.js";
import { parsePortSpec, MAX_PORTS_WITHOUT_OVERRIDE } from "./modules/ports.js";

export function buildProgram(): Command {
  const program = new Command();
  program
    .name("greenlight")
    .description(
      "Authorized-use reconnaissance & misconfiguration scanner for penetration testers. " +
        "Refuses to scan any non-private target without a recorded authorization."
    )
    .version("0.1.0");

  program
    .command("scan")
    .description("Scan a target for common misconfigurations, after checking authorization.")
    .argument("<target>", "hostname, domain, or IP to scan")
    .option("--authorize", "interactively confirm authorization for this run (type the target hostname back)")
    .option("--modules <list>", `comma-separated modules to run (${ALL_MODULES.join(",")})`)
    .option("--ports <spec>", "port list/ranges to check, e.g. \"22,80,443\" or \"1-1024\"")
    .option("--force-wide-scan", "allow port specs wider than " + MAX_PORTS_WITHOUT_OVERRIDE + " ports")
    .option("--port-timeout <ms>", "per-connection TCP timeout in ms", "1000")
    .option("--port-concurrency <n>", "max concurrent port connections (hard-capped at 20)", "20")
    .option("--http-timeout <ms>", "HTTP/TLS request timeout in ms", "5000")
    .option("--scheme <scheme>", "http or https for header/exposure checks", "https")
    .option("--json", "output machine-readable JSON instead of a formatted report")
    .action(async (target: string, options) => {
      printBanner();

      let modules: string[] | undefined;
      if (options.modules) {
        modules = String(options.modules)
          .split(",")
          .map((m: string) => m.trim())
          .filter(Boolean);
        for (const m of modules) {
          if (!ALL_MODULES.includes(m as any)) {
            console.error(`Unknown module "${m}". Valid modules: ${ALL_MODULES.join(", ")}`);
            process.exitCode = 2;
            return;
          }
        }
      }

      let ports: number[] | undefined;
      if (options.ports) {
        try {
          ports = parsePortSpec(String(options.ports));
        } catch (err) {
          console.error(`Invalid --ports value: ${(err as Error).message}`);
          process.exitCode = 2;
          return;
        }
        if (ports.length > MAX_PORTS_WITHOUT_OVERRIDE && !options.forceWideScan) {
          console.error(
            `Refusing to scan ${ports.length} ports without --force-wide-scan (sanity cap is ${MAX_PORTS_WITHOUT_OVERRIDE}). ` +
              `Wide port ranges increase load on the target; pass --force-wide-scan to override.`
          );
          process.exitCode = 2;
          return;
        }
      }

      const portConcurrency = Math.min(20, Math.max(1, Number(options.portConcurrency) || 20));

      try {
        const result = await runScan(target, {
          authorizeFlag: Boolean(options.authorize),
          modules,
          ports,
          portTimeoutMs: Number(options.portTimeout) || 1000,
          portConcurrency,
          httpTimeoutMs: Number(options.httpTimeout) || 5000,
          scheme: options.scheme === "http" ? "http" : "https",
        });

        if (options.json) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          printScanReport(result);
        }
        process.exitCode = exitCodeFor(result);
      } catch (err) {
        if (err instanceof AuthorizationError) {
          console.error(`\nAuthorization refused: ${err.message}\n`);
          process.exitCode = 2;
          return;
        }
        console.error(`\nScan failed: ${(err as Error).message}\n`);
        process.exitCode = 3;
      }
    });

  const authz = program.command("authz").description("Manage local authorization records for scan targets.");

  authz
    .command("add")
    .description("Record authorization to scan a target.")
    .argument("<target>", "hostname, domain, or IP that you are authorized to scan")
    .requiredOption("--note <text>", "justification for authorization (contract reference, written permission, etc.)")
    .option("--days <n>", "number of days the authorization remains current", "30")
    .action((target: string, options) => {
      try {
        const record = addAuthorization(target, options.note, Number(options.days) || 30);
        console.log(`Authorization recorded for "${record.target}" (expires ${record.expiresAt}).`);
      } catch (err) {
        console.error(`Could not add authorization: ${(err as Error).message}`);
        process.exitCode = 2;
      }
    });

  authz
    .command("list")
    .description("List all recorded authorizations.")
    .action(() => {
      const records = listAuthorizations();
      if (records.length === 0) {
        console.log("No authorization records found.");
        return;
      }
      for (const r of records) {
        const now = Date.now();
        const expired = new Date(r.expiresAt).getTime() < now;
        const status = r.revoked ? "REVOKED" : expired ? "EXPIRED" : "CURRENT";
        console.log(`[${status}] ${r.target} — created ${r.createdAt}, expires ${r.expiresAt}`);
        console.log(`         note: ${r.note}`);
      }
    });

  authz
    .command("revoke")
    .description("Revoke authorization for a target.")
    .argument("<target>", "hostname, domain, or IP to revoke")
    .action((target: string) => {
      const count = revokeAuthorization(target);
      if (count === 0) {
        console.log(`No active authorization record found for "${target}".`);
        process.exitCode = 1;
      } else {
        console.log(`Revoked ${count} authorization record(s) for "${target}".`);
      }
    });

  return program;
}

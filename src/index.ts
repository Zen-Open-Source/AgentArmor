import { Command } from "commander";
import { runScan } from "./scanner.js";
import { formatReport, formatJson } from "./utils/report.js";

const program = new Command();

program
  .name("agent-armor")
  .description("Security scanner for AI agents")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan an AI agent installation for security risks")
  .option("--agent <type>", "Agent type to scan (default: auto-detect)")
  .option("--json", "Output results as JSON")
  .option("--verbose", "Show all checks including passing ones")
  .action(async (opts: { agent?: string; json?: boolean; verbose?: boolean }) => {
    try {
      const report = await runScan(opts.agent);

      if (opts.json) {
        console.log(formatJson(report));
      } else {
        console.log(formatReport(report, opts.verbose ?? false));
      }

      // Exit with non-zero if critical issues found
      const criticalFails = report.checks.filter(
        (c) => c.status === "fail" && c.severity === "critical"
      );
      if (criticalFails.length > 0) {
        process.exit(1);
      }
    } catch (err) {
      console.error(
        `Error: ${err instanceof Error ? err.message : String(err)}`
      );
      process.exit(2);
    }
  });

program.parse();

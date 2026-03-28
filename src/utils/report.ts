import chalk from "chalk";
import type { ScanReport, CheckResult, CategorySummary } from "../types.js";

function scoreColor(score: number, max: number): (text: string) => string {
  const pct = (score / max) * 100;
  if (pct >= 80) return chalk.green;
  if (pct >= 60) return chalk.yellow;
  return chalk.red;
}

function statusIcon(status: CheckResult["status"]): string {
  switch (status) {
    case "pass":
      return chalk.green("✓");
    case "warn":
      return chalk.yellow("⚠");
    case "fail":
      return chalk.red("✗");
  }
}

function severityLabel(severity: CheckResult["severity"]): string {
  switch (severity) {
    case "critical":
      return chalk.red.bold("CRITICAL");
    case "high":
      return chalk.red("HIGH");
    case "medium":
      return chalk.yellow("MEDIUM");
    case "low":
      return chalk.dim("LOW");
  }
}

export function formatReport(report: ScanReport, verbose: boolean): string {
  const lines: string[] = [];
  const bar = "━".repeat(50);

  lines.push("");
  lines.push(
    chalk.bold(`  AgentArmor Security Scan — ${report.agent}`)
  );
  lines.push(`  ${chalk.dim(bar)}`);
  lines.push("");

  const colorFn = scoreColor(report.score, report.maxScore);
  lines.push(
    `  Score: ${colorFn(chalk.bold(`${report.score}/${report.maxScore}`))}`
  );
  lines.push("");

  for (const cat of report.categories) {
    const catColor = scoreColor(cat.earned, cat.possible);
    lines.push(
      `  ${chalk.bold(cat.name.padEnd(34))} ${catColor(`${cat.earned}/${cat.possible}`)}`
    );

    const checksToShow = verbose
      ? cat.checks
      : cat.checks.filter((c) => c.status !== "pass");

    for (const check of checksToShow) {
      const icon = statusIcon(check.status);
      const pts = check.status === "pass"
        ? chalk.dim(`${check.earned}/${check.points}`)
        : chalk.red(`${check.earned}/${check.points}`);
      lines.push(`    ${icon} ${check.name.padEnd(36)} ${pts}`);

      if (check.status !== "pass" && check.message) {
        lines.push(`      ${chalk.dim(check.message)}`);
      }
      if (check.status === "fail" && check.fix) {
        lines.push(`      ${chalk.cyan("Fix:")} ${check.fix}`);
      }
    }

    if (checksToShow.length > 0) lines.push("");
  }

  lines.push(`  ${chalk.dim(bar)}`);

  const critical = report.checks.filter(
    (c) => c.status === "fail" && c.severity === "critical"
  ).length;
  const warnings = report.checks.filter((c) => c.status === "warn").length;
  const fails = report.checks.filter((c) => c.status === "fail").length;

  const parts: string[] = [];
  if (critical > 0) parts.push(chalk.red.bold(`${critical} critical`));
  if (fails - critical > 0) parts.push(chalk.red(`${fails - critical} failed`));
  if (warnings > 0) parts.push(chalk.yellow(`${warnings} warnings`));
  if (parts.length === 0) parts.push(chalk.green("All checks passed!"));

  lines.push(`  ${parts.join(", ")}`);
  lines.push("");

  if (!verbose) {
    lines.push(chalk.dim("  Run with --verbose to see all checks"));
  }
  lines.push(chalk.dim("  Run with --json for machine-readable output"));
  lines.push("");

  return lines.join("\n");
}

export function formatJson(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}

import type { AgentPlugin, ScanReport, CategorySummary, CheckResult } from "./types.js";
import { agentRegistry } from "./agents/index.js";

export async function runScan(agentName?: string): Promise<ScanReport> {
  let plugin: AgentPlugin | undefined;

  if (agentName) {
    plugin = agentRegistry[agentName];
    if (!plugin) {
      throw new Error(
        `Unknown agent type: "${agentName}". Available: ${Object.keys(agentRegistry).join(", ")}`
      );
    }
  } else {
    // Auto-detect: try each plugin
    for (const p of Object.values(agentRegistry)) {
      if (await p.detect()) {
        plugin = p;
        break;
      }
    }
    if (!plugin) {
      throw new Error(
        "No supported AI agent detected. Available scanners: " +
          Object.keys(agentRegistry).join(", ")
      );
    }
  }

  const checks = await plugin.scan();
  const categories = buildCategories(checks);
  const score = checks.reduce((sum, c) => sum + c.earned, 0);
  const maxScore = checks.reduce((sum, c) => sum + c.points, 0);

  return {
    agent: plugin.displayName,
    timestamp: new Date().toISOString(),
    score,
    maxScore,
    checks,
    categories,
  };
}

function buildCategories(checks: CheckResult[]): CategorySummary[] {
  const catMap = new Map<string, CheckResult[]>();

  for (const check of checks) {
    const existing = catMap.get(check.category) ?? [];
    existing.push(check);
    catMap.set(check.category, existing);
  }

  return Array.from(catMap.entries()).map(([name, catChecks]) => ({
    name,
    earned: catChecks.reduce((s, c) => s + c.earned, 0),
    possible: catChecks.reduce((s, c) => s + c.points, 0),
    checks: catChecks,
  }));
}

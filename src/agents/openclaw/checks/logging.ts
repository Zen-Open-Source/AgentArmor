import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";
import { join } from "path";
import { checkPermissions } from "../../../utils/file-utils.js";
import { existsSync } from "fs";
import { readdir } from "fs/promises";

export const checkLogging: CheckFn = async (config, basePath) => {
  const results: CheckResult[] = [];

  const redact = getConfigValue(config, "logging.redactSensitive") as string | undefined;
  results.push({
    id: "logging-redaction",
    name: "Sensitive data redaction",
    category: "Logging & Privacy",
    severity: "medium",
    points: 2,
    earned: redact ? 2 : 0,
    status: redact ? "pass" : "warn",
    message: redact
      ? `Redaction enabled: ${redact}`
      : "No redaction configured — tool output may appear in logs",
    fix: 'Set logging.redactSensitive to "tools"',
  });

  // Check transcript directory permissions
  const agentsDir = join(basePath, "agents");
  let transcriptsExposed = false;

  if (existsSync(agentsDir)) {
    try {
      const agents = await readdir(agentsDir, { withFileTypes: true });
      for (const agent of agents) {
        if (!agent.isDirectory()) continue;
        const sessionsDir = join(agentsDir, agent.name, "sessions");
        if (existsSync(sessionsDir)) {
          const perms = await checkPermissions(sessionsDir);
          if (perms.isGroupReadable || perms.isWorldReadable) {
            transcriptsExposed = true;
            break;
          }
        }
      }
    } catch {
      // Ignore errors from missing dirs
    }
  }

  results.push({
    id: "transcript-retention",
    name: "Transcript files protected",
    category: "Logging & Privacy",
    severity: "medium",
    points: 2,
    earned: transcriptsExposed ? 0 : 2,
    status: transcriptsExposed ? "fail" : "pass",
    message: transcriptsExposed
      ? "Session transcripts are group/world readable"
      : "Session transcripts have proper permissions",
    fix: "Ensure ~/.openclaw/agents/*/sessions/ directories are mode 700",
  });

  return results;
};

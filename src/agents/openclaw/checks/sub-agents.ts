import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";

export const checkSubAgents: CheckFn = async (config) => {
  const results: CheckResult[] = [];

  const denyList = getConfigValue(config, "tools.deny") as string[] | undefined;
  const spawnDenied = denyList?.includes("sessions_spawn");

  results.push({
    id: "subagent-spawn-denied",
    name: "Sub-agent spawn restricted",
    category: "Sub-Agents",
    severity: "high",
    points: 0, // Points already counted in tool-authorization
    earned: 0,
    status: spawnDenied ? "pass" : "warn",
    message: spawnDenied
      ? "sessions_spawn is denied — agents cannot spawn sub-agents"
      : "sessions_spawn is not denied — agents can spawn sub-agents",
    fix: "Add sessions_spawn to tools.deny",
  });

  return results;
};

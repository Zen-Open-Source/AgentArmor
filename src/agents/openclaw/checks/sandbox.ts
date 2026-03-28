import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";

const DANGEROUS_DOCKER_FLAGS = [
  "agents.defaults.sandbox.docker.dangerouslyAllowReservedContainerTargets",
  "agents.defaults.sandbox.docker.dangerouslyAllowExternalBindSources",
  "agents.defaults.sandbox.docker.dangerouslyAllowContainerNamespaceJoin",
];

export const checkSandbox: CheckFn = async (config) => {
  const results: CheckResult[] = [];

  const mode = getConfigValue(config, "agents.defaults.sandbox.mode") as string | undefined;
  const isAll = mode === "all";
  results.push({
    id: "sandbox-enabled",
    name: "Sandbox mode enabled",
    category: "Sandboxing",
    severity: "critical",
    points: 4,
    earned: isAll ? 4 : 0,
    status: isAll ? "pass" : "fail",
    message: isAll
      ? "All tools run in Docker sandbox"
      : `Sandbox mode: ${mode ?? "off"} — tools run on host`,
    fix: 'Set agents.defaults.sandbox.mode to "all"',
  });

  const scope = getConfigValue(config, "agents.defaults.sandbox.scope") as string | undefined;
  const goodScope = !scope || scope === "agent" || scope === "session";
  results.push({
    id: "sandbox-scope",
    name: "Sandbox scope (per-agent/session)",
    category: "Sandboxing",
    severity: "high",
    points: 3,
    earned: goodScope ? 3 : 0,
    status: goodScope ? "pass" : "warn",
    message: `Sandbox scope: ${scope ?? "agent (default)"}`,
    fix: 'Set agents.defaults.sandbox.scope to "agent" or "session"',
  });

  // Check dangerous Docker flags
  const dangerousSet: string[] = [];
  for (const flag of DANGEROUS_DOCKER_FLAGS) {
    if (getConfigValue(config, flag) === true) {
      dangerousSet.push(flag.split(".").pop()!);
    }
  }

  results.push({
    id: "sandbox-dangerous-flags",
    name: "No dangerous Docker flags",
    category: "Sandboxing",
    severity: "high",
    points: 3,
    earned: dangerousSet.length === 0 ? 3 : 0,
    status: dangerousSet.length === 0 ? "pass" : "fail",
    message:
      dangerousSet.length === 0
        ? "No dangerous Docker sandbox flags enabled"
        : `Dangerous flags enabled: ${dangerousSet.join(", ")}`,
    fix: "Disable all dangerously* Docker flags in agents.defaults.sandbox.docker",
  });

  return results;
};

import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";

const DANGEROUS_TOOLS = ["gateway", "cron", "sessions_spawn", "sessions_send"];

export const checkToolAuth: CheckFn = async (config) => {
  const results: CheckResult[] = [];

  // Check 1: Dangerous tools denied
  const denyList = getConfigValue(config, "tools.deny") as string[] | undefined;
  const deniedTools = DANGEROUS_TOOLS.filter((t) => denyList?.includes(t));
  const allDenied = deniedTools.length === DANGEROUS_TOOLS.length;
  const someDenied = deniedTools.length > 0;

  results.push({
    id: "tools-deny-dangerous",
    name: "Dangerous tools denied",
    category: "Tool Authorization",
    severity: "critical",
    points: 5,
    earned: allDenied ? 5 : someDenied ? 2 : 0,
    status: allDenied ? "pass" : someDenied ? "warn" : "fail",
    message: allDenied
      ? "All control-plane tools (gateway, cron, sessions_spawn, sessions_send) are denied"
      : `Missing from deny list: ${DANGEROUS_TOOLS.filter((t) => !denyList?.includes(t)).join(", ")}`,
    fix: `Add to tools.deny: ${JSON.stringify(DANGEROUS_TOOLS)}`,
  });

  // Check 2: Elevated tools disabled
  const elevatedEnabled = getConfigValue(config, "tools.elevated.enabled") as boolean | undefined;
  results.push({
    id: "elevated-disabled",
    name: "Elevated tools disabled",
    category: "Tool Authorization",
    severity: "high",
    points: 3,
    earned: elevatedEnabled === true ? 0 : 3,
    status: elevatedEnabled === true ? "fail" : "pass",
    message: elevatedEnabled === true
      ? "Elevated tools (camera, screen, contacts, calendar, SMS) are enabled"
      : "Elevated tools are disabled",
    fix: "Set tools.elevated.enabled to false",
  });

  // Check 3: Tool profile
  const profile = getConfigValue(config, "tools.profile") as string | undefined;
  const restrictive = profile === "messaging" || profile === "readonly";
  results.push({
    id: "tool-profile",
    name: "Restrictive tool profile",
    category: "Tool Authorization",
    severity: "medium",
    points: 2,
    earned: restrictive ? 2 : profile ? 1 : 0,
    status: restrictive ? "pass" : "warn",
    message: profile
      ? `Tool profile: ${profile}`
      : "No tool profile set (using defaults)",
    fix: 'Set tools.profile to "messaging" for a restricted baseline',
  });

  return results;
};

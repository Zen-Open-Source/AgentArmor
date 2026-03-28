import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";

export const checkBrowserSecurity: CheckFn = async (config) => {
  const results: CheckResult[] = [];

  const ssrfAllow = getConfigValue(config, "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork") as boolean | undefined;
  results.push({
    id: "browser-ssrf",
    name: "SSRF private network blocked",
    category: "Browser Security",
    severity: "high",
    points: 3,
    earned: ssrfAllow === false ? 3 : 0,
    status: ssrfAllow === false ? "pass" : "warn",
    message: ssrfAllow === false
      ? "Browser SSRF policy blocks private network access"
      : "Browser may access private/internal network destinations (default allows it)",
    fix: "Set browser.ssrfPolicy.dangerouslyAllowPrivateNetwork to false",
  });

  // Check for browser mode
  const browserMode = getConfigValue(config, "gateway.nodes.browser.mode") as string | undefined;
  const isOff = browserMode === "off";
  results.push({
    id: "browser-profile",
    name: "Browser control restricted",
    category: "Browser Security",
    severity: "medium",
    points: 3,
    earned: isOff ? 3 : browserMode ? 1 : 2,
    status: isOff ? "pass" : "warn",
    message: isOff
      ? "Browser proxy routing is disabled"
      : browserMode
        ? `Browser mode: ${browserMode} — ensure dedicated profile is used`
        : "Browser mode not explicitly configured — use dedicated agent profile",
    fix: 'Set gateway.nodes.browser.mode to "off" if not needed, or use a dedicated browser profile',
  });

  return results;
};

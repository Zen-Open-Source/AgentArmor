import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";

export const checkNetwork: CheckFn = async (config) => {
  const results: CheckResult[] = [];

  const bind = getConfigValue(config, "gateway.bind") as string | undefined;
  const isLoopback = !bind || bind === "loopback";
  const isTailnet = bind === "tailnet";
  const isLan = bind === "lan";

  // Check 1: Bind to loopback
  results.push({
    id: "bind-loopback",
    name: "Gateway binds to loopback",
    category: "Network Exposure",
    severity: "critical",
    points: 6,
    earned: isLoopback ? 6 : isTailnet ? 4 : 0,
    status: isLoopback ? "pass" : isTailnet ? "warn" : "fail",
    message: isLoopback
      ? "Gateway bound to localhost only"
      : `Gateway bound to: ${bind}`,
    fix: 'Set gateway.bind to "loopback" in openclaw.json',
  });

  // Check 2: Not exposed on 0.0.0.0
  const mode = getConfigValue(config, "gateway.mode") as string | undefined;
  const isCustomWide = bind === "custom";
  results.push({
    id: "port-not-exposed",
    name: "Port not publicly exposed",
    category: "Network Exposure",
    severity: "high",
    points: 3,
    earned: !isCustomWide && !isLan ? 3 : 0,
    status: !isCustomWide && !isLan ? "pass" : "fail",
    message:
      isCustomWide || isLan
        ? `Gateway may be exposed on network (bind: ${bind})`
        : "Gateway not exposed beyond loopback/tailnet",
    fix: "Use loopback binding or Tailscale Serve instead of LAN bind",
  });

  // Check 3: Tailscale preferred over LAN
  results.push({
    id: "tailscale-pref",
    name: "Tailscale preferred over LAN",
    category: "Network Exposure",
    severity: "medium",
    points: 3,
    earned: isLoopback || isTailnet ? 3 : 0,
    status: isLoopback || isTailnet ? "pass" : isLan ? "warn" : "fail",
    message: isLoopback
      ? "Loopback is ideal (no remote exposure)"
      : isTailnet
        ? "Tailscale provides encrypted network access"
        : "LAN binding is less secure than Tailscale Serve",
    fix: 'Use gateway.bind: "tailnet" or Tailscale Serve instead of LAN',
  });

  return results;
};

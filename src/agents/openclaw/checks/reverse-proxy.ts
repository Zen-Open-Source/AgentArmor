import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";

export const checkReverseProxy: CheckFn = async (config) => {
  const results: CheckResult[] = [];

  const trustedProxies = getConfigValue(config, "gateway.trustedProxies") as string[] | undefined;
  const allowRealIpFallback = getConfigValue(config, "gateway.allowRealIpFallback") as boolean | undefined;
  const bind = getConfigValue(config, "gateway.bind") as string | undefined;

  // Only relevant if not loopback-only
  const isLoopback = !bind || bind === "loopback";

  if (!isLoopback) {
    results.push({
      id: "reverse-proxy-config",
      name: "Reverse proxy configured safely",
      category: "Reverse Proxy",
      severity: "high",
      points: 0, // Informational when not loopback
      earned: 0,
      status:
        trustedProxies && allowRealIpFallback === false ? "pass" : "warn",
      message:
        trustedProxies && allowRealIpFallback === false
          ? `Trusted proxies: ${trustedProxies.join(", ")}, real IP fallback disabled`
          : "When using a reverse proxy, set gateway.trustedProxies and disable allowRealIpFallback",
      fix: "Set gateway.trustedProxies to proxy IPs and gateway.allowRealIpFallback to false",
    });
  }

  return results;
};

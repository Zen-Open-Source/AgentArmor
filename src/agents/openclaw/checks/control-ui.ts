import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";

export const checkControlUi: CheckFn = async (config) => {
  const results: CheckResult[] = [];

  const origins = getConfigValue(config, "gateway.controlUi.allowedOrigins") as string[] | undefined;
  const isWildcard = origins?.includes("*");
  results.push({
    id: "control-ui-origins",
    name: "Control UI origin allowlist",
    category: "Control UI",
    severity: "high",
    points: 1,
    earned: isWildcard ? 0 : 1,
    status: isWildcard ? "fail" : "pass",
    message: isWildcard
      ? 'Control UI allows all origins ("*") — vulnerable to cross-origin attacks'
      : origins
        ? `Control UI origins restricted to: ${origins.join(", ")}`
        : "Control UI origins not explicitly set (default is secure for loopback)",
    fix: "Set gateway.controlUi.allowedOrigins to specific trusted origins",
  });

  const disableDeviceAuth = getConfigValue(
    config,
    "gateway.controlUi.dangerouslyDisableDeviceAuth"
  ) as boolean | undefined;
  results.push({
    id: "control-ui-device-auth",
    name: "Device auth enabled",
    category: "Control UI",
    severity: "high",
    points: 1,
    earned: disableDeviceAuth === true ? 0 : 1,
    status: disableDeviceAuth === true ? "fail" : "pass",
    message: disableDeviceAuth === true
      ? "Device identity checks are disabled — severe security downgrade"
      : "Device auth is enabled",
    fix: "Remove gateway.controlUi.dangerouslyDisableDeviceAuth",
  });

  return results;
};

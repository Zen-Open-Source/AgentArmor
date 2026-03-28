import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";

export const checkMdns: CheckFn = async (config) => {
  const mode = getConfigValue(config, "discovery.mdns.mode") as string | undefined;
  const isMinimal = mode === "minimal";
  const isOff = mode === "off";
  const secure = isMinimal || isOff;

  return [
    {
      id: "mdns-minimal",
      name: "mDNS discovery restricted",
      category: "mDNS/Discovery",
      severity: "low",
      points: 2,
      earned: secure ? 2 : 0,
      status: secure ? "pass" : "warn",
      message: secure
        ? `mDNS mode: ${mode}`
        : `mDNS mode: ${mode ?? "full (default)"} — broadcasts install path and SSH port`,
      fix: 'Set discovery.mdns.mode to "minimal" or "off"',
    },
  ];
};

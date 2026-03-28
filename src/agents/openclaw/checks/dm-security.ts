import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";

export const checkDmSecurity: CheckFn = async (config) => {
  const results: CheckResult[] = [];

  // Check DM policies across all channels
  const channels = getConfigValue(config, "channels") as Record<string, unknown> | undefined;
  let worstPolicy: string = "pairing"; // default is pairing

  if (channels) {
    for (const [, channelConfig] of Object.entries(channels)) {
      if (typeof channelConfig === "object" && channelConfig !== null) {
        const policy = (channelConfig as Record<string, unknown>).dmPolicy as string | undefined;
        if (policy === "open") worstPolicy = "open";
        else if (policy === "disabled") continue;
      }
    }
  }

  const isOpen = worstPolicy === "open";
  results.push({
    id: "dm-policy",
    name: "DM policy (pairing/allowlist)",
    category: "DM Security",
    severity: "critical",
    points: 5,
    earned: isOpen ? 0 : 5,
    status: isOpen ? "fail" : "pass",
    message: isOpen
      ? 'At least one channel has dmPolicy "open" — anyone can message the agent'
      : "DM policy uses pairing or allowlist",
    fix: 'Set dmPolicy to "pairing" or "allowlist" for all channels',
  });

  // Check DM scope isolation
  const dmScope = getConfigValue(config, "session.dmScope") as string | undefined;
  const isIsolated = dmScope === "per-channel-peer" || dmScope === "per-account-channel-peer";
  results.push({
    id: "dm-scope",
    name: "DM session isolation",
    category: "DM Security",
    severity: "medium",
    points: 3,
    earned: isIsolated ? 3 : 0,
    status: isIsolated ? "pass" : "warn",
    message: isIsolated
      ? `DM scope: ${dmScope} (isolated per sender)`
      : `DM scope: ${dmScope ?? "main"} (shared session — less isolated)`,
    fix: 'Set session.dmScope to "per-channel-peer" for sender isolation',
  });

  return results;
};

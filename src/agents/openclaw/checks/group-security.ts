import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";

export const checkGroupSecurity: CheckFn = async (config) => {
  const results: CheckResult[] = [];

  // Check requireMention across channels
  const channels = getConfigValue(config, "channels") as Record<string, unknown> | undefined;
  let mentionRequired = false;
  let hasOpenGroupPolicy = false;

  if (channels) {
    for (const [, channelConfig] of Object.entries(channels)) {
      if (typeof channelConfig !== "object" || channelConfig === null) continue;
      const groups = (channelConfig as Record<string, unknown>).groups as Record<string, unknown> | undefined;
      if (groups) {
        const wildcard = groups["*"] as Record<string, unknown> | undefined;
        if (wildcard?.requireMention === true) mentionRequired = true;
      }
      const groupPolicy = (channelConfig as Record<string, unknown>).groupPolicy as string | undefined;
      if (groupPolicy === "open") hasOpenGroupPolicy = true;
    }
  }

  results.push({
    id: "group-require-mention",
    name: "Groups require mention",
    category: "Group Security",
    severity: "high",
    points: 3,
    earned: mentionRequired ? 3 : 0,
    status: mentionRequired ? "pass" : "warn",
    message: mentionRequired
      ? "Groups require @mention to trigger bot"
      : "No requireMention configured — bot responds to all group messages",
    fix: 'Set channels.<channel>.groups["*"].requireMention: true',
  });

  results.push({
    id: "group-policy",
    name: "Group policy not open",
    category: "Group Security",
    severity: "high",
    points: 3,
    earned: hasOpenGroupPolicy ? 0 : 3,
    status: hasOpenGroupPolicy ? "fail" : "pass",
    message: hasOpenGroupPolicy
      ? "At least one channel has open group policy — anyone can trigger tools"
      : "No open group policies detected",
    fix: 'Set groupPolicy to "pairing" or "allowlist"',
  });

  return results;
};

import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";

export const checkPromptInjection: CheckFn = async (config) => {
  const results: CheckResult[] = [];

  // Check for unsafe external content flags
  const hooksUnsafe = getConfigValue(config, "hooks.gmail.allowUnsafeExternalContent") as boolean | undefined;
  const cronPayloads = getConfigValue(config, "cron") as unknown;
  let cronUnsafe = false;

  if (Array.isArray(cronPayloads)) {
    for (const job of cronPayloads) {
      if (typeof job === "object" && job !== null) {
        if ((job as Record<string, unknown>).allowUnsafeExternalContent === true) {
          cronUnsafe = true;
          break;
        }
      }
    }
  }

  const anyUnsafe = hooksUnsafe === true || cronUnsafe;

  results.push({
    id: "no-unsafe-content-flags",
    name: "Unsafe content flags disabled",
    category: "Prompt Injection",
    severity: "high",
    points: 0, // Points counted in dangerous-flags
    earned: 0,
    status: anyUnsafe ? "fail" : "pass",
    message: anyUnsafe
      ? "Unsafe external content flags are enabled — increases prompt injection risk"
      : "No unsafe external content bypass flags detected",
    fix: "Disable all allowUnsafeExternalContent flags",
  });

  return results;
};

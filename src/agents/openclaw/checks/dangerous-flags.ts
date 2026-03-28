import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";

const DANGEROUS_FLAGS = [
  { path: "gateway.controlUi.allowInsecureAuth", name: "allowInsecureAuth" },
  { path: "gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback", name: "dangerouslyAllowHostHeaderOriginFallback" },
  { path: "gateway.controlUi.dangerouslyDisableDeviceAuth", name: "dangerouslyDisableDeviceAuth" },
  { path: "hooks.gmail.allowUnsafeExternalContent", name: "gmail allowUnsafeExternalContent" },
  { path: "tools.exec.applyPatch.workspaceOnly", name: "applyPatch.workspaceOnly", expectTrue: true },
];

export const checkDangerousFlags: CheckFn = async (config) => {
  const flagged: string[] = [];

  for (const flag of DANGEROUS_FLAGS) {
    const val = getConfigValue(config, flag.path);
    if (flag.expectTrue && val === false) {
      flagged.push(flag.name);
    } else if (!flag.expectTrue && val === true) {
      flagged.push(flag.name);
    }
  }

  // Also check for hooks mappings with allowUnsafeExternalContent
  const hookMappings = getConfigValue(config, "hooks.mappings") as unknown[] | undefined;
  if (Array.isArray(hookMappings)) {
    for (const mapping of hookMappings) {
      if (typeof mapping === "object" && mapping !== null) {
        if ((mapping as Record<string, unknown>).allowUnsafeExternalContent === true) {
          flagged.push("hooks.mappings allowUnsafeExternalContent");
          break;
        }
      }
    }
  }

  return [
    {
      id: "no-insecure-flags",
      name: "No dangerous config flags",
      category: "Dangerous Flags",
      severity: "critical",
      points: 6,
      earned: flagged.length === 0 ? 6 : 0,
      status: flagged.length === 0 ? "pass" : "fail",
      message:
        flagged.length === 0
          ? "No dangerous/insecure config flags detected"
          : `Dangerous flags enabled: ${flagged.join(", ")}`,
      fix: "Disable all dangerous flags flagged by openclaw security audit",
    },
  ];
};

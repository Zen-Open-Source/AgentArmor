import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";

export const checkPlugins: CheckFn = async (config) => {
  const allow = getConfigValue(config, "plugins.allow") as string[] | undefined;

  return [
    {
      id: "plugins-allowlist",
      name: "Plugin allowlist configured",
      category: "Plugins",
      severity: "medium",
      points: 2,
      earned: Array.isArray(allow) ? 2 : 0,
      status: Array.isArray(allow) ? "pass" : "warn",
      message: Array.isArray(allow)
        ? `Plugin allowlist: ${allow.length} plugin(s) explicitly allowed`
        : "No explicit plugin allowlist — any installed plugin can load",
      fix: "Set plugins.allow to an explicit list of trusted plugin IDs",
    },
  ];
};

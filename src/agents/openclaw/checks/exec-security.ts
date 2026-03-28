import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";

export const checkExecSecurity: CheckFn = async (config) => {
  const results: CheckResult[] = [];

  const execSecurity = getConfigValue(config, "tools.exec.security") as string | undefined;
  const isDeny = !execSecurity || execSecurity === "deny";

  results.push({
    id: "exec-deny",
    name: "Exec tool denied",
    category: "Exec Security",
    severity: "critical",
    points: 5,
    earned: isDeny ? 5 : 0,
    status: isDeny ? "pass" : "fail",
    message: isDeny
      ? "Shell execution is denied by default"
      : `Exec security: ${execSecurity} — shell execution is permitted`,
    fix: 'Set tools.exec.security to "deny"',
  });

  const execAsk = getConfigValue(config, "tools.exec.ask") as string | undefined;
  results.push({
    id: "exec-ask-always",
    name: "Exec requires approval",
    category: "Exec Security",
    severity: "high",
    points: 3,
    earned: execAsk === "always" || isDeny ? 3 : 0,
    status: execAsk === "always" || isDeny ? "pass" : "fail",
    message: isDeny
      ? "Exec is denied (approval not needed)"
      : execAsk === "always"
        ? "Each execution requires explicit approval"
        : "Exec does not require per-command approval",
    fix: 'Set tools.exec.ask to "always"',
  });

  const strictInline = getConfigValue(config, "tools.exec.strictInlineEval") as boolean | undefined;
  const safeBins = getConfigValue(config, "tools.exec.safeBins") as string[] | undefined;
  const hasInterpreters = safeBins?.some((b) =>
    ["python", "node", "ruby", "perl", "php", "lua", "osascript"].includes(b)
  );

  results.push({
    id: "strict-inline-eval",
    name: "Strict inline eval",
    category: "Exec Security",
    severity: "medium",
    points: 2,
    earned: isDeny ? 2 : hasInterpreters && !strictInline ? 0 : 2,
    status: isDeny
      ? "pass"
      : hasInterpreters && !strictInline
        ? "fail"
        : "pass",
    message: isDeny
      ? "Exec is denied (inline eval moot)"
      : hasInterpreters && !strictInline
        ? "Interpreters in safeBins but strictInlineEval is not enabled"
        : "Strict inline eval configured appropriately",
    fix: "Enable tools.exec.strictInlineEval when allowlisting interpreters",
  });

  return results;
};

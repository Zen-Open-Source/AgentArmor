import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";

export const checkAuth: CheckFn = async (config) => {
  const results: CheckResult[] = [];

  // Check 1: Auth mode is configured
  const authMode = getConfigValue(config, "gateway.auth.mode") as string | undefined;
  results.push({
    id: "auth-enabled",
    name: "Gateway auth enabled",
    category: "Authentication",
    severity: "critical",
    points: 4,
    earned: authMode ? 4 : 0,
    status: authMode ? "pass" : "fail",
    message: authMode
      ? `Auth mode: ${authMode}`
      : "No gateway authentication configured — connections are unprotected",
    fix: 'Set gateway.auth.mode to "token" in openclaw.json',
  });

  // Check 2: Token mode (recommended)
  const isToken = authMode === "token";
  const isPassword = authMode === "password";
  results.push({
    id: "auth-mode-token",
    name: "Token auth mode (recommended)",
    category: "Authentication",
    severity: "medium",
    points: 4,
    earned: isToken ? 4 : isPassword ? 2 : 0,
    status: isToken ? "pass" : isPassword ? "warn" : "fail",
    message: isToken
      ? "Using recommended token auth"
      : isPassword
        ? "Password auth is acceptable but token auth is preferred"
        : "Auth mode is not set to token or password",
    fix: 'Set gateway.auth.mode to "token" and generate a token with: openclaw doctor --generate-gateway-token',
  });

  // Check 3: Token strength
  const token = getConfigValue(config, "gateway.auth.token") as string | undefined;
  const tokenLen = token?.length ?? 0;
  const strongToken = tokenLen >= 32;
  results.push({
    id: "auth-token-strength",
    name: "Auth token strength",
    category: "Authentication",
    severity: "high",
    points: 4,
    earned: strongToken ? 4 : tokenLen >= 16 ? 2 : 0,
    status: strongToken ? "pass" : tokenLen >= 16 ? "warn" : "fail",
    message: token
      ? `Token length: ${tokenLen} chars${strongToken ? "" : " (minimum 32 recommended)"}`
      : "No token configured",
    fix: "Generate a strong token: openclaw doctor --generate-gateway-token",
  });

  return results;
};

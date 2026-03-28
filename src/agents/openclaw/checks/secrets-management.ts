import { existsSync } from "fs";
import { readFile, readdir } from "fs/promises";
import { join } from "path";
import type { CheckResult, CheckFn } from "../../../types.js";
import { getConfigValue } from "../../../utils/config-reader.js";
import { checkPermissions } from "../../../utils/file-utils.js";

// Patterns that suggest plaintext secrets in config values
const SECRET_PATTERNS: { pattern: RegExp; label: string }[] = [
  { pattern: /^sk-[A-Za-z0-9]{20,}/, label: "OpenAI/Anthropic API key" },
  { pattern: /^xoxb-[0-9]+-[A-Za-z0-9]+/, label: "Slack bot token" },
  { pattern: /^xoxp-[0-9]+-[A-Za-z0-9]+/, label: "Slack user token" },
  { pattern: /^ghp_[A-Za-z0-9]{36}/, label: "GitHub personal access token" },
  { pattern: /^ghs_[A-Za-z0-9]{36}/, label: "GitHub app token" },
  { pattern: /^AIza[A-Za-z0-9_-]{35}/, label: "Google API key" },
  { pattern: /^AKIA[A-Z0-9]{16}$/, label: "AWS access key" },
  { pattern: /^[0-9]{9,10}:[A-Za-z0-9_-]{35}/, label: "Telegram bot token" },
  { pattern: /^Bot [A-Za-z0-9_.-]{59}/, label: "Discord bot token" },
  { pattern: /^[A-Za-z0-9]{32,}$/, label: "Possible hardcoded secret (32+ char string)" },
];

/** Recursively collect all string values from a config object with their paths */
function collectStringValues(
  obj: unknown,
  path = ""
): { path: string; value: string }[] {
  const results: { path: string; value: string }[] = [];

  if (typeof obj === "string") {
    results.push({ path, value: obj });
  } else if (Array.isArray(obj)) {
    obj.forEach((item, i) => {
      results.push(...collectStringValues(item, `${path}[${i}]`));
    });
  } else if (typeof obj === "object" && obj !== null) {
    for (const [key, val] of Object.entries(obj as Record<string, unknown>)) {
      // Skip known non-secret fields
      if (["mode", "bind", "profile", "scope", "workspaceAccess", "dmPolicy",
           "groupPolicy", "dmScope", "mdns", "redactSensitive"].includes(key)) continue;
      results.push(...collectStringValues(val, path ? `${path}.${key}` : key));
    }
  }

  return results;
}

/** Find agent auth-profile files */
async function findAuthProfiles(basePath: string): Promise<string[]> {
  const agentsDir = join(basePath, "agents");
  const profiles: string[] = [];

  if (!existsSync(agentsDir)) return profiles;

  const agents = await readdir(agentsDir, { withFileTypes: true });
  for (const agent of agents) {
    if (!agent.isDirectory()) continue;
    const profilePath = join(agentsDir, agent.name, "agent", "auth-profiles.json");
    if (existsSync(profilePath)) profiles.push(profilePath);
  }

  return profiles;
}

export const checkSecretsManagement: CheckFn = async (config, basePath) => {
  const results: CheckResult[] = [];

  // Check 1: secrets.json file permissions
  const secretsPath = join(basePath, "secrets.json");
  const secretsPerms = await checkPermissions(secretsPath);
  results.push({
    id: "secrets-file-perms",
    name: "secrets.json permissions",
    category: "Secrets Management",
    severity: "high",
    points: 2,
    earned: !secretsPerms.exists ? 2 : secretsPerms.isOwnerOnly ? 2 : 0,
    status: !secretsPerms.exists ? "pass" : secretsPerms.isOwnerOnly ? "pass" : "fail",
    message: !secretsPerms.exists
      ? "No secrets.json file found"
      : secretsPerms.isOwnerOnly
        ? `secrets.json permissions: ${secretsPerms.mode} (secure)`
        : `secrets.json permissions: ${secretsPerms.mode} — group/world readable`,
    fix: "chmod 600 ~/.openclaw/secrets.json",
  });

  // Check 2: Auth profile file permissions
  const authProfiles = await findAuthProfiles(basePath);
  const insecureProfiles: string[] = [];

  for (const p of authProfiles) {
    const perms = await checkPermissions(p);
    if (!perms.isOwnerOnly) insecureProfiles.push(p);
  }

  results.push({
    id: "auth-profiles-perms",
    name: "Auth profile file permissions",
    category: "Secrets Management",
    severity: "high",
    points: 2,
    earned: authProfiles.length === 0 ? 2 : insecureProfiles.length === 0 ? 2 : 0,
    status: authProfiles.length === 0 ? "pass" : insecureProfiles.length === 0 ? "pass" : "fail",
    message:
      authProfiles.length === 0
        ? "No auth profile files found"
        : insecureProfiles.length === 0
          ? `All ${authProfiles.length} auth profile(s) have proper permissions`
          : `${insecureProfiles.length} auth profile(s) are group/world readable`,
    fix: "chmod 600 ~/.openclaw/agents/*/agent/auth-profiles.json",
  });

  // Check 3: Password not hardcoded in config
  const hardcodedPassword = getConfigValue(config, "gateway.auth.password") as string | undefined;
  results.push({
    id: "password-not-hardcoded",
    name: "Password not hardcoded in config",
    category: "Secrets Management",
    severity: "critical",
    points: 3,
    earned: hardcodedPassword ? 0 : 3,
    status: hardcodedPassword ? "fail" : "pass",
    message: hardcodedPassword
      ? "Gateway password is hardcoded in openclaw.json"
      : "No hardcoded password in config",
    fix: "Use OPENCLAW_GATEWAY_PASSWORD environment variable instead of hardcoding in config",
  });

  // Check 4: Scan config string values for secret patterns
  const stringValues = collectStringValues(config);
  const secretsFound: string[] = [];

  for (const { path: valPath, value } of stringValues) {
    // Skip env var references and short values
    if (value.startsWith("${") || value.length < 16) continue;
    // Skip the gateway token (already handled by auth strength check)
    if (valPath === "gateway.auth.token") continue;

    for (const { pattern, label } of SECRET_PATTERNS) {
      // Only flag the last pattern (32+ char strings) for known sensitive paths
      if (label.includes("Possible hardcoded secret")) {
        const sensitiveKeys = ["token", "secret", "key", "password", "apiKey", "api_key"];
        const isInSensitivePath = sensitiveKeys.some((k) =>
          valPath.toLowerCase().includes(k)
        );
        if (!isInSensitivePath) continue;
      }

      if (pattern.test(value)) {
        secretsFound.push(`${label} at ${valPath}`);
        break;
      }
    }
  }

  // Also scan raw config file for patterns not caught by JSON parsing
  let rawConfigSecrets = false;
  try {
    const raw = await readFile(join(basePath, "openclaw.json"), "utf-8");
    for (const { pattern, label } of SECRET_PATTERNS.slice(0, -1)) {
      if (pattern.test(raw)) {
        secretsFound.push(`${label} (raw config scan)`);
        rawConfigSecrets = true;
        break;
      }
    }
  } catch {
    // Config may not exist
  }

  results.push({
    id: "no-plaintext-secrets",
    name: "No plaintext secrets in config",
    category: "Secrets Management",
    severity: "critical",
    points: 3,
    earned: secretsFound.length === 0 ? 3 : 0,
    status: secretsFound.length === 0 ? "pass" : "fail",
    message:
      secretsFound.length === 0
        ? "No plaintext API keys or tokens detected in config"
        : `Potential secrets found: ${secretsFound.join("; ")}`,
    fix: "Move secrets to environment variables or ~/.openclaw/secrets.json (chmod 600)",
  });

  // Check 5: secrets.json not inside an agent workspace
  const agentWorkspaces = collectAgentWorkspacePaths(config, basePath);
  let secretsInWorkspace = false;

  if (secretsPerms.exists) {
    for (const wsPath of agentWorkspaces) {
      if (secretsPath.startsWith(wsPath)) {
        secretsInWorkspace = true;
        break;
      }
    }
  }

  results.push({
    id: "secrets-not-in-workspace",
    name: "Secrets not in agent workspace",
    category: "Secrets Management",
    severity: "high",
    points: 2,
    earned: secretsInWorkspace ? 0 : 2,
    status: secretsInWorkspace ? "fail" : "pass",
    message: secretsInWorkspace
      ? "secrets.json is located inside an agent workspace — agent can read it"
      : "secrets.json is not inside any agent workspace",
    fix: "Keep secrets.json at ~/.openclaw/secrets.json, not inside agent workspace directories",
  });

  return results;
};

function collectAgentWorkspacePaths(
  config: Record<string, unknown>,
  basePath: string
): string[] {
  const paths: string[] = [];
  const agents = getConfigValue(config, "agents.list") as unknown[] | undefined;

  if (Array.isArray(agents)) {
    for (const agent of agents) {
      if (typeof agent === "object" && agent !== null) {
        const ws = (agent as Record<string, unknown>).workspace as string | undefined;
        if (ws) paths.push(ws.replace("~", process.env.HOME ?? ""));
      }
    }
  }

  // Default workspace location
  paths.push(join(basePath, "workspace"));

  return paths;
}

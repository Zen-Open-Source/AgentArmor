import { join } from "path";
import type { CheckResult, CheckFn } from "../../../types.js";
import { checkPermissions, findCredentialFiles } from "../../../utils/file-utils.js";

export const checkFilePermissions: CheckFn = async (_config, basePath) => {
  const results: CheckResult[] = [];

  // Check 1: ~/.openclaw directory is 700
  const dirPerms = await checkPermissions(basePath);
  const dirCorrect = dirPerms.exists && dirPerms.isOwnerOnly;
  results.push({
    id: "dir-perms",
    name: "~/.openclaw directory permissions",
    category: "File Permissions",
    severity: "critical",
    points: 4,
    earned: dirCorrect ? 4 : 0,
    status: dirCorrect ? "pass" : "fail",
    message: dirPerms.exists
      ? `Directory mode: ${dirPerms.mode} (expected: 700)`
      : "Directory does not exist",
    fix: "chmod 700 ~/.openclaw",
  });

  // Check 2: openclaw.json is 600
  const configPerms = await checkPermissions(join(basePath, "openclaw.json"));
  const configCorrect = configPerms.exists && configPerms.isOwnerOnly;
  results.push({
    id: "config-perms",
    name: "Config file permissions",
    category: "File Permissions",
    severity: "high",
    points: 3,
    earned: !configPerms.exists ? 3 : configCorrect ? 3 : 0,
    status: !configPerms.exists ? "pass" : configCorrect ? "pass" : "fail",
    message: configPerms.exists
      ? `Config mode: ${configPerms.mode} (expected: 600)`
      : "Config file not found (no exposure risk)",
    fix: "chmod 600 ~/.openclaw/openclaw.json",
  });

  // Check 3: Credential files not group/world readable
  const credFiles = await findCredentialFiles(basePath);
  let allCredsSecure = true;
  const insecureCreds: string[] = [];

  for (const credPath of credFiles) {
    const perms = await checkPermissions(credPath);
    if (perms.isGroupReadable || perms.isWorldReadable) {
      allCredsSecure = false;
      insecureCreds.push(credPath);
    }
  }

  results.push({
    id: "creds-perms",
    name: "Credential file permissions",
    category: "File Permissions",
    severity: "high",
    points: 3,
    earned: credFiles.length === 0 ? 3 : allCredsSecure ? 3 : 0,
    status: credFiles.length === 0 ? "pass" : allCredsSecure ? "pass" : "fail",
    message:
      credFiles.length === 0
        ? "No credential files found"
        : allCredsSecure
          ? `All ${credFiles.length} credential file(s) have proper permissions`
          : `${insecureCreds.length} credential file(s) are group/world readable`,
    fix: "chmod 600 on all files under ~/.openclaw/credentials/",
  });

  return results;
};

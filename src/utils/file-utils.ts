import { stat } from "fs/promises";
import { existsSync } from "fs";
import { join } from "path";
import { readdir } from "fs/promises";

export interface PermCheck {
  path: string;
  exists: boolean;
  mode: string;
  isGroupReadable: boolean;
  isWorldReadable: boolean;
  isOwnerOnly: boolean;
}

export async function checkPermissions(filePath: string): Promise<PermCheck> {
  if (!existsSync(filePath)) {
    return {
      path: filePath,
      exists: false,
      mode: "N/A",
      isGroupReadable: false,
      isWorldReadable: false,
      isOwnerOnly: false,
    };
  }

  const stats = await stat(filePath);
  const mode = (stats.mode & 0o777).toString(8);
  const groupBits = (stats.mode >> 3) & 0o7;
  const worldBits = stats.mode & 0o7;

  return {
    path: filePath,
    exists: true,
    mode,
    isGroupReadable: (groupBits & 0o4) !== 0,
    isWorldReadable: (worldBits & 0o4) !== 0,
    isOwnerOnly: groupBits === 0 && worldBits === 0,
  };
}

/** Find credential files recursively in a directory */
export async function findCredentialFiles(basePath: string): Promise<string[]> {
  const credPaths: string[] = [];
  const credDir = join(basePath, "credentials");

  if (!existsSync(credDir)) return credPaths;

  async function walk(dir: string) {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (
        entry.name.endsWith(".json") ||
        entry.name.endsWith(".key") ||
        entry.name.endsWith(".pem") ||
        entry.name.endsWith(".token")
      ) {
        credPaths.push(fullPath);
      }
    }
  }

  await walk(credDir);
  return credPaths;
}

import { readFile } from "fs/promises";
import { existsSync } from "fs";
import JSON5 from "json5";
import { join } from "path";

export async function readOpenClawConfig(
  basePath: string
): Promise<Record<string, unknown>> {
  const configPath = join(basePath, "openclaw.json");

  if (!existsSync(configPath)) {
    return {};
  }

  const raw = await readFile(configPath, "utf-8");
  return JSON5.parse(raw) as Record<string, unknown>;
}

/** Safely traverse a nested config object using dot-separated keys */
export function getConfigValue(
  config: Record<string, unknown>,
  path: string
): unknown {
  const keys = path.split(".");
  let current: unknown = config;

  for (const key of keys) {
    if (current === null || current === undefined || typeof current !== "object") {
      return undefined;
    }
    current = (current as Record<string, unknown>)[key];
  }

  return current;
}

import { existsSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import type { AgentPlugin, CheckResult } from "../../types.js";
import { readOpenClawConfig } from "../../utils/config-reader.js";
import { allChecks } from "./checks/index.js";

const DEFAULT_PATH = join(homedir(), ".openclaw");

export const openClawPlugin: AgentPlugin = {
  name: "openclaw",
  displayName: "OpenClaw",

  async detect(): Promise<boolean> {
    return existsSync(DEFAULT_PATH);
  },

  async scan(): Promise<CheckResult[]> {
    const basePath = DEFAULT_PATH;
    const config = await readOpenClawConfig(basePath);
    const results: CheckResult[] = [];

    for (const checkFn of allChecks) {
      const checkResults = await checkFn(config, basePath);
      results.push(...checkResults);
    }

    return results;
  },
};

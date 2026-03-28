import type { AgentPlugin } from "../types.js";
import { openClawPlugin } from "./openclaw/index.js";

export const agentRegistry: Record<string, AgentPlugin> = {
  openclaw: openClawPlugin,
};

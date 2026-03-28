import type { CheckFn } from "../../../types.js";
import { checkAuth } from "./auth.js";
import { checkFilePermissions } from "./file-permissions.js";
import { checkNetwork } from "./network.js";
import { checkDmSecurity } from "./dm-security.js";
import { checkGroupSecurity } from "./group-security.js";
import { checkToolAuth } from "./tool-authorization.js";
import { checkExecSecurity } from "./exec-security.js";
import { checkSandbox } from "./sandbox.js";
import { checkBrowserSecurity } from "./browser-security.js";
import { checkDangerousFlags } from "./dangerous-flags.js";
import { checkLogging } from "./logging.js";
import { checkMdns } from "./mdns.js";
import { checkControlUi } from "./control-ui.js";
import { checkPlugins } from "./plugins-security.js";
import { checkSubAgents } from "./sub-agents.js";
import { checkPromptInjection } from "./prompt-injection.js";
import { checkReverseProxy } from "./reverse-proxy.js";

export const allChecks: CheckFn[] = [
  checkAuth,
  checkFilePermissions,
  checkNetwork,
  checkDmSecurity,
  checkGroupSecurity,
  checkToolAuth,
  checkExecSecurity,
  checkSandbox,
  checkBrowserSecurity,
  checkDangerousFlags,
  checkLogging,
  checkMdns,
  checkControlUi,
  checkPlugins,
  checkSubAgents,
  checkPromptInjection,
  checkReverseProxy,
];

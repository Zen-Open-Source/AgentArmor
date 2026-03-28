export type Severity = "critical" | "high" | "medium" | "low";
export type CheckStatus = "pass" | "fail" | "warn";

export interface CheckResult {
  id: string;
  name: string;
  category: string;
  status: CheckStatus;
  severity: Severity;
  points: number;
  earned: number;
  message: string;
  fix?: string;
}

export interface ScanReport {
  agent: string;
  timestamp: string;
  score: number;
  maxScore: number;
  checks: CheckResult[];
  categories: CategorySummary[];
}

export interface CategorySummary {
  name: string;
  earned: number;
  possible: number;
  checks: CheckResult[];
}

export interface AgentPlugin {
  name: string;
  displayName: string;
  detect(): Promise<boolean>;
  scan(): Promise<CheckResult[]>;
}

export type CheckFn = (config: Record<string, unknown>, basePath: string) => Promise<CheckResult[]>;

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Fail,
    Warn,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub id: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub status: CheckStatus,
    pub severity: Severity,
    pub points: u32,
    pub earned: u32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CategorySummary {
    pub name: &'static str,
    pub earned: u32,
    pub possible: u32,
    pub checks: Vec<CheckResult>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub agent: &'static str,
    pub timestamp: String,
    pub normalized_score: u32,
    pub score: u32,
    pub max_score: u32,
    pub checks: Vec<CheckResult>,
    pub categories: Vec<CategorySummary>,
}

pub trait AgentPlugin {
    fn name(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn detect(&self) -> bool;
    fn scan(&self) -> anyhow::Result<Vec<CheckResult>>;
}

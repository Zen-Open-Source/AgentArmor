use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::{get, get_bool, get_str};

const DANGEROUS: &[&str] = &["gateway", "cron", "sessions_spawn", "sessions_send"];

pub fn check(config: &Value, _base: &Path) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let deny_list: Vec<&str> = get(config, "tools.deny")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let denied: Vec<&&str> = DANGEROUS.iter().filter(|t| deny_list.contains(*t)).collect();
    let all_denied = denied.len() == DANGEROUS.len();
    let some_denied = !denied.is_empty();
    let missing: Vec<&str> = DANGEROUS.iter().filter(|t| !deny_list.contains(*t)).copied().collect();

    results.push(CheckResult {
        id: "tools-deny-dangerous",
        name: "Dangerous tools denied",
        category: "Tool Authorization",
        severity: Severity::Critical,
        points: 5,
        earned: if all_denied { 5 } else if some_denied { 2 } else { 0 },
        status: if all_denied { CheckStatus::Pass } else if some_denied { CheckStatus::Warn } else { CheckStatus::Fail },
        message: if all_denied {
            "All control-plane tools (gateway, cron, sessions_spawn, sessions_send) are denied".into()
        } else {
            format!("Missing from deny list: {}", missing.join(", "))
        },
        fix: Some("Add [\"gateway\",\"cron\",\"sessions_spawn\",\"sessions_send\"] to tools.deny"),
    });

    let elevated = get_bool(config, "tools.elevated.enabled");
    results.push(CheckResult {
        id: "elevated-disabled",
        name: "Elevated tools disabled",
        category: "Tool Authorization",
        severity: Severity::High,
        points: 3,
        earned: if elevated == Some(true) { 0 } else { 3 },
        status: if elevated == Some(true) { CheckStatus::Fail } else { CheckStatus::Pass },
        message: if elevated == Some(true) {
            "Elevated tools (camera, screen, contacts, calendar, SMS) are enabled".into()
        } else {
            "Elevated tools are disabled".into()
        },
        fix: Some("Set tools.elevated.enabled to false"),
    });

    let profile = get_str(config, "tools.profile");
    let restrictive = matches!(profile, Some("messaging") | Some("readonly"));
    results.push(CheckResult {
        id: "tool-profile",
        name: "Restrictive tool profile",
        category: "Tool Authorization",
        severity: Severity::Medium,
        points: 2,
        earned: if restrictive { 2 } else if profile.is_some() { 1 } else { 0 },
        status: if restrictive { CheckStatus::Pass } else { CheckStatus::Warn },
        message: match profile {
            Some(p) => format!("Tool profile: {}", p),
            None => "No tool profile set (using defaults)".into(),
        },
        fix: Some("Set tools.profile to \"messaging\" for a restricted baseline"),
    });

    results
}

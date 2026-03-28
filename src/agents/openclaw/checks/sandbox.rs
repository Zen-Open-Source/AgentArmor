use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::{get_bool, get_str};

pub fn check(config: &Value, _base: &Path) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let mode = get_str(config, "agents.defaults.sandbox.mode");
    let is_all = mode == Some("all");
    results.push(CheckResult {
        id: "sandbox-enabled",
        name: "Sandbox mode enabled",
        category: "Sandboxing",
        severity: Severity::Critical,
        points: 4,
        earned: if is_all { 4 } else { 0 },
        status: if is_all { CheckStatus::Pass } else { CheckStatus::Fail },
        message: if is_all {
            "All tools run in Docker sandbox".into()
        } else {
            format!("Sandbox mode: {} — tools run on host", mode.unwrap_or("off"))
        },
        fix: Some("Set agents.defaults.sandbox.mode to \"all\""),
    });

    let scope = get_str(config, "agents.defaults.sandbox.scope");
    let good_scope = scope.is_none() || matches!(scope, Some("agent") | Some("session"));
    results.push(CheckResult {
        id: "sandbox-scope",
        name: "Sandbox scope (per-agent/session)",
        category: "Sandboxing",
        severity: Severity::High,
        points: 3,
        earned: if good_scope { 3 } else { 0 },
        status: if good_scope { CheckStatus::Pass } else { CheckStatus::Warn },
        message: format!("Sandbox scope: {}", scope.unwrap_or("agent (default)")),
        fix: Some("Set agents.defaults.sandbox.scope to \"agent\" or \"session\""),
    });

    let dangerous_flags = [
        "agents.defaults.sandbox.docker.dangerouslyAllowReservedContainerTargets",
        "agents.defaults.sandbox.docker.dangerouslyAllowExternalBindSources",
        "agents.defaults.sandbox.docker.dangerouslyAllowContainerNamespaceJoin",
    ];
    let flagged: Vec<&str> = dangerous_flags
        .iter()
        .filter(|f| get_bool(config, f) == Some(true))
        .map(|f| f.rsplit('.').next().unwrap_or(f))
        .collect();

    results.push(CheckResult {
        id: "sandbox-dangerous-flags",
        name: "No dangerous Docker flags",
        category: "Sandboxing",
        severity: Severity::High,
        points: 3,
        earned: if flagged.is_empty() { 3 } else { 0 },
        status: if flagged.is_empty() { CheckStatus::Pass } else { CheckStatus::Fail },
        message: if flagged.is_empty() {
            "No dangerous Docker sandbox flags enabled".into()
        } else {
            format!("Dangerous flags enabled: {}", flagged.join(", "))
        },
        fix: Some("Disable all dangerously* flags in agents.defaults.sandbox.docker"),
    });

    results
}

use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::get;

pub fn check(config: &Value, _base: &Path) -> Vec<CheckResult> {
    let deny_list: Vec<&str> = get(config, "tools.deny")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let spawn_denied = deny_list.contains(&"sessions_spawn");

    vec![CheckResult {
        id: "subagent-spawn-denied",
        name: "Sub-agent spawn restricted",
        category: "Sub-Agents",
        severity: Severity::High,
        points: 0,
        earned: 0,
        status: if spawn_denied { CheckStatus::Pass } else { CheckStatus::Warn },
        message: if spawn_denied {
            "sessions_spawn is denied — agents cannot spawn sub-agents".into()
        } else {
            "sessions_spawn is not denied — agents can spawn sub-agents".into()
        },
        fix: Some("Add sessions_spawn to tools.deny"),
    }]
}

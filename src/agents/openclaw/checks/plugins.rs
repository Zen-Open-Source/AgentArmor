use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::get;

pub fn check(config: &Value, _base: &Path) -> Vec<CheckResult> {
    let allow = get(config, "plugins.allow").and_then(|v| v.as_array());

    vec![CheckResult {
        id: "plugins-allowlist",
        name: "Plugin allowlist configured",
        category: "Plugins",
        severity: Severity::Medium,
        points: 2,
        earned: if allow.is_some() { 2 } else { 0 },
        status: if allow.is_some() { CheckStatus::Pass } else { CheckStatus::Warn },
        message: match allow {
            Some(arr) => format!("Plugin allowlist: {} plugin(s) explicitly allowed", arr.len()),
            None => "No explicit plugin allowlist — any installed plugin can load".into(),
        },
        fix: Some("Set plugins.allow to an explicit list of trusted plugin IDs"),
    }]
}

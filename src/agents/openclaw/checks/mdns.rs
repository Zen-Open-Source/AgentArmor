use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::get_str;

pub fn check(config: &Value, _base: &Path) -> Vec<CheckResult> {
    let mode = get_str(config, "discovery.mdns.mode");
    let secure = matches!(mode, Some("minimal") | Some("off"));

    vec![CheckResult {
        id: "mdns-minimal",
        name: "mDNS discovery restricted",
        category: "mDNS/Discovery",
        severity: Severity::Low,
        points: 2,
        earned: if secure { 2 } else { 0 },
        status: if secure { CheckStatus::Pass } else { CheckStatus::Warn },
        message: if secure {
            format!("mDNS mode: {}", mode.unwrap())
        } else {
            format!("mDNS mode: {} — broadcasts install path and SSH port", mode.unwrap_or("full (default)"))
        },
        fix: Some("Set discovery.mdns.mode to \"minimal\" or \"off\""),
    }]
}

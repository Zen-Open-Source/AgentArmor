use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::{get, get_str};

pub fn check(config: &Value, _base: &Path) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let mut has_open = false;
    if let Some(channels) = get(config, "channels").and_then(|v| v.as_object()) {
        for ch in channels.values() {
            if ch.get("dmPolicy").and_then(|v| v.as_str()) == Some("open") {
                has_open = true;
            }
        }
    }

    results.push(CheckResult {
        id: "dm-policy",
        name: "DM policy (pairing/allowlist)",
        category: "DM Security",
        severity: Severity::Critical,
        points: 5,
        earned: if has_open { 0 } else { 5 },
        status: if has_open { CheckStatus::Fail } else { CheckStatus::Pass },
        message: if has_open {
            "At least one channel has dmPolicy \"open\" — anyone can message the agent".into()
        } else {
            "DM policy uses pairing or allowlist".into()
        },
        fix: Some("Set dmPolicy to \"pairing\" or \"allowlist\" for all channels"),
    });

    let dm_scope = get_str(config, "session.dmScope");
    let isolated = matches!(dm_scope, Some("per-channel-peer") | Some("per-account-channel-peer"));
    results.push(CheckResult {
        id: "dm-scope",
        name: "DM session isolation",
        category: "DM Security",
        severity: Severity::Medium,
        points: 3,
        earned: if isolated { 3 } else { 0 },
        status: if isolated { CheckStatus::Pass } else { CheckStatus::Warn },
        message: if isolated {
            format!("DM scope: {} (isolated per sender)", dm_scope.unwrap())
        } else {
            format!("DM scope: {} (shared session — less isolated)", dm_scope.unwrap_or("main"))
        },
        fix: Some("Set session.dmScope to \"per-channel-peer\" for sender isolation"),
    });

    results
}

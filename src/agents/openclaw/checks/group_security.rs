use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::get;

pub fn check(config: &Value, _base: &Path) -> Vec<CheckResult> {
    let mut results = Vec::new();
    let mut mention_required = false;
    let mut has_open_group = false;

    if let Some(channels) = get(config, "channels").and_then(|v| v.as_object()) {
        for ch in channels.values() {
            if let Some(groups) = ch.get("groups").and_then(|v| v.as_object()) {
                if let Some(wildcard) = groups.get("*") {
                    if wildcard.get("requireMention").and_then(|v| v.as_bool()) == Some(true) {
                        mention_required = true;
                    }
                }
            }
            if ch.get("groupPolicy").and_then(|v| v.as_str()) == Some("open") {
                has_open_group = true;
            }
        }
    }

    results.push(CheckResult {
        id: "group-require-mention",
        name: "Groups require mention",
        category: "Group Security",
        severity: Severity::High,
        points: 3,
        earned: if mention_required { 3 } else { 0 },
        status: if mention_required { CheckStatus::Pass } else { CheckStatus::Warn },
        message: if mention_required {
            "Groups require @mention to trigger bot".into()
        } else {
            "No requireMention configured — bot responds to all group messages".into()
        },
        fix: Some("Set channels.<channel>.groups[\"*\"].requireMention: true"),
    });

    results.push(CheckResult {
        id: "group-policy",
        name: "Group policy not open",
        category: "Group Security",
        severity: Severity::High,
        points: 3,
        earned: if has_open_group { 0 } else { 3 },
        status: if has_open_group { CheckStatus::Fail } else { CheckStatus::Pass },
        message: if has_open_group {
            "At least one channel has open group policy — anyone can trigger tools".into()
        } else {
            "No open group policies detected".into()
        },
        fix: Some("Set groupPolicy to \"pairing\" or \"allowlist\""),
    });

    results
}

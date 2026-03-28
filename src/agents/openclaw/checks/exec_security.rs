use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::{get, get_bool, get_str};

const INTERPRETERS: &[&str] = &["python", "node", "ruby", "perl", "php", "lua", "osascript"];

pub fn check(config: &Value, _base: &Path) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let exec_security = get_str(config, "tools.exec.security");
    let is_deny = exec_security.is_none() || exec_security == Some("deny");

    results.push(CheckResult {
        id: "exec-deny",
        name: "Exec tool denied",
        category: "Exec Security",
        severity: Severity::Critical,
        points: 5,
        earned: if is_deny { 5 } else { 0 },
        status: if is_deny { CheckStatus::Pass } else { CheckStatus::Fail },
        message: if is_deny {
            "Shell execution is denied by default".into()
        } else {
            format!("Exec security: {} — shell execution is permitted", exec_security.unwrap())
        },
        fix: Some("Set tools.exec.security to \"deny\""),
    });

    let exec_ask = get_str(config, "tools.exec.ask");
    results.push(CheckResult {
        id: "exec-ask-always",
        name: "Exec requires approval",
        category: "Exec Security",
        severity: Severity::High,
        points: 3,
        earned: if exec_ask == Some("always") || is_deny { 3 } else { 0 },
        status: if exec_ask == Some("always") || is_deny { CheckStatus::Pass } else { CheckStatus::Fail },
        message: if is_deny {
            "Exec is denied (approval not needed)".into()
        } else if exec_ask == Some("always") {
            "Each execution requires explicit approval".into()
        } else {
            "Exec does not require per-command approval".into()
        },
        fix: Some("Set tools.exec.ask to \"always\""),
    });

    let strict_inline = get_bool(config, "tools.exec.strictInlineEval");
    let safe_bins: Vec<&str> = get(config, "tools.exec.safeBins")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let has_interpreters = safe_bins.iter().any(|b| INTERPRETERS.contains(b));

    results.push(CheckResult {
        id: "strict-inline-eval",
        name: "Strict inline eval",
        category: "Exec Security",
        severity: Severity::Medium,
        points: 2,
        earned: if is_deny || !has_interpreters || strict_inline == Some(true) { 2 } else { 0 },
        status: if !is_deny && has_interpreters && strict_inline != Some(true) {
            CheckStatus::Fail
        } else {
            CheckStatus::Pass
        },
        message: if is_deny {
            "Exec is denied (inline eval moot)".into()
        } else if has_interpreters && strict_inline != Some(true) {
            "Interpreters in safeBins but strictInlineEval is not enabled".into()
        } else {
            "Strict inline eval configured appropriately".into()
        },
        fix: Some("Enable tools.exec.strictInlineEval when allowlisting interpreters"),
    });

    results
}

use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::{get, get_bool};

pub fn check(config: &Value, _base: &Path) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let origins = get(config, "gateway.controlUi.allowedOrigins").and_then(|v| v.as_array());
    let is_wildcard = origins
        .map(|arr| arr.iter().any(|v| v.as_str() == Some("*")))
        .unwrap_or(false);

    results.push(CheckResult {
        id: "control-ui-origins",
        name: "Control UI origin allowlist",
        category: "Control UI",
        severity: Severity::High,
        points: 1,
        earned: if is_wildcard { 0 } else { 1 },
        status: if is_wildcard { CheckStatus::Fail } else { CheckStatus::Pass },
        message: if is_wildcard {
            "Control UI allows all origins (\"*\") — vulnerable to cross-origin attacks".into()
        } else if let Some(arr) = origins {
            let list: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
            format!("Control UI origins restricted to: {}", list.join(", "))
        } else {
            "Control UI origins not explicitly set (default is secure for loopback)".into()
        },
        fix: Some("Set gateway.controlUi.allowedOrigins to specific trusted origins"),
    });

    let disable_auth = get_bool(config, "gateway.controlUi.dangerouslyDisableDeviceAuth");
    results.push(CheckResult {
        id: "control-ui-device-auth",
        name: "Device auth enabled",
        category: "Control UI",
        severity: Severity::High,
        points: 1,
        earned: if disable_auth == Some(true) { 0 } else { 1 },
        status: if disable_auth == Some(true) { CheckStatus::Fail } else { CheckStatus::Pass },
        message: if disable_auth == Some(true) {
            "Device identity checks are disabled — severe security downgrade".into()
        } else {
            "Device auth is enabled".into()
        },
        fix: Some("Remove gateway.controlUi.dangerouslyDisableDeviceAuth"),
    });

    results
}

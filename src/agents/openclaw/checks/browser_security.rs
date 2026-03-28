use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::{get_bool, get_str};

pub fn check(config: &Value, _base: &Path) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let ssrf_allow = get_bool(config, "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork");
    results.push(CheckResult {
        id: "browser-ssrf",
        name: "SSRF private network blocked",
        category: "Browser Security",
        severity: Severity::High,
        points: 3,
        earned: if ssrf_allow == Some(false) { 3 } else { 0 },
        status: if ssrf_allow == Some(false) { CheckStatus::Pass } else { CheckStatus::Warn },
        message: if ssrf_allow == Some(false) {
            "Browser SSRF policy blocks private network access".into()
        } else {
            "Browser may access private/internal network destinations (default allows it)".into()
        },
        fix: Some("Set browser.ssrfPolicy.dangerouslyAllowPrivateNetwork to false"),
    });

    let browser_mode = get_str(config, "gateway.nodes.browser.mode");
    let is_off = browser_mode == Some("off");
    results.push(CheckResult {
        id: "browser-profile",
        name: "Browser control restricted",
        category: "Browser Security",
        severity: Severity::Medium,
        points: 3,
        earned: if is_off { 3 } else if browser_mode.is_some() { 1 } else { 2 },
        status: if is_off { CheckStatus::Pass } else { CheckStatus::Warn },
        message: if is_off {
            "Browser proxy routing is disabled".into()
        } else if let Some(m) = browser_mode {
            format!("Browser mode: {} — ensure dedicated profile is used", m)
        } else {
            "Browser mode not explicitly configured — use dedicated agent profile".into()
        },
        fix: Some("Set gateway.nodes.browser.mode to \"off\" if not needed, or use a dedicated browser profile"),
    });

    results
}

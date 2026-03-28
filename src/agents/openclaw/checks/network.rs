use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::get_str;

pub fn check(config: &Value, _base: &Path) -> Vec<CheckResult> {
    let mut results = Vec::new();
    let bind = get_str(config, "gateway.bind");
    let is_loopback = bind.is_none() || bind == Some("loopback");
    let is_tailnet = bind == Some("tailnet");
    let is_lan = bind == Some("lan");
    let is_custom = bind == Some("custom");

    results.push(CheckResult {
        id: "bind-loopback",
        name: "Gateway binds to loopback",
        category: "Network Exposure",
        severity: Severity::Critical,
        points: 6,
        earned: if is_loopback { 6 } else if is_tailnet { 4 } else { 0 },
        status: if is_loopback { CheckStatus::Pass } else if is_tailnet { CheckStatus::Warn } else { CheckStatus::Fail },
        message: if is_loopback {
            "Gateway bound to localhost only".into()
        } else {
            format!("Gateway bound to: {}", bind.unwrap_or("unknown"))
        },
        fix: Some("Set gateway.bind to \"loopback\" in openclaw.json"),
    });

    results.push(CheckResult {
        id: "port-not-exposed",
        name: "Port not publicly exposed",
        category: "Network Exposure",
        severity: Severity::High,
        points: 3,
        earned: if !is_custom && !is_lan { 3 } else { 0 },
        status: if !is_custom && !is_lan { CheckStatus::Pass } else { CheckStatus::Fail },
        message: if is_custom || is_lan {
            format!("Gateway may be exposed on network (bind: {})", bind.unwrap_or("unknown"))
        } else {
            "Gateway not exposed beyond loopback/tailnet".into()
        },
        fix: Some("Use loopback binding or Tailscale Serve instead of LAN bind"),
    });

    results.push(CheckResult {
        id: "tailscale-pref",
        name: "Tailscale preferred over LAN",
        category: "Network Exposure",
        severity: Severity::Medium,
        points: 3,
        earned: if is_loopback || is_tailnet { 3 } else { 0 },
        status: if is_loopback || is_tailnet {
            CheckStatus::Pass
        } else if is_lan {
            CheckStatus::Warn
        } else {
            CheckStatus::Fail
        },
        message: if is_loopback {
            "Loopback is ideal (no remote exposure)".into()
        } else if is_tailnet {
            "Tailscale provides encrypted network access".into()
        } else {
            "LAN binding is less secure than Tailscale Serve".into()
        },
        fix: Some("Use gateway.bind: \"tailnet\" or Tailscale Serve instead of LAN"),
    });

    results
}

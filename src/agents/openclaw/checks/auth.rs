use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::{get_str};

pub fn check(config: &Value, _base: &Path) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let auth_mode = get_str(config, "gateway.auth.mode");

    results.push(CheckResult {
        id: "auth-enabled",
        name: "Gateway auth enabled",
        category: "Authentication",
        severity: Severity::Critical,
        points: 4,
        earned: if auth_mode.is_some() { 4 } else { 0 },
        status: if auth_mode.is_some() { CheckStatus::Pass } else { CheckStatus::Fail },
        message: match auth_mode {
            Some(m) => format!("Auth mode: {}", m),
            None => "No gateway authentication configured — connections are unprotected".into(),
        },
        fix: Some("Set gateway.auth.mode to \"token\" in openclaw.json"),
    });

    let is_token = auth_mode == Some("token");
    let is_password = auth_mode == Some("password");
    results.push(CheckResult {
        id: "auth-mode-token",
        name: "Token auth mode (recommended)",
        category: "Authentication",
        severity: Severity::Medium,
        points: 4,
        earned: if is_token { 4 } else if is_password { 2 } else { 0 },
        status: if is_token { CheckStatus::Pass } else if is_password { CheckStatus::Warn } else { CheckStatus::Fail },
        message: if is_token {
            "Using recommended token auth".into()
        } else if is_password {
            "Password auth is acceptable but token auth is preferred".into()
        } else {
            "Auth mode is not set to token or password".into()
        },
        fix: Some("Set gateway.auth.mode to \"token\" and run: openclaw doctor --generate-gateway-token"),
    });

    let token = get_str(config, "gateway.auth.token");
    let token_len = token.map(|t| t.len()).unwrap_or(0);
    let strong = token_len >= 32;
    results.push(CheckResult {
        id: "auth-token-strength",
        name: "Auth token strength",
        category: "Authentication",
        severity: Severity::High,
        points: 4,
        earned: if strong { 4 } else if token_len >= 16 { 2 } else { 0 },
        status: if strong { CheckStatus::Pass } else if token_len >= 16 { CheckStatus::Warn } else { CheckStatus::Fail },
        message: if let Some(t) = token {
            format!("Token length: {} chars{}", t.len(), if strong { "" } else { " (minimum 32 recommended)" })
        } else {
            "No token configured".into()
        },
        fix: Some("Generate a strong token: openclaw doctor --generate-gateway-token"),
    });

    results
}

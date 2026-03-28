use regex::Regex;
use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::{get, get_str};
use crate::utils::fs::{check_permissions, find_auth_profiles};

struct SecretPattern {
    pattern: &'static str,
    label: &'static str,
}

const SECRET_PATTERNS: &[SecretPattern] = &[
    SecretPattern { pattern: r"^sk-[A-Za-z0-9]{20,}", label: "OpenAI/Anthropic API key" },
    SecretPattern { pattern: r"^xoxb-[0-9]+-[A-Za-z0-9]+", label: "Slack bot token" },
    SecretPattern { pattern: r"^xoxp-[0-9]+-[A-Za-z0-9]+", label: "Slack user token" },
    SecretPattern { pattern: r"^ghp_[A-Za-z0-9]{36}", label: "GitHub personal access token" },
    SecretPattern { pattern: r"^ghs_[A-Za-z0-9]{36}", label: "GitHub app token" },
    SecretPattern { pattern: r"^AIza[A-Za-z0-9_-]{35}", label: "Google API key" },
    SecretPattern { pattern: r"^AKIA[A-Z0-9]{16}$", label: "AWS access key" },
    SecretPattern { pattern: r"^\d{9,10}:[A-Za-z0-9_-]{35}", label: "Telegram bot token" },
    SecretPattern { pattern: r"^Bot [A-Za-z0-9_.\-]{59}", label: "Discord bot token" },
];


fn collect_string_values(value: &Value, path: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::String(s) => out.push((path.to_string(), s.clone())),
        Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                collect_string_values(item, &format!("{}[{}]", path, i), out);
            }
        }
        Value::Object(map) => {
            const SKIP: &[&str] = &[
                "mode", "bind", "profile", "scope", "workspaceAccess",
                "dmPolicy", "groupPolicy", "dmScope", "redactSensitive",
            ];
            for (key, val) in map {
                if SKIP.contains(&key.as_str()) {
                    continue;
                }
                let new_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", path, key)
                };
                collect_string_values(val, &new_path, out);
            }
        }
        _ => {}
    }
}

pub fn check(config: &Value, base: &Path) -> Vec<CheckResult> {
    let mut results = Vec::new();

    // Check 1: secrets.json permissions
    let secrets_path = base.join("secrets.json");
    let secrets_perms = check_permissions(&secrets_path);
    results.push(CheckResult {
        id: "secrets-file-perms",
        name: "secrets.json permissions",
        category: "Secrets Management",
        severity: Severity::High,
        points: 2,
        earned: if !secrets_perms.exists || secrets_perms.is_owner_only { 2 } else { 0 },
        status: if !secrets_perms.exists || secrets_perms.is_owner_only { CheckStatus::Pass } else { CheckStatus::Fail },
        message: if !secrets_perms.exists {
            "No secrets.json file found".into()
        } else if secrets_perms.is_owner_only {
            format!("secrets.json permissions: {} (secure)", secrets_perms.mode)
        } else {
            format!("secrets.json permissions: {} — group/world readable", secrets_perms.mode)
        },
        fix: Some("chmod 600 ~/.openclaw/secrets.json"),
    });

    // Check 2: Auth profile permissions
    let profiles = find_auth_profiles(base);
    let insecure = profiles
        .iter()
        .filter(|p| {
            let perms = check_permissions(p);
            !perms.is_owner_only
        })
        .count();

    results.push(CheckResult {
        id: "auth-profiles-perms",
        name: "Auth profile file permissions",
        category: "Secrets Management",
        severity: Severity::High,
        points: 2,
        earned: if insecure == 0 { 2 } else { 0 },
        status: if insecure == 0 { CheckStatus::Pass } else { CheckStatus::Fail },
        message: if profiles.is_empty() {
            "No auth profile files found".into()
        } else if insecure == 0 {
            format!("All {} auth profile(s) have proper permissions", profiles.len())
        } else {
            format!("{} auth profile(s) are group/world readable", insecure)
        },
        fix: Some("chmod 600 ~/.openclaw/agents/*/agent/auth-profiles.json"),
    });

    // Check 3: Password not hardcoded
    let hardcoded_pw = get_str(config, "gateway.auth.password").is_some();
    results.push(CheckResult {
        id: "password-not-hardcoded",
        name: "Password not hardcoded in config",
        category: "Secrets Management",
        severity: Severity::Critical,
        points: 3,
        earned: if hardcoded_pw { 0 } else { 3 },
        status: if hardcoded_pw { CheckStatus::Fail } else { CheckStatus::Pass },
        message: if hardcoded_pw {
            "Gateway password is hardcoded in openclaw.json".into()
        } else {
            "No hardcoded password in config".into()
        },
        fix: Some("Use OPENCLAW_GATEWAY_PASSWORD environment variable instead"),
    });

    // Check 4: Plaintext secrets scan
    let mut string_values: Vec<(String, String)> = Vec::new();
    collect_string_values(config, "", &mut string_values);

    let compiled: Vec<(Regex, &str)> = SECRET_PATTERNS
        .iter()
        .filter_map(|p| Regex::new(p.pattern).ok().map(|r| (r, p.label)))
        .collect();

    let mut found: Vec<String> = Vec::new();

    for (path, value) in &string_values {
        if value.starts_with("${") || value.len() < 16 || path == "gateway.auth.token" {
            continue;
        }
        for (regex, label) in &compiled {
            if regex.is_match(value) {
                found.push(format!("{} at {}", label, path));
                break;
            }
        }
    }

    // Also scan raw config file
    if let Ok(raw) = std::fs::read_to_string(base.join("openclaw.json")) {
        for (regex, label) in &compiled {
            if regex.is_match(&raw) && !found.iter().any(|f| f.contains(label)) {
                found.push(format!("{} (raw config scan)", label));
                break;
            }
        }
    }

    results.push(CheckResult {
        id: "no-plaintext-secrets",
        name: "No plaintext secrets in config",
        category: "Secrets Management",
        severity: Severity::Critical,
        points: 3,
        earned: if found.is_empty() { 3 } else { 0 },
        status: if found.is_empty() { CheckStatus::Pass } else { CheckStatus::Fail },
        message: if found.is_empty() {
            "No plaintext API keys or tokens detected in config".into()
        } else {
            format!("Potential secrets found: {}", found.join("; "))
        },
        fix: Some("Move secrets to environment variables or ~/.openclaw/secrets.json (chmod 600)"),
    });

    // Check 5: secrets.json not in agent workspace
    let in_workspace = if secrets_perms.exists {
        let mut ws_paths: Vec<std::path::PathBuf> = get(config, "agents.list")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| a.get("workspace")?.as_str())
                    .map(|ws| {
                        let expanded = ws.replace(
                            '~',
                            &dirs::home_dir()
                                .map(|h| h.to_string_lossy().to_string())
                                .unwrap_or_default(),
                        );
                        std::path::PathBuf::from(expanded)
                    })
                    .collect()
            })
            .unwrap_or_default();
        ws_paths.push(base.join("workspace"));
        ws_paths.iter().any(|ws| secrets_path.starts_with(ws))
    } else {
        false
    };

    results.push(CheckResult {
        id: "secrets-not-in-workspace",
        name: "Secrets not in agent workspace",
        category: "Secrets Management",
        severity: Severity::High,
        points: 2,
        earned: if in_workspace { 0 } else { 2 },
        status: if in_workspace { CheckStatus::Fail } else { CheckStatus::Pass },
        message: if in_workspace {
            "secrets.json is located inside an agent workspace — agent can read it".into()
        } else {
            "secrets.json is not inside any agent workspace".into()
        },
        fix: Some("Keep secrets.json at ~/.openclaw/secrets.json, not inside agent workspace dirs"),
    });

    results
}

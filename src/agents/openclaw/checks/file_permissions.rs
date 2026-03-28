use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::fs::{check_permissions, find_credential_files};

pub fn check(_config: &Value, base: &Path) -> Vec<CheckResult> {
    let mut results = Vec::new();

    // ~/.openclaw directory should be 700
    let dir = check_permissions(base);
    let dir_ok = dir.exists && dir.is_owner_only;
    results.push(CheckResult {
        id: "dir-perms",
        name: "~/.openclaw directory permissions",
        category: "File Permissions",
        severity: Severity::Critical,
        points: 4,
        earned: if dir_ok { 4 } else { 0 },
        status: if dir_ok { CheckStatus::Pass } else { CheckStatus::Fail },
        message: if dir.exists {
            format!("Directory mode: {} (expected: 700)", dir.mode)
        } else {
            "Directory does not exist".into()
        },
        fix: Some("chmod 700 ~/.openclaw"),
    });

    // openclaw.json should be 600
    let config_perms = check_permissions(&base.join("openclaw.json"));
    let config_ok = !config_perms.exists || config_perms.is_owner_only;
    results.push(CheckResult {
        id: "config-perms",
        name: "Config file permissions",
        category: "File Permissions",
        severity: Severity::High,
        points: 3,
        earned: if config_ok { 3 } else { 0 },
        status: if config_ok { CheckStatus::Pass } else { CheckStatus::Fail },
        message: if config_perms.exists {
            format!("Config mode: {} (expected: 600)", config_perms.mode)
        } else {
            "Config file not found (no exposure risk)".into()
        },
        fix: Some("chmod 600 ~/.openclaw/openclaw.json"),
    });

    // Credential files should not be group/world readable
    let creds = find_credential_files(base);
    let insecure: usize = creds
        .iter()
        .map(|p| check_permissions(p))
        .filter(|p| p.is_group_readable || p.is_world_readable)
        .count();

    results.push(CheckResult {
        id: "creds-perms",
        name: "Credential file permissions",
        category: "File Permissions",
        severity: Severity::High,
        points: 3,
        earned: if insecure == 0 { 3 } else { 0 },
        status: if insecure == 0 { CheckStatus::Pass } else { CheckStatus::Fail },
        message: if creds.is_empty() {
            "No credential files found".into()
        } else if insecure == 0 {
            format!("All {} credential file(s) have proper permissions", creds.len())
        } else {
            format!("{} credential file(s) are group/world readable", insecure)
        },
        fix: Some("chmod 600 on all files under ~/.openclaw/credentials/"),
    });

    results
}

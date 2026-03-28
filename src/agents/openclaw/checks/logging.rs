use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::get_str;
use crate::utils::fs::check_permissions;

pub fn check(config: &Value, base: &Path) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let redact = get_str(config, "logging.redactSensitive");
    results.push(CheckResult {
        id: "logging-redaction",
        name: "Sensitive data redaction",
        category: "Logging & Privacy",
        severity: Severity::Medium,
        points: 2,
        earned: if redact.is_some() { 2 } else { 0 },
        status: if redact.is_some() { CheckStatus::Pass } else { CheckStatus::Warn },
        message: match redact {
            Some(r) => format!("Redaction enabled: {}", r),
            None => "No redaction configured — tool output may appear in logs".into(),
        },
        fix: Some("Set logging.redactSensitive to \"tools\""),
    });

    // Check transcript directory permissions
    let agents_dir = base.join("agents");
    let exposed = if agents_dir.exists() {
        std::fs::read_dir(&agents_dir)
            .ok()
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                    .map(|e| e.path().join("sessions"))
                    .filter(|p| p.exists())
                    .any(|p| {
                        let perms = check_permissions(&p);
                        perms.is_group_readable || perms.is_world_readable
                    })
            })
            .unwrap_or(false)
    } else {
        false
    };

    results.push(CheckResult {
        id: "transcript-retention",
        name: "Transcript files protected",
        category: "Logging & Privacy",
        severity: Severity::Medium,
        points: 2,
        earned: if exposed { 0 } else { 2 },
        status: if exposed { CheckStatus::Fail } else { CheckStatus::Pass },
        message: if exposed {
            "Session transcripts are group/world readable".into()
        } else {
            "Session transcripts have proper permissions".into()
        },
        fix: Some("Ensure ~/.openclaw/agents/*/sessions/ directories are mode 700"),
    });

    results
}

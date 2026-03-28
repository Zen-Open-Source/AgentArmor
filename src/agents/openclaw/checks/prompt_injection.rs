use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::{get_bool, get_array};

pub fn check(config: &Value, _base: &Path) -> Vec<CheckResult> {
    let hooks_unsafe = get_bool(config, "hooks.gmail.allowUnsafeExternalContent") == Some(true);
    let cron_unsafe = get_array(config, "cron")
        .map(|jobs| {
            jobs.iter().any(|j| {
                j.get("allowUnsafeExternalContent")
                    .and_then(|v| v.as_bool())
                    == Some(true)
            })
        })
        .unwrap_or(false);

    let any_unsafe = hooks_unsafe || cron_unsafe;

    vec![CheckResult {
        id: "no-unsafe-content-flags",
        name: "Unsafe content flags disabled",
        category: "Prompt Injection",
        severity: Severity::High,
        points: 0,
        earned: 0,
        status: if any_unsafe { CheckStatus::Fail } else { CheckStatus::Pass },
        message: if any_unsafe {
            "Unsafe external content flags are enabled — increases prompt injection risk".into()
        } else {
            "No unsafe external content bypass flags detected".into()
        },
        fix: Some("Disable all allowUnsafeExternalContent flags"),
    }]
}

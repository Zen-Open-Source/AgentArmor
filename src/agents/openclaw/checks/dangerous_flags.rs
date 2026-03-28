use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::{get_bool, get_array};

pub fn check(config: &Value, _base: &Path) -> Vec<CheckResult> {
    let mut flagged: Vec<&str> = Vec::new();

    let bool_flags = [
        ("gateway.controlUi.allowInsecureAuth", false, "allowInsecureAuth"),
        ("gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback", false, "dangerouslyAllowHostHeaderOriginFallback"),
        ("gateway.controlUi.dangerouslyDisableDeviceAuth", false, "dangerouslyDisableDeviceAuth"),
        ("hooks.gmail.allowUnsafeExternalContent", false, "gmail allowUnsafeExternalContent"),
    ];

    for (path, expect_true, label) in &bool_flags {
        if let Some(val) = get_bool(config, path) {
            if val != *expect_true {
                flagged.push(label);
            }
        }
    }

    // applyPatch.workspaceOnly should be true (fail if explicitly false)
    if get_bool(config, "tools.exec.applyPatch.workspaceOnly") == Some(false) {
        flagged.push("applyPatch.workspaceOnly disabled");
    }

    // Check hooks.mappings for allowUnsafeExternalContent
    if let Some(mappings) = get_array(config, "hooks.mappings") {
        let any_unsafe = mappings.iter().any(|m| {
            m.get("allowUnsafeExternalContent")
                .and_then(|v| v.as_bool())
                == Some(true)
        });
        if any_unsafe {
            flagged.push("hooks.mappings allowUnsafeExternalContent");
        }
    }

    vec![CheckResult {
        id: "no-insecure-flags",
        name: "No dangerous config flags",
        category: "Dangerous Flags",
        severity: Severity::Critical,
        points: 6,
        earned: if flagged.is_empty() { 6 } else { 0 },
        status: if flagged.is_empty() { CheckStatus::Pass } else { CheckStatus::Fail },
        message: if flagged.is_empty() {
            "No dangerous/insecure config flags detected".into()
        } else {
            format!("Dangerous flags enabled: {}", flagged.join(", "))
        },
        fix: Some("Disable all dangerous flags flagged by: openclaw security audit"),
    }]
}

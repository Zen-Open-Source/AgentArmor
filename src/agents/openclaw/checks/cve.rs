use serde_json::Value;
use std::path::Path;
use std::process::Command;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::get_str;

/// A parsed version in YYYY.M.DD format.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Version {
    year: u32,
    month: u32,
    day: u32,
}

impl Version {
    fn parse(s: &str) -> Option<Version> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        Some(Version {
            year: parts[0].parse().ok()?,
            month: parts[1].parse().ok()?,
            day: parts[2].parse().ok()?,
        })
    }

    fn display(&self) -> String {
        format!("{}.{}.{}", self.year, self.month, self.day)
    }
}

/// Detect the installed OpenClaw version by trying multiple methods.
fn detect_version() -> Option<Version> {
    // Method 1: Run `openclaw --version`
    if let Some(v) = detect_from_command() {
        return Some(v);
    }

    // Method 2: Check ~/.openclaw/version file
    if let Some(v) = detect_from_version_file() {
        return Some(v);
    }

    // Method 3: Check package.json in common locations
    if let Some(v) = detect_from_package_json() {
        return Some(v);
    }

    None
}

fn detect_from_command() -> Option<Version> {
    let output = Command::new("openclaw")
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_version_string(stdout.trim())
}

fn detect_from_version_file() -> Option<Version> {
    let home = dirs::home_dir()?;
    let version_path = home.join(".openclaw").join("version");
    let contents = std::fs::read_to_string(version_path).ok()?;
    parse_version_string(contents.trim())
}

fn detect_from_package_json() -> Option<Version> {
    let home = dirs::home_dir()?;
    let candidates = [
        home.join(".openclaw").join("package.json"),
        home.join("openclaw").join("package.json"),
    ];
    for path in &candidates {
        if let Ok(contents) = std::fs::read_to_string(path) {
            if let Ok(json) = serde_json::from_str::<Value>(&contents) {
                if let Some(ver) = json.get("version").and_then(|v| v.as_str()) {
                    if let Some(v) = parse_version_string(ver) {
                        return Some(v);
                    }
                }
            }
        }
    }
    None
}

/// Parse a version string, handling formats like "openclaw vYYYY.M.DD",
/// "openclaw YYYY.M.DD", "vYYYY.M.DD", or bare "YYYY.M.DD".
fn parse_version_string(s: &str) -> Option<Version> {
    // Take the last whitespace-delimited token
    let token = s.split_whitespace().last()?;
    // Strip leading 'v' if present
    let cleaned = token.strip_prefix('v').unwrap_or(token);
    Version::parse(cleaned)
}

// ---------------------------------------------------------------------------
// CVE database
// ---------------------------------------------------------------------------

enum Severity2 {
    Critical,
    High,
}

struct CveEntry {
    id: &'static str,
    cvss: f32,
    severity: Severity2,
    title: &'static str,
    description: &'static str,
    fixed_version: &'static str,
    config_check: Option<fn(&Value) -> bool>,
    config_detail: Option<&'static str>,
}

fn config_shared_auth(config: &Value) -> bool {
    get_str(config, "gateway.controlUi.auth")
        .map(|a| a.contains("shared"))
        .unwrap_or(false)
}

fn config_docker_network_container(config: &Value) -> bool {
    get_str(config, "agents.defaults.sandbox.docker.network")
        .map(|n| n.starts_with("container:"))
        .unwrap_or(false)
}

fn config_control_ui_risky(config: &Value) -> bool {
    let bind = get_str(config, "gateway.controlUi.bind");
    let non_loopback = bind.map(|b| b != "127.0.0.1" && b != "localhost" && b != "::1").unwrap_or(false);
    let weak_token = get_str(config, "gateway.auth.token")
        .map(|t| t.len() < 32)
        .unwrap_or(true);
    let device_auth_disabled = get_str(config, "gateway.dangerouslyDisableDeviceAuth")
        .map(|v| v == "true")
        .unwrap_or(false);
    non_loopback || weak_token || device_auth_disabled
}

fn config_feishu_enabled(config: &Value) -> bool {
    crate::utils::config::get(config, "channels.feishu").is_some()
}

fn config_exec_not_denied(config: &Value) -> bool {
    // Extra risk if tools.exec is not explicitly denied
    let denied = crate::utils::config::get_array(config, "agents.defaults.tools.denied")
        .map(|arr| arr.iter().any(|v| v.as_str() == Some("exec")))
        .unwrap_or(false);
    !denied
}

fn config_sandbox_browser_enabled(config: &Value) -> bool {
    let mode = get_str(config, "gateway.nodes.browser.mode");
    mode.is_none() || mode != Some("off")
}

static CVE_DATABASE: &[CveEntry] = &[
    CveEntry {
        id: "CVE-2026-22172",
        cvss: 9.9,
        severity: Severity2::Critical,
        title: "Scope elevation in WebSocket shared-auth connections",
        description: "Gateway local shared-auth reconnect silently widens paired device scope from operator.read to operator.admin, enabling full node RCE.",
        fixed_version: "2026.3.12",
        config_check: Some(config_shared_auth),
        config_detail: Some("gateway.controlUi uses shared-auth (actively exploitable)"),
    },
    CveEntry {
        id: "CVE-2026-32038",
        cvss: 9.3,
        severity: Severity2::Critical,
        title: "Sandbox network isolation bypass via docker.network parameter",
        description: "Sandbox network hardening blocks network=host but allows network=container:<id>, letting a sandbox join another container's network namespace and reach internal services.",
        fixed_version: "2026.2.24",
        config_check: Some(config_docker_network_container),
        config_detail: Some("docker.network uses container: prefix (actively exploitable)"),
    },
    CveEntry {
        id: "CVE-2026-28446",
        cvss: 9.2,
        severity: Severity2::Critical,
        title: "Inbound allowlist policy bypass in voice-call extension",
        description: "Voice-call extension bypasses inbound message allowlist policy, allowing unauthenticated callers to interact with agent.",
        fixed_version: "2026.2.1",
        config_check: None,
        config_detail: None,
    },
    CveEntry {
        id: "CVE-2026-25253",
        cvss: 8.8,
        severity: Severity2::High,
        title: "1-click RCE via authentication token exfiltration",
        description: "Control UI blindly trusts gatewayUrl parameter and leaks auth token to attacker-controlled server. Visiting a malicious link gives full agent control.",
        fixed_version: "2026.1.29",
        config_check: Some(config_control_ui_risky),
        config_detail: Some("non-loopback bind, weak auth token, or dangerouslyDisableDeviceAuth"),
    },
    CveEntry {
        id: "CVE-2026-22171",
        cvss: 8.8,
        severity: Severity2::High,
        title: "Path traversal in Feishu media temporary file naming",
        description: "Feishu channel media handler does not sanitize filenames, allowing path traversal to write files outside the intended directory.",
        fixed_version: "2026.2.19",
        config_check: Some(config_feishu_enabled),
        config_detail: Some("channels.feishu is configured (actively exploitable)"),
    },
    CveEntry {
        id: "CVE-2026-24763",
        cvss: 8.8,
        severity: Severity2::High,
        title: "Command injection via PATH environment variable",
        description: "The exec tool does not sanitize the PATH environment variable, allowing attackers to inject malicious binaries that get executed instead of intended commands.",
        fixed_version: "2026.2.10",
        config_check: Some(config_exec_not_denied),
        config_detail: Some("tools.exec is not denied (actively exploitable)"),
    },
    CveEntry {
        id: "CVE-2026-28478",
        cvss: 8.7,
        severity: Severity2::High,
        title: "DoS via unbounded webhook request buffering",
        description: "Webhook handlers buffer request bodies without byte or time limits. Oversized JSON payloads or slow uploads cause memory exhaustion.",
        fixed_version: "2026.2.13",
        config_check: None,
        config_detail: None,
    },
    CveEntry {
        id: "CVE-2026-29609",
        cvss: 8.7,
        severity: Severity2::High,
        title: "DoS via unbounded URL-backed media fetch",
        description: "Media fetch does not limit response size, allowing attackers to trigger unbounded memory allocation via large media URLs.",
        fixed_version: "2026.2.14",
        config_check: None,
        config_detail: None,
    },
    CveEntry {
        id: "CVE-2026-28462",
        cvss: 8.7,
        severity: Severity2::High,
        title: "Path traversal in trace and download output paths",
        description: "Trace and download file output paths are not sanitized, allowing writes outside the intended output directory.",
        fixed_version: "2026.2.13",
        config_check: None,
        config_detail: None,
    },
    CveEntry {
        id: "CVE-2026-28479",
        cvss: 8.7,
        severity: Severity2::High,
        title: "Cache poisoning via deprecated SHA-1 hash",
        description: "Cache keys use SHA-1 which is vulnerable to collision attacks, enabling cache poisoning of agent responses.",
        fixed_version: "2026.2.15",
        config_check: None,
        config_detail: None,
    },
    CveEntry {
        id: "CVE-2026-32011",
        cvss: 8.7,
        severity: Severity2::High,
        title: "Slow-request DoS via pre-auth webhook parsing",
        description: "Webhook body parsing occurs before authentication, allowing unauthenticated slow-request attacks that exhaust server resources.",
        fixed_version: "2026.3.2",
        config_check: None,
        config_detail: None,
    },
    CveEntry {
        id: "CVE-2026-32013",
        cvss: 8.7,
        severity: Severity2::High,
        title: "Symlink traversal in agents.files methods",
        description: "agents.files methods follow symlinks without validation, allowing sandbox escape to read/write arbitrary host files.",
        fixed_version: "2026.2.25",
        config_check: None,
        config_detail: None,
    },
    CveEntry {
        id: "CVE-2026-32051",
        cvss: 8.7,
        severity: Severity2::High,
        title: "Authorization bypass in agent runs via owner-only tool access",
        description: "Owner-only tool access checks can be bypassed during agent runs, allowing unauthorized tool execution.",
        fixed_version: "2026.3.1",
        config_check: None,
        config_detail: None,
    },
    CveEntry {
        id: "CVE-2026-32064",
        cvss: 7.7,
        severity: Severity2::High,
        title: "Unauthenticated VNC in sandbox browser entrypoint",
        description: "Sandbox browser entrypoint launches x11vnc without authentication, allowing unauthenticated access to observe or interact with the sandbox browser.",
        fixed_version: "2026.2.21",
        config_check: Some(config_sandbox_browser_enabled),
        config_detail: Some("sandbox browser is enabled (actively exploitable)"),
    },
    CveEntry {
        id: "CVE-2026-32056",
        cvss: 7.5,
        severity: Severity2::High,
        title: "Shell environment variable injection in system.run",
        description: "system.run does not sanitize HOME and ZDOTDIR environment variables, allowing attackers to inject malicious shell startup files (.bash_profile, .zshenv) to achieve arbitrary code execution.",
        fixed_version: "2026.2.22",
        config_check: Some(config_exec_not_denied),
        config_detail: Some("tools.exec is not denied (actively exploitable)"),
    },
];

// ---------------------------------------------------------------------------
// Check entry point
// ---------------------------------------------------------------------------

pub fn check(config: &Value, _base: &Path) -> Vec<CheckResult> {
    let mut results = Vec::new();
    let installed = detect_version();

    if installed.is_none() {
        results.push(CheckResult {
            id: "cve-version-unknown",
            name: "OpenClaw version detection",
            category: "Known Vulnerabilities (CVE)",
            severity: Severity::High,
            points: 0,
            earned: 0,
            status: CheckStatus::Warn,
            message: "Could not detect OpenClaw version — cannot verify CVE status.\nRun: openclaw --version to verify".into(),
            fix: None,
        });
    }

    for cve in CVE_DATABASE {
        let fixed = Version::parse(cve.fixed_version).expect("invalid fixed_version in CVE database");
        let points: u32 = match cve.severity {
            Severity2::Critical => 5,
            Severity2::High => 3,
        };
        let severity = match cve.severity {
            Severity2::Critical => Severity::Critical,
            Severity2::High => Severity::High,
        };

        let (status, earned, message) = match &installed {
            Some(ver) if *ver >= fixed => {
                (
                    CheckStatus::Pass,
                    points,
                    format!("CVSS {} \u{2014} {}\nPatched in installed version {}", cve.cvss, cve.title, ver.display()),
                )
            }
            Some(ver) => {
                let config_note = cve.config_check
                    .and_then(|check_fn| {
                        if check_fn(config) {
                            cve.config_detail
                        } else {
                            None
                        }
                    });
                let mut msg = format!(
                    "CVSS {} \u{2014} {}\n{}\nInstalled: {} \u{2014} Fixed in: {}",
                    cve.cvss, cve.title, cve.description, ver.display(), cve.fixed_version
                );
                if let Some(detail) = config_note {
                    msg.push_str(&format!("\nConfig risk: {}", detail));
                }
                (CheckStatus::Fail, 0, msg)
            }
            None => {
                (
                    CheckStatus::Warn,
                    0,
                    format!("CVSS {} \u{2014} {}\n{}\nCannot verify \u{2014} version unknown. Fixed in: {}", cve.cvss, cve.title, cve.description, cve.fixed_version),
                )
            }
        };

        results.push(CheckResult {
            id: cve.id,
            name: cve.id,
            category: "Known Vulnerabilities (CVE)",
            severity,
            points,
            earned,
            status,
            message,
            fix: Some("Update OpenClaw to the latest version: openclaw update"),
        });
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parse() {
        let v = Version::parse("2026.3.12").unwrap();
        assert_eq!(v, Version { year: 2026, month: 3, day: 12 });
    }

    #[test]
    fn test_version_comparison() {
        let a = Version::parse("2026.2.20").unwrap();
        let b = Version::parse("2026.3.12").unwrap();
        assert!(a < b);

        let c = Version::parse("2026.3.12").unwrap();
        assert_eq!(b, c);
    }

    #[test]
    fn test_parse_version_string() {
        assert_eq!(
            parse_version_string("openclaw v2026.3.12"),
            Some(Version { year: 2026, month: 3, day: 12 })
        );
        assert_eq!(
            parse_version_string("openclaw 2026.3.12"),
            Some(Version { year: 2026, month: 3, day: 12 })
        );
        assert_eq!(
            parse_version_string("v2026.3.12"),
            Some(Version { year: 2026, month: 3, day: 12 })
        );
        assert_eq!(
            parse_version_string("2026.3.12"),
            Some(Version { year: 2026, month: 3, day: 12 })
        );
    }

    #[test]
    fn test_cve_database_has_all_entries() {
        assert_eq!(CVE_DATABASE.len(), 15);
    }
}

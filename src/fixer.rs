use std::fs;
use std::io::{self, BufRead, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Local;
use colored::Colorize;
use rand::Rng;
use serde_json::Value;

use crate::scanner;
use crate::utils::config::read_config;
use crate::utils::fs::{find_auth_profiles, find_credential_files};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum FixCategory {
    Permission,
    ConfigSet,
    ConfigRemove,
    TokenGen,
}

#[derive(Debug, Clone)]
pub struct FixAction {
    pub id: &'static str,
    pub description: String,
    pub category: FixCategory,
}

#[derive(Debug)]
pub struct FixResult {
    pub description: String,
    pub success: bool,
    pub message: String,
}

pub struct FixOptions {
    pub agent: Option<String>,
    pub dry_run: bool,
    pub interactive: bool,
    pub verbose: bool,
    pub backup_dir: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn run_fix(opts: FixOptions) -> Result<()> {
    let base = openclaw_base();
    let bar = "\u{2501}".repeat(50);

    // --- initial scan ---
    let before_score = match scanner::run_scan(opts.agent.as_deref()) {
        Ok(r) => r.normalized_score,
        Err(_) => {
            // If no agent detected yet (dir doesn't exist), score is 0
            0
        }
    };

    // --- build fix plan ---
    let config = read_config(&base).unwrap_or_else(|_| Value::Object(serde_json::Map::new()));
    let fixes = plan_fixes(&config, &base);

    if fixes.is_empty() {
        println!();
        println!("  {}", "AgentArmor Fix \u{2014} OpenClaw".bold());
        println!("  {}", bar.dimmed());
        println!();
        println!("  No fixes needed \u{2014} everything looks good!");
        println!();
        return Ok(());
    }

    // --- dry-run mode ---
    if opts.dry_run {
        println!();
        println!("  {}", "AgentArmor Fix \u{2014} Dry Run".bold());
        println!("  {}", bar.dimmed());
        println!();
        println!("  Would apply {} fixes:", fixes.len());
        println!();
        for fix in &fixes {
            println!("    {} {}", "\u{270e}".cyan(), fix.description);
        }
        println!();
        println!("  Run without --dry-run to apply these fixes.");
        println!();
        return Ok(());
    }

    // --- real fix mode ---
    println!();
    println!("  {}", "AgentArmor Fix \u{2014} OpenClaw".bold());
    println!("  {}", bar.dimmed());
    println!();

    // Ensure base dir exists
    ensure_base_dir(&base)?;

    // Backup
    let backup_root = opts
        .backup_dir
        .unwrap_or_else(|| default_backup_root());
    let backup_path = create_backup(&base, &backup_root)?;
    println!(
        "  Backup saved to {}/",
        backup_path.display().to_string().dimmed()
    );
    println!();

    // Re-read config after ensuring dir exists (may have created empty one)
    let mut config = read_config(&base).unwrap_or_else(|_| Value::Object(serde_json::Map::new()));

    // Apply fixes
    println!("  Applying fixes:");
    let mut applied = 0u32;
    let mut failed = 0u32;

    for fix in &fixes {
        if opts.interactive {
            print!("    Apply: {}? [Y/n] ", fix.description);
            io::stdout().flush().ok();
            let mut line = String::new();
            io::stdin().lock().read_line(&mut line).ok();
            let trimmed = line.trim().to_lowercase();
            if trimmed == "n" || trimmed == "no" {
                println!("    {} {} (skipped)", "\u{2014}".dimmed(), fix.description);
                continue;
            }
        }

        let result = apply_fix(fix, &mut config, &base, opts.verbose);
        if result.success {
            applied += 1;
            println!("    {} {}", "\u{2713}".green(), result.description);
            if opts.verbose && !result.message.is_empty() {
                println!("      {}", result.message.dimmed());
            }
        } else {
            failed += 1;
            println!(
                "    {} Failed: {} ({})",
                "\u{2717}".red(),
                result.description,
                result.message
            );
        }
    }

    // Write back config
    write_config_atomic(&base, &config)?;

    // --- post-fix scan ---
    let after_score = match scanner::run_scan(opts.agent.as_deref()) {
        Ok(r) => r.normalized_score,
        Err(_) => 0,
    };

    let delta = after_score as i32 - before_score as i32;
    let delta_str = if delta > 0 {
        format!("(+{})", delta).green().to_string()
    } else if delta == 0 {
        "(+0)".dimmed().to_string()
    } else {
        format!("({})", delta).red().to_string()
    };

    println!();
    println!(
        "  Score: {}/100 \u{2192} {}/100 {}",
        before_score, after_score, delta_str
    );
    println!("  {}", bar.dimmed());
    let total = applied + failed;
    println!(
        "  Applied {} of {} fixes. {} failed.",
        applied, total, failed
    );
    println!();

    Ok(())
}

// ---------------------------------------------------------------------------
// Fix planning
// ---------------------------------------------------------------------------

fn plan_fixes(config: &Value, base: &Path) -> Vec<FixAction> {
    let mut fixes = Vec::new();

    // --- permission fixes ---

    // dir-perms: ~/.openclaw should be 700
    if needs_perm_fix(base, 0o700) {
        fixes.push(FixAction {
            id: "dir-perms",
            description: format!("chmod 700 {}", base.display()),
            category: FixCategory::Permission,
        });
    }

    // config-perms
    let config_path = base.join("openclaw.json");
    if config_path.exists() && needs_perm_fix(&config_path, 0o600) {
        fixes.push(FixAction {
            id: "config-perms",
            description: format!("chmod 600 {}", config_path.display()),
            category: FixCategory::Permission,
        });
    }

    // secrets-file-perms
    let secrets_path = base.join("secrets.json");
    if secrets_path.exists() && needs_perm_fix(&secrets_path, 0o600) {
        fixes.push(FixAction {
            id: "secrets-file-perms",
            description: format!("chmod 600 {}", secrets_path.display()),
            category: FixCategory::Permission,
        });
    }

    // creds-perms
    for cred in find_credential_files(base) {
        if needs_perm_fix(&cred, 0o600) {
            fixes.push(FixAction {
                id: "creds-perms",
                description: format!("chmod 600 {}", cred.display()),
                category: FixCategory::Permission,
            });
        }
    }

    // auth-profiles-perms
    for prof in find_auth_profiles(base) {
        if needs_perm_fix(&prof, 0o600) {
            fixes.push(FixAction {
                id: "auth-profiles-perms",
                description: format!("chmod 600 {}", prof.display()),
                category: FixCategory::Permission,
            });
        }
    }

    // transcript-retention: session dirs should be 700
    let agents_dir = base.join("agents");
    if agents_dir.exists() {
        if let Ok(entries) = fs::read_dir(&agents_dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    let sessions = entry.path().join("sessions");
                    if sessions.exists() && needs_perm_fix(&sessions, 0o700) {
                        fixes.push(FixAction {
                            id: "transcript-retention",
                            description: format!("chmod 700 {}", sessions.display()),
                            category: FixCategory::Permission,
                        });
                    }
                }
            }
        }
    }

    // --- config fixes ---
    use crate::utils::config::{get, get_bool, get_str};

    // auth-enabled / auth-mode-token: set gateway.auth.mode to "token"
    if get_str(config, "gateway.auth.mode") != Some("token") {
        fixes.push(FixAction {
            id: "auth-mode-token",
            description: "Set gateway.auth.mode \u{2192} \"token\"".into(),
            category: FixCategory::ConfigSet,
        });
    }

    // auth-token-strength: generate a strong token
    let token = get_str(config, "gateway.auth.token");
    let token_len = token.map(|t| t.len()).unwrap_or(0);
    if token_len < 32 {
        fixes.push(FixAction {
            id: "auth-token-strength",
            description: "Generate new auth token (64 chars)".into(),
            category: FixCategory::TokenGen,
        });
    }

    // bind-loopback
    let bind = get_str(config, "gateway.bind");
    if !(bind.is_none() || bind == Some("loopback")) {
        fixes.push(FixAction {
            id: "bind-loopback",
            description: "Set gateway.bind \u{2192} \"loopback\"".into(),
            category: FixCategory::ConfigSet,
        });
    }

    // tools-deny-dangerous
    let deny_list: Vec<&str> = get(config, "tools.deny")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let dangerous = ["gateway", "cron", "sessions_spawn", "sessions_send"];
    let missing: Vec<&&str> = dangerous.iter().filter(|t| !deny_list.contains(*t)).collect();
    if !missing.is_empty() {
        fixes.push(FixAction {
            id: "tools-deny-dangerous",
            description: format!(
                "Add {} to tools.deny",
                missing.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(", ")
            ),
            category: FixCategory::ConfigSet,
        });
    }

    // elevated-disabled
    if get_bool(config, "tools.elevated.enabled") == Some(true) {
        fixes.push(FixAction {
            id: "elevated-disabled",
            description: "Set tools.elevated.enabled \u{2192} false".into(),
            category: FixCategory::ConfigSet,
        });
    }

    // sandbox-enabled
    if get_str(config, "agents.defaults.sandbox.mode") != Some("all") {
        fixes.push(FixAction {
            id: "sandbox-enabled",
            description: "Set agents.defaults.sandbox.mode \u{2192} \"all\"".into(),
            category: FixCategory::ConfigSet,
        });
    }

    // mdns-minimal
    let mdns = get_str(config, "discovery.mdns.mode");
    if !matches!(mdns, Some("minimal") | Some("off")) {
        fixes.push(FixAction {
            id: "mdns-minimal",
            description: "Set discovery.mdns.mode \u{2192} \"minimal\"".into(),
            category: FixCategory::ConfigSet,
        });
    }

    // logging-redaction
    if get_str(config, "logging.redactSensitive").is_none() {
        fixes.push(FixAction {
            id: "logging-redaction",
            description: "Set logging.redactSensitive \u{2192} \"tools\"".into(),
            category: FixCategory::ConfigSet,
        });
    }

    // browser-ssrf
    if get_bool(config, "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork") != Some(false) {
        fixes.push(FixAction {
            id: "browser-ssrf",
            description: "Set browser.ssrfPolicy.dangerouslyAllowPrivateNetwork \u{2192} false"
                .into(),
            category: FixCategory::ConfigSet,
        });
    }

    // password-not-hardcoded: remove gateway.auth.password
    if get_str(config, "gateway.auth.password").is_some() {
        fixes.push(FixAction {
            id: "password-not-hardcoded",
            description: "Remove hardcoded gateway.auth.password".into(),
            category: FixCategory::ConfigRemove,
        });
    }

    // no-insecure-flags: remove/disable dangerously* flags
    let dangerous_bool_flags = [
        "gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback",
        "gateway.controlUi.dangerouslyDisableDeviceAuth",
        "agents.defaults.sandbox.docker.dangerouslyAllowReservedContainerTargets",
        "agents.defaults.sandbox.docker.dangerouslyAllowExternalBindSources",
        "agents.defaults.sandbox.docker.dangerouslyAllowContainerNamespaceJoin",
    ];
    for flag in &dangerous_bool_flags {
        if get_bool(config, flag) == Some(true) {
            let short = flag.rsplit('.').next().unwrap_or(flag);
            fixes.push(FixAction {
                id: "no-insecure-flags",
                description: format!("Remove dangerous flag: {}", short),
                category: FixCategory::ConfigRemove,
            });
        }
    }

    // dm-scope
    let dm_scope = get_str(config, "session.dmScope");
    if !matches!(dm_scope, Some("per-channel-peer") | Some("per-account-channel-peer")) {
        fixes.push(FixAction {
            id: "dm-scope",
            description: "Set session.dmScope \u{2192} \"per-channel-peer\"".into(),
            category: FixCategory::ConfigSet,
        });
    }

    fixes
}

// ---------------------------------------------------------------------------
// Applying fixes
// ---------------------------------------------------------------------------

fn apply_fix(fix: &FixAction, config: &mut Value, base: &Path, _verbose: bool) -> FixResult {
    match fix.category {
        FixCategory::Permission => apply_permission_fix(fix, base),
        FixCategory::ConfigSet => apply_config_set(fix, config),
        FixCategory::ConfigRemove => apply_config_remove(fix, config),
        FixCategory::TokenGen => apply_token_gen(fix, config),
    }
}

fn apply_permission_fix(fix: &FixAction, _base: &Path) -> FixResult {
    // Parse the path and mode from the description (e.g. "chmod 700 /path")
    let parts: Vec<&str> = fix.description.splitn(3, ' ').collect();
    if parts.len() < 3 {
        return FixResult {
            description: fix.description.clone(),
            success: false,
            message: "internal: could not parse permission fix".into(),
        };
    }
    let mode_str = parts[1];
    let path_str = parts[2];
    let path = Path::new(path_str);

    let mode = u32::from_str_radix(mode_str, 8).unwrap_or(0o600);

    if !path.exists() {
        return FixResult {
            description: fix.description.clone(),
            success: false,
            message: "file not found".into(),
        };
    }

    match fs::set_permissions(path, fs::Permissions::from_mode(mode)) {
        Ok(_) => FixResult {
            description: fix.description.clone(),
            success: true,
            message: String::new(),
        },
        Err(e) => FixResult {
            description: fix.description.clone(),
            success: false,
            message: e.to_string(),
        },
    }
}

fn apply_config_set(fix: &FixAction, config: &mut Value) -> FixResult {
    use crate::utils::config::get;

    let result = match fix.id {
        "auth-mode-token" | "auth-enabled" => {
            set_config_value(config, "gateway.auth.mode", Value::String("token".into()));
            Ok(())
        }
        "bind-loopback" => {
            set_config_value(config, "gateway.bind", Value::String("loopback".into()));
            Ok(())
        }
        "tools-deny-dangerous" => {
            let dangerous = ["gateway", "cron", "sessions_spawn", "sessions_send"];
            let mut merged: Vec<Value> = get(config, "tools.deny")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let existing_strs: Vec<String> = merged
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            for tool in &dangerous {
                if !existing_strs.iter().any(|s| s == *tool) {
                    merged.push(Value::String(tool.to_string()));
                }
            }
            set_config_value(config, "tools.deny", Value::Array(merged));
            Ok(())
        }
        "elevated-disabled" => {
            set_config_value(config, "tools.elevated.enabled", Value::Bool(false));
            Ok(())
        }
        "sandbox-enabled" => {
            set_config_value(
                config,
                "agents.defaults.sandbox.mode",
                Value::String("all".into()),
            );
            Ok(())
        }
        "mdns-minimal" => {
            set_config_value(
                config,
                "discovery.mdns.mode",
                Value::String("minimal".into()),
            );
            Ok(())
        }
        "logging-redaction" => {
            set_config_value(
                config,
                "logging.redactSensitive",
                Value::String("tools".into()),
            );
            Ok(())
        }
        "browser-ssrf" => {
            set_config_value(
                config,
                "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork",
                Value::Bool(false),
            );
            Ok(())
        }
        "dm-scope" => {
            set_config_value(
                config,
                "session.dmScope",
                Value::String("per-channel-peer".into()),
            );
            Ok(())
        }
        _ => Err(format!("unknown config-set fix id: {}", fix.id)),
    };

    match result {
        Ok(_) => FixResult {
            description: fix.description.clone(),
            success: true,
            message: String::new(),
        },
        Err(msg) => FixResult {
            description: fix.description.clone(),
            success: false,
            message: msg,
        },
    }
}

fn apply_config_remove(fix: &FixAction, config: &mut Value) -> FixResult {
    match fix.id {
        "password-not-hardcoded" => {
            remove_config_value(config, "gateway.auth.password");
            FixResult {
                description: fix.description.clone(),
                success: true,
                message: String::new(),
            }
        }
        "no-insecure-flags" => {
            // Parse the flag name from description
            let dangerous_flags = [
                "gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback",
                "gateway.controlUi.dangerouslyDisableDeviceAuth",
                "agents.defaults.sandbox.docker.dangerouslyAllowReservedContainerTargets",
                "agents.defaults.sandbox.docker.dangerouslyAllowExternalBindSources",
                "agents.defaults.sandbox.docker.dangerouslyAllowContainerNamespaceJoin",
            ];
            // Find which flag this is about by matching the short name in description
            for flag in &dangerous_flags {
                let short = flag.rsplit('.').next().unwrap_or(flag);
                if fix.description.contains(short) {
                    remove_config_value(config, flag);
                    return FixResult {
                        description: fix.description.clone(),
                        success: true,
                        message: String::new(),
                    };
                }
            }
            FixResult {
                description: fix.description.clone(),
                success: false,
                message: "could not identify flag to remove".into(),
            }
        }
        _ => FixResult {
            description: fix.description.clone(),
            success: false,
            message: format!("unknown config-remove fix id: {}", fix.id),
        },
    }
}

fn apply_token_gen(_fix: &FixAction, config: &mut Value) -> FixResult {
    let token = generate_hex_token(32);
    set_config_value(config, "gateway.auth.token", Value::String(token));
    FixResult {
        description: "Generated new auth token (64 chars)".into(),
        success: true,
        message: String::new(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn openclaw_base() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".openclaw")
}

fn default_backup_root() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".agent-armor")
        .join("backups")
}

fn ensure_base_dir(base: &Path) -> Result<()> {
    if !base.exists() {
        fs::create_dir_all(base).context("Failed to create ~/.openclaw directory")?;
        fs::set_permissions(base, fs::Permissions::from_mode(0o700))
            .context("Failed to set permissions on ~/.openclaw")?;
    }
    Ok(())
}

fn needs_perm_fix(path: &Path, target: u32) -> bool {
    if !path.exists() {
        return false;
    }
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let current = meta.permissions().mode() & 0o777;
    current != target
}

fn create_backup(base: &Path, backup_root: &Path) -> Result<PathBuf> {
    let ts = Local::now().format("%Y-%m-%d_%H%M%S").to_string();
    let dest = backup_root.join(&ts);
    fs::create_dir_all(&dest).context("Failed to create backup directory")?;

    // Copy openclaw.json if it exists
    let config_src = base.join("openclaw.json");
    if config_src.exists() {
        fs::copy(&config_src, dest.join("openclaw.json"))
            .context("Failed to backup openclaw.json")?;
    }

    // Copy secrets.json if it exists
    let secrets_src = base.join("secrets.json");
    if secrets_src.exists() {
        fs::copy(&secrets_src, dest.join("secrets.json"))
            .context("Failed to backup secrets.json")?;
    }

    Ok(dest)
}

fn generate_hex_token(num_bytes: usize) -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..num_bytes).map(|_| rng.gen()).collect();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Set a value at a dot-separated config path, creating intermediate objects
/// as needed.
fn set_config_value(config: &mut Value, path: &str, value: Value) {
    let keys: Vec<&str> = path.split('.').collect();
    let mut current = config;
    for (i, key) in keys.iter().enumerate() {
        if i == keys.len() - 1 {
            current[*key] = value;
            return;
        }
        if !current.get(*key).map(|v| v.is_object()).unwrap_or(false) {
            current[*key] = Value::Object(serde_json::Map::new());
        }
        current = current.get_mut(*key).unwrap();
    }
}

/// Remove a value at a dot-separated config path.
fn remove_config_value(config: &mut Value, path: &str) {
    let keys: Vec<&str> = path.split('.').collect();
    if keys.is_empty() {
        return;
    }
    if keys.len() == 1 {
        if let Some(obj) = config.as_object_mut() {
            obj.remove(keys[0]);
        }
        return;
    }

    // Navigate to parent
    let mut current = config;
    for key in &keys[..keys.len() - 1] {
        match current.get_mut(*key) {
            Some(v) if v.is_object() => current = v,
            _ => return,
        }
    }
    if let Some(obj) = current.as_object_mut() {
        obj.remove(keys[keys.len() - 1]);
    }
}

/// Write config JSON atomically: write to temp file then rename.
fn write_config_atomic(base: &Path, config: &Value) -> Result<()> {
    let config_path = base.join("openclaw.json");
    let tmp_path = base.join(".openclaw.json.tmp");

    let json = serde_json::to_string_pretty(config).context("Failed to serialize config")?;
    fs::write(&tmp_path, json.as_bytes()).context("Failed to write temp config")?;
    fs::rename(&tmp_path, &config_path).context("Failed to rename temp config")?;

    // Ensure 600 permissions
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
        .context("Failed to set permissions on openclaw.json")?;

    Ok(())
}

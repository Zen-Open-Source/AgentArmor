mod auth;
mod browser_security;
mod control_ui;
mod cve;
mod dangerous_flags;
mod dm_security;
mod exec_security;
mod file_permissions;
mod group_security;
mod logging;
mod mdns;
mod network;
mod plugins;
mod prompt_injection;
mod reverse_proxy;
mod sandbox;
mod secrets;
mod sub_agents;
mod tool_authorization;

use serde_json::Value;
use std::path::Path;
use crate::types::CheckResult;

pub type CheckFn = fn(&Value, &Path) -> Vec<CheckResult>;

pub const ALL_CHECKS: &[CheckFn] = &[
    auth::check,
    file_permissions::check,
    network::check,
    dm_security::check,
    group_security::check,
    tool_authorization::check,
    exec_security::check,
    sandbox::check,
    browser_security::check,
    dangerous_flags::check,
    logging::check,
    mdns::check,
    control_ui::check,
    plugins::check,
    sub_agents::check,
    prompt_injection::check,
    reverse_proxy::check,
    secrets::check,
    cve::check,
];

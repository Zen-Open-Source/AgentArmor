mod checks;

use anyhow::Result;
use dirs::home_dir;
use crate::types::{AgentPlugin, CheckResult};
use crate::utils::config::read_config;

pub struct OpenClawPlugin;

impl AgentPlugin for OpenClawPlugin {
    fn name(&self) -> &'static str {
        "openclaw"
    }

    fn display_name(&self) -> &'static str {
        "OpenClaw"
    }

    fn detect(&self) -> bool {
        base_path().exists()
    }

    fn scan(&self) -> Result<Vec<CheckResult>> {
        let base = base_path();
        let config = read_config(&base)?;
        let mut results = Vec::new();

        for check_fn in checks::ALL_CHECKS {
            results.extend(check_fn(&config, &base));
        }

        Ok(results)
    }
}

fn base_path() -> std::path::PathBuf {
    home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join(".openclaw")
}

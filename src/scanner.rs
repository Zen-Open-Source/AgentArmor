use anyhow::Result;
use chrono::Utc;
use crate::agents::all_plugins;
use crate::types::{CategorySummary, CheckResult, ScanReport};

pub fn run_scan(agent_name: Option<&str>) -> Result<ScanReport> {
    let plugins = all_plugins();

    let plugin = if let Some(name) = agent_name {
        plugins
            .iter()
            .find(|p| p.name() == name)
            .ok_or_else(|| {
                let available: Vec<&str> = plugins.iter().map(|p| p.name()).collect();
                anyhow::anyhow!(
                    "Unknown agent type: \"{}\". Available: {}",
                    name,
                    available.join(", ")
                )
            })?
    } else {
        plugins
            .iter()
            .find(|p| p.detect())
            .ok_or_else(|| {
                let available: Vec<&str> = plugins.iter().map(|p| p.name()).collect();
                anyhow::anyhow!(
                    "No supported AI agent detected. Available scanners: {}",
                    available.join(", ")
                )
            })?
    };

    let checks = plugin.scan()?;
    let categories = build_categories(&checks);
    let score: u32 = checks.iter().map(|c| c.earned).sum();
    let max_score: u32 = checks.iter().map(|c| c.points).sum();
    let normalized = if max_score > 0 {
        ((score as f64 / max_score as f64) * 100.0).round() as u32
    } else {
        0
    };

    Ok(ScanReport {
        agent: plugin.display_name(),
        timestamp: Utc::now().to_rfc3339(),
        normalized_score: normalized,
        score,
        max_score,
        checks,
        categories,
    })
}

fn build_categories(checks: &[CheckResult]) -> Vec<CategorySummary> {
    // Preserve insertion order by tracking seen categories
    let mut order: Vec<&'static str> = Vec::new();
    let mut map: std::collections::HashMap<&'static str, Vec<CheckResult>> =
        std::collections::HashMap::new();

    for check in checks {
        if !map.contains_key(check.category) {
            order.push(check.category);
        }
        map.entry(check.category).or_default().push(check.clone());
    }

    order
        .into_iter()
        .map(|name| {
            let cat_checks = map.remove(name).unwrap_or_default();
            let earned = cat_checks.iter().map(|c| c.earned).sum();
            let possible = cat_checks.iter().map(|c| c.points).sum();
            CategorySummary { name, earned, possible, checks: cat_checks }
        })
        .collect()
}

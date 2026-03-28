use colored::Colorize;
use crate::types::{CheckResult, CheckStatus, ScanReport, Severity};

fn score_color(earned: u32, possible: u32) -> colored::Color {
    if possible == 0 {
        return colored::Color::White;
    }
    let pct = (earned as f32 / possible as f32) * 100.0;
    if pct >= 80.0 {
        colored::Color::Green
    } else if pct >= 60.0 {
        colored::Color::Yellow
    } else {
        colored::Color::Red
    }
}

fn status_icon(status: &CheckStatus) -> colored::ColoredString {
    match status {
        CheckStatus::Pass => "✓".green(),
        CheckStatus::Warn => "⚠".yellow(),
        CheckStatus::Fail => "✗".red(),
    }
}


fn pts_str(check: &CheckResult) -> colored::ColoredString {
    let s = format!("{}/{}", check.earned, check.points);
    if check.status == CheckStatus::Pass {
        s.dimmed()
    } else {
        s.red()
    }
}

pub fn format_report(report: &ScanReport, verbose: bool) -> String {
    let bar = "━".repeat(50);
    let mut lines: Vec<String> = Vec::new();

    lines.push(String::new());
    lines.push(format!("  {}", format!("AgentArmor Security Scan — {}", report.agent).bold()));
    lines.push(format!("  {}", bar.dimmed()));
    lines.push(String::new());

    let color = score_color(report.score, report.max_score);
    let score_str = format!("{}/100", report.normalized_score)
        .color(color)
        .bold()
        .to_string();
    let raw_str = format!("({}/{} pts)", report.score, report.max_score)
        .dimmed()
        .to_string();
    lines.push(format!("  Score: {} {}", score_str, raw_str));
    lines.push(String::new());

    for cat in &report.categories {
        let color = score_color(cat.earned, cat.possible);
        let cat_score = format!("{}/{}", cat.earned, cat.possible).color(color).to_string();
        lines.push(format!(
            "  {}  {}",
            format!("{:<34}", cat.name).bold(),
            cat_score
        ));

        let checks_to_show: Vec<&CheckResult> = if verbose {
            cat.checks.iter().collect()
        } else {
            cat.checks.iter().filter(|c| c.status != CheckStatus::Pass).collect()
        };

        for check in &checks_to_show {
            let icon = status_icon(&check.status);
            let name_padded = format!("{:<38}", check.name);
            lines.push(format!("    {} {} {}", icon, name_padded, pts_str(check)));

            if check.status != CheckStatus::Pass {
                lines.push(format!("      {}", check.message.dimmed()));
            }
            if check.status == CheckStatus::Fail {
                if let Some(fix) = check.fix {
                    lines.push(format!("      {} {}", "Fix:".cyan(), fix));
                }
            }
        }

        if !checks_to_show.is_empty() || verbose {
            lines.push(String::new());
        }
    }

    lines.push(format!("  {}", bar.dimmed()));

    let critical_fails: usize = report
        .checks
        .iter()
        .filter(|c| c.status == CheckStatus::Fail && c.severity == Severity::Critical)
        .count();
    let total_fails: usize = report.checks.iter().filter(|c| c.status == CheckStatus::Fail).count();
    let warnings: usize = report.checks.iter().filter(|c| c.status == CheckStatus::Warn).count();

    let mut parts: Vec<String> = Vec::new();
    if critical_fails > 0 {
        parts.push(format!("{} critical", critical_fails).red().bold().to_string());
    }
    if total_fails - critical_fails > 0 {
        parts.push(format!("{} failed", total_fails - critical_fails).red().to_string());
    }
    if warnings > 0 {
        parts.push(format!("{} warnings", warnings).yellow().to_string());
    }
    if parts.is_empty() {
        parts.push("All checks passed!".green().to_string());
    }

    lines.push(format!("  {}", parts.join(", ")));
    lines.push(String::new());

    if !verbose {
        lines.push(format!("  {}", "Run with --verbose to see all checks".dimmed()));
    }
    lines.push(format!("  {}", "Run with --json for machine-readable output".dimmed()));
    lines.push(String::new());

    lines.join("\n")
}

pub fn format_json(report: &ScanReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_default()
}

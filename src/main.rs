mod agents;
mod fixer;
mod scanner;
mod types;
mod utils;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use utils::report::{format_json, format_report};

#[derive(Parser)]
#[command(name = "agent-armor", about = "Security scanner for AI agents", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan an AI agent installation for security risks
    Scan {
        /// Agent type to scan (default: auto-detect)
        #[arg(long)]
        agent: Option<String>,

        /// Output results as JSON
        #[arg(long)]
        json: bool,

        /// Show all checks including passing ones
        #[arg(long)]
        verbose: bool,
    },

    /// Auto-remediate security issues found by scan
    Fix {
        /// Agent type (default: auto-detect)
        #[arg(long)]
        agent: Option<String>,

        /// Show what would change without modifying anything
        #[arg(long)]
        dry_run: bool,

        /// Prompt before each fix [Y/n]
        #[arg(long)]
        interactive: bool,

        /// Show detailed output
        #[arg(long)]
        verbose: bool,

        /// Custom backup directory (default: ~/.agent-armor/backups/)
        #[arg(long)]
        backup_dir: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { agent, json, verbose } => {
            match scanner::run_scan(agent.as_deref()) {
                Ok(report) => {
                    if json {
                        println!("{}", format_json(&report));
                    } else {
                        print!("{}", format_report(&report, verbose));
                    }

                    let critical_fails = report
                        .checks
                        .iter()
                        .filter(|c| {
                            c.status == types::CheckStatus::Fail
                                && c.severity == types::Severity::Critical
                        })
                        .count();

                    if critical_fails > 0 {
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(2);
                }
            }
        }
        Commands::Fix {
            agent,
            dry_run,
            interactive,
            verbose,
            backup_dir,
        } => {
            let opts = fixer::FixOptions {
                agent,
                dry_run,
                interactive,
                verbose,
                backup_dir,
            };
            if let Err(e) = fixer::run_fix(opts) {
                eprintln!("Error: {}", e);
                std::process::exit(2);
            }
        }
    }
}

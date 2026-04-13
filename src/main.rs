mod agent;
mod config;
mod findings;
mod llm;
mod report;
mod tools;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use tracing_subscriber::EnvFilter;

use crate::agent::react_loop::ReactLoop;
use crate::config::Config;
use crate::findings::db::FindingsDb;
use crate::llm::client::LlmClient;
use crate::report::generator::ReportGenerator;
use crate::tools::registry::ToolRegistry;

fn print_banner() {
    let banner = r#"
    ╔═══════════════════════════════════════════╗
    ║         AgentSpyBoo v0.1.0                ║
    ║   AI Red Team Agent · AMD NPU Powered     ║
    ║         Rust · Zero Cloud · Air-Gap OK     ║
    ╚═══════════════════════════════════════════╝
    "#;
    println!("{}", banner.bright_green());
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::parse();

    // Set up tracing
    let filter = match config.verbose {
        0 => "agentspyboo=info",
        1 => "agentspyboo=debug",
        _ => "agentspyboo=trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .init();

    print_banner();

    println!(
        "{} {}",
        "Target:".bright_yellow(),
        config.target.bright_white()
    );
    println!(
        "{} {}",
        "LLM Endpoint:".bright_yellow(),
        config.llm_url.bright_white()
    );
    println!(
        "{} {}",
        "Model:".bright_yellow(),
        config.model.bright_white()
    );
    println!(
        "{} {}",
        "Max Steps:".bright_yellow(),
        config.max_steps.to_string().bright_white()
    );
    println!();

    // Initialize components
    let db = FindingsDb::new(&config.db_path)?;
    let llm_client = LlmClient::new(&config.llm_url, &config.model);
    let registry = ToolRegistry::new_with_defaults(config.tool_timeout_duration());

    println!(
        "{} {} tools registered",
        "[*]".bright_cyan(),
        registry.tool_count()
    );

    // Print registered tools
    for name in registry.tool_names() {
        println!("    {} {}", ">".bright_green(), name.bright_white());
    }
    println!();

    // Run the ReAct loop
    let mut react_loop = ReactLoop::new(config.clone(), llm_client, registry, db);

    println!(
        "{} Starting autonomous recon on {}",
        "[!]".bright_red(),
        config.target.bright_white()
    );
    println!("{}", "=".repeat(50).bright_yellow());

    let findings = react_loop.run().await?;

    // Generate report
    println!();
    println!(
        "{} Generating report with {} findings...",
        "[*]".bright_cyan(),
        findings.len()
    );

    let generator = ReportGenerator::new();
    let report_content = generator.generate(&config.target, &findings)?;
    std::fs::write(&config.output, &report_content)?;

    println!(
        "{} Report written to {}",
        "[+]".bright_green(),
        config.output.display().to_string().bright_white()
    );
    println!();
    println!(
        "{}",
        "AgentSpyBoo engagement complete.".bright_green().bold()
    );

    Ok(())
}

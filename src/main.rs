// AgentSpyBoo — Phase 3 (CPU-track + Pius org-level preflight)
//
// Multi-step ReAct loop with three chained tools (subfinder -> httpx -> nuclei).
// Optional org-level preflight via Pius (--org flag) discovers domains + CIDRs
// before the agent loop starts. The LLM never sees Pius — it just gets a
// richer subfinder seed list on iteration 1.
//
// Module layout:
//   config       — CLI definition + env var resolution
//   scope        — glob-based target allowlist
//   preflight/   — Pius org-level recon (runs before the agent loop)
//   llm/         — OpenAI-compatible chat client, parser, prompt templates
//   tools/       — ToolKind dispatch + subfinder/httpx/nuclei wrappers
//   findings/    — Severity, Finding, tool-output parsers
//   agent/       — ReAct loop + run/step bookkeeping
//   report/      — markdown report rendering

mod agent;
mod config;
mod findings;
mod llm;
mod preflight;
mod report;
mod scope;
mod tools;

use anyhow::{bail, Result};
use clap::Parser;
use std::io::{self, BufRead, Write};

use crate::agent::run_recon;
use crate::config::{Cli, Cmd};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Recon {
            domain,
            active,
            yes,
            ..
        } => {
            if *active {
                require_active_confirmation(domain, *yes)?;
            }
            run_recon(&cli, domain).await
        }
    }
}

/// When --active is set we send real outbound requests at the target via ffuf.
/// Demand explicit confirmation unless --yes or AGENTSPYBOO_ACTIVE_CONFIRMED=1
/// (so CI / scripted runs don't hang on an interactive prompt).
fn require_active_confirmation(domain: &str, yes_flag: bool) -> Result<()> {
    if yes_flag || std::env::var("AGENTSPYBOO_ACTIVE_CONFIRMED").as_deref() == Ok("1") {
        return Ok(());
    }
    eprintln!();
    eprintln!("================ ACTIVE MODE WARNING ================");
    eprintln!("Target: {domain}");
    eprintln!("ffuf will send real outbound HTTP requests to discover");
    eprintln!("paths. Only run this against scope you are authorized");
    eprintln!("to test (own infra, hackerone scope, etc.).");
    eprintln!("=====================================================");
    eprint!("Type 'yes' to proceed, anything else to abort: ");
    io::stderr().flush().ok();
    let mut line = String::new();
    let stdin = io::stdin();
    stdin.lock().read_line(&mut line)?;
    if line.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        bail!("active mode aborted by user");
    }
}

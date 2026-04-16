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

use anyhow::Result;
use clap::Parser;

use crate::agent::run_recon;
use crate::config::{Cli, Cmd};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Recon { domain, .. } => run_recon(&cli, domain).await,
    }
}

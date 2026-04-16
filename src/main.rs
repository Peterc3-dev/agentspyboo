// AgentSpyBoo — Phase 2 (CPU-track)
//
// Multi-step ReAct loop with three chained tools (subfinder -> httpx -> nuclei).
// Scope allowlist, per-iteration rate limit, severity-rated findings, and a
// markdown report that matches the ai-redteam-reports/ format.
//
// Phase 2 NPU inference (ort + Vitis) — driver unblocked, runtime blocked —
// see PHASE-2-RECON.md. This file is the CPU-track Phase 2.
//
// Module layout (Phase 2.5 refactor):
//   config       — CLI definition + env var resolution
//   scope        — glob-based target allowlist
//   llm/         — OpenAI-compatible chat client, parser, prompt templates
//   tools/       — ToolKind dispatch + subfinder/httpx/nuclei wrappers
//   findings/    — Severity, Finding, tool-output parsers
//   agent/       — ReAct loop + run/step bookkeeping
//   report/      — markdown report rendering

mod agent;
mod config;
mod findings;
mod llm;
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
        Cmd::Recon { domain } => run_recon(&cli, domain).await,
    }
}

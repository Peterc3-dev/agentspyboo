// CLI definition + resolved run config (CLI flag + env var merging).

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "agentspyboo", about = "AI red team agent (Phase 2 CPU)")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,

    /// LLM model ID (env: AGENTSPYBOO_MODEL)
    #[arg(long, global = true)]
    pub model: Option<String>,

    /// LLM API base URL, OpenAI-compatible (env: LEMONADE_BASE_URL)
    #[arg(long, global = true)]
    pub base_url: Option<String>,

    /// Bearer token for the LLM API
    #[arg(long, default_value = "lemonade", global = true)]
    pub api_key: String,

    /// Maximum ReAct iterations (env: AGENTSPYBOO_MAX_ITERS)
    #[arg(long, global = true)]
    pub max_iterations: Option<usize>,

    /// Minimum delay between tool invocations, in ms (env: AGENTSPYBOO_RATE_LIMIT_MS)
    #[arg(long, global = true)]
    pub rate_limit: Option<u64>,

    /// httpx host cap — caps subfinder-fed host list before probing
    #[arg(long, global = true, default_value_t = 150)]
    pub httpx_cap: usize,

    /// Scope allowlist (comma-separated globs, e.g. "example.com,*.example.com").
    /// Default is "<target>,*.<target>".
    #[arg(long, global = true)]
    pub scope: Option<String>,

    /// Verbose step-by-step logging
    #[arg(long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Run a multi-step recon + vuln assessment pass against a domain.
    Recon {
        /// Target domain (e.g. example.com)
        domain: String,
    },
}

/// Resolved config after CLI + env var merging.
pub struct Config {
    pub model: String,
    pub base_url: String,
    pub api_key: String,
    pub max_iterations: usize,
    pub rate_limit_ms: u64,
    pub httpx_cap: usize,
    pub scope_patterns: Vec<String>,
    pub verbose: bool,
}

impl Config {
    pub fn resolve(cli: &Cli, target: &str) -> Self {
        let model = cli
            .model
            .clone()
            .or_else(|| std::env::var("AGENTSPYBOO_MODEL").ok())
            .unwrap_or_else(|| "Qwen3-1.7B-GGUF".to_string());
        let base_url = cli
            .base_url
            .clone()
            .or_else(|| std::env::var("LEMONADE_BASE_URL").ok())
            .unwrap_or_else(|| "http://127.0.0.1:13305/api/v1".to_string());
        let max_iterations = cli
            .max_iterations
            .or_else(|| {
                std::env::var("AGENTSPYBOO_MAX_ITERS")
                    .ok()
                    .and_then(|s| s.parse().ok())
            })
            .unwrap_or(5);
        let rate_limit_ms = cli
            .rate_limit
            .or_else(|| {
                std::env::var("AGENTSPYBOO_RATE_LIMIT_MS")
                    .ok()
                    .and_then(|s| s.parse().ok())
            })
            .unwrap_or(500);
        let scope_patterns: Vec<String> = cli
            .scope
            .clone()
            .unwrap_or_else(|| format!("{target},*.{target}"))
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        Self {
            model,
            base_url,
            api_key: cli.api_key.clone(),
            max_iterations,
            rate_limit_ms,
            httpx_cap: cli.httpx_cap,
            scope_patterns,
            verbose: cli.verbose,
        }
    }
}

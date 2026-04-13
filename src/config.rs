use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug, Clone)]
#[command(name = "agentspyboo")]
#[command(about = "AI-powered autonomous penetration testing agent running on AMD NPU")]
pub struct Config {
    /// Target domain or IP to test
    #[arg(short, long)]
    pub target: String,

    /// LLM API endpoint (OpenAI-compatible)
    #[arg(long, default_value = "http://localhost:8000/v1")]
    pub llm_url: String,

    /// LLM model name
    #[arg(long, default_value = "qwen3-1.7b")]
    pub model: String,

    /// Maximum ReAct loop iterations
    #[arg(long, default_value_t = 50)]
    pub max_steps: usize,

    /// Output report file path
    #[arg(short, long, default_value = "report.md")]
    pub output: PathBuf,

    /// Tool execution timeout in seconds
    #[arg(long, default_value_t = 120)]
    pub tool_timeout: u64,

    /// SQLite database path for findings
    #[arg(long, default_value = "findings.db")]
    pub db_path: PathBuf,

    /// Verbosity level (0=info, 1=debug, 2=trace)
    #[arg(short, long, default_value_t = 0)]
    pub verbose: u8,
}

impl Config {
    pub fn tool_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.tool_timeout)
    }
}

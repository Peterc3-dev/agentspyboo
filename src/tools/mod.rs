pub mod registry;
pub mod subfinder;
pub mod httpx;
pub mod nuclei;
pub mod naabu;
pub mod ffuf;
pub mod gau;
pub mod findomain;
pub mod nmap;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::findings::models::Finding;

/// Output from a tool execution.
#[derive(Debug, Clone)]
pub struct ToolOutput {
    /// Raw stdout from the tool
    pub stdout: String,
    /// Raw stderr from the tool
    pub stderr: String,
    /// Exit code
    pub exit_code: i32,
    /// Parsed findings (if any)
    pub findings: Option<Vec<Finding>>,
    /// Assets discovered (subdomains, URLs, IPs, etc.)
    pub discovered_assets: Vec<String>,
}

impl ToolOutput {
    pub fn success(stdout: String) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            exit_code: 0,
            findings: None,
            discovered_assets: Vec::new(),
        }
    }

    pub fn with_findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings = Some(findings);
        self
    }

    pub fn with_assets(mut self, assets: Vec<String>) -> Self {
        self.discovered_assets = assets;
        self
    }

    pub fn to_display_string(&self) -> String {
        if !self.stdout.is_empty() {
            self.stdout.clone()
        } else if !self.stderr.is_empty() {
            format!("[stderr] {}", self.stderr)
        } else {
            "[no output]".to_string()
        }
    }
}

/// Trait that all recon/attack tools must implement.
#[async_trait]
pub trait Tool: Send + Sync {
    /// Tool name (used in LLM tool calls)
    fn name(&self) -> &str;

    /// Human-readable description
    fn description(&self) -> &str;

    /// JSON Schema describing the parameters this tool accepts.
    /// The LLM uses this to generate valid tool calls.
    fn schema(&self) -> Value;

    /// Execute the tool with the given parameters.
    async fn execute(&self, params: Value) -> Result<ToolOutput>;
}

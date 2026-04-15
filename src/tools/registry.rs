// Tool dispatch enum + per-tool timeout config + the ToolExecution record.

use serde_json::Value;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    Subfinder,
    Httpx,
    Nuclei,
}

impl ToolKind {
    pub fn name(&self) -> &'static str {
        match self {
            ToolKind::Subfinder => "subfinder",
            ToolKind::Httpx => "httpx",
            ToolKind::Nuclei => "nuclei",
        }
    }

    pub fn from_name(n: &str) -> Option<ToolKind> {
        match n.trim().to_lowercase().as_str() {
            "subfinder" => Some(ToolKind::Subfinder),
            "httpx" => Some(ToolKind::Httpx),
            "nuclei" => Some(ToolKind::Nuclei),
            _ => None,
        }
    }

    pub fn timeout(&self) -> Duration {
        match self {
            ToolKind::Subfinder => Duration::from_secs(90),
            ToolKind::Httpx => Duration::from_secs(180),
            ToolKind::Nuclei => Duration::from_secs(900),
        }
    }
}

pub struct ToolExecution {
    #[allow(dead_code)]
    pub tool: ToolKind,
    pub args: Value,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
    pub duration_ms: u128,
}

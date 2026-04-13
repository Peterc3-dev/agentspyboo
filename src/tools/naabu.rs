use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::{Tool, ToolOutput};

pub struct Naabu {
    timeout: Duration,
}

impl Naabu {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait]
impl Tool for Naabu {
    fn name(&self) -> &str {
        "naabu"
    }

    fn description(&self) -> &str {
        "Fast port scanner. Scans targets for open TCP ports using SYN/CONNECT scanning."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP or domain to scan"
                },
                "ports": {
                    "type": "string",
                    "description": "Port range to scan (e.g., '80,443,8080' or '1-1000'). Defaults to top 100 ports."
                },
                "top_ports": {
                    "type": "integer",
                    "description": "Scan top N most common ports (e.g., 100, 1000)"
                }
            },
            "required": ["target"]
        })
    }

    async fn execute(&self, params: Value) -> Result<ToolOutput> {
        let target = params["target"]
            .as_str()
            .context("Missing 'target' parameter")?;

        let mut cmd = Command::new("naabu");
        cmd.arg("-host").arg(target).arg("-silent");

        if let Some(ports) = params["ports"].as_str() {
            cmd.arg("-p").arg(ports);
        } else if let Some(top) = params["top_ports"].as_u64() {
            cmd.arg("-top-ports").arg(top.to_string());
        }

        let output = tokio::time::timeout(self.timeout, cmd.output())
            .await
            .context("naabu timed out")?
            .context("Failed to execute naabu")?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Parse open ports as assets (host:port format)
        let assets: Vec<String> = stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.trim().to_string())
            .collect();

        Ok(ToolOutput {
            stdout,
            stderr,
            exit_code: output.status.code().unwrap_or(-1),
            findings: None,
            discovered_assets: assets,
        })
    }
}

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::{Tool, ToolOutput};

pub struct Httpx {
    timeout: Duration,
}

impl Httpx {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait]
impl Tool for Httpx {
    fn name(&self) -> &str {
        "httpx"
    }

    fn description(&self) -> &str {
        "HTTP probing tool. Takes a list of domains/URLs and probes for live HTTP services, returning status codes, titles, technologies, and more."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "List of domains or URLs to probe"
                },
                "tech_detect": {
                    "type": "boolean",
                    "description": "Enable technology detection",
                    "default": true
                },
                "status_code": {
                    "type": "boolean",
                    "description": "Show status codes in output",
                    "default": true
                }
            },
            "required": ["targets"]
        })
    }

    async fn execute(&self, params: Value) -> Result<ToolOutput> {
        let targets = params["targets"]
            .as_array()
            .context("Missing 'targets' parameter")?;

        let tech_detect = params["tech_detect"].as_bool().unwrap_or(true);
        let status_code = params["status_code"].as_bool().unwrap_or(true);

        // Write targets to a temp file for stdin
        let target_list: String = targets
            .iter()
            .filter_map(|t| t.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        let mut cmd = Command::new("httpx");
        cmd.arg("-silent");

        if tech_detect {
            cmd.arg("-td");
        }
        if status_code {
            cmd.arg("-sc");
        }

        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().context("Failed to spawn httpx")?;

        // Write targets to stdin
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin
                .write_all(target_list.as_bytes())
                .await
                .context("Failed to write to httpx stdin")?;
            drop(stdin);
        }

        let output = tokio::time::timeout(self.timeout, child.wait_with_output())
            .await
            .context("httpx timed out")?
            .context("Failed to wait for httpx")?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Parse live hosts as discovered assets
        let assets: Vec<String> = stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                // httpx output lines can be "https://sub.example.com [200] [Title]"
                // Extract just the URL
                l.split_whitespace()
                    .next()
                    .unwrap_or(l)
                    .trim()
                    .to_string()
            })
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

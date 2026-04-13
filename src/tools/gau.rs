use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::{Tool, ToolOutput};

pub struct Gau {
    timeout: Duration,
}

impl Gau {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait]
impl Tool for Gau {
    fn name(&self) -> &str {
        "gau"
    }

    fn description(&self) -> &str {
        "Fetch known URLs for a domain from the Wayback Machine, Common Crawl, Open Threat Exchange, and URLScan. Useful for discovering endpoints, parameters, and hidden paths."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain to fetch URLs for"
                },
                "providers": {
                    "type": "string",
                    "description": "Comma-separated providers: wayback, commoncrawl, otx, urlscan"
                },
                "blacklist": {
                    "type": "string",
                    "description": "Comma-separated extensions to exclude (e.g., 'png,jpg,gif,css')"
                }
            },
            "required": ["domain"]
        })
    }

    async fn execute(&self, params: Value) -> Result<ToolOutput> {
        let domain = params["domain"]
            .as_str()
            .context("Missing 'domain' parameter")?;

        let mut cmd = Command::new("gau");
        cmd.arg(domain);

        if let Some(providers) = params["providers"].as_str() {
            cmd.arg("--providers").arg(providers);
        }
        if let Some(blacklist) = params["blacklist"].as_str() {
            cmd.arg("--blacklist").arg(blacklist);
        }

        let output = tokio::time::timeout(self.timeout, cmd.output())
            .await
            .context("gau timed out")?
            .context("Failed to execute gau")?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Each line is a URL
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

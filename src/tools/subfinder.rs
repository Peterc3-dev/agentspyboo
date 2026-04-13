use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::{Tool, ToolOutput};

pub struct Subfinder {
    timeout: Duration,
}

impl Subfinder {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait]
impl Tool for Subfinder {
    fn name(&self) -> &str {
        "subfinder"
    }

    fn description(&self) -> &str {
        "Subdomain enumeration tool. Discovers subdomains for a given domain using passive sources (APIs, DNS, certificate transparency)."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain to enumerate subdomains for"
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Enable recursive subdomain enumeration",
                    "default": false
                }
            },
            "required": ["domain"]
        })
    }

    async fn execute(&self, params: Value) -> Result<ToolOutput> {
        let domain = params["domain"]
            .as_str()
            .context("Missing 'domain' parameter")?;

        let recursive = params["recursive"].as_bool().unwrap_or(false);

        let mut cmd = Command::new("subfinder");
        cmd.arg("-d").arg(domain).arg("-silent");

        if recursive {
            cmd.arg("-recursive");
        }

        let output = tokio::time::timeout(self.timeout, cmd.output())
            .await
            .context("subfinder timed out")?
            .context("Failed to execute subfinder")?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Parse discovered subdomains
        let assets: Vec<String> = stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.trim().to_string())
            .collect();

        Ok(ToolOutput {
            stdout: stdout.clone(),
            stderr,
            exit_code: output.status.code().unwrap_or(-1),
            findings: None,
            discovered_assets: assets,
        })
    }
}

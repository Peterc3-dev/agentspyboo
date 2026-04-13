use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::{Tool, ToolOutput};

pub struct Findomain {
    timeout: Duration,
}

impl Findomain {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait]
impl Tool for Findomain {
    fn name(&self) -> &str {
        "findomain"
    }

    fn description(&self) -> &str {
        "Alternative subdomain enumeration tool. Cross-platform subdomain finder using certificate transparency and DNS."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain to enumerate subdomains for"
                }
            },
            "required": ["domain"]
        })
    }

    async fn execute(&self, params: Value) -> Result<ToolOutput> {
        let domain = params["domain"]
            .as_str()
            .context("Missing 'domain' parameter")?;

        let mut cmd = Command::new("findomain");
        cmd.arg("-t").arg(domain).arg("-q"); // quiet mode

        let output = tokio::time::timeout(self.timeout, cmd.output())
            .await
            .context("findomain timed out")?
            .context("Failed to execute findomain")?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

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

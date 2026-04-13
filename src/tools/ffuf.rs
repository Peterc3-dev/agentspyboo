use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::{Tool, ToolOutput};
use crate::findings::models::{Finding, Severity};

pub struct Ffuf {
    timeout: Duration,
}

impl Ffuf {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait]
impl Tool for Ffuf {
    fn name(&self) -> &str {
        "ffuf"
    }

    fn description(&self) -> &str {
        "Web fuzzer for directory/file discovery, parameter fuzzing, and virtual host enumeration. Uses FUZZ keyword as placeholder."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL with FUZZ keyword (e.g., 'https://example.com/FUZZ')"
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist file",
                    "default": "/usr/share/wordlists/dirb/common.txt"
                },
                "extensions": {
                    "type": "string",
                    "description": "File extensions to fuzz (comma-separated, e.g., 'php,html,js')"
                },
                "filter_code": {
                    "type": "string",
                    "description": "Filter out these HTTP status codes (comma-separated, e.g., '404,403')"
                },
                "match_code": {
                    "type": "string",
                    "description": "Only show these HTTP status codes (comma-separated, e.g., '200,301')"
                },
                "rate": {
                    "type": "integer",
                    "description": "Requests per second rate limit",
                    "default": 100
                }
            },
            "required": ["url"]
        })
    }

    async fn execute(&self, params: Value) -> Result<ToolOutput> {
        let url = params["url"]
            .as_str()
            .context("Missing 'url' parameter")?;

        let wordlist = params["wordlist"]
            .as_str()
            .unwrap_or("/usr/share/wordlists/dirb/common.txt");

        let mut cmd = Command::new("ffuf");
        cmd.arg("-u")
            .arg(url)
            .arg("-w")
            .arg(wordlist)
            .arg("-o")
            .arg("/dev/stdout")
            .arg("-of")
            .arg("json")
            .arg("-s"); // silent mode

        if let Some(ext) = params["extensions"].as_str() {
            cmd.arg("-e").arg(ext);
        }
        if let Some(fc) = params["filter_code"].as_str() {
            cmd.arg("-fc").arg(fc);
        }
        if let Some(mc) = params["match_code"].as_str() {
            cmd.arg("-mc").arg(mc);
        }
        if let Some(rate) = params["rate"].as_u64() {
            cmd.arg("-rate").arg(rate.to_string());
        }

        let output = tokio::time::timeout(self.timeout, cmd.output())
            .await
            .context("ffuf timed out")?
            .context("Failed to execute ffuf")?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Parse JSON output for discovered paths
        let mut findings = Vec::new();
        let mut assets = Vec::new();

        if let Ok(json_out) = serde_json::from_str::<Value>(&stdout) {
            if let Some(results) = json_out.get("results").and_then(|r| r.as_array()) {
                for result in results {
                    let input_word = result
                        .pointer("/input/FUZZ")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let status = result.get("status").and_then(|v| v.as_u64()).unwrap_or(0);
                    let length = result.get("length").and_then(|v| v.as_u64()).unwrap_or(0);
                    let result_url = result.get("url").and_then(|v| v.as_str()).unwrap_or("");

                    assets.push(result_url.to_string());

                    // Interesting findings (non-404 paths)
                    let severity = match status {
                        200 => Severity::Info,
                        301 | 302 => Severity::Info,
                        403 => Severity::Low,
                        500..=599 => Severity::Medium,
                        _ => Severity::Info,
                    };

                    findings.push(Finding::new(
                        "ffuf",
                        severity,
                        &format!("Discovered path: /{} (HTTP {})", input_word, status),
                        &format!(
                            "ffuf discovered path /{} returning HTTP {} with content length {}",
                            input_word, status, length
                        ),
                        &format!("URL: {}, Status: {}, Length: {}", result_url, status, length),
                        result_url,
                    ));
                }
            }
        }

        Ok(ToolOutput {
            stdout,
            stderr,
            exit_code: output.status.code().unwrap_or(-1),
            findings: if findings.is_empty() {
                None
            } else {
                Some(findings)
            },
            discovered_assets: assets,
        })
    }
}

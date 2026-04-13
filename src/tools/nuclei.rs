use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::{Tool, ToolOutput};
use crate::findings::models::{Finding, Severity};

pub struct Nuclei {
    timeout: Duration,
}

impl Nuclei {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait]
impl Tool for Nuclei {
    fn name(&self) -> &str {
        "nuclei"
    }

    fn description(&self) -> &str {
        "Vulnerability scanner using YAML templates. Scans targets for known CVEs, misconfigurations, exposed panels, default credentials, and more."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL or domain to scan"
                },
                "templates": {
                    "type": "string",
                    "description": "Specific template or template directory to use (e.g., 'cves/', 'misconfigurations/')"
                },
                "severity": {
                    "type": "string",
                    "description": "Filter by severity: critical, high, medium, low, info",
                    "enum": ["critical", "high", "medium", "low", "info"]
                },
                "tags": {
                    "type": "string",
                    "description": "Filter templates by tags (comma-separated, e.g., 'cve,rce,sqli')"
                }
            },
            "required": ["target"]
        })
    }

    async fn execute(&self, params: Value) -> Result<ToolOutput> {
        let target = params["target"]
            .as_str()
            .context("Missing 'target' parameter")?;

        let mut cmd = Command::new("nuclei");
        cmd.arg("-u").arg(target).arg("-silent").arg("-jsonl");

        if let Some(templates) = params["templates"].as_str() {
            cmd.arg("-t").arg(templates);
        }
        if let Some(severity) = params["severity"].as_str() {
            cmd.arg("-s").arg(severity);
        }
        if let Some(tags) = params["tags"].as_str() {
            cmd.arg("-tags").arg(tags);
        }

        let output = tokio::time::timeout(self.timeout, cmd.output())
            .await
            .context("nuclei timed out")?
            .context("Failed to execute nuclei")?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Parse JSONL output into findings
        let mut findings = Vec::new();
        for line in stdout.lines() {
            if let Ok(entry) = serde_json::from_str::<Value>(line) {
                let severity = entry
                    .pointer("/info/severity")
                    .and_then(|v| v.as_str())
                    .map(Severity::from_str)
                    .unwrap_or(Severity::Info);

                let title = entry
                    .pointer("/info/name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown Finding")
                    .to_string();

                let description = entry
                    .pointer("/info/description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let matched_at = entry
                    .get("matched-at")
                    .and_then(|v| v.as_str())
                    .unwrap_or(target)
                    .to_string();

                let template_id = entry
                    .get("template-id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                findings.push(Finding::new(
                    "nuclei",
                    severity,
                    &title,
                    &description,
                    &format!("Template: {}, Matched at: {}", template_id, matched_at),
                    &matched_at,
                ));
            }
        }

        let result = ToolOutput {
            stdout: stdout.clone(),
            stderr,
            exit_code: output.status.code().unwrap_or(-1),
            findings: if findings.is_empty() {
                None
            } else {
                Some(findings)
            },
            discovered_assets: Vec::new(),
        };

        Ok(result)
    }
}

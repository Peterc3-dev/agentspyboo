use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::{Tool, ToolOutput};
use crate::findings::models::{Finding, Severity};

pub struct Nmap {
    timeout: Duration,
}

impl Nmap {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait]
impl Tool for Nmap {
    fn name(&self) -> &str {
        "nmap"
    }

    fn description(&self) -> &str {
        "Network scanner for port discovery, service detection, OS fingerprinting, and NSE script scanning. More thorough than naabu but slower."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP, hostname, or CIDR range"
                },
                "ports": {
                    "type": "string",
                    "description": "Port specification (e.g., '22,80,443', '1-1000', '-' for all)"
                },
                "scan_type": {
                    "type": "string",
                    "description": "Scan type: 'service' (-sV), 'scripts' (-sC), 'os' (-O), 'aggressive' (-A), 'quick' (-F)",
                    "enum": ["service", "scripts", "os", "aggressive", "quick"],
                    "default": "service"
                },
                "scripts": {
                    "type": "string",
                    "description": "NSE scripts to run (e.g., 'vuln', 'http-enum', 'ssl-cert')"
                }
            },
            "required": ["target"]
        })
    }

    async fn execute(&self, params: Value) -> Result<ToolOutput> {
        let target = params["target"]
            .as_str()
            .context("Missing 'target' parameter")?;

        let scan_type = params["scan_type"].as_str().unwrap_or("service");

        let mut cmd = Command::new("nmap");

        match scan_type {
            "service" => {
                cmd.arg("-sV");
            }
            "scripts" => {
                cmd.arg("-sC");
            }
            "os" => {
                cmd.arg("-O");
            }
            "aggressive" => {
                cmd.arg("-A");
            }
            "quick" => {
                cmd.arg("-F");
            }
            _ => {
                cmd.arg("-sV");
            }
        }

        if let Some(ports) = params["ports"].as_str() {
            cmd.arg("-p").arg(ports);
        }

        if let Some(scripts) = params["scripts"].as_str() {
            cmd.arg("--script").arg(scripts);
        }

        // Output in XML for parsing, but also capture normal output
        cmd.arg("-oN").arg("-"); // normal output to stdout
        cmd.arg(target);

        let output = tokio::time::timeout(self.timeout, cmd.output())
            .await
            .context("nmap timed out")?
            .context("Failed to execute nmap")?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Parse nmap output for open ports and services
        let mut assets = Vec::new();
        let mut findings = Vec::new();

        for line in stdout.lines() {
            let trimmed = line.trim();

            // Match lines like "22/tcp   open  ssh     OpenSSH 8.9p1"
            if trimmed.contains("/tcp") && trimmed.contains("open") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 3 {
                    let port_proto = parts[0]; // e.g., "22/tcp"
                    let service = parts.get(2).unwrap_or(&"unknown");

                    assets.push(format!("{}:{}", target, port_proto.split('/').next().unwrap_or("0")));

                    // Flag potentially risky services
                    let severity = match *service {
                        "ftp" | "telnet" | "rsh" | "rlogin" => Severity::Medium,
                        "ms-sql-s" | "mysql" | "postgresql" | "mongodb" => Severity::Medium,
                        "snmp" => Severity::Low,
                        _ => Severity::Info,
                    };

                    if severity != Severity::Info {
                        findings.push(Finding::new(
                            "nmap",
                            severity,
                            &format!("Exposed service: {} on {}", service, port_proto),
                            &format!(
                                "Service {} is exposed on {}. Full line: {}",
                                service, port_proto, trimmed
                            ),
                            trimmed,
                            target,
                        ));
                    }
                }
            }

            // Detect VULNERS/vuln script output
            if trimmed.contains("VULNERABLE") || trimmed.contains("CVE-") {
                findings.push(Finding::new(
                    "nmap",
                    Severity::High,
                    &format!("Nmap script finding: {}", truncate_str(trimmed, 100)),
                    trimmed,
                    trimmed,
                    target,
                ));
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

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

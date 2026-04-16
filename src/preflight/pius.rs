use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::Stdio;
use tokio::process::Command;

use crate::scope::host_in_scope;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PiusRecord {
    r#type: String,
    value: String,
    source: String,
    data: Value,
}

impl PiusRecord {
    fn confidence(&self) -> Option<f64> {
        self.data.get("confidence").and_then(|v| v.as_f64())
    }

    fn needs_review(&self) -> Option<bool> {
        self.data.get("needs_review").and_then(|v| v.as_bool())
    }

    fn asn(&self) -> Option<&str> {
        self.data.get("asn").and_then(|v| v.as_str())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PiusDomain {
    pub host: String,
    pub sources: Vec<String>,
    pub confidence: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PiusCidr {
    pub cidr: String,
    pub source: String,
    pub asn: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PiusGithubOrg {
    pub login: String,
    pub name: String,
    pub confidence: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct PiusResult {
    pub domains: Vec<PiusDomain>,
    pub cidrs: Vec<PiusCidr>,
    pub github_orgs: Vec<PiusGithubOrg>,
    pub total_raw: usize,
    pub filtered_out: usize,
    pub plugins_fired: Vec<String>,
    pub runtime_secs: f64,
}

fn locate_pius() -> Result<String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/raz".into());

    // Check PATH first
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("pius");
            if candidate.is_file() {
                return Ok(candidate.to_string_lossy().into_owned());
            }
        }
    }

    // Fall back to known locations
    let candidates = [
        format!("{home}/.openclaw/workspace/pius-scout/bin/pius"),
        format!("{home}/.openclaw/workspace/pius/bin/pius"),
        format!("{home}/go/bin/pius"),
    ];
    for c in &candidates {
        if std::path::Path::new(c).exists() {
            return Ok(c.clone());
        }
    }
    Err(anyhow!("pius binary not found on PATH or common locations"))
}

pub async fn run_pius(
    org: &str,
    domain_hint: Option<&str>,
    asn_hint: Option<&str>,
    scope_patterns: &[String],
    verbose: bool,
) -> Result<PiusResult> {
    let bin = locate_pius()?;
    let start = std::time::Instant::now();

    let mut cmd = Command::new(&bin);
    cmd.arg("run")
        .arg("--org").arg(org)
        .arg("--mode").arg("passive")
        .arg("--output").arg("ndjson");

    if let Some(d) = domain_hint {
        cmd.arg("--domain").arg(d);
    }
    if let Some(a) = asn_hint {
        cmd.arg("--asn").arg(a);
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    if verbose {
        println!("[preflight] running: pius run --org {org:?} --mode passive --output ndjson");
    }

    let child = cmd.spawn().context("failed to spawn pius")?;
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| anyhow!("pius timed out after 5 minutes"))?
    .context("pius process error")?;

    let runtime_secs = start.elapsed().as_secs_f64();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if verbose && !stderr.is_empty() {
        for line in stderr.lines().take(10) {
            println!("[preflight] pius: {line}");
        }
    }

    let mut domain_map: std::collections::BTreeMap<String, PiusDomain> =
        std::collections::BTreeMap::new();
    let mut cidrs: Vec<PiusCidr> = Vec::new();
    let mut github_orgs: Vec<PiusGithubOrg> = Vec::new();
    let mut total_raw = 0;
    let mut filtered_out = 0;
    let mut plugins_seen = std::collections::HashSet::new();

    for line in stdout.as_ref().lines() {
        let record: PiusRecord = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                if verbose {
                    eprintln!("[preflight] skip malformed line: {e}");
                }
                continue;
            }
        };
        total_raw += 1;
        plugins_seen.insert(record.source.clone());

        match record.r#type.as_str() {
            "preseed" => {
                filtered_out += 1;
                continue;
            }
            "cidr" => {
                cidrs.push(PiusCidr {
                    cidr: record.value.clone(),
                    source: record.source.clone(),
                    asn: record.asn().map(String::from),
                });
            }
            "domain" => {
                if record.needs_review().unwrap_or(false)
                    && record.confidence().unwrap_or(1.0) < 0.5
                {
                    filtered_out += 1;
                    continue;
                }
                if record.value.contains(' ') {
                    filtered_out += 1;
                    continue;
                }
                if record.value.contains('/') {
                    if record.source == "github-org" {
                        let login = record.value.rsplit('/').next().unwrap_or("").to_string();
                        let name = record
                            .data
                            .get("github_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        github_orgs.push(PiusGithubOrg {
                            login,
                            name,
                            confidence: record.confidence(),
                        });
                    }
                    filtered_out += 1;
                    continue;
                }
                if !host_in_scope(&record.value, scope_patterns) {
                    if verbose {
                        println!(
                            "[preflight] out of scope: {} (from {})",
                            record.value, record.source
                        );
                    }
                    filtered_out += 1;
                    continue;
                }
                let entry = domain_map
                    .entry(record.value.clone())
                    .or_insert_with(|| PiusDomain {
                        host: record.value.clone(),
                        sources: Vec::new(),
                        confidence: None,
                    });
                if !entry.sources.contains(&record.source) {
                    entry.sources.push(record.source.clone());
                }
                // Keep the highest confidence seen for this host.
                entry.confidence = match (entry.confidence, record.confidence()) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (Some(a), None) => Some(a),
                    (None, b) => b,
                };
            }
            other => {
                if verbose {
                    println!("[preflight] unknown type {other:?}, skipping");
                }
                filtered_out += 1;
            }
        }
    }

    let domains: Vec<PiusDomain> = domain_map.into_values().collect();

    let mut plugins_fired: Vec<String> = plugins_seen.into_iter().collect();
    plugins_fired.sort();

    if verbose {
        println!(
            "[preflight] pius done in {runtime_secs:.1}s: {} raw, {} filtered, {} domains, {} CIDRs, {} github orgs",
            total_raw, filtered_out, domains.len(), cidrs.len(), github_orgs.len()
        );
    }

    Ok(PiusResult {
        domains,
        cidrs,
        github_orgs,
        total_raw,
        filtered_out,
        plugins_fired,
        runtime_secs,
    })
}

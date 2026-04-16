// Tool-output parsers that produce Finding rows + caches for the ReAct loop.

use super::models::{Finding, Severity};
use crate::scope::normalize_host;
use serde_json::Value;

pub fn extract_hosts_from_subfinder(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Parse httpx -json output into (live URLs, finding rows).
pub fn parse_httpx_output(stdout: &str) -> (Vec<String>, Vec<Finding>) {
    let mut live_urls: Vec<String> = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let url = v
            .get("url")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let host = v
            .get("host")
            .and_then(|x| x.as_str())
            .map(String::from)
            .unwrap_or_else(|| normalize_host(&url));
        let status = v
            .get("status_code")
            .and_then(|x| x.as_i64())
            .unwrap_or(0);
        let title = v.get("title").and_then(|x| x.as_str()).unwrap_or("");
        let tech: Vec<String> = v
            .get("tech")
            .and_then(|t| t.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if !url.is_empty() {
            live_urls.push(url.clone());
        }
        // Severity rules for httpx: info by default; low if non-standard tech
        // disclosed; bump to medium if title hints at auth/admin/login panel.
        let title_l = title.to_lowercase();
        let admin_hint = ["admin", "login", "sign in", "dashboard", "phpmyadmin"]
            .iter()
            .any(|k| title_l.contains(k));
        let sev = if admin_hint {
            Severity::Medium
        } else if !tech.is_empty() {
            Severity::Low
        } else {
            Severity::Info
        };
        let details = format!(
            "status={} title=\"{}\" tech=[{}]",
            status,
            title.chars().take(80).collect::<String>(),
            tech.join(", ")
        );
        findings.push(Finding::new(
            sev,
            "http-probe",
            host,
            details,
        ));
    }
    (live_urls, findings)
}

/// Parse nuclei -jsonl output → findings.
pub fn parse_nuclei_output(stdout: &str) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let info = v.get("info").cloned().unwrap_or(serde_json::json!({}));
        let sev_str = info
            .get("severity")
            .and_then(|x| x.as_str())
            .unwrap_or("info");
        let name = info
            .get("name")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string();
        let template_id = v
            .get("template-id")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let matched = v
            .get("matched-at")
            .and_then(|x| x.as_str())
            .or_else(|| v.get("host").and_then(|x| x.as_str()))
            .unwrap_or("")
            .to_string();
        let details = format!("{name} [{template_id}]");
        out.push(Finding::new(
            Severity::from_str_loose(sev_str),
            "nuclei",
            matched,
            details,
        ));
    }
    out
}

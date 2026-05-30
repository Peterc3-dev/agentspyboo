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
        let status = v.get("status_code").and_then(|x| x.as_i64()).unwrap_or(0);
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
        findings.push(Finding::new(sev, "http-probe", host, details));
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
        let template_id = v.get("template-id").and_then(|x| x.as_str()).unwrap_or("");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subfinder_extraction_trims_and_drops_blanks() {
        let stdout = "  api.example.com  \n\nexample.com\n   \nwww.example.com\n";
        let hosts = extract_hosts_from_subfinder(stdout);
        assert_eq!(
            hosts,
            vec![
                "api.example.com".to_string(),
                "example.com".to_string(),
                "www.example.com".to_string(),
            ]
        );
    }

    #[test]
    fn httpx_parses_url_status_and_severity() {
        let stdout = concat!(
            r#"{"url":"https://example.com","host":"example.com","status_code":200,"title":"Home","tech":["nginx"]}"#,
            "\n",
            r#"{"url":"https://example.com/admin","host":"example.com","status_code":401,"title":"Admin Login"}"#,
            "\n",
            r#"{"url":"https://example.com/plain","host":"example.com","status_code":200,"title":""}"#,
            "\n",
            "not json, should be skipped\n",
        );
        let (urls, findings) = parse_httpx_output(stdout);
        assert_eq!(
            urls,
            vec![
                "https://example.com".to_string(),
                "https://example.com/admin".to_string(),
                "https://example.com/plain".to_string(),
            ]
        );
        assert_eq!(findings.len(), 3);
        // tech disclosed but no admin hint -> Low
        assert_eq!(findings[0].severity, Severity::Low);
        // admin/login title -> Medium
        assert_eq!(findings[1].severity, Severity::Medium);
        // no tech, no admin hint -> Info
        assert_eq!(findings[2].severity, Severity::Info);
        assert_eq!(findings[0].kind, "http-probe");
    }

    #[test]
    fn httpx_derives_host_from_url_when_absent() {
        let stdout = r#"{"url":"https://derived.example.com:8443/x","status_code":200}"#;
        let (_urls, findings) = parse_httpx_output(stdout);
        assert_eq!(findings.len(), 1);
        // host field missing -> normalized from url (scheme/port/path stripped)
        assert_eq!(findings[0].target, "derived.example.com");
    }

    #[test]
    fn nuclei_parses_severity_name_and_target() {
        let stdout = concat!(
            r#"{"template-id":"CVE-2021-1234","info":{"name":"Example RCE","severity":"critical"},"matched-at":"https://example.com/x"}"#,
            "\n",
            r#"{"template-id":"tech-detect","info":{"name":"Tech Detect","severity":"info"},"host":"example.com"}"#,
            "\n",
            "garbage\n",
        );
        let findings = parse_nuclei_output(stdout);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].target, "https://example.com/x");
        assert_eq!(findings[0].details, "Example RCE [CVE-2021-1234]");
        // falls back to "host" when "matched-at" absent
        assert_eq!(findings[1].target, "example.com");
        assert_eq!(findings[1].severity, Severity::Info);
    }

    #[test]
    fn nuclei_defaults_unknown_fields_gracefully() {
        let stdout = r#"{"template-id":"t1"}"#;
        let findings = parse_nuclei_output(stdout);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].details, "unknown [t1]");
    }
}

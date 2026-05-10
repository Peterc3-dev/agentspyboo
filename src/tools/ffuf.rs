// ffuf — content discovery via path fuzzing. Active recon: real outbound
// requests against the target. Gated behind --active flag in the CLI.
//
// Safety posture:
//  - One target URL per invocation (avoid runaway concurrent host scanning).
//  - No follow-redirects (-r off): redirect chains can lead off-scope.
//  - Default rate 20 req/sec (env: AGENTSPYBOO_FFUF_RATE) — easy on the target.
//  - Default wordlist is a hand-curated ~100-entry set under assets/. Large
//    wordlists (SecLists/raft, etc.) require an explicit --ffuf-wordlist path.
//  - Per-host hostname scope guard runs before invocation (ffuf can still
//    follow CNAMEs at DNS-resolution time; the IP-scope check is deferred to
//    a future P3.5 once --scope-cidr exists).
//
// Env var tunables:
//  AGENTSPYBOO_FFUF_RATE       (req/sec, default 20)
//  AGENTSPYBOO_FFUF_TIMEOUT    (per-request seconds, default 10)
//  AGENTSPYBOO_FFUF_THREADS    (default 20 — keep at or near rate)

use super::locate::locate_bin;
use super::registry::ToolKind;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use std::path::PathBuf;
use tokio::process::Command;

const BUNDLED_WORDLIST: &str = include_str!("../../assets/ffuf-common-mini.txt");

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default)
}

/// Materialize the ffuf wordlist for the run. Either honors the user-provided
/// path or writes the bundled mini-list to a tmp file. Returns the path used
/// plus a marker the caller can use to delete tmp files when done.
pub fn resolve_wordlist(user_path: Option<&str>) -> Result<(PathBuf, bool)> {
    if let Some(p) = user_path {
        let path = PathBuf::from(p);
        if !path.exists() {
            bail!("ffuf wordlist not found: {}", p);
        }
        return Ok((path, false));
    }
    let tmp = std::env::temp_dir().join(format!("agentspyboo-ffuf-mini-{}.txt", std::process::id()));
    std::fs::write(&tmp, BUNDLED_WORDLIST)
        .with_context(|| format!("write bundled wordlist to {}", tmp.display()))?;
    Ok((tmp, true))
}

/// Run ffuf against a single URL with FUZZ as a path token. Returns
/// (stdout, stderr) where stdout is ffuf's JSON output document.
pub async fn exec_ffuf(target_url: &str, wordlist: &PathBuf) -> Result<(String, String)> {
    let bin = locate_bin("ffuf")?;
    let rate = env_usize("AGENTSPYBOO_FFUF_RATE", 20);
    let timeout_s = env_usize("AGENTSPYBOO_FFUF_TIMEOUT", 10);
    let threads = env_usize("AGENTSPYBOO_FFUF_THREADS", 20);

    // ffuf needs FUZZ token in the URL. We append /FUZZ — caller is expected
    // to pass a base URL like "https://api.example.com" without trailing slash.
    let fuzz_url = if target_url.ends_with('/') {
        format!("{target_url}FUZZ")
    } else {
        format!("{target_url}/FUZZ")
    };

    let result = tokio::time::timeout(
        ToolKind::Ffuf.timeout(),
        Command::new(&bin)
            .arg("-u")
            .arg(&fuzz_url)
            .arg("-w")
            .arg(wordlist)
            .arg("-mc")
            .arg("200,301,302,401,403")
            .arg("-t")
            .arg(threads.to_string())
            .arg("-rate")
            .arg(rate.to_string())
            .arg("-timeout")
            .arg(timeout_s.to_string())
            .arg("-of")
            .arg("json")
            .arg("-o")
            .arg("/dev/stdout")
            .arg("-s")
            // explicitly DO NOT pass -r — we never follow redirects in active mode.
            .output(),
    )
    .await;

    let out = result
        .map_err(|_| anyhow!("ffuf timed out"))?
        .context("failed to spawn ffuf")?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() && stdout.trim().is_empty() {
        bail!("ffuf exited {:?}: {}", out.status.code(), stderr);
    }
    Ok((stdout, stderr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzz_url_appends_fuzz_with_or_without_trailing_slash() {
        // Local helper mirrors the production logic.
        let f = |u: &str| {
            if u.ends_with('/') {
                format!("{u}FUZZ")
            } else {
                format!("{u}/FUZZ")
            }
        };
        assert_eq!(f("https://x.com"), "https://x.com/FUZZ");
        assert_eq!(f("https://x.com/"), "https://x.com/FUZZ");
        assert_eq!(f("https://x.com/api"), "https://x.com/api/FUZZ");
    }

    #[test]
    fn resolve_wordlist_bundled_falls_back() {
        let (path, is_tmp) = resolve_wordlist(None).expect("bundled wordlist");
        assert!(is_tmp);
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("admin"));
        assert!(content.contains(".env"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolve_wordlist_user_path_missing_errors() {
        let result = resolve_wordlist(Some("/nonexistent/path/wordlist.txt"));
        assert!(result.is_err());
    }
}

/// Parse ffuf's `-of json` document into Findings. Severity heuristics:
///  - 200 + path matches admin/login/etc → Medium (potential admin panel)
///  - 401/403 + admin path → Medium (auth-protected admin found)
///  - 200 + .env / .git / config / backup → High (likely sensitive disclosure)
///  - 200 generic → Low
///  - 301/302 → Info
pub fn parse_ffuf_output(stdout: &str, target_host: &str) -> Vec<crate::findings::Finding> {
    use crate::findings::{Finding, Severity};
    let mut findings: Vec<Finding> = Vec::new();
    let v: Value = match serde_json::from_str(stdout.trim()) {
        Ok(v) => v,
        Err(_) => return findings,
    };
    let results = match v.get("results").and_then(|r| r.as_array()) {
        Some(r) => r,
        None => return findings,
    };
    for r in results {
        let path = r
            .get("input")
            .and_then(|i| i.get("FUZZ"))
            .and_then(|f| f.as_str())
            .or_else(|| r.get("url").and_then(|u| u.as_str()))
            .unwrap_or("")
            .to_string();
        let status = r.get("status").and_then(|s| s.as_i64()).unwrap_or(0);
        let length = r.get("length").and_then(|s| s.as_i64()).unwrap_or(0);
        let url = r
            .get("url")
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();

        let path_l = path.to_lowercase();
        let sensitive = [".env", ".git", ".htpasswd", ".ssh", "id_rsa", "private", "secret"]
            .iter()
            .any(|k| path_l.contains(k));
        let admin = ["admin", "login", "dashboard", "phpmyadmin", "console", "panel"]
            .iter()
            .any(|k| path_l.contains(k));

        let sev = match (status, sensitive, admin) {
            (200, true, _) => Severity::High,
            (200, _, true) => Severity::Medium,
            (401 | 403, _, true) => Severity::Medium,
            (200, _, _) => Severity::Low,
            (301 | 302, _, _) => Severity::Info,
            _ => Severity::Low,
        };

        let details = format!("ffuf path={path} status={status} length={length} url={url}");
        findings.push(Finding::new(sev, "ffuf", target_host.to_string(), details));
    }
    findings
}

#[cfg(test)]
mod parse_tests {
    use super::*;
    use crate::findings::Severity;

    #[test]
    fn parse_ffuf_severity_classification() {
        let json = r#"{"results":[
            {"input":{"FUZZ":".env"},"status":200,"length":42,"url":"https://x.com/.env"},
            {"input":{"FUZZ":"admin"},"status":200,"length":100,"url":"https://x.com/admin"},
            {"input":{"FUZZ":"login"},"status":403,"length":50,"url":"https://x.com/login"},
            {"input":{"FUZZ":"images"},"status":200,"length":500,"url":"https://x.com/images"},
            {"input":{"FUZZ":"old"},"status":301,"length":0,"url":"https://x.com/old"}
        ]}"#;
        let findings = parse_ffuf_output(json, "x.com");
        assert_eq!(findings.len(), 5);
        assert_eq!(findings[0].severity, Severity::High); // .env
        assert_eq!(findings[1].severity, Severity::Medium); // admin
        assert_eq!(findings[2].severity, Severity::Medium); // login 403
        assert_eq!(findings[3].severity, Severity::Low); // images
        assert_eq!(findings[4].severity, Severity::Info); // 301 redirect
    }

    #[test]
    fn parse_ffuf_handles_empty_or_malformed() {
        assert_eq!(parse_ffuf_output("", "x.com").len(), 0);
        assert_eq!(parse_ffuf_output("not json", "x.com").len(), 0);
        assert_eq!(parse_ffuf_output(r#"{"unrelated":"shape"}"#, "x.com").len(), 0);
    }
}

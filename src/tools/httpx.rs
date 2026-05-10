// httpx — HTTP probe over discovered hosts. Writes the host list to a temp
// file because httpx is happier with -l than with -stdin for large inputs.
//
// Flags tuned in Phase 4 P1.2 for reliability:
//  - timeout 15s (default 10s — too tight for slow/high-latency endpoints)
//  - retries 2 (default 0 — single dropped connection was scoring hosts dead)
//  - follow-redirects on (default off — 301/302 to canonical host was
//    recording the original subdomain as non-responsive)
// Threads stays at httpx's default of 50 (already aggressive enough).
//
// Overridable via env vars:
//  AGENTSPYBOO_HTTPX_TIMEOUT   (seconds, default 15)
//  AGENTSPYBOO_HTTPX_RETRIES   (count,   default 2)
//  AGENTSPYBOO_HTTPX_THREADS   (count,   default 50)

use super::locate::locate_bin;
use super::registry::ToolKind;
use anyhow::{anyhow, bail, Context, Result};
use tokio::process::Command;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default)
}

pub async fn exec_httpx(hosts: &[String], cap: usize) -> Result<(String, String)> {
    if hosts.is_empty() {
        return Ok((String::new(), "no hosts to probe".into()));
    }
    let bin = locate_bin("httpx")?;
    let capped: Vec<String> = hosts.iter().take(cap).cloned().collect();
    let tmp = std::env::temp_dir().join(format!("agentspyboo-httpx-{}.txt", std::process::id()));
    std::fs::write(&tmp, capped.join("\n")).context("write httpx input")?;

    let timeout_s = env_usize("AGENTSPYBOO_HTTPX_TIMEOUT", 15);
    let retries = env_usize("AGENTSPYBOO_HTTPX_RETRIES", 2);
    let threads = env_usize("AGENTSPYBOO_HTTPX_THREADS", 50);

    let result = tokio::time::timeout(
        ToolKind::Httpx.timeout(),
        Command::new(&bin)
            .arg("-silent")
            .arg("-status-code")
            .arg("-title")
            .arg("-tech-detect")
            .arg("-json")
            .arg("-follow-redirects")
            .arg("-timeout")
            .arg(timeout_s.to_string())
            .arg("-retries")
            .arg(retries.to_string())
            .arg("-threads")
            .arg(threads.to_string())
            .arg("-l")
            .arg(&tmp)
            .output(),
    )
    .await;
    let _ = std::fs::remove_file(&tmp);
    let out = result
        .map_err(|_| anyhow!("httpx timed out"))?
        .context("failed to spawn httpx")?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() && stdout.trim().is_empty() {
        bail!("httpx exited {:?}: {}", out.status.code(), stderr);
    }
    Ok((stdout, stderr))
}

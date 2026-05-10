// dnsx — DNS resolution filter between subfinder and httpx. Drops
// NXDOMAIN/SERVFAIL subdomains so httpx doesn't burn timeout+retries on
// hosts with no public DNS. Preserves CNAME-only hosts via -cname.

use super::locate::locate_bin;
use super::registry::DNSX_TIMEOUT;
use anyhow::{anyhow, bail, Context, Result};
use tokio::process::Command;

pub async fn exec_dnsx(hosts: &[String]) -> Result<(String, String)> {
    if hosts.is_empty() {
        return Ok((String::new(), "no hosts to resolve".into()));
    }
    let bin = locate_bin("dnsx")?;
    let tmp = std::env::temp_dir().join(format!("agentspyboo-dnsx-{}.txt", std::process::id()));
    std::fs::write(&tmp, hosts.join("\n")).context("write dnsx input")?;
    let threads = std::env::var("AGENTSPYBOO_DNSX_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100);
    let result = tokio::time::timeout(
        DNSX_TIMEOUT,
        Command::new(&bin)
            .arg("-silent")
            .arg("-a")
            .arg("-aaaa")
            .arg("-cname")
            .arg("-l")
            .arg(&tmp)
            .arg("-t")
            .arg(threads.to_string())
            .output(),
    )
    .await;
    let _ = std::fs::remove_file(&tmp);
    let out = result
        .map_err(|_| anyhow!("dnsx timed out"))?
        .context("failed to spawn dnsx")?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() && stdout.trim().is_empty() {
        bail!("dnsx exited {:?}: {}", out.status.code(), stderr);
    }
    Ok((stdout, stderr))
}

/// Parse dnsx `-silent` output into a resolved-host list. Takes the first
/// whitespace-delimited token per line so this stays robust whether dnsx
/// emits bare hostnames or `host [record]` pairs.
pub fn parse_dnsx_output(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(|s| s.trim_end_matches('.').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

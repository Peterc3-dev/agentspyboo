// httpx — HTTP probe over discovered hosts. Writes the host list to a temp
// file because httpx is happier with -l than with -stdin for large inputs.

use super::locate::locate_bin;
use super::registry::ToolKind;
use anyhow::{anyhow, bail, Context, Result};
use tokio::process::Command;

pub async fn exec_httpx(hosts: &[String], cap: usize) -> Result<(String, String)> {
    if hosts.is_empty() {
        return Ok((String::new(), "no hosts to probe".into()));
    }
    let bin = locate_bin("httpx")?;
    let capped: Vec<String> = hosts.iter().take(cap).cloned().collect();
    let tmp = std::env::temp_dir().join(format!("agentspyboo-httpx-{}.txt", std::process::id()));
    std::fs::write(&tmp, capped.join("\n")).context("write httpx input")?;
    let result = tokio::time::timeout(
        ToolKind::Httpx.timeout(),
        Command::new(&bin)
            .arg("-silent")
            .arg("-status-code")
            .arg("-title")
            .arg("-tech-detect")
            .arg("-json")
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

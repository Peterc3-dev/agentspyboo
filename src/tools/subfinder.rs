// subfinder — passive subdomain enumeration via projectdiscovery's Go binary.

use super::locate::locate_bin;
use super::registry::ToolKind;
use anyhow::{anyhow, bail, Context, Result};
use tokio::process::Command;

pub async fn exec_subfinder(domain: &str) -> Result<(String, String)> {
    let bin = locate_bin("subfinder")?;
    let out = tokio::time::timeout(
        ToolKind::Subfinder.timeout(),
        Command::new(&bin)
            .arg("-d")
            .arg(domain)
            .arg("-silent")
            .output(),
    )
    .await
    .map_err(|_| anyhow!("subfinder timed out"))?
    .context("failed to spawn subfinder")?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() && stdout.trim().is_empty() {
        bail!("subfinder exited {:?}: {}", out.status.code(), stderr);
    }
    Ok((stdout, stderr))
}

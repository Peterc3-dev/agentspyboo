// nuclei — templated vulnerability scan. Resolves the templates root and
// picks a curated subset of template dirs (cves, exposures, misconfiguration,
// vulnerabilities) to keep scan time bounded.

use super::locate::locate_bin;
use super::registry::ToolKind;
use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;
use tokio::process::Command;

/// Resolve the nuclei-templates root. Prefer ~/nuclei-templates, fall back to
/// ~/.nuclei-templates. Return None if neither exists — the caller should warn.
pub fn nuclei_templates_root() -> Option<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/raz".into());
    for rel in ["nuclei-templates", ".nuclei-templates"] {
        let p = PathBuf::from(&home).join(rel);
        if p.is_dir() {
            return Some(p);
        }
    }
    None
}

pub async fn exec_nuclei(urls: &[String]) -> Result<(String, String)> {
    if urls.is_empty() {
        return Ok((String::new(), "no urls to scan".into()));
    }
    let bin = locate_bin("nuclei")?;
    let root = nuclei_templates_root()
        .ok_or_else(|| anyhow!("nuclei-templates not found at ~/nuclei-templates. Run `nuclei -update-templates` once before using Phase 2."))?;

    // Resolve template subdirs. Nuclei stores everything under http/ in modern layouts.
    let mut tmpl_args: Vec<String> = Vec::new();
    for sub in ["cves", "exposures", "misconfiguration", "vulnerabilities"] {
        let http_form = root.join("http").join(sub);
        let flat_form = root.join(sub);
        let path = if http_form.is_dir() {
            http_form
        } else if flat_form.is_dir() {
            flat_form
        } else {
            continue;
        };
        tmpl_args.push("-t".to_string());
        tmpl_args.push(path.to_string_lossy().into_owned());
    }
    if tmpl_args.is_empty() {
        bail!("no curated nuclei template dirs exist under {}", root.display());
    }

    let tmp = std::env::temp_dir().join(format!("agentspyboo-nuclei-{}.txt", std::process::id()));
    std::fs::write(&tmp, urls.join("\n")).context("write nuclei input")?;

    let mut cmd = Command::new(&bin);
    cmd.arg("-l").arg(&tmp);
    for a in &tmpl_args {
        cmd.arg(a);
    }
    cmd.arg("-severity")
        .arg("medium,high,critical")
        .arg("-jsonl")
        .arg("-silent")
        .arg("-disable-update-check")
        .arg("-no-interactsh");

    let result = tokio::time::timeout(ToolKind::Nuclei.timeout(), cmd.output()).await;
    let _ = std::fs::remove_file(&tmp);
    let out = result
        .map_err(|_| anyhow!("nuclei timed out after 900s"))?
        .context("failed to spawn nuclei")?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    // nuclei exits 0 even on findings; a non-zero exit with empty stdout is a real fail.
    if !out.status.success() && stdout.trim().is_empty() {
        bail!("nuclei exited {:?}: {}", out.status.code(), stderr);
    }
    Ok((stdout, stderr))
}

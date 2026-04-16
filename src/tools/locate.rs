// Locate a Go-bin tool. Prefers $HOME/go/bin for projectdiscovery binaries
// (subfinder/httpx/nuclei) since $HOME/.local/bin often shadows them with
// unrelated Python CLIs of the same name (e.g. encode/httpx the HTTP client).

use anyhow::{bail, Result};
use std::path::PathBuf;

pub fn locate_bin(name: &str) -> Result<String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/raz".into());
    let go_candidate = format!("{}/go/bin/{}", home, name);
    if std::path::Path::new(&go_candidate).exists() {
        return Ok(go_candidate);
    }
    if let Some(p) = which(name) {
        return Ok(p);
    }
    bail!("{name} not found in ~/go/bin or on PATH")
}

fn which(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    let dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
    for dir in dirs {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

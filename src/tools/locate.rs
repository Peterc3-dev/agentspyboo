// Locate a Go-bin tool, preferring $PATH, falling back to $HOME/go/bin.

use anyhow::{bail, Result};
use std::path::PathBuf;

pub fn locate_bin(name: &str) -> Result<String> {
    if let Some(p) = which(name) {
        return Ok(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/raz".into());
    let candidate = format!("{}/go/bin/{}", home, name);
    if std::path::Path::new(&candidate).exists() {
        return Ok(candidate);
    }
    bail!("{name} not found on PATH or in ~/go/bin")
}

fn which(name: &str) -> Option<String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/raz".into());
    let go_bin = format!("{}/go/bin", home);
    let path = std::env::var_os("PATH")?;
    let mut dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
    dirs.push(PathBuf::from(go_bin));
    for dir in dirs {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

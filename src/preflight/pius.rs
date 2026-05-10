use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::Stdio;
use tokio::process::Command;

use crate::scope::host_in_scope;

/// Pius plugins gated on environment variables. Pius reads these directly from
/// its own environment; tokio::process::Command inherits the parent env, so
/// keys present in agentspyboo's env flow through automatically. This table
/// only exists for *detection* — telling the user which plugins were skipped
/// because a required key was missing.
struct KeyGate {
    plugin: &'static str,
    env_vars: &'static [&'static str],
    /// `true` = plugin fires without the key but works better with it.
    /// `false` = plugin silently skips when the key is missing.
    optional: bool,
    note: &'static str,
}

const KEY_GATED_PLUGINS: &[KeyGate] = &[
    KeyGate {
        plugin: "passive-dns",
        env_vars: &["SECURITYTRAILS_API_KEY"],
        optional: false,
        note: "paid only (SecurityTrails ~$50/mo min)",
    },
    KeyGate {
        plugin: "reverse-whois",
        env_vars: &["VIEWDNS_API_KEY"],
        optional: false,
        note: "free tier available at viewdns.info",
    },
    KeyGate {
        plugin: "apollo",
        env_vars: &["APOLLO_API_KEY"],
        optional: false,
        note: "B2B paid plan only",
    },
    KeyGate {
        plugin: "favicon-hash",
        env_vars: &["SHODAN_API_KEY"],
        optional: false,
        note: "Shodan 100/mo free, burns fast",
    },
    KeyGate {
        plugin: "shodan",
        env_vars: &["SHODAN_API_KEY"],
        optional: false,
        note: "Shodan 100/mo free, burns fast",
    },
    KeyGate {
        plugin: "censys-org",
        env_vars: &["CENSYS_API_TOKEN"],
        optional: false,
        note: "Censys Starter+ plan, ~$100 min credits",
    },
    KeyGate {
        plugin: "github-org",
        env_vars: &["GITHUB_TOKEN"],
        optional: true,
        note: "free personal token, raises rate limit",
    },
    KeyGate {
        plugin: "reverse-ip",
        env_vars: &["VIEWDNS_API_KEY"],
        optional: true,
        note: "free tier; HackerTarget used as fallback when key missing",
    },
];

/// Per-plugin reckoning of whether a Pius plugin fired and whether the
/// required key was present in the environment. Surfaced in the preflight
/// report so the user can see at a glance which plugins were dark.
#[derive(Debug, Clone, Serialize)]
pub struct PluginKeyStatus {
    pub plugin: String,
    pub env_vars_required: Vec<String>,
    pub env_vars_set: Vec<String>,
    pub fired: bool,
    pub optional: bool,
    pub note: String,
    /// One of: "fired", "fired_optional_no_key", "skipped_no_key",
    /// "skipped_with_key" (the key was present but the plugin still
    /// didn't appear — usually a Pius-side error).
    pub status: String,
}

fn compute_key_status(plugins_fired: &[String]) -> Vec<PluginKeyStatus> {
    let fired_set: std::collections::HashSet<&str> =
        plugins_fired.iter().map(String::as_str).collect();
    KEY_GATED_PLUGINS
        .iter()
        .map(|gate| {
            let env_set: Vec<String> = gate
                .env_vars
                .iter()
                .filter(|v| std::env::var(v).is_ok())
                .map(|s| (*s).to_string())
                .collect();
            let fired = fired_set.contains(gate.plugin);
            let all_keys_present = env_set.len() == gate.env_vars.len();
            let status = match (fired, all_keys_present, gate.optional) {
                (true, true, _) => "fired",
                (true, false, true) => "fired_optional_no_key",
                (true, false, false) => "fired", // shouldn't happen, but trust observation
                (false, true, _) => "skipped_with_key",
                (false, false, _) => "skipped_no_key",
            };
            PluginKeyStatus {
                plugin: gate.plugin.to_string(),
                env_vars_required: gate.env_vars.iter().map(|s| (*s).to_string()).collect(),
                env_vars_set: env_set,
                fired,
                optional: gate.optional,
                note: gate.note.to_string(),
                status: status.to_string(),
            }
        })
        .collect()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PiusRecord {
    r#type: String,
    value: String,
    source: String,
    data: Value,
}

impl PiusRecord {
    fn confidence(&self) -> Option<f64> {
        self.data.get("confidence").and_then(|v| v.as_f64())
    }

    fn needs_review(&self) -> Option<bool> {
        self.data.get("needs_review").and_then(|v| v.as_bool())
    }

    fn asn(&self) -> Option<&str> {
        self.data.get("asn").and_then(|v| v.as_str())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PiusDomain {
    pub host: String,
    pub sources: Vec<String>,
    pub confidence: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PiusCidr {
    pub cidr: String,
    pub source: String,
    pub asn: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PiusGithubOrg {
    pub login: String,
    pub name: String,
    pub confidence: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct PiusResult {
    pub domains: Vec<PiusDomain>,
    pub cidrs: Vec<PiusCidr>,
    pub github_orgs: Vec<PiusGithubOrg>,
    pub total_raw: usize,
    pub filtered_out: usize,
    pub plugins_fired: Vec<String>,
    pub key_status: Vec<PluginKeyStatus>,
    pub runtime_secs: f64,
}

fn locate_pius() -> Result<String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/raz".into());

    // Check PATH first
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("pius");
            if candidate.is_file() {
                return Ok(candidate.to_string_lossy().into_owned());
            }
        }
    }

    // Fall back to known locations
    let candidates = [
        format!("{home}/.openclaw/workspace/pius-scout/bin/pius"),
        format!("{home}/.openclaw/workspace/pius/bin/pius"),
        format!("{home}/go/bin/pius"),
    ];
    for c in &candidates {
        if std::path::Path::new(c).exists() {
            return Ok(c.clone());
        }
    }
    Err(anyhow!("pius binary not found on PATH or common locations"))
}

pub async fn run_pius(
    org: &str,
    domain_hint: Option<&str>,
    asn_hint: Option<&str>,
    scope_patterns: &[String],
    verbose: bool,
) -> Result<PiusResult> {
    let bin = locate_pius()?;
    let start = std::time::Instant::now();

    let mut cmd = Command::new(&bin);
    cmd.arg("run")
        .arg("--org").arg(org)
        .arg("--mode").arg("passive")
        .arg("--output").arg("ndjson");

    if let Some(d) = domain_hint {
        cmd.arg("--domain").arg(d);
    }
    if let Some(a) = asn_hint {
        cmd.arg("--asn").arg(a);
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    if verbose {
        println!("[preflight] running: pius run --org {org:?} --mode passive --output ndjson");
    }

    let child = cmd.spawn().context("failed to spawn pius")?;
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| anyhow!("pius timed out after 5 minutes"))?
    .context("pius process error")?;

    let runtime_secs = start.elapsed().as_secs_f64();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if verbose && !stderr.is_empty() {
        for line in stderr.lines().take(10) {
            println!("[preflight] pius: {line}");
        }
    }

    let mut domain_map: std::collections::BTreeMap<String, PiusDomain> =
        std::collections::BTreeMap::new();
    let mut cidrs: Vec<PiusCidr> = Vec::new();
    let mut github_orgs: Vec<PiusGithubOrg> = Vec::new();
    let mut total_raw = 0;
    let mut filtered_out = 0;
    let mut plugins_seen = std::collections::HashSet::new();

    for line in stdout.as_ref().lines() {
        let record: PiusRecord = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                if verbose {
                    eprintln!("[preflight] skip malformed line: {e}");
                }
                continue;
            }
        };
        total_raw += 1;
        plugins_seen.insert(record.source.clone());

        match record.r#type.as_str() {
            "preseed" => {
                filtered_out += 1;
                continue;
            }
            "cidr" => {
                cidrs.push(PiusCidr {
                    cidr: record.value.clone(),
                    source: record.source.clone(),
                    asn: record.asn().map(String::from),
                });
            }
            "domain" => {
                if record.needs_review().unwrap_or(false)
                    && record.confidence().unwrap_or(1.0) < 0.5
                {
                    filtered_out += 1;
                    continue;
                }
                if record.value.contains(' ') {
                    filtered_out += 1;
                    continue;
                }
                if record.value.contains('/') {
                    if record.source == "github-org" {
                        let login = record.value.rsplit('/').next().unwrap_or("").to_string();
                        let name = record
                            .data
                            .get("github_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        github_orgs.push(PiusGithubOrg {
                            login,
                            name,
                            confidence: record.confidence(),
                        });
                    }
                    filtered_out += 1;
                    continue;
                }
                if !host_in_scope(&record.value, scope_patterns) {
                    if verbose {
                        println!(
                            "[preflight] out of scope: {} (from {})",
                            record.value, record.source
                        );
                    }
                    filtered_out += 1;
                    continue;
                }
                let entry = domain_map
                    .entry(record.value.clone())
                    .or_insert_with(|| PiusDomain {
                        host: record.value.clone(),
                        sources: Vec::new(),
                        confidence: None,
                    });
                if !entry.sources.contains(&record.source) {
                    entry.sources.push(record.source.clone());
                }
                // Keep the highest confidence seen for this host.
                entry.confidence = match (entry.confidence, record.confidence()) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (Some(a), None) => Some(a),
                    (None, b) => b,
                };
            }
            other => {
                if verbose {
                    println!("[preflight] unknown type {other:?}, skipping");
                }
                filtered_out += 1;
            }
        }
    }

    let domains: Vec<PiusDomain> = domain_map.into_values().collect();

    let mut plugins_fired: Vec<String> = plugins_seen.into_iter().collect();
    plugins_fired.sort();

    let key_status = compute_key_status(&plugins_fired);

    if verbose {
        println!(
            "[preflight] pius done in {runtime_secs:.1}s: {} raw, {} filtered, {} domains, {} CIDRs, {} github orgs",
            total_raw, filtered_out, domains.len(), cidrs.len(), github_orgs.len()
        );
        let skipped_no_key: Vec<&str> = key_status
            .iter()
            .filter(|s| s.status == "skipped_no_key")
            .map(|s| s.plugin.as_str())
            .collect();
        if !skipped_no_key.is_empty() {
            println!(
                "[preflight] {} key-gated plugin(s) skipped for missing keys: {}",
                skipped_no_key.len(),
                skipped_no_key.join(", ")
            );
        }
    }

    Ok(PiusResult {
        domains,
        cidrs,
        github_orgs,
        total_raw,
        filtered_out,
        plugins_fired,
        key_status,
        runtime_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clear_known_keys() {
        for gate in KEY_GATED_PLUGINS {
            for v in gate.env_vars {
                std::env::remove_var(v);
            }
        }
    }

    // env var tests share global mutable state, so they are combined into
    // one sequential test rather than fighting cargo's parallel runner.
    #[test]
    fn key_status_classifies_each_plugin_correctly() {
        clear_known_keys();

        // Phase 1: no keys set, github-org fired anyway, shodan didn't.
        let fired: Vec<String> = vec!["wayback".into(), "crt-sh".into(), "github-org".into()];
        let status = compute_key_status(&fired);

        let github = status.iter().find(|s| s.plugin == "github-org").unwrap();
        assert!(github.fired);
        assert_eq!(github.status, "fired_optional_no_key");

        let shodan = status.iter().find(|s| s.plugin == "shodan").unwrap();
        assert!(!shodan.fired);
        assert_eq!(shodan.status, "skipped_no_key");

        // Phase 2: GITHUB_TOKEN now set; github-org status flips to clean.
        std::env::set_var("GITHUB_TOKEN", "ghp_fake");
        let status = compute_key_status(&fired);
        let github = status.iter().find(|s| s.plugin == "github-org").unwrap();
        assert_eq!(github.status, "fired");

        // Phase 3: SHODAN_API_KEY set but shodan plugin didn't fire — Pius
        // saw the key but the plugin produced no records (silent skip).
        std::env::set_var("SHODAN_API_KEY", "shodan_fake");
        let status = compute_key_status(&fired);
        let shodan = status.iter().find(|s| s.plugin == "shodan").unwrap();
        assert_eq!(shodan.status, "skipped_with_key");

        clear_known_keys();
    }
}

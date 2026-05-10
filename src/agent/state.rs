// Per-iteration and per-run bookkeeping records. Serialized into the JSON
// findings file alongside the markdown report.

use crate::findings::{DedupedFinding, Finding};
use crate::preflight::{PiusCidr, PiusDomain, PiusGithubOrg, PluginKeyStatus};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct PreflightReport {
    pub org: String,
    pub asn: Option<String>,
    pub mode: String,
    pub runtime_secs: f64,
    pub total_raw: usize,
    pub filtered_out: usize,
    pub plugins_fired: Vec<String>,
    pub key_status: Vec<PluginKeyStatus>,
    pub domains: Vec<PiusDomain>,
    pub cidrs: Vec<PiusCidr>,
    pub github_orgs: Vec<PiusGithubOrg>,
}

#[derive(Debug, Serialize)]
pub struct StepRecord {
    pub iteration: usize,
    pub llm_raw: String,
    pub tool: Option<String>,
    pub args: Option<Value>,
    pub stdout_lines: usize,
    pub stdout_preview: String,
    pub stderr_preview: String,
    pub error: Option<String>,
    pub duration_ms: u128,
}

#[derive(Debug, Serialize)]
pub struct RunRecord {
    pub target: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub iterations: usize,
    pub model: String,
    pub scope: Vec<String>,
    pub tools_fired: Vec<String>,
    pub steps: Vec<StepRecord>,
    /// Deduped findings by default. When --no-dedup is set, this holds the
    /// flat finding rows instead (one Finding per row, targets length == 1).
    pub findings: Vec<DedupedFinding>,
    /// Un-deduped flat findings list, preserved so downstream consumers can
    /// reconstruct the exact per-target observations if dedup collapsed them.
    pub raw_findings: Vec<Finding>,
    pub dedup_enabled: bool,
    pub final_summary: String,
    pub next_steps: Vec<String>,
    /// When nuclei was run on fewer hosts than httpx returned (nuclei_cap pruning).
    /// Tuple of (nuclei_scanned, httpx_live).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nuclei_narrow: Option<(usize, usize)>,
    /// Pius org-level preflight results (populated when --org is set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preflight: Option<PreflightReport>,
}

pub fn preview(s: &str, n: usize) -> String {
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .take(n)
        .collect::<Vec<_>>()
        .join("\n")
}

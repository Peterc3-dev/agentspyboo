// Per-iteration and per-run bookkeeping records. Serialized into the JSON
// findings file alongside the markdown report.

use crate::findings::Finding;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

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
    pub findings: Vec<Finding>,
    pub final_summary: String,
    pub next_steps: Vec<String>,
}

pub fn preview(s: &str, n: usize) -> String {
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .take(n)
        .collect::<Vec<_>>()
        .join("\n")
}

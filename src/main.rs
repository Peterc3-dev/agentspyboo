// AgentSpyBoo — Phase 2 (CPU-track)
//
// Multi-step ReAct loop with three chained tools (subfinder -> httpx -> nuclei).
// Scope allowlist, per-iteration rate limit, severity-rated findings, and a
// markdown report that matches the ai-redteam-reports/ format.
//
// Phase 2 NPU inference (ort + Vitis) is parked on a kernel-driver blocker —
// see PHASE-2-RECON.md. This file is the CPU-track Phase 2.
//
// Still flat, per the Phase 1.5 architectural decision. When we split, we split
// along tool-count lines (tool #4 or tool #5), not arbitrary module scaffolding.

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command;

// ===================== CLI =====================

#[derive(Parser, Debug)]
#[command(name = "agentspyboo", about = "AI red team agent (Phase 2 CPU)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// LLM model ID (env: AGENTSPYBOO_MODEL)
    #[arg(long, global = true)]
    model: Option<String>,

    /// LLM API base URL, OpenAI-compatible (env: LEMONADE_BASE_URL)
    #[arg(long, global = true)]
    base_url: Option<String>,

    /// Bearer token for the LLM API
    #[arg(long, default_value = "lemonade", global = true)]
    api_key: String,

    /// Maximum ReAct iterations (env: AGENTSPYBOO_MAX_ITERS)
    #[arg(long, global = true)]
    max_iterations: Option<usize>,

    /// Minimum delay between tool invocations, in ms (env: AGENTSPYBOO_RATE_LIMIT_MS)
    #[arg(long, global = true)]
    rate_limit: Option<u64>,

    /// httpx host cap — caps subfinder-fed host list before probing
    #[arg(long, global = true, default_value_t = 150)]
    httpx_cap: usize,

    /// Scope allowlist (comma-separated globs, e.g. "example.com,*.example.com").
    /// Default is "<target>,*.<target>".
    #[arg(long, global = true)]
    scope: Option<String>,

    /// Verbose step-by-step logging
    #[arg(long, global = true)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run a multi-step recon + vuln assessment pass against a domain.
    Recon {
        /// Target domain (e.g. example.com)
        domain: String,
    },
}

/// Resolved config after CLI + env var merging.
struct Config {
    model: String,
    base_url: String,
    api_key: String,
    max_iterations: usize,
    rate_limit_ms: u64,
    httpx_cap: usize,
    scope_patterns: Vec<String>,
    verbose: bool,
}

impl Config {
    fn resolve(cli: &Cli, target: &str) -> Self {
        let model = cli
            .model
            .clone()
            .or_else(|| std::env::var("AGENTSPYBOO_MODEL").ok())
            .unwrap_or_else(|| "Qwen3-1.7B-GGUF".to_string());
        let base_url = cli
            .base_url
            .clone()
            .or_else(|| std::env::var("LEMONADE_BASE_URL").ok())
            .unwrap_or_else(|| "http://127.0.0.1:13305/api/v1".to_string());
        let max_iterations = cli
            .max_iterations
            .or_else(|| {
                std::env::var("AGENTSPYBOO_MAX_ITERS")
                    .ok()
                    .and_then(|s| s.parse().ok())
            })
            .unwrap_or(5);
        let rate_limit_ms = cli
            .rate_limit
            .or_else(|| {
                std::env::var("AGENTSPYBOO_RATE_LIMIT_MS")
                    .ok()
                    .and_then(|s| s.parse().ok())
            })
            .unwrap_or(500);
        let scope_patterns: Vec<String> = cli
            .scope
            .clone()
            .unwrap_or_else(|| format!("{target},*.{target}"))
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        Self {
            model,
            base_url,
            api_key: cli.api_key.clone(),
            max_iterations,
            rate_limit_ms,
            httpx_cap: cli.httpx_cap,
            scope_patterns,
            verbose: cli.verbose,
        }
    }
}

// ===================== Scope guard =====================

/// Hand-rolled glob matcher: supports a single leading "*." wildcard, or bare host match.
/// Matches case-insensitively. Strips scheme + port + path from `host` before comparing.
fn host_in_scope(host: &str, patterns: &[String]) -> bool {
    let h = normalize_host(host);
    for p in patterns {
        if let Some(suffix) = p.strip_prefix("*.") {
            if h == suffix || h.ends_with(&format!(".{suffix}")) {
                return true;
            }
        } else if h == *p {
            return true;
        }
    }
    false
}

fn normalize_host(raw: &str) -> String {
    let mut s = raw.trim().to_lowercase();
    if let Some(rest) = s.strip_prefix("http://") {
        s = rest.to_string();
    } else if let Some(rest) = s.strip_prefix("https://") {
        s = rest.to_string();
    }
    if let Some(idx) = s.find('/') {
        s.truncate(idx);
    }
    if let Some(idx) = s.rfind(':') {
        // only strip if after last ':' looks like a port
        if s[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
            s.truncate(idx);
        }
    }
    s
}

// ===================== OpenAI chat types =====================

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: &'a [ChatMessage],
    temperature: f32,
    max_tokens: u32,
    stream: bool,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: RespMsg,
}

#[derive(Debug, Deserialize)]
struct RespMsg {
    content: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    reasoning_content: Option<String>,
}

struct LlmClient {
    base: String,
    model: String,
    key: String,
    http: reqwest::Client,
}

impl LlmClient {
    fn new(base: &str, model: &str, key: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            model: model.to_string(),
            key: key.to_string(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(300))
                .build()
                .expect("reqwest client"),
        }
    }

    async fn chat(&self, messages: &[ChatMessage]) -> Result<String> {
        let url = format!("{}/chat/completions", self.base);
        let req = ChatRequest {
            model: &self.model,
            messages,
            temperature: 0.1,
            max_tokens: 1024,
            stream: false,
        };
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.key)
            .json(&req)
            .send()
            .await
            .context("LLM request failed to send")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("LLM {} — {}", status, &body[..body.len().min(600)]);
        }
        let parsed: ChatResponse = resp.json().await.context("bad JSON from LLM")?;
        let content = parsed
            .choices
            .into_iter()
            .next()
            .and_then(|c| c.message.content)
            .ok_or_else(|| anyhow!("LLM returned no content"))?;
        Ok(content)
    }
}

// ===================== Tool abstraction =====================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolKind {
    Subfinder,
    Httpx,
    Nuclei,
}

impl ToolKind {
    fn name(&self) -> &'static str {
        match self {
            ToolKind::Subfinder => "subfinder",
            ToolKind::Httpx => "httpx",
            ToolKind::Nuclei => "nuclei",
        }
    }

    fn from_name(n: &str) -> Option<ToolKind> {
        match n.trim().to_lowercase().as_str() {
            "subfinder" => Some(ToolKind::Subfinder),
            "httpx" => Some(ToolKind::Httpx),
            "nuclei" => Some(ToolKind::Nuclei),
            _ => None,
        }
    }

    fn timeout(&self) -> Duration {
        match self {
            ToolKind::Subfinder => Duration::from_secs(90),
            ToolKind::Httpx => Duration::from_secs(180),
            ToolKind::Nuclei => Duration::from_secs(300),
        }
    }
}

struct ToolExecution {
    tool: ToolKind,
    args: Value,
    stdout: String,
    stderr: String,
    error: Option<String>,
    duration_ms: u128,
}

/// Locate a Go-bin tool, preferring $PATH, falling back to $HOME/go/bin.
fn locate_bin(name: &str) -> Result<String> {
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

async fn exec_subfinder(domain: &str) -> Result<(String, String)> {
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

async fn exec_httpx(hosts: &[String], cap: usize) -> Result<(String, String)> {
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

/// Resolve the nuclei-templates root. Prefer ~/nuclei-templates, fall back to
/// ~/.nuclei-templates. Return None if neither exists — the caller should warn.
fn nuclei_templates_root() -> Option<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/raz".into());
    for rel in ["nuclei-templates", ".nuclei-templates"] {
        let p = PathBuf::from(&home).join(rel);
        if p.is_dir() {
            return Some(p);
        }
    }
    None
}

async fn exec_nuclei(urls: &[String]) -> Result<(String, String)> {
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
        .map_err(|_| anyhow!("nuclei timed out after 300s"))?
        .context("failed to spawn nuclei")?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    // nuclei exits 0 even on findings; a non-zero exit with empty stdout is a real fail.
    if !out.status.success() && stdout.trim().is_empty() {
        bail!("nuclei exited {:?}: {}", out.status.code(), stderr);
    }
    Ok((stdout, stderr))
}

// ===================== Parsing LLM actions =====================

#[derive(Debug)]
enum AgentAction {
    Tool {
        name: String,
        args: Value,
    },
    Done {
        summary: String,
        next_steps: Vec<String>,
    },
}

fn strip_think(s: &str) -> String {
    let mut out = s.to_string();
    while let Some(start) = out.find("<think>") {
        if let Some(end) = out[start..].find("</think>") {
            let end_abs = start + end + "</think>".len();
            out.replace_range(start..end_abs, "");
        } else {
            out.replace_range(start.., "");
            break;
        }
    }
    out
}

fn extract_json(text: &str) -> Option<Value> {
    let cleaned = strip_think(text)
        .replace("```json", "```")
        .split("```")
        .find(|chunk| chunk.contains('{'))
        .map(|s| s.to_string())
        .unwrap_or_else(|| strip_think(text));

    let bytes = cleaned.as_bytes();
    let mut depth = 0i32;
    let mut start: Option<usize> = None;
    let mut best: Option<Value> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'{' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = start {
                        let slice = &cleaned[s..=i];
                        if let Ok(v) = serde_json::from_str::<Value>(slice) {
                            best = Some(v);
                            break;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    best
}

fn parse_action(raw: &str) -> Option<AgentAction> {
    let v = extract_json(raw)?;

    if let Some(action) = v.get("action").and_then(|a| a.as_str()) {
        if action == "done" || action == "stop" || action == "finish" {
            let summary = v
                .get("summary")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let next_steps = v
                .get("next_steps")
                .and_then(|n| n.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            return Some(AgentAction::Done {
                summary,
                next_steps,
            });
        }
    }

    if let Some(tool) = v.get("tool").and_then(|t| t.as_str()) {
        let args = v
            .get("arguments")
            .or_else(|| v.get("args"))
            .cloned()
            .unwrap_or(json!({}));
        return Some(AgentAction::Tool {
            name: tool.to_string(),
            args,
        });
    }

    if let Some(calls) = v.get("tool_calls").and_then(|t| t.as_array()) {
        if let Some(first) = calls.first() {
            let func = first.get("function").unwrap_or(first);
            let name = func
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let args_raw = func.get("arguments").cloned().unwrap_or(json!({}));
            let args = match args_raw {
                Value::String(s) => serde_json::from_str::<Value>(&s).unwrap_or(json!({})),
                v => v,
            };
            if !name.is_empty() {
                return Some(AgentAction::Tool { name, args });
            }
        }
    }

    None
}

// ===================== Findings + severity =====================

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn from_str_loose(s: &str) -> Severity {
        match s.trim().to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "moderate" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
    fn icon(&self) -> &'static str {
        match self {
            Severity::Info => "ℹ️",
            Severity::Low => "🔵",
            Severity::Medium => "🟡",
            Severity::High => "🟠",
            Severity::Critical => "🔴",
        }
    }
    fn label(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct Finding {
    severity: Severity,
    kind: String,
    target: String,
    details: String,
}

// ===================== ReAct loop =====================

fn system_prompt(target: &str, scope_display: &str) -> String {
    format!(
        "/nothink You are AgentSpyBoo, an autonomous red team recon + assessment agent.\n\
Target: {target}\n\
Scope: {scope_display}\n\n\
Available tools (run in order, skip steps when prior output is empty):\n\
  1. subfinder — Passive subdomain enumeration. args: {{\"domain\": \"{target}\"}}\n\
  2. httpx — HTTP probe over discovered hosts. args: {{\"hosts_from\": \"subfinder\"}} (preferred) or {{\"hosts\": [\"a.{target}\", ...]}}.\n\
  3. nuclei — Templated vulnerability scan against live URLs. args: {{\"urls_from\": \"httpx\"}} (preferred) or {{\"urls\": [\"https://a.{target}\", ...]}}.\n\n\
Intelligent skipping rules — YOU MUST FOLLOW THESE:\n\
  - If subfinder returned 0 subdomains → emit done immediately. Do not run httpx on nothing.\n\
  - If httpx returned 0 live hosts → emit done immediately. Do not run nuclei on nothing.\n\
  - If nuclei finishes (even with 0 findings) → emit done on the next step.\n\n\
Respond ONLY with a single JSON object. No prose, no markdown fences.\n\
  Tool call: {{\"tool\": \"subfinder\", \"arguments\": {{\"domain\": \"{target}\"}}}}\n\
  Finish:    {{\"action\": \"done\", \"summary\": \"3-5 sentence exec summary\", \"next_steps\": [\"...\", \"...\"]}}\n"
    )
}

#[derive(Debug, Serialize)]
struct StepRecord {
    iteration: usize,
    llm_raw: String,
    tool: Option<String>,
    args: Option<Value>,
    stdout_lines: usize,
    stdout_preview: String,
    stderr_preview: String,
    error: Option<String>,
    duration_ms: u128,
}

#[derive(Debug, Serialize)]
struct RunRecord {
    target: String,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    iterations: usize,
    model: String,
    scope: Vec<String>,
    tools_fired: Vec<String>,
    steps: Vec<StepRecord>,
    findings: Vec<Finding>,
    final_summary: String,
    next_steps: Vec<String>,
}

fn preview(s: &str, n: usize) -> String {
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .take(n)
        .collect::<Vec<_>>()
        .join("\n")
}

fn extract_hosts_from_subfinder(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Parse httpx -json output into (url, host, status, title, tech[]) tuples plus finding rows.
fn parse_httpx_output(stdout: &str) -> (Vec<String>, Vec<Finding>) {
    let mut live_urls: Vec<String> = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let url = v
            .get("url")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let host = v
            .get("host")
            .and_then(|x| x.as_str())
            .map(String::from)
            .unwrap_or_else(|| normalize_host(&url));
        let status = v
            .get("status_code")
            .and_then(|x| x.as_i64())
            .unwrap_or(0);
        let title = v.get("title").and_then(|x| x.as_str()).unwrap_or("");
        let tech: Vec<String> = v
            .get("tech")
            .and_then(|t| t.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if !url.is_empty() {
            live_urls.push(url.clone());
        }
        // Severity rules for httpx: info by default; low if non-standard tech
        // disclosed; bump to medium if title hints at auth/admin/login panel.
        let title_l = title.to_lowercase();
        let admin_hint = ["admin", "login", "sign in", "dashboard", "phpmyadmin"]
            .iter()
            .any(|k| title_l.contains(k));
        let sev = if admin_hint {
            Severity::Medium
        } else if !tech.is_empty() {
            Severity::Low
        } else {
            Severity::Info
        };
        let details = format!(
            "status={} title=\"{}\" tech=[{}]",
            status,
            title.chars().take(80).collect::<String>(),
            tech.join(", ")
        );
        findings.push(Finding {
            severity: sev,
            kind: "http-probe".into(),
            target: host,
            details,
        });
    }
    (live_urls, findings)
}

/// Parse nuclei -jsonl output → findings.
fn parse_nuclei_output(stdout: &str) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let info = v.get("info").cloned().unwrap_or(json!({}));
        let sev_str = info
            .get("severity")
            .and_then(|x| x.as_str())
            .unwrap_or("info");
        let name = info
            .get("name")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string();
        let template_id = v
            .get("template-id")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let matched = v
            .get("matched-at")
            .and_then(|x| x.as_str())
            .or_else(|| v.get("host").and_then(|x| x.as_str()))
            .unwrap_or("")
            .to_string();
        let details = format!("{name} [{template_id}]");
        out.push(Finding {
            severity: Severity::from_str_loose(sev_str),
            kind: "nuclei".into(),
            target: matched,
            details,
        });
    }
    out
}

async fn run_recon(cli: &Cli, domain: &str) -> Result<()> {
    let cfg = Config::resolve(cli, domain);
    let scope_display = cfg.scope_patterns.join(", ");

    println!("[*] AgentSpyBoo Phase 2 (CPU-track)");
    println!("[*] Target        : {domain}");
    println!("[*] Scope         : {scope_display}");
    println!("[*] LLM           : {} ({})", cfg.model, cfg.base_url);
    println!("[*] Max iterations: {}", cfg.max_iterations);
    println!("[*] Rate limit    : {}ms", cfg.rate_limit_ms);
    println!("[*] httpx cap     : {}", cfg.httpx_cap);
    println!();

    // Preflight: refuse if target itself is out of scope.
    if !host_in_scope(domain, &cfg.scope_patterns) {
        bail!("target '{domain}' does not match scope patterns {scope_display:?}");
    }

    // Preflight: warn if nuclei templates are missing — don't fail, the LLM may skip.
    if nuclei_templates_root().is_none() {
        eprintln!("[!] nuclei-templates not found — run `nuclei -update-templates` once. Nuclei tool calls will error.");
    }

    let llm = LlmClient::new(&cfg.base_url, &cfg.model, &cfg.api_key);
    let started_at = Utc::now();

    let sys = system_prompt(domain, &scope_display);
    let mut messages: Vec<ChatMessage> = vec![
        ChatMessage {
            role: "system".into(),
            content: sys,
        },
        ChatMessage {
            role: "user".into(),
            content: format!(
                "Perform a vuln assessment on {domain}. Chain subfinder -> httpx -> nuclei, and skip steps when prior output is empty."
            ),
        },
    ];

    let mut steps: Vec<StepRecord> = Vec::new();
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut tools_fired: Vec<String> = Vec::new();
    let mut last_subfinder_hosts: Vec<String> = Vec::new();
    let mut last_httpx_urls: Vec<String> = Vec::new();
    let mut final_summary = String::new();
    let mut next_steps_llm: Vec<String> = Vec::new();
    let mut retry_used = false;

    for iter in 1..=cfg.max_iterations {
        if iter > 1 && cfg.rate_limit_ms > 0 {
            tokio::time::sleep(Duration::from_millis(cfg.rate_limit_ms)).await;
        }

        println!(
            "[>] Iteration {iter}/{} — asking LLM for next action...",
            cfg.max_iterations
        );
        let raw = match llm.chat(&messages).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[!] LLM call failed: {e:#}");
                bail!("LLM error on iteration {iter}: {e}");
            }
        };
        if cfg.verbose {
            println!("[<] LLM raw:\n{}\n", raw.trim());
        } else {
            let short = raw
                .trim()
                .lines()
                .next()
                .unwrap_or("")
                .chars()
                .take(120)
                .collect::<String>();
            println!("[<] LLM: {short}...");
        }

        let action = parse_action(&raw);
        let action = match action {
            Some(a) => a,
            None => {
                eprintln!("[!] Could not parse JSON action from LLM output");
                if !retry_used {
                    retry_used = true;
                    println!("[>] Retrying with clarifying system message...");
                    messages.push(ChatMessage {
                        role: "assistant".into(),
                        content: raw.clone(),
                    });
                    messages.push(ChatMessage {
                        role: "system".into(),
                        content: "Your previous response was not valid JSON. Respond ONLY with a single JSON object like {\"tool\": \"...\", \"arguments\": {...}} or {\"action\": \"done\", \"summary\": \"...\", \"next_steps\": [...]}. No prose.".into(),
                    });
                    steps.push(StepRecord {
                        iteration: iter,
                        llm_raw: raw,
                        tool: None,
                        args: None,
                        stdout_lines: 0,
                        stdout_preview: String::new(),
                        stderr_preview: String::new(),
                        error: Some("unparseable; retry requested".into()),
                        duration_ms: 0,
                    });
                    continue;
                } else {
                    println!("[!] Retry also failed — treating raw text as final summary");
                    final_summary = strip_think(&raw).trim().to_string();
                    steps.push(StepRecord {
                        iteration: iter,
                        llm_raw: raw,
                        tool: None,
                        args: None,
                        stdout_lines: 0,
                        stdout_preview: String::new(),
                        stderr_preview: String::new(),
                        error: Some("unparseable after retry".into()),
                        duration_ms: 0,
                    });
                    break;
                }
            }
        };

        match action {
            AgentAction::Done {
                summary,
                next_steps,
            } => {
                println!("[+] LLM signaled done.");
                final_summary = summary;
                next_steps_llm = next_steps;
                steps.push(StepRecord {
                    iteration: iter,
                    llm_raw: raw,
                    tool: Some("done".into()),
                    args: None,
                    stdout_lines: 0,
                    stdout_preview: String::new(),
                    stderr_preview: String::new(),
                    error: None,
                    duration_ms: 0,
                });
                break;
            }
            AgentAction::Tool { name, args } => {
                let kind = match ToolKind::from_name(&name) {
                    Some(k) => k,
                    None => {
                        let err = format!("unknown tool '{name}'");
                        println!("[!] {err}");
                        messages.push(ChatMessage {
                            role: "assistant".into(),
                            content: raw.clone(),
                        });
                        messages.push(ChatMessage {
                            role: "user".into(),
                            content: format!(
                                "Observation: {err}. Available tools are subfinder, httpx, nuclei. Try again or emit done."
                            ),
                        });
                        steps.push(StepRecord {
                            iteration: iter,
                            llm_raw: raw,
                            tool: Some(name),
                            args: Some(args),
                            stdout_lines: 0,
                            stdout_preview: String::new(),
                            stderr_preview: String::new(),
                            error: Some(err),
                            duration_ms: 0,
                        });
                        continue;
                    }
                };

                println!("[>] Executing {} with args {}", kind.name(), args);
                let t0 = std::time::Instant::now();
                let exec = match kind {
                    ToolKind::Subfinder => {
                        let d = args
                            .get("domain")
                            .and_then(|x| x.as_str())
                            .unwrap_or(domain)
                            .to_string();
                        if !host_in_scope(&d, &cfg.scope_patterns) {
                            println!("[!] scope guard: '{d}' not in scope, skipping subfinder");
                            ToolExecution {
                                tool: kind,
                                args: args.clone(),
                                stdout: String::new(),
                                stderr: String::new(),
                                error: Some(format!("out-of-scope target '{d}'")),
                                duration_ms: 0,
                            }
                        } else {
                            match exec_subfinder(&d).await {
                                Ok((so, se)) => ToolExecution {
                                    tool: kind,
                                    args: args.clone(),
                                    stdout: so,
                                    stderr: se,
                                    error: None,
                                    duration_ms: t0.elapsed().as_millis(),
                                },
                                Err(e) => ToolExecution {
                                    tool: kind,
                                    args: args.clone(),
                                    stdout: String::new(),
                                    stderr: String::new(),
                                    error: Some(format!("{e:#}")),
                                    duration_ms: t0.elapsed().as_millis(),
                                },
                            }
                        }
                    }
                    ToolKind::Httpx => {
                        let raw_hosts: Vec<String> = if args
                            .get("hosts_from")
                            .and_then(|s| s.as_str())
                            .map(|s| s.eq_ignore_ascii_case("subfinder"))
                            .unwrap_or(false)
                        {
                            last_subfinder_hosts.clone()
                        } else if let Some(arr) = args.get("hosts").and_then(|h| h.as_array()) {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        } else {
                            last_subfinder_hosts.clone()
                        };
                        // Apply scope guard.
                        let before = raw_hosts.len();
                        let hosts: Vec<String> = raw_hosts
                            .into_iter()
                            .filter(|h| host_in_scope(h, &cfg.scope_patterns))
                            .collect();
                        let dropped = before - hosts.len();
                        if dropped > 0 {
                            println!("[!] scope guard: dropped {dropped} out-of-scope hosts before httpx");
                        }
                        match exec_httpx(&hosts, cfg.httpx_cap).await {
                            Ok((so, se)) => ToolExecution {
                                tool: kind,
                                args: args.clone(),
                                stdout: so,
                                stderr: se,
                                error: None,
                                duration_ms: t0.elapsed().as_millis(),
                            },
                            Err(e) => ToolExecution {
                                tool: kind,
                                args: args.clone(),
                                stdout: String::new(),
                                stderr: String::new(),
                                error: Some(format!("{e:#}")),
                                duration_ms: t0.elapsed().as_millis(),
                            },
                        }
                    }
                    ToolKind::Nuclei => {
                        let raw_urls: Vec<String> = if args
                            .get("urls_from")
                            .and_then(|s| s.as_str())
                            .map(|s| s.eq_ignore_ascii_case("httpx"))
                            .unwrap_or(false)
                        {
                            last_httpx_urls.clone()
                        } else if let Some(arr) = args.get("urls").and_then(|h| h.as_array()) {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        } else {
                            last_httpx_urls.clone()
                        };
                        let before = raw_urls.len();
                        let urls: Vec<String> = raw_urls
                            .into_iter()
                            .filter(|u| host_in_scope(u, &cfg.scope_patterns))
                            .collect();
                        let dropped = before - urls.len();
                        if dropped > 0 {
                            println!("[!] scope guard: dropped {dropped} out-of-scope urls before nuclei");
                        }
                        match exec_nuclei(&urls).await {
                            Ok((so, se)) => ToolExecution {
                                tool: kind,
                                args: args.clone(),
                                stdout: so,
                                stderr: se,
                                error: None,
                                duration_ms: t0.elapsed().as_millis(),
                            },
                            Err(e) => ToolExecution {
                                tool: kind,
                                args: args.clone(),
                                stdout: String::new(),
                                stderr: String::new(),
                                error: Some(format!("{e:#}")),
                                duration_ms: t0.elapsed().as_millis(),
                            },
                        }
                    }
                };

                let line_count = exec.stdout.lines().filter(|l| !l.trim().is_empty()).count();
                if let Some(err) = &exec.error {
                    println!("[!] {} error: {}", kind.name(), err);
                } else {
                    println!(
                        "[+] {} returned {} lines in {} ms",
                        kind.name(),
                        line_count,
                        exec.duration_ms
                    );
                    if cfg.verbose {
                        for l in exec.stdout.lines().take(8) {
                            println!("    {l}");
                        }
                    }
                    if !tools_fired.contains(&kind.name().to_string()) {
                        tools_fired.push(kind.name().to_string());
                    }
                }

                // Post-processing per tool: collect findings + cache outputs.
                match kind {
                    ToolKind::Subfinder => {
                        if exec.error.is_none() {
                            last_subfinder_hosts = extract_hosts_from_subfinder(&exec.stdout);
                            for h in &last_subfinder_hosts {
                                all_findings.push(Finding {
                                    severity: Severity::Info,
                                    kind: "subdomain".into(),
                                    target: h.clone(),
                                    details: "discovered via subfinder".into(),
                                });
                            }
                        }
                    }
                    ToolKind::Httpx => {
                        if exec.error.is_none() {
                            let (urls, httpx_findings) = parse_httpx_output(&exec.stdout);
                            last_httpx_urls = urls;
                            all_findings.extend(httpx_findings);
                        }
                    }
                    ToolKind::Nuclei => {
                        if exec.error.is_none() {
                            let n = parse_nuclei_output(&exec.stdout);
                            all_findings.extend(n);
                        }
                    }
                }

                // Feed a SLIM observation back to the LLM. Full httpx/nuclei JSON
                // blows Lemonade's context window on Qwen3-1.7B. Summarize instead.
                let observation = if let Some(err) = &exec.error {
                    format!("Observation: {} FAILED: {}", kind.name(), err)
                } else if line_count == 0 {
                    format!(
                        "Observation: {} returned 0 lines (empty). Per rules, emit done now.",
                        kind.name()
                    )
                } else {
                    let slim = match kind {
                        ToolKind::Subfinder => {
                            let hosts: Vec<&str> = exec
                                .stdout
                                .lines()
                                .map(|l| l.trim())
                                .filter(|l| !l.is_empty())
                                .take(10)
                                .collect();
                            format!(
                                "{} subdomains found. First {}: {}",
                                line_count,
                                hosts.len(),
                                hosts.join(", ")
                            )
                        }
                        ToolKind::Httpx => {
                            let urls: Vec<String> = last_httpx_urls
                                .iter()
                                .take(10)
                                .cloned()
                                .collect();
                            format!(
                                "{} live hosts responded. First {}: {}",
                                line_count,
                                urls.len(),
                                urls.join(", ")
                            )
                        }
                        ToolKind::Nuclei => {
                            let n = all_findings
                                .iter()
                                .filter(|f| f.kind == "nuclei")
                                .count();
                            format!(
                                "nuclei scan complete: {} JSONL lines, {} parsed findings. Next step should be done.",
                                line_count, n
                            )
                        }
                    };
                    format!("Observation: {}. {}", kind.name(), slim)
                };
                messages.push(ChatMessage {
                    role: "assistant".into(),
                    content: raw.clone(),
                });
                messages.push(ChatMessage {
                    role: "user".into(),
                    content: format!("{observation}\n\nWhat next? Respond with a single JSON action."),
                });

                steps.push(StepRecord {
                    iteration: iter,
                    llm_raw: raw,
                    tool: Some(kind.name().into()),
                    args: Some(exec.args.clone()),
                    stdout_lines: line_count,
                    stdout_preview: preview(&exec.stdout, 25),
                    stderr_preview: preview(&exec.stderr, 8),
                    error: exec.error.clone(),
                    duration_ms: exec.duration_ms,
                });
            }
        }
    }

    // If we ran out of iterations with no done, force a summary.
    if final_summary.is_empty() {
        println!("[>] Loop hit max iterations — requesting final summary...");
        messages.push(ChatMessage {
            role: "user".into(),
            content: "You've hit the iteration cap. Reply ONLY with {\"action\": \"done\", \"summary\": \"...\", \"next_steps\": [\"...\"]} summarizing what you found in 3-5 sentences.".into(),
        });
        if let Ok(raw) = llm.chat(&messages).await {
            match parse_action(&raw) {
                Some(AgentAction::Done {
                    summary,
                    next_steps,
                }) => {
                    final_summary = summary;
                    next_steps_llm = next_steps;
                }
                _ => final_summary = strip_think(&raw).trim().to_string(),
            }
        }
    }

    // Sort findings by severity desc for report rendering.
    all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    let finished_at = Utc::now();
    let record = RunRecord {
        target: domain.to_string(),
        started_at,
        finished_at,
        iterations: steps.len(),
        model: cfg.model.clone(),
        scope: cfg.scope_patterns.clone(),
        tools_fired: tools_fired.clone(),
        steps,
        findings: all_findings,
        final_summary: final_summary.clone(),
        next_steps: next_steps_llm,
    };

    let ts = started_at.format("%Y%m%dT%H%M%SZ").to_string();
    let findings_dir = std::path::Path::new("findings");
    let reports_dir = std::path::Path::new("reports");
    std::fs::create_dir_all(findings_dir).context("create findings/")?;
    std::fs::create_dir_all(reports_dir).context("create reports/")?;

    let findings_path = findings_dir.join(format!("{}-{}.json", domain, ts));
    let report_path = reports_dir.join(format!("{}-{}.md", domain, ts));

    std::fs::write(&findings_path, serde_json::to_string_pretty(&record)?)
        .context("write findings json")?;
    std::fs::write(&report_path, render_report(&record))
        .context("write markdown report")?;

    println!();
    println!("========== AGENT SUMMARY ==========");
    println!("{}", final_summary.trim());
    println!("===================================");
    println!("[+] Findings : {}", findings_path.display());
    println!("[+] Report   : {}", report_path.display());
    Ok(())
}

// ===================== Markdown report =====================

fn render_report(r: &RunRecord) -> String {
    let mut out = String::new();
    out.push_str(&format!("# AgentSpyBoo Assessment — {}\n\n", r.target));
    out.push_str(&format!(
        "**Date:** {}  \n**Model:** {}  \n**Iterations:** {}  \n**Scope:** {}  \n**Tools fired:** {}\n\n",
        r.started_at.to_rfc3339(),
        r.model,
        r.iterations,
        r.scope.join(", "),
        if r.tools_fired.is_empty() {
            "(none)".to_string()
        } else {
            r.tools_fired.join(" → ")
        }
    ));
    out.push_str("---\n\n");

    out.push_str("## Executive Summary\n\n");
    let summary = if r.final_summary.trim().is_empty() {
        "_No summary produced._".to_string()
    } else {
        r.final_summary.trim().to_string()
    };
    out.push_str(&summary);
    out.push_str("\n\n---\n\n");

    // Findings table
    out.push_str("## Findings Table\n\n");
    if r.findings.is_empty() {
        out.push_str("_No findings recorded._\n\n");
    } else {
        out.push_str("| # | Severity | Type | Target | Details |\n");
        out.push_str("|---|----------|------|--------|---------|\n");
        for (i, f) in r.findings.iter().enumerate() {
            let details_clean = f
                .details
                .replace('|', "\\|")
                .replace('\n', " ")
                .chars()
                .take(120)
                .collect::<String>();
            let target_clean = f.target.replace('|', "\\|");
            out.push_str(&format!(
                "| {} | {} {} | {} | {} | {} |\n",
                i + 1,
                f.severity.icon(),
                f.severity.label(),
                f.kind,
                target_clean,
                details_clean
            ));
        }
        out.push_str("\n");
    }

    // Methodology — auto-generated from the chain.
    out.push_str("---\n\n## Methodology\n\n");
    out.push_str(
        "A small LLM running locally on Lemonade Server (AMD Ryzen AI, Qwen3-1.7B) drives \
         a ReAct loop with intelligent step skipping: it reasons about whether each tool \
         is worth running based on the prior tool's output. Scope allowlist enforces \
         a glob-based target filter on every host before the tool spawns. Rate limiting \
         inserts a floor between iterations.\n\n",
    );
    out.push_str("Tool chain executed this run:\n\n");
    if r.tools_fired.is_empty() {
        out.push_str("- _(no tools fired — LLM skipped straight to done)_\n");
    } else {
        for t in &r.tools_fired {
            let desc = match t.as_str() {
                "subfinder" => "passive subdomain enumeration",
                "httpx" => "live HTTP probe (status, title, tech detect, JSON output)",
                "nuclei" => "templated vuln scan (cves + exposures + misconfiguration + vulnerabilities, severity>=medium)",
                _ => "",
            };
            out.push_str(&format!("- `{t}` — {desc}\n"));
        }
    }
    out.push_str("\n");

    // Step detail
    out.push_str("## Step Detail\n\n");
    for s in &r.steps {
        out.push_str(&format!(
            "### Iteration {} — {}\n\n",
            s.iteration,
            s.tool.clone().unwrap_or_else(|| "(none)".into())
        ));
        if let Some(a) = &s.args {
            out.push_str(&format!("**Args:** `{}`\n\n", a));
        }
        if let Some(e) = &s.error {
            out.push_str(&format!("**Error:** {}\n\n", e));
        }
        if !s.stdout_preview.is_empty() {
            out.push_str("**Preview:**\n\n```\n");
            out.push_str(&s.stdout_preview);
            out.push_str("\n```\n\n");
        }
    }

    // Recommended next steps — prefer LLM's; fall back to boilerplate.
    out.push_str("---\n\n## Recommended Next Steps\n\n");
    if !r.next_steps.is_empty() {
        for n in &r.next_steps {
            out.push_str(&format!("- {n}\n"));
        }
    } else {
        out.push_str("- Review the discovered subdomains for staging/dev/admin/internal hosts that should not be exposed.\n");
        out.push_str("- Promote medium+ nuclei findings into a formal report with reproduction steps.\n");
        out.push_str("- For interesting HTTP titles (admin/login panels), run targeted directory enumeration (ffuf) on a case-by-case basis.\n");
    }
    out.push_str("\n---\n\n");
    out.push_str("_Generated by AgentSpyBoo Phase 2 (CPU-track) — https://github.com/Peterc3-dev (private)_\n");
    out
}

// ===================== main =====================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Recon { domain } => run_recon(&cli, domain).await,
    }
}

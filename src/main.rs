// AgentSpyBoo — Phase 1.5
//
// Multi-step ReAct loop with two chained tools (subfinder -> httpx).
// Writes findings JSON + markdown report to disk. Same phosphor-y CLI vibe
// as Phase 1, but now with an actual loop and actual output artifacts.
//
// Deliberately one file. When we hit tool #4 or #5 we split.

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
#[command(name = "agentspyboo", about = "AI red team agent (Phase 1.5)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// LLM model ID
    #[arg(long, default_value = "Qwen3-1.7B-GGUF", global = true)]
    model: String,

    /// LLM API base URL (OpenAI-compatible)
    #[arg(long, default_value = "http://127.0.0.1:13305/api/v1", global = true)]
    base_url: String,

    /// Bearer token for the LLM API
    #[arg(long, default_value = "lemonade", global = true)]
    api_key: String,

    /// Maximum ReAct iterations
    #[arg(long, default_value_t = 5, global = true)]
    max_iterations: usize,

    /// Verbose step-by-step logging
    #[arg(long, global = true)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run a multi-step recon pass against a domain.
    Recon {
        /// Target domain (e.g. example.com)
        domain: String,
    },
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
//
// Small enum + executor. We keep this dumb on purpose: adding a third tool
// is one new enum variant + one match arm.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolKind {
    Subfinder,
    Httpx,
}

impl ToolKind {
    fn name(&self) -> &'static str {
        match self {
            ToolKind::Subfinder => "subfinder",
            ToolKind::Httpx => "httpx",
        }
    }

    fn from_name(n: &str) -> Option<ToolKind> {
        match n.trim().to_lowercase().as_str() {
            "subfinder" => Some(ToolKind::Subfinder),
            "httpx" => Some(ToolKind::Httpx),
            _ => None,
        }
    }

    fn timeout(&self) -> Duration {
        match self {
            ToolKind::Subfinder => Duration::from_secs(90),
            ToolKind::Httpx => Duration::from_secs(180),
        }
    }

    fn description(&self) -> &'static str {
        match self {
            ToolKind::Subfinder => {
                "Passive subdomain enumeration. args: {\"domain\": \"<target>\"}"
            }
            ToolKind::Httpx => {
                "HTTP probe over a list of hosts; returns status, title, tech. \
                 args: {\"hosts\": [\"a.example.com\", \"b.example.com\"]}  OR  \
                 {\"hosts_from\": \"subfinder\"} to reuse the last subfinder output."
            }
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
    // Augmented PATH: include $HOME/go/bin so spawn-finding works too.
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

const HTTPX_HOST_CAP: usize = 150;

async fn exec_httpx(hosts: &[String]) -> Result<(String, String)> {
    if hosts.is_empty() {
        return Ok((String::new(), "no hosts to probe".into()));
    }
    let bin = locate_bin("httpx")?;
    // Cap the host list so a runaway subfinder result doesn't blow the timeout.
    let capped: Vec<String> = hosts.iter().take(HTTPX_HOST_CAP).cloned().collect();
    // Write hosts to a tempfile.
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
    // Best-effort cleanup.
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

// ===================== Parsing LLM actions =====================

#[derive(Debug)]
enum AgentAction {
    Tool { name: String, args: Value },
    Done { summary: String },
}

fn strip_think(s: &str) -> String {
    // Remove <think>...</think> blocks (Qwen3 leaks them even with /nothink sometimes).
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

    // done action
    if let Some(action) = v.get("action").and_then(|a| a.as_str()) {
        if action == "done" || action == "stop" || action == "finish" {
            let summary = v
                .get("summary")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            return Some(AgentAction::Done { summary });
        }
    }

    // flat {tool, arguments}
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

    // OpenAI tool_calls[]
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

// ===================== ReAct loop =====================

fn system_prompt(target: &str) -> String {
    format!(
        "/nothink You are AgentSpyBoo, an autonomous red team recon agent.\n\
Target: {target}\n\n\
Available tools:\n\
  1. subfinder — Passive subdomain enumeration. args: {{\"domain\": \"{target}\"}}\n\
  2. httpx — HTTP probe over discovered hosts. args: {{\"hosts_from\": \"subfinder\"}} (reuses last subfinder output) or {{\"hosts\": [\"a.{target}\", ...]}}.\n\n\
Workflow:\n\
  Step 1: call subfinder to enumerate subdomains.\n\
  Step 2: call httpx with hosts_from=subfinder to probe the live ones.\n\
  Step 3: emit the 'done' action with a 3-5 sentence operator summary.\n\n\
Respond ONLY with a single JSON object. No prose, no markdown.\n\
  To call a tool: {{\"tool\": \"subfinder\", \"arguments\": {{\"domain\": \"{target}\"}}}}\n\
  To finish:     {{\"action\": \"done\", \"summary\": \"...\"}}\n"
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
    steps: Vec<StepRecord>,
    final_summary: String,
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

async fn run_recon(cli: &Cli, domain: &str) -> Result<()> {
    println!("[*] AgentSpyBoo Phase 1.5");
    println!("[*] Target        : {domain}");
    println!("[*] LLM           : {} ({})", cli.model, cli.base_url);
    println!("[*] Max iterations: {}", cli.max_iterations);
    println!();

    let llm = LlmClient::new(&cli.base_url, &cli.model, &cli.api_key);
    let started_at = Utc::now();

    let sys = system_prompt(domain);
    let mut messages: Vec<ChatMessage> = vec![
        ChatMessage {
            role: "system".into(),
            content: sys,
        },
        ChatMessage {
            role: "user".into(),
            content: format!(
                "Perform passive recon on {domain}. Start with subfinder, then httpx, then finish."
            ),
        },
    ];

    let mut steps: Vec<StepRecord> = Vec::new();
    let mut last_subfinder_hosts: Vec<String> = Vec::new();
    let mut final_summary = String::new();
    let mut retry_used = false;

    for iter in 1..=cli.max_iterations {
        println!("[>] Iteration {iter}/{} — asking LLM for next action...", cli.max_iterations);
        let raw = match llm.chat(&messages).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[!] LLM call failed: {e:#}");
                bail!("LLM error on iteration {iter}: {e}");
            }
        };
        if cli.verbose {
            println!("[<] LLM raw:\n{}\n", raw.trim());
        } else {
            let short = raw.trim().lines().next().unwrap_or("").chars().take(120).collect::<String>();
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
                        content: "Your previous response was not valid JSON. Respond ONLY with a single JSON object like {\"tool\": \"...\", \"arguments\": {...}} or {\"action\": \"done\", \"summary\": \"...\"}. No prose.".into(),
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
            AgentAction::Done { summary } => {
                println!("[+] LLM signaled done.");
                final_summary = summary;
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
                                "Observation: {err}. Available tools are subfinder and httpx. Try again or emit done."
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
                    ToolKind::Httpx => {
                        let hosts: Vec<String> = if args
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
                        match exec_httpx(&hosts).await {
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
                    println!("[+] {} returned {} lines in {} ms", kind.name(), line_count, exec.duration_ms);
                    if cli.verbose {
                        for l in exec.stdout.lines().take(8) {
                            println!("    {l}");
                        }
                    }
                }

                // If subfinder, remember the hosts for httpx.
                if kind == ToolKind::Subfinder && exec.error.is_none() {
                    last_subfinder_hosts = extract_hosts_from_subfinder(&exec.stdout);
                }

                // Feed observation back to LLM.
                let observation = if let Some(err) = &exec.error {
                    format!("Observation: {} FAILED: {}", kind.name(), err)
                } else if line_count == 0 {
                    format!("Observation: {} returned 0 lines (empty).", kind.name())
                } else {
                    format!(
                        "Observation: {} returned {} lines. Preview:\n{}",
                        kind.name(),
                        line_count,
                        preview(&exec.stdout, 25)
                    )
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
            content: "You've hit the iteration cap. Reply ONLY with {\"action\": \"done\", \"summary\": \"...\"} summarizing what you found in 3-5 sentences.".into(),
        });
        if let Ok(raw) = llm.chat(&messages).await {
            match parse_action(&raw) {
                Some(AgentAction::Done { summary }) => final_summary = summary,
                _ => final_summary = strip_think(&raw).trim().to_string(),
            }
        }
    }

    let finished_at = Utc::now();
    let record = RunRecord {
        target: domain.to_string(),
        started_at,
        finished_at,
        iterations: steps.len(),
        model: cli.model.clone(),
        steps,
        final_summary: final_summary.clone(),
    };

    // Write outputs.
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
    out.push_str(&format!("# AgentSpyBoo Recon Report -- {}\n\n", r.target));
    out.push_str(&format!("**Target:** {}\n", r.target));
    out.push_str(&format!("**Started:** {}\n", r.started_at.to_rfc3339()));
    out.push_str(&format!("**Finished:** {}\n", r.finished_at.to_rfc3339()));
    out.push_str(&format!("**Model:** {}\n", r.model));
    out.push_str(&format!("**Iterations:** {}\n", r.iterations));
    out.push_str("**Scope:** Passive external recon (subfinder + httpx)\n");
    out.push_str("**Classification:** Defensive / reconnaissance\n\n");
    out.push_str("---\n\n");

    out.push_str("## Executive Summary\n\n");
    let summary = if r.final_summary.trim().is_empty() {
        "_No summary produced._".to_string()
    } else {
        r.final_summary.trim().to_string()
    };
    out.push_str(&summary);
    out.push_str("\n\n---\n\n");

    // Findings table: one row per tool step.
    out.push_str("## Findings\n\n");
    out.push_str("| # | Tool | Lines | Duration (ms) | Status |\n");
    out.push_str("|---|------|-------|---------------|--------|\n");
    for s in &r.steps {
        let tool = s.tool.clone().unwrap_or_else(|| "(none)".into());
        let status = if let Some(e) = &s.error {
            format!("ERROR: {}", e.chars().take(60).collect::<String>())
        } else {
            "ok".to_string()
        };
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            s.iteration, tool, s.stdout_lines, s.duration_ms, status
        ));
    }
    out.push_str("\n");

    // Per-step detail with preview.
    out.push_str("## Step Detail\n\n");
    for s in &r.steps {
        out.push_str(&format!(
            "### Iteration {} -- {}\n\n",
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

    out.push_str("---\n\n");
    out.push_str("## Methodology\n\n");
    out.push_str(
        "A small LLM (running locally on Lemonade Server, AMD Ryzen AI) drives a ReAct \
         loop with two tools: `subfinder` for passive subdomain enumeration, and `httpx` \
         for live HTTP probing with status/title/tech detection. Each iteration, the \
         model observes the previous tool's output and decides the next action. The loop \
         terminates when the model emits `{\"action\": \"done\"}` or hits the iteration \
         cap. No active scanning, no credentialed access, no exploitation.\n\n",
    );

    out.push_str("## Recommended Next Steps\n\n");
    out.push_str("- Review the discovered subdomains for staging/dev/admin/internal hosts that should not be exposed.\n");
    out.push_str("- Cross-reference httpx tech fingerprints with known CVEs (nuclei templates are the natural next pass).\n");
    out.push_str("- For any host returning non-200 with interesting titles, run directory enumeration (ffuf) on a case-by-case basis.\n");
    out.push_str("- If this is an authorized engagement, promote interesting findings into a formal report with severity ratings.\n\n");

    out.push_str("---\n\n");
    out.push_str("_Generated by AgentSpyBoo Phase 1.5 -- https://github.com/Peterc3-dev (private repo)_\n");
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

// AgentSpyBoo — Phase 1 MVP
//
// A minimal ReAct-style loop: the LLM (Qwen3-1.7B on Lemonade) is told about
// one tool (subfinder), it emits a tool call, we execute it, feed the result
// back, and ask for a final summary. One tool, one iteration. Proves the pipe.
//
// The rich scaffold under src/agent, src/llm, src/tools, etc. is left on disk
// as portfolio scaffolding — not wired into the build yet. Phase 2 will grow
// the real registry, state machine, and NPU path.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::process::Command;

#[derive(Parser, Debug)]
#[command(name = "agentspyboo", about = "AI red team agent (Phase 1 MVP)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// LLM API base URL (OpenAI-compatible)
    #[arg(long, default_value = "http://127.0.0.1:13305/api/v1", global = true)]
    llm_url: String,

    /// LLM model ID
    #[arg(long, default_value = "Qwen3-1.7B-GGUF", global = true)]
    model: String,

    /// Bearer token for the LLM API
    #[arg(long, default_value = "lemonade", global = true)]
    api_key: String,

    /// Tool execution timeout (seconds)
    #[arg(long, default_value_t = 120, global = true)]
    tool_timeout: u64,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run a single-tool recon pass against a domain.
    Recon {
        /// Target domain (e.g. example.com)
        domain: String,
    },
}

// ---------- OpenAI-compatible chat types ----------

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

// ---------- LLM client ----------

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

// ---------- Tool: subfinder ----------

async fn run_subfinder(domain: &str, timeout: Duration) -> Result<String> {
    // Prefer ~/go/bin/subfinder if it's not on PATH (GPD setup).
    let bin = if which("subfinder").is_some() {
        "subfinder".to_string()
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/raz".into());
        let candidate = format!("{}/go/bin/subfinder", home);
        if std::path::Path::new(&candidate).exists() {
            candidate
        } else {
            bail!("subfinder not found on PATH or in ~/go/bin");
        }
    };

    let mut cmd = Command::new(&bin);
    cmd.arg("-d").arg(domain).arg("-silent");

    let out = tokio::time::timeout(timeout, cmd.output())
        .await
        .map_err(|_| anyhow!("subfinder timed out after {:?}", timeout))?
        .context("failed to spawn subfinder")?;

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() && stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("subfinder exited {:?}: {}", out.status.code(), stderr);
    }
    Ok(stdout)
}

fn which(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

// ---------- Tool call parsing ----------
//
// We ask the model to reply with a JSON object of the form:
//   {"tool": "subfinder", "arguments": {"domain": "example.com"}}
// wrapped in ```json fences or not. We scan for the first balanced JSON object.

fn extract_json(text: &str) -> Option<Value> {
    // Strip code fences if present.
    let cleaned = text
        .replace("```json", "```")
        .split("```")
        .find(|chunk| chunk.contains('{'))
        .map(|s| s.to_string())
        .unwrap_or_else(|| text.to_string());

    let bytes = cleaned.as_bytes();
    let mut depth = 0i32;
    let mut start: Option<usize> = None;
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
                            return Some(v);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
}

// ---------- ReAct loop (one iteration) ----------

const SYSTEM_PROMPT: &str = "/nothink You are AgentSpyBoo, an autonomous red team recon agent. \
You have exactly ONE tool available this turn:\n\n\
  Tool: subfinder\n\
  Description: Passive subdomain enumeration for a target domain.\n\
  Arguments: {\"domain\": \"<target>\"}\n\n\
When asked to recon a target, respond ONLY with a JSON object like:\n\
{\"tool\": \"subfinder\", \"arguments\": {\"domain\": \"example.com\"}}\n\n\
Do not add any other text. Do not explain. Just the JSON.";

const SUMMARY_PROMPT: &str = "/nothink You are AgentSpyBoo. You just ran subfinder and received \
the results below. Write a concise 3-5 sentence recon summary for the operator: how many \
subdomains were found, any that look interesting (staging, dev, admin, api, internal, etc.), \
and one suggested next step. Plain text, no JSON.";

async fn run_recon(cli: &Cli, domain: &str) -> Result<()> {
    println!("[*] AgentSpyBoo Phase 1 MVP");
    println!("[*] Target : {domain}");
    println!("[*] LLM    : {} ({})", cli.model, cli.llm_url);
    println!();

    let llm = LlmClient::new(&cli.llm_url, &cli.model, &cli.api_key);

    // --- Step 1: ask LLM what to do ---
    println!("[>] Asking LLM for next action...");
    let plan_msgs = vec![
        ChatMessage {
            role: "system".into(),
            content: SYSTEM_PROMPT.into(),
        },
        ChatMessage {
            role: "user".into(),
            content: format!("Target domain: {domain}\nTask: perform passive subdomain recon."),
        },
    ];
    let plan_raw = llm.chat(&plan_msgs).await?;
    println!("[<] LLM raw:\n{}\n", plan_raw.trim());

    // --- Step 2: parse tool call (with a hard fallback so the demo can't deadlock) ---
    let (tool, args) = match extract_json(&plan_raw) {
        Some(v) => {
            let tool = v
                .get("tool")
                .and_then(|t| t.as_str())
                .unwrap_or("subfinder")
                .to_string();
            let args = v.get("arguments").cloned().unwrap_or(json!({}));
            (tool, args)
        }
        None => {
            println!("[!] Could not parse a tool call from LLM output — defaulting to subfinder");
            (
                "subfinder".to_string(),
                json!({ "domain": domain.to_string() }),
            )
        }
    };

    if tool != "subfinder" {
        bail!("LLM requested unknown tool: {tool}");
    }
    let target = args
        .get("domain")
        .and_then(|d| d.as_str())
        .unwrap_or(domain);

    // --- Step 3: execute the tool ---
    println!("[>] Executing subfinder -d {target} -silent ...");
    let timeout = Duration::from_secs(cli.tool_timeout);
    let stdout = run_subfinder(target, timeout).await?;
    let line_count = stdout.lines().filter(|l| !l.trim().is_empty()).count();
    println!("[+] subfinder returned {line_count} subdomains");
    let preview: Vec<&str> = stdout.lines().take(15).collect();
    for line in &preview {
        println!("    {}", line);
    }
    if line_count > preview.len() {
        println!("    ... ({} more)", line_count - preview.len());
    }
    println!();

    // --- Step 4: feed result back, get summary ---
    println!("[>] Asking LLM to summarize findings...");
    let tool_result_preview: String = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(60)
        .collect::<Vec<_>>()
        .join("\n");

    let summary_msgs = vec![
        ChatMessage {
            role: "system".into(),
            content: SUMMARY_PROMPT.into(),
        },
        ChatMessage {
            role: "user".into(),
            content: format!(
                "Target: {target}\nTool: subfinder\nSubdomains found: {line_count}\n\nResults:\n{tool_result_preview}"
            ),
        },
    ];
    let summary = llm.chat(&summary_msgs).await?;

    println!();
    println!("========== AGENT SUMMARY ==========");
    println!("{}", summary.trim());
    println!("===================================");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Recon { domain } => run_recon(&cli, domain).await,
    }
}

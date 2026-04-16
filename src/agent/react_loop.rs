// The ReAct loop: observe → think → act → repeat.
//
// Drives the LLM through tool chain subfinder → httpx → nuclei with
// intelligent skipping, scope guards, and a per-iteration rate limit.
// Produces a RunRecord which is then written to JSON + markdown by `report`.

use crate::config::{Cli, Config};
use crate::findings::{
    dedup_findings, extract_hosts_from_subfinder, parse_httpx_output, parse_nuclei_output,
    DedupedFinding, Finding, Severity,
};
use crate::llm::{parse_action, strip_think, system_prompt, AgentAction, ChatMessage, LlmClient};
use crate::preflight::run_pius;
use crate::report::render_report;

use super::state::PreflightReport;
use crate::scope::host_in_scope;
use crate::tools::{
    exec_httpx, exec_nuclei, exec_subfinder, nuclei_templates_root,
    select_interesting_urls, ToolExecution, ToolKind,
};

use super::state::{preview, RunRecord, StepRecord};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use std::time::Duration;

pub async fn run_recon(cli: &Cli, domain: &str) -> Result<()> {
    let cfg = Config::resolve(cli, domain);
    let scope_display = cfg.scope_patterns.join(", ");

    println!("[*] AgentSpyBoo Phase 3 (CPU-track + Pius preflight)");
    println!("[*] Target        : {domain}");
    if let Some(ref org) = cfg.org {
        println!("[*] Org           : {org}");
    }
    if let Some(ref asn) = cfg.asn {
        println!("[*] ASN           : {asn}");
    }
    println!("[*] Scope         : {scope_display}");
    println!("[*] LLM           : {} ({})", cfg.model, cfg.base_url);
    println!("[*] Max iterations: {}", cfg.max_iterations);
    println!("[*] Rate limit    : {}ms", cfg.rate_limit_ms);
    println!("[*] httpx cap     : {}", cfg.httpx_cap);
    println!("[*] nuclei cap    : {}", cfg.nuclei_cap);
    println!(
        "[*] dedup         : {}",
        if cfg.no_dedup { "off (--no-dedup)" } else { "on" }
    );
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
    let mut preflight_report: Option<PreflightReport> = None;

    // --- Pius preflight (runs before the agent loop if --org is set) ---
    if let Some(ref org) = cfg.org {
        println!("[*] Running Pius org-level preflight for {org:?}...");
        match run_pius(
            org,
            Some(domain),
            cfg.asn.as_deref(),
            &cfg.scope_patterns,
            cfg.verbose,
        )
        .await
        {
            Ok(result) => {
                println!(
                    "[+] Pius: {} domains, {} CIDRs, {} github orgs ({:.1}s)",
                    result.domains.len(),
                    result.cidrs.len(),
                    result.github_orgs.len(),
                    result.runtime_secs,
                );
                // Pre-seed subfinder host list with Pius-discovered domains
                for d in &result.domains {
                    if !last_subfinder_hosts.contains(&d.host) {
                        last_subfinder_hosts.push(d.host.clone());
                    }
                }
                // CIDRs go directly to findings as severity::Low
                for cidr in &result.cidrs {
                    let asn_suffix = cidr
                        .asn
                        .as_deref()
                        .map(|a| format!(", asn: {a}"))
                        .unwrap_or_default();
                    all_findings.push(Finding::new(
                        Severity::Low,
                        "cidr-discovered",
                        &cidr.cidr,
                        format!(
                            "CIDR block discovered via Pius (source: {}{asn_suffix})",
                            cidr.source
                        ),
                    ));
                }
                preflight_report = Some(PreflightReport {
                    org: org.clone(),
                    asn: cfg.asn.clone(),
                    mode: "passive".into(),
                    runtime_secs: result.runtime_secs,
                    total_raw: result.total_raw,
                    filtered_out: result.filtered_out,
                    plugins_fired: result.plugins_fired,
                    domains: result.domains,
                    cidrs: result.cidrs,
                    github_orgs: result.github_orgs,
                });
                println!();
            }
            Err(e) => {
                eprintln!("[!] Pius preflight failed: {e}");
                eprintln!("[!] Continuing without org-level recon.");
                println!();
            }
        }
    }
    let mut last_httpx_urls: Vec<String> = Vec::new();
    let mut last_httpx_stdout: String = String::new();
    // Records whether nuclei was narrowed from a larger httpx pool (for report methodology note).
    let mut nuclei_narrow_note: Option<(usize, usize)> = None;
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
                        // Prefer explicit URLs from the LLM; otherwise pull from httpx.
                        // When falling back to httpx, run the interesting-host
                        // heuristic so nuclei only scans the top N URLs.
                        let explicit_urls: Option<Vec<String>> = args
                            .get("urls")
                            .and_then(|h| h.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            });
                        // urls_from is accepted for LLM compatibility but we
                        // always fall back to httpx when no explicit URLs are
                        // given — no other source exists in-pipeline.
                        let _ = args.get("urls_from");
                        let raw_urls: Vec<String> = if let Some(u) = explicit_urls {
                            u
                        } else {
                            last_httpx_urls.clone()
                        };
                        let live_count = last_httpx_urls.len();
                        let before = raw_urls.len();
                        let scoped: Vec<String> = raw_urls
                            .into_iter()
                            .filter(|u| host_in_scope(u, &cfg.scope_patterns))
                            .collect();
                        let dropped = before - scoped.len();
                        if dropped > 0 {
                            println!("[!] scope guard: dropped {dropped} out-of-scope urls before nuclei");
                        }
                        // Select the most-interesting URLs from the raw httpx
                        // stdout, then intersect with scoped set. If we don't
                        // have httpx JSON (e.g. LLM gave explicit URLs), just
                        // take the first `nuclei_cap` in order.
                        let urls: Vec<String> = if !last_httpx_stdout.is_empty() {
                            let ranked = select_interesting_urls(
                                &last_httpx_stdout,
                                cfg.nuclei_cap.saturating_mul(4),
                            );
                            let scoped_set: std::collections::HashSet<String> =
                                scoped.iter().cloned().collect();
                            let mut out: Vec<String> = ranked
                                .into_iter()
                                .filter(|u| scoped_set.contains(u))
                                .take(cfg.nuclei_cap)
                                .collect();
                            // If heuristic produced fewer than cap (e.g. LLM
                            // supplied its own URL list not in stdout), fill
                            // from the scoped list in order.
                            if out.len() < cfg.nuclei_cap {
                                for u in &scoped {
                                    if out.len() >= cfg.nuclei_cap {
                                        break;
                                    }
                                    if !out.contains(u) {
                                        out.push(u.clone());
                                    }
                                }
                            }
                            out
                        } else {
                            scoped.iter().take(cfg.nuclei_cap).cloned().collect()
                        };
                        if live_count > urls.len() {
                            nuclei_narrow_note = Some((urls.len(), live_count));
                        }
                        println!(
                            "[>] Executing nuclei against {} of {} live hosts (cap via --nuclei-cap, heuristic: status/tech/non-cdn)",
                            urls.len(),
                            live_count
                        );
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
                                all_findings.push(Finding::new(
                                    Severity::Info,
                                    "subdomain",
                                    h.clone(),
                                    "discovered via subfinder",
                                ));
                            }
                        }
                    }
                    ToolKind::Httpx => {
                        if exec.error.is_none() {
                            let (urls, httpx_findings) = parse_httpx_output(&exec.stdout);
                            last_httpx_urls = urls;
                            last_httpx_stdout = exec.stdout.clone();
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

    // Sort raw findings by severity desc for report rendering.
    all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    let raw_findings_view = all_findings.clone();

    // Dedup (default) or passthrough.
    let findings_view: Vec<DedupedFinding> = if cfg.no_dedup {
        all_findings
            .iter()
            .map(|f| DedupedFinding {
                severity: f.severity,
                kind: f.kind.clone(),
                targets: vec![f.target.clone()],
                details: f.details.clone(),
                count: 1,
                first_seen: f.first_seen,
            })
            .collect()
    } else {
        dedup_findings(&all_findings)
    };

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
        findings: findings_view,
        raw_findings: raw_findings_view,
        dedup_enabled: !cfg.no_dedup,
        final_summary: final_summary.clone(),
        next_steps: next_steps_llm,
        nuclei_narrow: nuclei_narrow_note,
        preflight: preflight_report,
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

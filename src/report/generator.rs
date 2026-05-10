// Render a RunRecord into the markdown format used by ai-redteam-reports/.

use crate::agent::RunRecord;

pub fn render_report(r: &RunRecord) -> String {
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

    // Organization Recon (Pius preflight) — only rendered when --org was set.
    if let Some(p) = &r.preflight {
        out.push_str("## Organization Recon (Pius)\n\n");
        out.push_str(&format!(
            "**Organization:** {}  \n**ASN hint:** {}  \n**Mode:** {}  \n**Runtime:** {:.1}s  \n**Plugins fired:** {}  \n**Records:** {} raw, {} filtered out\n\n",
            p.org,
            p.asn.as_deref().unwrap_or("(none)"),
            p.mode,
            p.runtime_secs,
            if p.plugins_fired.is_empty() {
                "(none)".to_string()
            } else {
                p.plugins_fired.join(", ")
            },
            p.total_raw,
            p.filtered_out,
        ));

        out.push_str("### Domains discovered\n\n");
        if p.domains.is_empty() {
            out.push_str("_No domains after filtering._\n\n");
        } else {
            out.push_str("| Domain | Sources | Confidence |\n");
            out.push_str("|--------|---------|------------|\n");
            for d in &p.domains {
                let conf = d
                    .confidence
                    .map(|c| format!("{c:.1}"))
                    .unwrap_or_else(|| "—".to_string());
                out.push_str(&format!(
                    "| `{}` | {} | {} |\n",
                    d.host,
                    d.sources.join(", "),
                    conf
                ));
            }
            out.push_str("\n");
        }

        out.push_str("### CIDR blocks\n\n");
        if p.cidrs.is_empty() {
            out.push_str("_No CIDR blocks discovered (supply `--asn` to enable BGP lookup)._\n\n");
        } else {
            out.push_str("| CIDR | Source | ASN |\n");
            out.push_str("|------|--------|-----|\n");
            for c in &p.cidrs {
                out.push_str(&format!(
                    "| `{}` | {} | {} |\n",
                    c.cidr,
                    c.source,
                    c.asn.as_deref().unwrap_or("—")
                ));
            }
            out.push_str("\n");
        }

        out.push_str("### GitHub organizations\n\n");
        if p.github_orgs.is_empty() {
            out.push_str("_None identified._\n\n");
        } else {
            out.push_str("| Login | Name | Confidence |\n");
            out.push_str("|-------|------|------------|\n");
            for g in &p.github_orgs {
                let conf = g
                    .confidence
                    .map(|c| format!("{c:.1}"))
                    .unwrap_or_else(|| "—".to_string());
                out.push_str(&format!("| `{}` | {} | {} |\n", g.login, g.name, conf));
            }
            out.push_str("\n");
        }

        // Key-gated plugin status: render only when there's something
        // actionable (plugins skipped for missing keys, or fired-but-suboptimal
        // optional plugins). All-fired-clean is silent — no need to lecture
        // the user about plugins that worked.
        let actionable: Vec<&crate::preflight::PluginKeyStatus> = p
            .key_status
            .iter()
            .filter(|s| s.status != "fired")
            .collect();
        if !actionable.is_empty() {
            out.push_str("### Key-gated plugins\n\n");
            out.push_str("| Plugin | Status | Required env vars | Note |\n");
            out.push_str("|--------|--------|-------------------|------|\n");
            for s in &actionable {
                let status_label = match s.status.as_str() {
                    "skipped_no_key" => "skipped (key missing)",
                    "skipped_with_key" => "skipped (key set, plugin silent)",
                    "fired_optional_no_key" => "fired (no key — degraded)",
                    other => other,
                };
                out.push_str(&format!(
                    "| `{}` | {} | `{}` | {} |\n",
                    s.plugin,
                    status_label,
                    s.env_vars_required.join(", "),
                    s.note,
                ));
            }
            out.push_str("\n");
            let missing_keys: Vec<&str> = actionable
                .iter()
                .filter(|s| s.status == "skipped_no_key")
                .flat_map(|s| {
                    s.env_vars_required
                        .iter()
                        .filter(|v| !s.env_vars_set.contains(v))
                        .map(String::as_str)
                })
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            if !missing_keys.is_empty() {
                out.push_str(&format!(
                    "_To enable the skipped plugins, set: `{}`. See `docs/pius-api-keys.md` for free-tier reality._\n\n",
                    missing_keys.join("`, `")
                ));
            }
        }

        out.push_str(
            "_Pius runs once before iteration 1. Passing domains pre-seed the subfinder host \
             list; CIDR blocks feed directly into findings as Severity::Low (`cidr-discovered`). \
             The LLM never sees Pius output._\n\n---\n\n",
        );
    }

    // Findings table
    out.push_str("## Findings Table\n\n");
    if r.findings.is_empty() {
        out.push_str("_No findings recorded._\n\n");
    } else {
        if r.dedup_enabled && r.raw_findings.len() != r.findings.len() {
            out.push_str(&format!(
                "_Dedup folded {} raw observations into {} grouped findings. Disable with `--no-dedup`._\n\n",
                r.raw_findings.len(),
                r.findings.len()
            ));
        }
        out.push_str("| # | Severity | Type | Targets | Details |\n");
        out.push_str("|---|----------|------|---------|---------|\n");
        let mut expand_sections: Vec<(usize, &crate::findings::DedupedFinding)> = Vec::new();
        for (i, f) in r.findings.iter().enumerate() {
            let details_clean = f
                .details
                .replace('|', "\\|")
                .replace('\n', " ")
                .chars()
                .take(120)
                .collect::<String>();
            let target_cell = if f.targets.len() == 1 {
                f.targets[0].replace('|', "\\|")
            } else {
                format!("{} targets (x{})", f.targets.len(), f.count)
            };
            out.push_str(&format!(
                "| {} | {} {} | {} | {} | {} |\n",
                i + 1,
                f.severity.icon(),
                f.severity.label(),
                f.kind,
                target_cell,
                details_clean
            ));
            if f.targets.len() > 1 {
                expand_sections.push((i + 1, f));
            }
        }
        out.push_str("\n");
        // Per-finding target lists for the collapsed entries.
        for (idx, f) in expand_sections {
            out.push_str(&format!(
                "<details><summary>Finding #{idx} — {} target(s)</summary>\n\n",
                f.targets.len()
            ));
            for t in &f.targets {
                out.push_str(&format!("- `{t}`\n"));
            }
            out.push_str("\n</details>\n\n");
        }
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
    if let Some((scanned, live)) = r.nuclei_narrow {
        out.push_str(&format!(
            "### Host selection\n\nnuclei was run against **{scanned} of {live}** live hosts, \
             narrowed from the httpx-live set by an interesting-host heuristic \
             (status code, tech-stack count, CDN/DNS-only penalty, admin/api/auth keyword bonus). \
             Override with `--nuclei-cap <n>` to scan more or fewer.\n\n",
        ));
    }
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
    out.push_str("_Generated by AgentSpyBoo Phase 3 (CPU-track + Pius preflight) — https://github.com/Peterc3-dev (private)_\n");
    out
}
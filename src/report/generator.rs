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
    out.push_str("_Generated by AgentSpyBoo Phase 2 (CPU-track) — https://github.com/Peterc3-dev (private)_\n");
    out
}
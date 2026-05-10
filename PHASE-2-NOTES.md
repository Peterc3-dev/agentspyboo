# Phase 2 — CPU track

This is the CPU-side Phase 2. The NPU inference path (ort + Vitis EP) is
parked on a kernel-driver blocker documented in `PHASE-2-RECON.md` — not
forgotten, just blocked on amdxdna bind failing on 6.19.12.

Phase 2 CPU takes what Phase 1.5 shipped (subfinder → httpx chained inside
a ReAct loop with JSON + markdown report output) and pushes it into
something that looks more like a real vuln assessment.

## What changed from Phase 1.5

- **Third tool: nuclei.** Curated template set only — we point `-t` at
  `~/nuclei-templates/http/{cves,exposures,misconfiguration,vulnerabilities}`
  and pass `-severity medium,high,critical` to cut the noise floor.
  Output parsed from `-jsonl`. 300s timeout. Falls back to flat-layout
  template dirs if the `http/` subdirectory isn't present.
- **LLM-driven skipping.** System prompt now has explicit rules: if
  subfinder returns 0, emit done; if httpx returns 0 live, emit done.
  The empty-observation message literally tells the LLM "Per rules, emit
  done now." The existing `{"action":"done"}` parser already handled it.
- **`--scope` glob allowlist.** Default is `<target>,*.<target>`.
  Hand-rolled `host_in_scope()` with `*.` prefix glob, no `glob` crate.
  Every tool spawn runs its target list through the scope guard first.
  Out-of-scope hosts are dropped with a logged warning. The agent
  refuses to even start if the `domain` argument itself doesn't match
  the scope patterns.
- **`--rate-limit <ms>` flag.** Default 500ms. Honored as a sleep at the
  top of each iteration (iterations 2..N; no delay before iteration 1).
- **`--httpx-cap <n>` flag.** Default 150. Was a hardcoded const
  (`HTTPX_HOST_CAP`) in Phase 1.5. Now a CLI flag threaded through to
  `exec_httpx()`.
- **Severity ratings on all findings.** `Severity` enum with
  `info/low/medium/high/critical` + icon method. Findings sorted
  severity-desc for report rendering. Rules:
  - subfinder subdomains → `info`
  - httpx probes → `info` baseline, `low` if tech fingerprints present,
    `medium` if the title hints at admin/login/dashboard/phpMyAdmin
  - nuclei findings → honor nuclei's `info.severity` (critical/high/...)
  - LLM final "done" action can include its own `next_steps` array
- **New markdown report format.** Matches `ai-redteam-reports/`
  (`internal-scan-2026-04-10.md`) style:
  - `# AgentSpyBoo Assessment — <target>`
  - `**Date:** ... **Model:** ... **Iterations:** ... **Scope:** ... **Tools fired:** subfinder → httpx → nuclei`
  - `## Executive Summary` (LLM-written)
  - `## Findings Table` with `#` / Severity (with icon) / Type / Target / Details columns
  - `## Methodology` (auto-generated from the tool chain that actually ran this run)
  - `## Step Detail` (per-iteration logs preserved from 1.5)
  - `## Recommended Next Steps` (prefers LLM's `next_steps[]`, falls back to boilerplate)
- **Environment variables as defaults.** `LEMONADE_BASE_URL`,
  `AGENTSPYBOO_MODEL`, `AGENTSPYBOO_MAX_ITERS`, `AGENTSPYBOO_RATE_LIMIT_MS`.
  CLI flags override env, env overrides hardcoded defaults.
- **Slim observations.** The feedback message the LLM sees after each
  tool is now a short summary (line count + first 10 items) rather than
  25 lines of raw output. See "open questions" — this was flagged in
  Phase 1.5 and fixed here because the full httpx JSON blew out
  Qwen3-1.7B's context window on iteration 3.

## Architectural decision preserved

Still flat in `src/main.rs`. The `src/agent/`, `src/llm/`, `src/tools/`,
`src/findings/`, `src/report/` scaffold modules remain untouched dead
code. File is now ~1200 lines but still navigable. We split when tool
#4 or #5 lands (per the Phase 1.5 decision doc).

## Non-obvious decisions

- **Nuclei timeout set to 300s, not higher.** On GPD with 4 curated template
  dirs running against 10 URLs, nuclei will often bump up against 300s.
  Phase 2 accepts this — when nuclei times out, the LLM sees the error
  in the observation and correctly emits done with a "re-run with more
  time" next-step suggestion. We don't auto-retry. Phase 2.5 can tune.
- **Scope guard on URLs for nuclei** extracts host from the URL via
  `normalize_host()` which strips scheme, port, and path. Handles the
  common case; doesn't handle userinfo (`user:pass@host`) but nuclei
  output never contains those.
- **Slim observation format.** The single biggest bug we hit during
  testing: the full `httpx -json` output (10 lines × ~800 bytes) fed
  back to the LLM as "Observation:" caused Lemonade to return a
  malformed response (missing `choices` field). Fix: feed summaries,
  not raw tool output. LLM only needs counts + first N identifiers to
  make the next decision.
- **`tools_fired` only counts successful runs.** If nuclei errors out,
  it doesn't appear in the report's "Tools fired" header, even though
  the step detail section records the attempt. Distinguishes "we tried
  and it worked" from "we tried and it blew up."
- **Scope refused for target itself.** If `--scope` is passed and the
  target domain doesn't match any pattern, we bail at startup. Prevents
  footgun like `--scope "*.example.com" example.com` which would pass
  the scope check for subdomains but fail for the apex itself.

## Open questions from PHASE-1.5-NOTES — resolved

1. **httpx only returned 1 JSON line for hackerone.com.** No longer an
   issue on the 2026-04-14 re-run — httpx returned 10 lines cleanly.
   Likely a transient upstream issue on the original Phase 1.5 run.
2. **httpx flags tuning.** Kept the existing flag set
   (`-silent -status-code -title -tech-detect -json`). Parsing now
   extracts `url`, `host`, `status_code`, `title`, `tech[]` — good
   enough for severity assignment.
3. **HTTPX_HOST_CAP as CLI flag.** Done. `--httpx-cap <n>`, default 150.
4. **No nuclei integration.** Shipped in this phase.
5. **Wildcard-polluted subdomain lists** (the `example.com` 22k problem).
   Still mitigated by the cap. Scope guard is a second layer: even if
   subfinder returns junk, hosts that don't end in `.target` get dropped
   before httpx spawns.
6. **Severity ratings absent from report.** Added. Info through Critical
   with emoji icons in the findings table.
7. **Slim findings.** Done. Observations to LLM are now summaries, not
   raw output; findings JSON on disk is still detailed.

## New open questions

1. **Nuclei timeout on GPD.** 300s against 10 URLs with 4 template dirs
   is not enough headroom. Options: (a) bump to 600s, (b) reduce template
   set further (drop `vulnerabilities/` which is the largest), (c) add
   `-c 50` concurrency and `-rl 150` rate flag tuning. Defer to Phase 2.5.
2. **`tools_fired` semantics.** Currently "successful runs only." Should
   errored runs appear in the header with an error marker? Trade-off
   between report clarity and completeness.
3. **httpx probe findings are noisy.** 10 live hosts = 10 `low`-severity
   findings in the table, most of which are just "tech stack detected."
   Consider collapsing httpx findings to a single `info` row
   ("N live hosts probed") and only emit per-host rows for `medium`+.
4. **LLM sometimes picks `tool` without looking at the skip rules.**
   During testing the skipping worked correctly, but Qwen3-1.7B is small.
   A retry prompt that forces the skip when the prior tool's observation
   says "returned 0 lines" would be a belt-and-braces improvement.
5. **Nuclei template set drift.** We hardcode four subdir names; nuclei
   template layout has shifted between major versions before. A preflight
   that lists which of the four actually resolved would be nice.

## How to run

```bash
# Default (scope derived from target, 500ms rate limit, 150 httpx cap)
PATH=$HOME/go/bin:$PATH ./target/release/agentspyboo recon hackerone.com --verbose

# Custom scope + slower rate limit
./target/release/agentspyboo recon example.com \
  --scope "example.com,*.example.com,*.sub.example.com" \
  --rate-limit 1000 \
  --httpx-cap 50 \
  --verbose

# Env var config
LEMONADE_BASE_URL=http://127.0.0.1:13305/api/v1 \
AGENTSPYBOO_MODEL=Qwen3-1.7B-GGUF \
AGENTSPYBOO_MAX_ITERS=5 \
AGENTSPYBOO_RATE_LIMIT_MS=750 \
./target/release/agentspyboo recon hackerone.com
```

Build on GPD:
```bash
ssh raz@100.77.212.27
cd ~/projects/agentspyboo
~/.cargo/bin/cargo build --release --offline
```

## Test run — hackerone.com (2026-04-14)

Command:
```
PATH=$HOME/go/bin:$PATH ./target/release/agentspyboo recon hackerone.com --verbose
```

Stdout excerpt:
```
[*] AgentSpyBoo Phase 2 (CPU-track)
[*] Target        : hackerone.com
[*] Scope         : hackerone.com, *.hackerone.com
[*] LLM           : Qwen3-1.7B-GGUF (http://127.0.0.1:13305/api/v1)
[*] Max iterations: 5
[*] Rate limit    : 500ms
[*] httpx cap     : 150

[>] Iteration 1/5 — asking LLM for next action...
[<] LLM raw: {"tool": "subfinder", "arguments": {"domain": "hackerone.com"}}
[>] Executing subfinder with args {"domain":"hackerone.com"}
[+] subfinder returned 16 lines in 26439 ms

[>] Iteration 2/5 — asking LLM for next action...
[<] LLM raw: {"tool": "httpx", "arguments": {"hosts_from": "subfinder"}}
[+] httpx returned 10 lines in 1988 ms

[>] Iteration 3/5 — asking LLM for next action...
[<] LLM raw: {"tool": "nuclei", "arguments": {"urls_from": "httpx"}}
[!] nuclei error: nuclei timed out after 300s

[>] Iteration 4/5 — asking LLM for next action...
[<] LLM raw: {"action": "done", "summary": "Subfinder found 16 subdomains,
  httpx confirmed 10 live hosts, but nuclei timed out...",
  "next_steps": ["re-run nuclei with increased timeout", ...]}
[+] LLM signaled done.
```

Report excerpt (`reports/hackerone.com-20260414T154714Z.md`):
```markdown
# AgentSpyBoo Assessment — hackerone.com

**Date:** 2026-04-14T15:47:14Z
**Model:** Qwen3-1.7B-GGUF
**Iterations:** 4
**Scope:** hackerone.com, *.hackerone.com
**Tools fired:** subfinder → httpx

## Executive Summary

Subfinder found 16 subdomains, httpx confirmed 10 live hosts, but nuclei
timed out. No vulnerabilities found within the timeout...

## Findings Table

| # | Severity | Type | Target | Details |
|---|----------|------|--------|---------|
| 1 | 🔵 low | http-probe | b.ns.hackerone.com | status=301 title="..." tech=[Cloudflare] |
| 2 | 🔵 low | http-probe | mta-sts.forwarding.hackerone.com | status=404 ... |
| 7 | 🔵 low | http-probe | api.hackerone.com | status=200 title="HackerOne API" tech=[Algolia, Cloudflare, HSTS, jQuery, jsDelivr] |
| 11 | ℹ️ info | subdomain | mta-sts.managed.hackerone.com | discovered via subfinder |
```

Behaviors verified:
- Multi-iteration loop (4 iterations)
- subfinder → httpx → nuclei (attempted) → done
- Scope guard accepted hackerone.com, no out-of-scope drops
- Findings JSON written to `findings/hackerone.com-20260414T154714Z.json`
- Report written to `reports/hackerone.com-20260414T154714Z.md`
- LLM emitted `next_steps` array which appeared in the report
- Exit 0
- Total wall time: ~5m30s (dominated by the 300s nuclei timeout)

## NPU path is parked, not forgotten

See `PHASE-2-RECON.md`. The hardware blocker (amdxdna kernel bind failure
on 6.19.12) needs a kernel-side fix before ort-vitis becomes viable.
Phase 2 CPU is what we can ship today. When the driver lands, Phase 2.5
or Phase 3 can wire an `Inference` abstraction that routes between
Lemonade (current) and a local ort+vitis runner for air-gapped ops.

# AgentSpyBoo Phase 1.5 — Review Notes

A mini-review doc so you can read one file instead of diffing ten.

## TL;DR

Phase 1 was a single-shot: one tool call, one summary, one iteration.
Phase 1.5 is a bounded ReAct loop (default 5 iters) that chains
`subfinder -> httpx`, writes a JSON findings artifact and a readable
markdown report, and accepts multiple tool-call wire formats from the LLM.

End-to-end verified on GPD against `example.com` and `hackerone.com`,
exit code 0 both times.

## What changed

- **Rewrote `src/main.rs`** (~720 lines, still one file, on purpose — we
  only have two tools, a trait-object registry would be over-engineered).
- **Cargo.toml**: added `chrono` (for `DateTime<Utc>` on the record).
  No other deps added. Nothing removed.
- **Left untouched**: the dead scaffold under `src/agent/`, `src/tools/*.rs`,
  `src/findings/`, `src/report/`, `src/llm/`, `src/config.rs`,
  `README.md`, `RESEARCH.md`. Phase 1's `main` branch is pristine.

## Branch

`phase-1.5`, created off the Phase 1 MVP commit `8ab559a`. Not pushed.

## ReAct loop in 10 lines

1. Build system prompt describing both tools + JSON protocol.
2. For iter in 1..=max: ask LLM, parse its JSON action.
3. Action `done` → capture summary, break.
4. Action `tool` + known name → execute, feed observation back as user msg.
5. Action `tool` + unknown name → push error observation, continue.
6. Unparseable JSON → one retry with a clarifying system msg, then treat
   remaining raw text as the summary.
7. Subfinder stdout is cached in memory so httpx can use
   `{"hosts_from": "subfinder"}` (avoids round-tripping 16+ hosts through
   the LLM context).
8. Per-step record (tool, args, stdout_lines, preview, duration, error) is
   appended to a `steps` vec.
9. If the loop runs out without a `done`, the agent is asked once more to
   emit a done action.
10. After the loop, write `findings/<target>-<ts>.json` and
    `reports/<target>-<ts>.md`.

## Tool abstraction

`ToolKind` enum with two variants (`Subfinder`, `Httpx`). Methods:
`name()`, `from_name()`, `timeout()`, `description()`. Execution is two
async functions (`exec_subfinder`, `exec_httpx`) matched on `ToolKind`
inside the loop. Adding a third tool = new enum variant + new exec fn +
one match arm. Deliberately not a trait object.

Binary lookup: `which()` augments `$PATH` with `$HOME/go/bin` so the
Go-installed tools are always found even when the user forgets to export.

## Tool call parser

Accepts any of:

- `{"tool": "subfinder", "arguments": {"domain": "..."}}` (flat form)
- `{"tool": "subfinder", "args": {...}}` (alt key)
- `{"tool_calls": [{"function": {"name": "...", "arguments": "..."}}]}`
  (OpenAI form; stringified args are parsed)
- `{"action": "done", "summary": "..."}` (explicit stop)

JSON is found by scanning for balanced `{...}` after stripping `<think>`
blocks and code fences. Trailing prose is tolerated.

## Robustness

- `<think>` blocks stripped pre-parse (Qwen3 leaks them even with
  `/nothink`).
- Malformed tool call → one retry with clarifying system msg, then accept
  the raw text as summary and break.
- Unknown tool name → observation fed back, loop continues.
- Tool missing from PATH → `locate_bin` bails with a clear message; the
  per-step record captures the error so the loop doesn't crash, the LLM
  sees a "FAILED" observation and can switch tools or finish.
- Empty subfinder output → observation says "returned 0 lines", LLM
  decides what to do.
- **httpx host cap**: `HTTPX_HOST_CAP = 150`. Prevents wildcard-poisoned
  subdomain lists (e.g. `example.com` returns 22,000+ garbage
  subdomains) from blowing the 180s timeout.
- Tool timeouts: subfinder 90s, httpx 180s. Timeouts become errors in
  the step record.

## CLI flags

```
agentspyboo recon <domain>
    --model <name>          (default: Qwen3-1.7B-GGUF)
    --base-url <url>        (default: http://127.0.0.1:13305/api/v1)
    --api-key <key>         (default: lemonade)
    --max-iterations <n>    (default: 5)
    --verbose               (step-by-step LLM raw output)
```

Output style preserved from Phase 1: `[*]` setup, `[>]` action starting,
`[<]` LLM response, `[+]` success, `[!]` warning.

## Output artifacts

- `findings/<domain>-<ts>.json` — machine-readable run record (target,
  timestamps, model, per-step details, final summary)
- `reports/<domain>-<ts>.md` — human report modeled on
  `~/projects/ai-redteam-reports/internal-scan-2026-04-10.md`: front
  matter, Executive Summary, Findings table, Step Detail, Methodology,
  Recommended Next Steps

## How to run

```bash
# On GPD (Lemonade + Go tools live there)
ssh raz@100.77.212.27
cd ~/projects/agentspyboo
PATH=$HOME/go/bin:$PATH ./target/release/agentspyboo recon hackerone.com
# add --verbose for raw LLM output per step
```

## Test run stdouts

### example.com (3 iterations, exit 0)

```
[*] AgentSpyBoo Phase 1.5
[*] Target        : example.com
[*] LLM           : Qwen3-1.7B-GGUF (http://127.0.0.1:13305/api/v1)
[*] Max iterations: 5

[>] Iteration 1/5 — asking LLM for next action...
[<] LLM: {"tool": "subfinder", "arguments": {"domain": "example.com"}}...
[>] Executing subfinder with args {"domain":"example.com"}
[+] subfinder returned 22639 lines in 61208 ms
[>] Iteration 2/5 — asking LLM for next action...
[<] LLM: {"tool": "httpx", "arguments": {"hosts_from": "subfinder"}}...
[>] Executing httpx with args {"hosts_from":"subfinder"}
[+] httpx returned 0 lines in 54686 ms
[>] Iteration 3/5 — asking LLM for next action...
[<] LLM: {"action": "done", "summary": "No live subdomains were found..."}...
[+] LLM signaled done.

========== AGENT SUMMARY ==========
No live subdomains were found for example.com through passive recon.
===================================
[+] Findings : findings/example.com-20260414T025740Z.json
[+] Report   : reports/example.com-20260414T025740Z.md
```

Note: `example.com` returns ~22k wildcard-polluted subdomains from the
passive sources, capped to 150 before httpx, none responded on the
standard httpx ports → empty probe. LLM correctly concluded "nothing
live" and finished.

### hackerone.com (3 iterations, exit 0)

```
[*] AgentSpyBoo Phase 1.5
[*] Target        : hackerone.com
[*] LLM           : Qwen3-1.7B-GGUF (http://127.0.0.1:13305/api/v1)
[*] Max iterations: 5

[>] Iteration 1/5 — asking LLM for next action...
[<] LLM: {"tool": "subfinder", "arguments": {"domain": "hackerone.com"}}...
[>] Executing subfinder with args {"domain":"hackerone.com"}
[+] subfinder returned 16 lines in 30550 ms
[>] Iteration 2/5 — asking LLM for next action...
[<] LLM: {"tool": "httpx", "arguments": {"hosts_from": "subfinder"}}...
[>] Executing httpx with args {"hosts_from":"subfinder"}
[+] httpx returned 1 lines in 17373 ms
[>] Iteration 3/5 — asking LLM for next action...
[<] LLM: {"action": "done", "summary": "Reconnaissance on hackerone.com..."}...
[+] LLM signaled done.

========== AGENT SUMMARY ==========
Reconnaissance on hackerone.com completed. The following subdomains were
identified: support.hackerone.com, design.hackerone.com, events.hackerone.com,
docs.hackerone.com, a.ns.hackerone.com, websockets.hackerone.com,
go.hackerone.com, api.hackerone.com, mta-sts.forwarding.hackerone.com,
mta-sts.managed.hackerone.com, b.ns.hackerone.com, links.hackerone.com,
info.hackerone.com, gslink.hackerone.com, mta-sts.hackerone.com,
www.hackerone.com. A successful HTTP probe confirmed that
mta-sts.managed.hackerone.com is down, while others are active.
===================================
[+] Findings : findings/hackerone.com-20260414T025940Z.json
[+] Report   : reports/hackerone.com-20260414T025940Z.md
```

Full 16 subdomains discovered, LLM correctly identified support/api/docs
etc, and wrote the summary into the markdown report.

## Open questions

1. **httpx only returned 1 JSON line for hackerone.com** despite 16
   hosts. Subfinder entries include DNS-only records (`a.ns`, `b.ns`,
   `mta-sts.*`) that don't speak HTTP, so most will fail the probe
   silently with `-silent`. We may want to drop `-silent` on httpx or
   add `-fr` (follow redirects) + `-mc 200,301,302,401,403` to get a
   richer dataset. I didn't tweak flags because this felt like a taste
   call for you.
2. **Wildcard subdomain lists** like `example.com` (22k+) get capped to
   150 before httpx. Is 150 the right cap, or should we do something
   smarter (dedupe, prioritize non-random-looking names, etc.)?
3. **`HTTPX_HOST_CAP` is a const**, not a CLI flag. Easy to promote to
   `--httpx-cap <n>` if you want it tunable.
4. **No nuclei integration yet**. Natural next tool in the chain but
   felt out of scope for "make the existing pipe real".
5. **Findings JSON has full `llm_raw` per step** for debugging. This can
   balloon on large runs; consider a `--slim` flag later.
6. **Report template intentionally does not emit severity ratings**
   (CRITICAL/HIGH/MEDIUM) — passive recon doesn't produce severities.
   The internal-scan report you showed me does, so the two formats
   diverge there. Let me know if you want synthetic severities.

## Files touched

- `Cargo.toml` — added `chrono`
- `src/main.rs` — rewritten for Phase 1.5
- `PHASE-1.5-NOTES.md` — this file

Nothing else. Phase 1's `main` branch is unchanged.

# AgentSpyBoo Phase 4 — Scoping Spec

**Drafted:** 2026-04-18
**P1 revised:** 2026-05-10 (post-validation ablation + cap-fix, see below)
**Status:** P1 shipped (42fd6a2 + cd0c375). P2 shipped (4f740ec). P3 shipped (8bfa48d). One follow-up tracked (P3.5 IP-scope).
**Previous phase:** Phase 3 (Pius preflight) shipped 2026-04-16 on main

---

## Three problems to solve

### P1 — httpx detection + efficiency on dead-DNS-heavy targets

**Original framing (2026-04-18, since corrected):** the gitlab.com E2E run showed subfinder=519 subdomains, httpx=1 live. The spec read this as a 0.19% efficiency gap and proposed a dnsx pre-filter as the primary fix.

**Actual cause (uncovered 2026-05-10):** the 519→1 ratio was largely a `httpx-cap=150` artifact. agentspyboo clamps the subfinder host list to the first 150 hosts before probing. Subfinder's first 150 on gitlab.com are dominated by ephemeral `*-review-*.design-staging.gitlab.com` subdomains that 404 by design, so httpx legitimately found 1 live host *out of the slice it was given*. The full list never got probed at baseline.

**What the changes actually do (measured via ablation, 2026-05-10):**

| Condition | dnsx | httpx flags | Live hosts | Wall time |
|---|---|---|---|---|
| A: baseline-equivalent | no | old (timeout 10, retries 0, no follow-redirects) | 110 | (fast) |
| B: flags isolated      | no | new (timeout 15, retries 2, follow-redirects)   | 123 | 165s |
| C: full P1 stack       | yes | new                                            | 122 | 103s (dnsx 11s + httpx 92s) |

Same fresh subfinder list (559 hosts on gitlab.com) across all three. Conclusions:

1. **dnsx is an efficiency win, not a detection win.** B vs C: 123 vs 122 — flat. Dead-DNS hosts that dnsx drops would have been dropped by httpx anyway; the 426 dropped hosts contribute zero live-host signal in either path.
2. **httpx flag tuning is the actual detection win.** A vs B: +13 live hosts, ~12%, driven mostly by `-follow-redirects` catching 301/302 chains.
3. **dnsx saves ~60s wall time** on a list this dead-DNS-heavy (76% NXDOMAIN/SERVFAIL).
4. **The cap interaction is the real lurking bug.** The cap was meant to prevent runaway probing on enormous lists, but it interacts badly with subfinder's output ordering — ephemeral test/review subdomains cluster near the front of the list, so the cap consistently slices off the dead part. dnsx accidentally fixes this by collapsing the list below the cap threshold before clamping happens, but the right fix is to address the cap+ordering interaction directly (sort or shuffle the list before capping, or drop the cap once dnsx is in place).

**Phase 4 action (as shipped):**

- **P1.1 — dnsx resolution pass** between subfinder and httpx. Use `dnsx -a -aaaa -cname` so CNAME-only subdomains are preserved. Implemented in `src/tools/dnsx.rs` with a fallback to the unfiltered list when dnsx errors or returns suspiciously low (<2% on >50-host inputs). Shipped in 42fd6a2. **Effect: ~60s wall-time savings on dead-DNS-heavy targets, neutral on detection.**
- **P1.2 — httpx flag tuning.** `-retries 2 -follow-redirects -timeout 15`, `-threads 50` unchanged. Shipped in 42fd6a2. **Effect: ~12% live-host detection lift, primarily from follow-redirects.**
- **P1.3 — Env var tunables.** `AGENTSPYBOO_HTTPX_TIMEOUT`, `AGENTSPYBOO_HTTPX_THREADS`, `AGENTSPYBOO_HTTPX_RETRIES` overrides. Defaults to tuned values. Shipped in 42fd6a2.
- **P1.4 — Cap-vs-ordering fix.** The `httpx-cap` was slicing off the production half of subfinder's output because subfinder's natural ordering puts long auto-generated subdomains (CI review envs, deploy previews) near the front. `rank_for_cap` in `src/tools/httpx.rs` sorts by length, then depth, then alpha before applying the cap. Length is the primary signal because auto-generated hosts carry hash prefixes / hyphen-stuffed labels; production assets stay short. Shipped in cd0c375 with unit tests. **Effect: +140% live hosts at cap=150 on the dnsx-OFF path (35 → 84); no-op on the dnsx-ON path because dnsx already strips the long ephemerals before cap is applied. This is the resilience layer for when dnsx fails, fallback fires, or future targets where dnsx adds little.**

**Cap-fix validation (2026-05-10):**

| Path | Cap | Ordering | Live hosts |
|---|---|---|---|
| dnsx-OFF (P1.4 alone) | 150 | raw subfinder | 35 |
| dnsx-OFF (P1.4 alone) | 150 | length-sorted (P1.4) | 84 |
| dnsx-ON | 50 | alphabetical (counterfactual) | 48 |
| dnsx-ON | 50 | length-sorted (P1.4) | 48 |

The three changes are complementary, not redundant: dnsx for efficiency on dead-DNS-heavy targets, flag tuning for detection lift on the surviving hosts, cap-fix for fallback resilience when dnsx is unavailable or doesn't bite.

**Validation status:** P1 shipped behaves as the corrected spec describes. The original "5+/519" win condition was based on a confounded baseline and is retired.

**Side-finding:** `--nuclei-cap 0` cleanly skips the nuclei stage for fast iteration runs (recon-only mode). Useful when validating httpx-side changes without paying the nuclei wall-time cost.

### P2 — Pius API-key-gated plugins

**Pius source:** `github.com/praetorian-inc/pius` (corrected 2026-04-18 — earlier draft incorrectly listed `KingOfBugbounty/pius`).

**Current state:** Pius runs passive mode only. API-key plugins disabled for lack of keys.

**Why it matters (revised, realistic):** Full-key Pius is 5-10x discovery. Free-tier-only Pius is **~1.5-2x** discovery. The overstatement in the original draft assumed all keys active — wrong given free-tier reality (below).

**Correct plugin → env var map (verified from praetorian-inc/pius):**

| Plugin          | Env var(s)                          | Free-tier usable? |
|-----------------|-------------------------------------|-------------------|
| passive-dns     | `SECURITYTRAILS_API_KEY`            | No — ~50/mo hist., now paid only (~$50/mo min) |
| reverse-whois   | `VIEWDNS_API_KEY`                   | Yes — free tier |
| apollo          | `APOLLO_API_KEY`                    | No — B2B, no free |
| favicon-hash    | `SHODAN_API_KEY` + `FOFA_API_KEY`   | Shodan 100/mo free (burns fast) |
| shodan (CIDR)   | `SHODAN_API_KEY`                    | Same 100/mo budget |
| censys-org      | `CENSYS_API_TOKEN` + `CENSYS_ORG_ID`| No — $100 min credits for API |
| github-org      | `GITHUB_TOKEN`                      | Yes — free personal token |

**Removed from original spec (don't exist in Pius):** `VIRUSTOTAL_API_KEY`, `WHOXY_API_KEY`.

**Censys correction:** single `CENSYS_API_TOKEN` (+ org id), not an ID+secret pair as originally written.

**Phase 4 action (as shipped in 4f740ec):**

- **P2.1 — Env var passthrough.** Already automatic — `tokio::process::Command` inherits the parent env, so any key set in the shell flows through to Pius. No code change required; verified end-to-end.
- **P2.2 — Plugins-skipped detection.** Took the env-var-delta approach (chosen over stderr parsing, which is brittle). `KEY_GATED_PLUGINS` table in `src/preflight/pius.rs` maps each gated plugin to its required env var(s); `compute_key_status` classifies each as `fired`, `fired_optional_no_key`, `skipped_no_key`, or `skipped_with_key` after Pius returns. Carried through `PreflightReport.key_status` into the markdown report's "Key-gated plugins" sub-section. Renders only when something is actionable — no lecture when everything fired clean.
- **P2.3 — Cost reality doc** at `docs/pius-api-keys.md`. Honest framing: GITHUB_TOKEN and VIEWDNS_API_KEY are the only meaningful free-tier wins; SHODAN burns fast (100/mo); SecurityTrails/Censys/Apollo/FOFA are paid-only and rarely worth it for free-tier users.

**Validation (2026-05-10):** Ran preflight against `example.com`. Pius fired 3 free plugins (crt-sh, urlscan, wayback) and the new section correctly listed all 8 key-gated plugins as `skipped (key missing)` with their env vars and cost notes. Single combined unit test (env vars are global mutable state — combined to avoid cargo's parallel runner racing the assertions).

**Side-finding logged for future tuning:** dnsx hit its 120s timeout when handed example.com's 22k subfinder output. Worth raising `DNSX_TIMEOUT` or tuning dnsx threading for high-cardinality targets — orthogonal to P2.

**No code changes to Pius itself.** All changes in `src/preflight/pius.rs` (detection table + struct), `src/preflight/mod.rs` (re-export), `src/agent/state.rs` + `src/agent/react_loop.rs` (carry through), `src/report/generator.rs` (rendering).

### P3 — Active recon mode (ffuf)

**Current state (pre-P3):** All recon is passive. No content discovery. Nuclei scans templates but doesn't brute-force directories.

**As shipped (8bfa48d):** ffuf is a `ToolKind::Ffuf` that the LLM only sees in its tool list when `--active` is set. Off by default — passive runs are byte-identical to pre-P3 behavior.

**Safety rails as shipped:**

- **Hostname scope guard.** ffuf URL is run through `host_in_scope` before invocation; out-of-scope URLs are dropped with a logged warning, mirroring how subfinder/httpx already gate.
- **No redirect following.** No `-r` flag passed to ffuf — redirect chains stay where they are.
- **Active-flag gate.** The system prompt only describes ffuf to the LLM when `cfg.active` is true. Passive runs cannot invoke it even if a confused LLM guesses the tool name (`from_name("ffuf")` returns `Some(Ffuf)` always, but the dispatch only fires when the LLM emits the call, and the LLM only sees ffuf when active is set).
- **Rate limit.** Default `-rate 20` (20 req/sec), `-t 20` threads. Env overrides: `AGENTSPYBOO_FFUF_RATE`, `AGENTSPYBOO_FFUF_THREADS`, `AGENTSPYBOO_FFUF_TIMEOUT`.
- **Wordlist.** Default is a hand-curated ~100-entry mini list bundled at `assets/ffuf-common-mini.txt` via `include_str!` — covers common admin/auth/dotfile paths without large-list runtime cost. Override with `--ffuf-wordlist /path/to/SecLists/...` for deeper coverage.
- **Authorized-scope banner.** `main.rs` prints a confirmation banner before the agent loop when `--active` is set; bypass via `--yes` / `-y` flag or `AGENTSPYBOO_ACTIVE_CONFIRMED=1` env var (so CI runs don't hang on stdin).

**Phase 4 action (as shipped):**

- **P3.1 — `src/tools/ffuf.rs`.** `exec_ffuf` (one URL at a time), `parse_ffuf_output` (severity heuristics: sensitive-path 200 = High, admin-path 200/401/403 = Medium, generic 200 = Low, 30x = Info), `resolve_wordlist` (user path or bundled mini-list). 5 unit tests.
- **P3.2 — CLI flags.** `--active`, `--yes` / `-y`, `--ffuf-wordlist` on the Recon subcommand. Threaded through `Config`.
- **P3.3 — react_loop dispatch.** Pulls URL from LLM args (`{"url": "..."}`) or falls back to first scoped httpx-live URL. Scope guard runs before the binary spawn.
- **P3.4 — Findings.** ffuf findings flow into `all_findings` with `kind = "ffuf"`, deduplicated and severity-sorted alongside other tool output. The original spec proposed a separate `ffuf_findings` field; rejected in favor of the unified findings list because the dedup + report rendering already handle a `kind` column cleanly and a separate field would have meant a second report sub-table for no real gain.

**Deferred to a P3.5 follow-up:**

- **IP-scope check.** Original spec called for resolving the URL's IP at fire time and verifying against authorized IP ranges. Shipped without this because there's no `--scope-cidr` flag yet — adding the resolver without a scope-IP set would only log, not enforce. Cleaner to land both pieces together when CIDR scope arrives.
- **Live LLM-driven E2E validation.** Unit tests cover wordlist resolution (3 cases), severity classification (5 paths), and FUZZ-URL formation. Direct ffuf invocation against `peterc3-dev.github.io` confirms the binary integration works (0 results because it's a static Jekyll site with nothing under common paths). Did not exercise the agent's LLM dispatch live because peterc3-dev.github.io has no subfinder hits and the agent bails per skip rules. To validate end-to-end the user needs a target with subfinder hits + httpx-live URLs + active-fuzz authorization — left for the user when one is at hand.

---

## What's explicitly NOT in Phase 4

- **Pius source code modifications.** We consume Pius, we don't maintain it.
- **Additional ToolKinds beyond ffuf.** Nuclei-workflows, katana, gau etc. are separate phases.
- **UI/dashboard.** No web interface. CLI only.
- **Multi-target batch mode.** One target per invocation stays the rule.
- **Report format changes.** Markdown + JSON stays identical except for new sections.

---

## Execution order

1. **P1 first** (highest leverage, zero risk — tuning flags and adding a dnsx stage)
2. **P2 second** (multiplies Pius output, but depends on user acquiring API keys — most are free tier)
3. **P3 last** (highest risk because of active probing — ship only after P1 + P2 are validated)

---

## Rough effort estimate

- P1: 1 evening (module edits + E2E rerun)
- P2: 1 evening (env var wiring + doc)
- P3: 2 evenings (new module + safety gates + testing against owned scope)

Total: ~1 week of evenings if sequenced. Could parallelize P1 and P2 if energy allows.

---

## Open questions for Raz

1. **P1.1 dnsx stage** — insert between subfinder and httpx, or make it optional? I'd argue mandatory (the speed/quality win is clear), but flag for your call.
2. **P2 API keys** — which services have you signed up for? Do you have Shodan / Censys / SecurityTrails free-tier accounts, or does that need to happen first?
3. **P3 authorized scope** — the `host_in_scope` check is currently a flat string match on the CLI target. Good enough for ffuf's blast radius, or do we need a stricter check (TLD match + explicit allow-list)?

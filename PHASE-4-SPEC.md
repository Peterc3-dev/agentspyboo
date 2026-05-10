# AgentSpyBoo Phase 4 — Scoping Spec

**Drafted:** 2026-04-18
**Status:** Draft for review
**Previous phase:** Phase 3 (Pius preflight) shipped 2026-04-16 on main

---

## Three problems to solve

### P1 — The 519→1 httpx efficiency gap

**Symptom:** On the gitlab.com E2E run, subfinder returned 519 subdomains. httpx confirmed 1 live. Ratio 0.19%.

**Probable causes (ranked by likelihood, corrected per Boo2 verification 2026-04-18):**

httpx defaults (verified): `-timeout 10s`, `-retries 0`, `-follow-redirects off`, `-threads 50`, `-rate-limit 150rps`. Defaults are **aggressive on throughput, fragile on reliability** — not conservative as originally characterized. The 519→1 gap is driven by the reliability side (0 retries, no redirect following, stale DNS) not throughput.

1. No retries on transient failures. A single dropped connection = host recorded as dead.
2. No redirect following. Subdomains that 301/302 to a canonical host are recorded as non-responsive.
3. Stale DNS from subfinder sources. Cert-transparency logs list historical subdomains that no longer have public A records. Fix requires dnsx stage between subfinder and httpx.
4. Genuinely internal/staging subdomains legitimately return nothing over public internet.

**Phase 4 action:**

- **P1.1 — Add a dnsx resolution pass** between subfinder and httpx. Use `dnsx -a -aaaa -cname` so CNAME-only subdomains (which httpx can still resolve) are preserved — filter only on NXDOMAIN/SERVFAIL. Expected effect: cut probe list from 519 to ~100-150 hosts with actual DNS presence without losing CNAME-resolvable ones.
- **P1.2 — Tune httpx flags.** Add `-retries 2 -follow-redirects -timeout 15`. Keep default `-threads 50` (already aggressive). The original proposal's `-timeout 10` was a no-op — same as default. `-timeout 15` gives slow/high-latency endpoints more room. Expected effect: +30-50% live host confirmation on the filtered list.
- **P1.3 — Expose tunables via env vars.** `AGENTSPYBOO_HTTPX_TIMEOUT`, `AGENTSPYBOO_HTTPX_THREADS`, `AGENTSPYBOO_HTTPX_RETRIES`. Default to tuned values; allow override per run.

**Test target:** rerun gitlab.com E2E after changes. Baseline was 1/519. Win condition: 5+/519.

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

**Phase 4 action:**

- **P2.1 — Env var passthrough** for the full corrected list above. Pius consumes them via its own config flow.
- **P2.2 — Plugins-skipped detection.** Pius doesn't emit structured "skipped for no key" data. Strategy: parse Pius stderr for skip notices, OR compute the delta between `plugins_expected` (derived from which env vars are set) and `plugins_fired` (from Pius output). Second approach is more robust.
- **P2.3 — Document cost reality** in `docs/pius-api-keys.md`:
  - Free and useful: GitHub personal token, ViewDNS free tier
  - Burns fast: Shodan (100/mo)
  - Paid only for useful coverage: SecurityTrails, Censys, Apollo, FOFA
  - Per-service cost table with current pricing snapshot

**No code changes to Pius itself.** All changes in `src/preflight/pius.rs` and the env var loader.

### P3 — Active recon mode (ffuf)

**Current state:** All recon is passive. No content discovery. Nuclei scans templates but doesn't brute-force directories.

**Proposed:** ffuf as a new `ToolKind::Ffuf`, fired only when `--active` flag is set on the CLI.

**Safety rails (hard requirements):**

- **Scope enforcement — both hostname AND IP.** Ffuf only fires against hosts confirmed in scope by the existing host_in_scope check. Additional check: resolve the host's IP at ffuf-fire time and verify the IP isn't out of scope (e.g., the hostname matches but resolves to a third-party CDN edge that's technically out of authorized scope). Added 2026-04-18 per Boo2 review.
- **No redirect following in active mode.** ffuf default `-follow-redirects off` stays off during active probing. Redirect chains can lead to out-of-scope hosts — blast radius risk. Added 2026-04-18 per Boo2 review.
- **Active-flag gate.** Passive mode (default) never invokes ffuf. Period.
- **Rate limit default.** `-rate 20` hard default (20 req/sec). Env var override `AGENTSPYBOO_FFUF_RATE`.
- **Wordlist default.** Small wordlist (common.txt, ~4600 entries) by default. Large wordlists opt-in via `--ffuf-wordlist large`.
- **Authorized-scope banner.** When `--active` is set, print a confirmation prompt unless `-y` or env var `AGENTSPYBOO_ACTIVE_CONFIRMED=1`.

**Phase 4 action:**

- **P3.1 — Implement `src/tools/ffuf.rs`** following the existing httpx/nuclei module pattern.
- **P3.2 — Add `ActiveMode` config enum** and CLI flag `--active`.
- **P3.3 — Wire into react_loop.rs** as an optional stage after nuclei, gated on active mode.
- **P3.4 — Add `ffuf_findings` to `RunRecord`** as its own field (don't mix with nuclei findings — different classes of finding). Use the same confidence-scoring schema as nuclei findings for consistency across the report.

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

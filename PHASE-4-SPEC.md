# AgentSpyBoo Phase 4 — Scoping Spec

**Drafted:** 2026-04-18
**P1 revised:** 2026-05-10 (post-validation ablation, see below)
**Status:** P1 shipped (commit 42fd6a2). P2/P3 pending.
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

**Phase 4 action (as shipped in 42fd6a2):**

- **P1.1 — dnsx resolution pass** between subfinder and httpx. Use `dnsx -a -aaaa -cname` so CNAME-only subdomains are preserved. Implemented in `src/tools/dnsx.rs` with a fallback to the unfiltered list when dnsx errors or returns suspiciously low (<2% on >50-host inputs). **Effect: ~60s wall-time savings on dead-DNS-heavy targets, neutral on detection.**
- **P1.2 — httpx flag tuning.** `-retries 2 -follow-redirects -timeout 15`, `-threads 50` unchanged. **Effect: ~12% live-host detection lift, primarily from follow-redirects.**
- **P1.3 — Env var tunables.** `AGENTSPYBOO_HTTPX_TIMEOUT`, `AGENTSPYBOO_HTTPX_THREADS`, `AGENTSPYBOO_HTTPX_RETRIES` overrides. Defaults to tuned values.

**Open follow-up for P1:** the `httpx-cap=150` interaction with subfinder ordering is now exposed as a real bug, not the symptom the original spec described. Consider sorting the host list by depth (shallow subdomains first) or by source confidence before capping, or removing the cap entirely now that dnsx pre-filters the list. Tracked separately — not part of P1 close-out.

**Validation status:** P1 shipped behaves as the corrected spec describes (efficiency from dnsx, detection from flag tuning). The original "5+/519" win condition was based on a confounded baseline and is retired.

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

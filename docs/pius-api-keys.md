# Pius API Keys — what's worth setting

agentspyboo's preflight stage shells out to [pius](https://github.com/praetorian-inc/pius) for org-level recon. Pius is a plugin orchestrator: most plugins are free and on by default, a handful read API keys from the environment to unlock paid data sources. agentspyboo passes the parent process environment through to pius unchanged, so any key set in your shell flows through automatically.

This doc is the cost/value matrix. The summary up front, then per-key detail.

## The honest take

Most of pius's value is free. crt-sh, urlscan, wayback, whois, GLEIF, asn-bgp, the RIRs (ARIN/RIPE/APNIC/AFRINIC/LACNIC), Wikidata, EDGAR, and reverse-RIR all run without any key and cover the majority of OSINT-discoverable surface. Setting GITHUB_TOKEN is a free, near-zero-effort win. Everything else is gated on paid plans where the free tier is either nonexistent (Apollo, Censys, SecurityTrails) or burns out fast (Shodan, 100/mo).

**If you set nothing**, pius still runs ~16 free plugins and produces useful output. agentspyboo will note in the report which plugins were skipped.

**If you set GITHUB_TOKEN**, you raise GitHub's API rate limit from 60/hr unauth to 5000/hr authed. github-org plugin fires more reliably on bigger orgs.

**If you set VIEWDNS_API_KEY**, you unlock reverse-whois (domain portfolio discovery) and improve reverse-ip beyond the HackerTarget fallback.

**Beyond that**, every additional key requires a paid plan and only makes sense if your engagement scope justifies the cost.

## Per-key detail

### `GITHUB_TOKEN` — strongly recommended, free

- **Plugins:** `github-org` (optional — fires either way, just better with token)
- **What it gets you:** GitHub org search, blog domain discovery, repo metadata. Without a token, GitHub's unauth rate limit is 60/hr and gets exhausted fast on multi-org sweeps.
- **How to set:** `gh auth token` if you already have `gh` logged in, or generate a Personal Access Token at github.com/settings/tokens. No special scopes needed for org-search; `public_repo` if you want to enumerate private orgs you're a member of.
- **Cost:** Free.

### `VIEWDNS_API_KEY` — recommended, free tier exists

- **Plugins:** `reverse-whois` (required), `reverse-ip` (optional fallback to HackerTarget without it)
- **What it gets you:** Reverse WHOIS lookup ("what other domains does this org's registrant own?") + reverse IP ("what hosts share this IP?"). High-signal for surfacing parked/forgotten domains under the same registrant.
- **How to set:** Sign up at viewdns.info, free tier is 250 queries/day. API key visible on dashboard.
- **Cost:** Free for 250/day. Paid plans start ~$50/mo.

### `SHODAN_API_KEY` — burns fast, conditional

- **Plugins:** `shodan` (CIDR discovery), `favicon-hash` (related-infra discovery)
- **What it gets you:** Pre-indexed scan data ("which hosts run Apache 2.4 in this CIDR?"), favicon-based pivoting to discover related infrastructure.
- **How to set:** Sign up at shodan.io. Free tier is 100 queries/month — enough for one or two careful runs, gone fast if you scan multiple targets.
- **Cost:** $5 one-time membership unlocks paid tier. Subscriptions $69+/mo for higher quotas.

### `SECURITYTRAILS_API_KEY` — paid only

- **Plugins:** `passive-dns` (historical DNS records)
- **What it gets you:** Historical DNS resolution data — see what subdomains existed and what they resolved to over time. High-signal for finding decommissioned-but-still-live infrastructure.
- **Cost:** Free tier deprecated. Paid plans start ~$50/mo and require contacting sales for API access. Skip unless you have a paid engagement.

### `CENSYS_API_TOKEN` — paid only

- **Plugins:** `censys-org`
- **What it gets you:** Cert-transparency-driven domain discovery via Censys's index.
- **Cost:** Free trial gives 250 queries. Beyond that, Starter+ plan minimum ~$100 in credits. Skip unless you have a budget for it.

### `APOLLO_API_KEY` — paid B2B only

- **Plugins:** `apollo`
- **What it gets you:** Apollo.io organization enrichment — corporate hierarchy, subsidiary discovery from the B2B sales-data side.
- **Cost:** No meaningful free tier. Paid plans target sales teams. Almost never worth it for security recon — GLEIF + Wikidata + reverse-WHOIS cover most of the same ground for free.

### `FOFA_API_KEY` — paid, China-centric

- **Plugins:** `favicon-hash` (alongside Shodan)
- **What it gets you:** FOFA's index complements Shodan, particularly for China-region infrastructure.
- **Cost:** Free tier in Chinese is 100 queries/day; English-language paid plans start ~$60/mo. Useful only if your scope crosses the Great Firewall.

## How to verify what's working

Run agentspyboo with `--org` and `--verbose`:

```sh
agentspyboo recon example.com --org "Example Corp" --asn AS12345 --verbose
```

The preflight log will print which plugins fired. If any key-gated plugin was skipped for a missing key, the verbose log calls it out:

```
[preflight] 3 key-gated plugin(s) skipped for missing keys: passive-dns, shodan, censys-org
```

The markdown report includes a "Key-gated plugins" sub-section under "Organization Recon (Pius)" with full per-plugin status when there's anything actionable.

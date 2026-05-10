# AgentSpyBoo Assessment — hackerone.com

**Date:** 2026-04-15T03:02:40.858516867+00:00  
**Model:** Qwen3-1.7B-GGUF  
**Iterations:** 4  
**Scope:** hackerone.com, *.hackerone.com  
**Tools fired:** subfinder → httpx

---

## Executive Summary

Subfinder found 16 subdomains, httpx confirmed 10 live hosts, but nuclei timed out. No vulnerabilities found within the timeout. Next steps: review logs, consider increasing timeout, and re-evaluate if further assessment is needed.

---

## Findings Table

| # | Severity | Type | Target | Details |
|---|----------|------|--------|---------|
| 1 | 🔵 low | http-probe | b.ns.hackerone.com | status=301 title="301 Moved Permanently" tech=[Cloudflare] |
| 2 | 🔵 low | http-probe | a.ns.hackerone.com | status=301 title="301 Moved Permanently" tech=[Cloudflare] |
| 3 | 🔵 low | http-probe | mta-sts.hackerone.com | status=404 title="Page not found · GitHub Pages" tech=[Fastly, GitHub Pages, Varnish] |
| 4 | 🔵 low | http-probe | docs.hackerone.com | status=302 title="" tech=[Cloudflare, HSTS] |
| 5 | 🔵 low | http-probe | mta-sts.forwarding.hackerone.com | status=404 title="Page not found · GitHub Pages" tech=[Fastly, GitHub Pages, Varnish] |
| 6 | 🔵 low | http-probe | mta-sts.managed.hackerone.com | status=404 title="Page not found · GitHub Pages" tech=[Fastly, GitHub Pages, Varnish] |
| 7 | 🔵 low | http-probe | support.hackerone.com | status=302 title="" tech=[Amazon S3, Amazon Web Services, Cloudflare, Cloudflare Bot Management, Envoy, HSTS] |
| 8 | 🔵 low | http-probe | api.hackerone.com | status=200 title="HackerOne API" tech=[Algolia, Cloudflare, HSTS, jQuery, jsDelivr] |
| 9 | 🔵 low | http-probe | gslink.hackerone.com | status=404 title="404 Not Found" tech=[Amazon CloudFront, Amazon Web Services, Nginx] |
| 10 | 🔵 low | http-probe | www.hackerone.com | status=200 title="HackerOne \| Global leader in offensive security \| Security for AI \| Crowdsourced" tech=[Cloudflare, |
| 11 | ℹ️ info | subdomain | events.hackerone.com | discovered via subfinder |
| 12 | ℹ️ info | subdomain | docs.hackerone.com | discovered via subfinder |
| 13 | ℹ️ info | subdomain | mta-sts.managed.hackerone.com | discovered via subfinder |
| 14 | ℹ️ info | subdomain | support.hackerone.com | discovered via subfinder |
| 15 | ℹ️ info | subdomain | www.hackerone.com | discovered via subfinder |
| 16 | ℹ️ info | subdomain | go.hackerone.com | discovered via subfinder |
| 17 | ℹ️ info | subdomain | design.hackerone.com | discovered via subfinder |
| 18 | ℹ️ info | subdomain | a.ns.hackerone.com | discovered via subfinder |
| 19 | ℹ️ info | subdomain | links.hackerone.com | discovered via subfinder |
| 20 | ℹ️ info | subdomain | api.hackerone.com | discovered via subfinder |
| 21 | ℹ️ info | subdomain | mta-sts.forwarding.hackerone.com | discovered via subfinder |
| 22 | ℹ️ info | subdomain | b.ns.hackerone.com | discovered via subfinder |
| 23 | ℹ️ info | subdomain | websockets.hackerone.com | discovered via subfinder |
| 24 | ℹ️ info | subdomain | gslink.hackerone.com | discovered via subfinder |
| 25 | ℹ️ info | subdomain | mta-sts.hackerone.com | discovered via subfinder |
| 26 | ℹ️ info | subdomain | info.hackerone.com | discovered via subfinder |

---

## Methodology

A small LLM running locally on Lemonade Server (AMD Ryzen AI, Qwen3-1.7B) drives a ReAct loop with intelligent step skipping: it reasons about whether each tool is worth running based on the prior tool's output. Scope allowlist enforces a glob-based target filter on every host before the tool spawns. Rate limiting inserts a floor between iterations.

Tool chain executed this run:

- `subfinder` — passive subdomain enumeration
- `httpx` — live HTTP probe (status, title, tech detect, JSON output)

## Step Detail

### Iteration 1 — subfinder

**Args:** `{"domain":"hackerone.com"}`

**Preview:**

```
events.hackerone.com
docs.hackerone.com
mta-sts.managed.hackerone.com
support.hackerone.com
www.hackerone.com
go.hackerone.com
design.hackerone.com
a.ns.hackerone.com
links.hackerone.com
api.hackerone.com
mta-sts.forwarding.hackerone.com
b.ns.hackerone.com
websockets.hackerone.com
gslink.hackerone.com
mta-sts.hackerone.com
info.hackerone.com
```

### Iteration 2 — httpx

**Args:** `{"hosts_from":"subfinder"}`

**Preview:**

```
{"timestamp":"2026-04-14T23:02:47.449543957-04:00","cdn_name":"cloudflare","cdn_type":"waf","port":"80","url":"http://b.ns.hackerone.com","input":"b.ns.hackerone.com","location":"https://b.ns.hackerone.com/","title":"301 Moved Permanently","scheme":"http","webserver":"cloudflare","content_type":"text/html","method":"GET","host":"b.ns.hackerone.com","host_ip":"2400:cb00:2049:1::a29f:11f","path":"/","time":"76.232542ms","a":["162.159.1.31"],"aaaa":["2400:cb00:2049:1::a29f:11f"],"tech":["Cloudflare"],"words":5,"lines":7,"status_code":301,"content_length":167,"failed":false,"cdn":true,"knowledgebase":{"PageType":"error","pHash":0},"resolvers":["1.0.0.1:53"]}
{"timestamp":"2026-04-14T23:02:47.452362594-04:00","cdn_name":"cloudflare","cdn_type":"waf","port":"80","url":"http://a.ns.hackerone.com","input":"a.ns.hackerone.com","location":"https://a.ns.hackerone.com/","title":"301 Moved Permanently","scheme":"http","webserver":"cloudflare","content_type":"text/html","method":"GET","host":"a.ns.hackerone.com","host_ip":"2400:cb00:2049:1::a29f:1f","path":"/","time":"72.038319ms","a":["162.159.0.31"],"aaaa":["2400:cb00:2049:1::a29f:1f"],"tech":["Cloudflare"],"words":5,"lines":7,"status_code":301,"content_length":167,"failed":false,"cdn":true,"knowledgebase":{"PageType":"error","pHash":0},"resolvers":["1.1.1.1:53","1.0.0.1:53"]}
{"timestamp":"2026-04-14T23:02:47.526064379-04:00","port":"443","url":"https://mta-sts.hackerone.com","input":"mta-sts.hackerone.com","title":"Page not found · GitHub Pages","scheme":"https","webserver":"GitHub.com","content_type":"text/html","method":"GET","host":"mta-sts.hackerone.com","host_ip":"2606:50c0:8001::153","path":"/","time":"273.469016ms","a":["185.199.110.153","185.199.108.153","185.199.111.153","185.199.109.153"],"aaaa":["2606:50c0:8000::153","2606:50c0:8001::153","2606:50c0:8002::153","2606:50c0:8003::153"],"cname":["hacker0x01.github.io"],"tech":["Fastly","GitHub Pages","Varnish"],"words":718,"lines":89,"status_code":404,"content_length":9379,"failed":false,"knowledgebase":{"PageType":"nonerror","pHash":0},"resolvers":["8.8.8.8:53","1.1.1.1:53"]}
{"timestamp":"2026-04-14T23:02:47.541545572-04:00","cdn_name":"cloudflare","cdn_type":"waf","port":"443","url":"https://docs.hackerone.com","input":"docs.hackerone.com","location":"https://docs.hackerone.com/en/","scheme":"https","webserver":"cloudflare","content_type":"text/html","method":"GET","host":"docs.hackerone.com","host_ip":"2606:4700:440a::6812:24d6","path":"/","time":"303.336641ms","a":["104.18.36.214","172.64.151.42"],"aaaa":["2a06:98c1:3106::ac40:972a","2606:4700:440a::6812:24d6"],"tech":["Cloudflare","HSTS"],"words":0,"lines":0,"status_code":302,"content_length":0,"failed":false,"cdn":true,"knowledgebase":{"PageType":"other","pHash":0},"resolvers":["1.0.0.1:53","127.0.0.53:53"]}
{"timestamp":"2026-04-14T23:02:47.543809122-04:00","port":"443","url":"https://mta-sts.forwarding.hackerone.com","input":"mta-sts.forwarding.hackerone.com","title":"Page not found · GitHub Pages","scheme":"https","webserver":"GitHub.com","content_type":"text/html","method":"GET","host":"mta-sts.forwarding.hackerone.com","host_ip":"2606:50c0:8003::153","path":"/","time":"294.06006ms","a":["185.199.110.153","185.199.111.153","185.199.108.153","185.199.109.153"],"aaaa":["2606:50c0:8002::153","2606:50c0:8000::153","2606:50c0:8003::153","2606:50c0:8001::153"],"cname":["hacker0x01.github.io"],"tech":["Fastly","GitHub Pages","Varnish"],"words":718,"lines":89,"status_code":404,"content_length":9379,"failed":false,"knowledgebase":{"PageType":"nonerror","pHash":0},"resolvers":["1.1.1.1:53","8.8.8.8:53"]}
{"timestamp":"2026-04-14T23:02:47.580655901-04:00","port":"443","url":"https://mta-sts.managed.hackerone.com","input":"mta-sts.managed.hackerone.com","title":"Page not found · GitHub Pages","scheme":"https","webserver":"GitHub.com","content_type":"text/html","method":"GET","host":"mta-sts.managed.hackerone.com","host_ip":"2606:50c0:8000::153","path":"/","time":"321.460139ms","a":["185.199.109.153","185.199.111.153","185.199.110.153","185.199.108.153"],"aaaa":["2606:50c0:8002::153","2606:50c0:8003::153","2606:50c0:8001::153","2606:50c0:8000::153"],"cname":["hacker0x01.github.io"],"tech":["Fastly","GitHub Pages","Varnish"],"words":718,"lines":89,"status_code":404,"content_length":9379,"failed":false,"knowledgebase":{"PageType":"nonerror","pHash":0},"resolvers":["127.0.0.53:53","1.1.1.1:53"]}
{"timestamp":"2026-04-14T23:02:47.645339367-04:00","cdn_name":"cloudflare","cdn_type":"waf","port":"443","url":"https://support.hackerone.com","input":"support.hackerone.com","location":"https://support.hackerone.com/support/home","scheme":"https","webserver":"cloudflare","content_type":"text/html","method":"GET","host":"support.hackerone.com","host_ip":"162.159.140.147","path":"/","time":"403.19853ms","a":["172.66.0.145","162.159.140.147"],"cname":["2fe254e58a0ea8096400b2fda121ee35.freshdesk.com"],"tech":["Amazon S3","Amazon Web Services","Cloudflare","Cloudflare Bot Management","Envoy","HSTS"],"words":5,"lines":1,"status_code":302,"content_length":108,"failed":false,"cdn":true,"knowledgebase":{"PageType":"nonerror","pHash":0},"resolvers":["8.8.8.8:53","1.1.1.1:53"]}
{"timestamp":"2026-04-14T23:02:47.672063815-04:00","cdn_name":"cloudflare","cdn_type":"waf","port":"443","url":"https://api.hackerone.com","input":"api.hackerone.com","title":"HackerOne API","scheme":"https","webserver":"cloudflare","content_type":"text/html","method":"GET","host":"api.hackerone.com","host_ip":"2a06:98c1:3106::ac40:972a","path":"/","time":"399.920442ms","a":["104.18.36.214","172.64.151.42"],"aaaa":["2a06:98c1:3106::ac40:972a","2606:4700:440a::6812:24d6"],"tech":["Algolia","Cloudflare","HSTS","jQuery","jsDelivr"],"words":1731,"lines":368,"status_code":200,"content_length":9126,"failed":false,"cdn":true,"knowledgebase":{"PageType":"nonerror","pHash":0},"resolvers":["8.8.4.4:53"]}
{"timestamp":"2026-04-14T23:02:47.690749894-04:00","cdn_name":"aws","cdn_type":"cloud","port":"443","url":"https://gslink.hackerone.com","input":"gslink.hackerone.com","title":"404 Not Found","scheme":"https","webserver":"nginx","content_type":"text/html","method":"GET","host":"gslink.hackerone.com","host_ip":"2600:9000:2486:3400:1:9f06:1140:93a1","path":"/","time":"453.518218ms","a":["108.156.85.32","108.156.85.70","108.156.85.41","108.156.85.24"],"aaaa":["2600:9000:2486:5800:1:9f06:1140:93a1","2600:9000:2486:e600:1:9f06:1140:93a1","2600:9000:2486:f800:1:9f06:1140:93a1","2600:9000:2486:3000:1:9f06:1140:93a1","2600:9000:2486:3400:1:9f06:1140:93a1","2600:9000:2486:b400:1:9f06:1140:93a1","2600:9000:2486:fa00:1:9f06:1140:93a1","2600:9000:2486:e00:1:9f06:1140:93a1"],"cname":["d3rxkn2g2bbsjp.cloudfront.net"],"tech":["Amazon CloudFront","Amazon Web Services","Nginx"],"words":5,"lines":7,"status_code":404,"content_length":146,"failed":false,"knowledgebase":{"PageType":"error","pHash":0},"resolvers":["8.8.4.4:53","127.0.0.53:53"]}
{"timestamp":"2026-04-14T23:02:47.97886273-04:00","cdn_name":"cloudflare","cdn_type":"waf","port":"443","url":"https://www.hackerone.com","input":"www.hackerone.com","title":"HackerOne | Global leader in offensive security | Security for AI | Crowdsourced Security","scheme":"https","webserver":"cloudflare","content_type":"text/html","method":"GET","host":"www.hackerone.com","host_ip":"2a06:98c1:3106::ac40:972a","path":"/","time":"252.325923ms","a":["104.18.36.214","172.64.151.42"],"aaaa":["2606:4700:440a::6812:24d6","2a06:98c1:3106::ac40:972a"],"tech":["Cloudflare","Drupal","Fastly","Google Tag Manager","HSTS","MariaDB","Nginx","PHP","Pantheon","Varnish","jQuery"],"words":56593,"lines":3289,"status_code":200,"content_length":223497,"failed":false,"cdn":true,"knowledgebase":{"PageType":"other","pHash":0},"resolvers":["1.1.1.1:53","8.8.4.4:53"],"cpe":[{"product":"webp_server_go","vendor":"webp","cpe":"cpe:2.3:a:webp:webp_server_go:*:*:*:*:*:*:*:*"}]}
```

### Iteration 3 — nuclei

**Args:** `{"urls_from":"httpx"}`

**Error:** nuclei timed out after 900s

### Iteration 4 — done

---

## Recommended Next Steps

- re-evaluate timeout settings
- review logs for potential vulnerabilities
- consider additional tools for deeper assessment

---

_Generated by AgentSpyBoo Phase 2 (CPU-track) — https://github.com/Peterc3-dev (private)_

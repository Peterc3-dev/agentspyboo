# AgentSpyBoo Assessment — gitlab.com

**Date:** 2026-04-16T23:08:56.811532433+00:00  
**Model:** qwen3:8b  
**Iterations:** 4  
**Scope:** gitlab.com, *.gitlab.com  
**Tools fired:** subfinder → httpx → nuclei

---

## Executive Summary

Subdomain enumeration identified 519 subdomains, including ci.gitlab.com and geo1.gitlab.com. HTTP probing found 1 live host (archives.docs.gitlab.com). Nuclei scan yielded no vulnerabilities. Limited live hosts constrained further analysis.

---

## Organization Recon (Pius)

**Organization:** GitLab  
**ASN hint:** AS57787  
**Mode:** passive  
**Runtime:** 150.0s  
**Plugins fired:** asn-bgp, github-org, gleif, urlscan, wayback, whois  
**Records:** 21 raw, 13 filtered out

### Domains discovered

| Domain | Sources | Confidence |
|--------|---------|------------|
| `about.gitlab.com` | urlscan | — |
| `advisories.gitlab.com` | urlscan | — |
| `docs.gitlab.com` | urlscan | — |
| `enable.gitlab.com` | urlscan | — |
| `gitlab.com` | urlscan, wayback | — |
| `www.gitlab.com` | wayback | — |

### CIDR blocks

| CIDR | Source | ASN |
|------|--------|-----|
| `91.235.46.0/24` | asn-bgp | AS57787 |

### GitHub organizations

| Login | Name | Confidence |
|-------|------|------------|
| `gitlabhq` | GitLab | 1.0 |
| `runcitadel` | Citadel [MOVED TO GITLAB] | 0.9 |

_Pius runs once before iteration 1. Passing domains pre-seed the subfinder host list; CIDR blocks feed directly into findings as Severity::Low (`cidr-discovered`). The LLM never sees Pius output._

---

## Findings Table

_Dedup folded 521 raw observations into 3 grouped findings. Disable with `--no-dedup`._

| # | Severity | Type | Targets | Details |
|---|----------|------|---------|---------|
| 1 | 🔵 low | cidr-discovered | 91.235.46.0/24 | CIDR block discovered via Pius (source: asn-bgp, asn: AS57787) |
| 2 | ℹ️ info | subdomain | 519 targets (x519) | discovered via subfinder |
| 3 | ℹ️ info | http-probe | archives.docs.gitlab.com | status=200 title="GitLab Docs Archives" tech=[] |

<details><summary>Finding #2 — 519 target(s)</summary>

- `ci.gitlab.com`
- `geo1.gitlab.com`
- `4456656-review-gt-update-7ocwl1.design-staging.gitlab.com`
- `4456656-review-work-item-z7jn6r.design-staging.gitlab.com`
- `4456656-review-372-button-cu19b4.design-staging.gitlab.com`
- `license.gitlab.com`
- `4456656-review-1527-type-0ahnvf.design-staging.gitlab.com`
- `4456656-review-katiemacoy-28xw6w.design-staging.gitlab.com`
- `4456656-review-bugfix-loc-qvog2t.design-staging.gitlab.com`
- `registry.gke.pre.gitlab.com`
- `4456656-review-1204-add-c-a529gy.design-staging.gitlab.com`
- `4456656-review-1384-migra-hi3gz1.design-staging.gitlab.com`
- `4456656-review-viewcompon-kkveh5.design-staging.gitlab.com`
- `biz.gitlab.com`
- `4456656-review-372-migrat-fsc737.design-staging.gitlab.com`
- `gitlab-org-gitlab-services-design-gitlab-com.design.gitlab.com`
- `4456656-review-1454-clean-24ifbs.design-staging.gitlab.com`
- `4456656-review-1466-homep-b9nz0w.design-staging.gitlab.com`
- `registry.gke.staging.gitlab.com`
- `jitsu-server.product-analytics.prototype.gitlab.com`
- `registry.staging-ref.gitlab.com`
- `4456656-review-1529-vpat-t9lc7u.design-staging.gitlab.com`
- `www.learn.gitlab.com`
- `chat.gitlab.com`
- `4456656-review-main-patch-t0zk8u.design-staging.gitlab.com`
- `4456656-review-1464-add-p-jxfmxs.design-staging.gitlab.com`
- `archives.docs.gitlab.com`
- `4456656-review-leipert-de-ukc4pq.design-staging.gitlab.com`
- `4456656-review-1517-dropd-biebor.design-staging.gitlab.com`
- `www.aptly.gitlab.com`
- `www.docs.gitlab.com`
- `4456656-review-1471-updat-bl7fl4.design-staging.gitlab.com`
- `4456656-review-main-patch-1axc6b.design-staging.gitlab.com`
- `customers.staging-ref.gitlab.com`
- `www.canary.staging.gitlab.com`
- `4456656-review-main-patch-ukqrqf.design-staging.gitlab.com`
- `cxr.gitlab.com`
- `4456656-review-katiemacoy-6mkyxy.design-staging.gitlab.com`
- `4456656-review-ui-kit-dep-cjugbw.design-staging.gitlab.com`
- `o1.ptr3386.mx.gitlab.com`
- `advisories.gitlab.com`
- `prometheus-2.gitlab.com`
- `4456656-review-danmh-ui-k-1zf7up.design-staging.gitlab.com`
- `4456656-review-fix-main-a8e81c.design-staging.gitlab.com`
- `auth.gcp.gitlab.com`
- `email.customers.gitlab.com`
- `lb-teleport.gstg.gitlab.com`
- `4456656-review-danmh-main-7byn0x.design-staging.gitlab.com`
- `4456656-review-danmh-line-602hhc.design-staging.gitlab.com`
- `4456656-review-leipert-in-fn9qbu.design-staging.gitlab.com`
- `4456656-review-monica-gal-oepnqj.design-staging.gitlab.com`
- `docs.gitlab.com`
- `4456656-review-pgascouvai-1f4bo8.design-staging.gitlab.com`
- `4456656-review-15-11-fig-lodxco.design-staging.gitlab.com`
- `prod.geo.gitlab.com`
- `4456656-review-msj-extern-e112lv.design-staging.gitlab.com`
- `4456656-review-main-patch-htq0lf.design-staging.gitlab.com`
- `single.gitlab.com`
- `contributors.gitlab.com`
- `4456656-review-1532-fix-a-vslnpm.design-staging.gitlab.com`
- `4456656-review-lvanc-main-vhyovi.design-staging.gitlab.com`
- `customers.gitlab.com`
- `4456656-review-monica-gal-pz78s2.design-staging.gitlab.com`
- `redash.gitlab.com`
- `4456656-review-feat-add-i-jfatva.design-staging.gitlab.com`
- `new.docs.gitlab.com`
- `runners-cache-3.gitlab.com`
- `campaign-manager.gitlab.com`
- `4456656-review-1534-dropd-ybke0g.design-staging.gitlab.com`
- `www.page.gitlab.com`
- `triage-serverless.gitlab.com`
- `4456656-review-leipert-so-fnmdgi.design-staging.gitlab.com`
- `4456656-review-1524-docs-riq0la.design-staging.gitlab.com`
- `www.redash.gitlab.com`
- `shared-runners-manager-4.gitlab.com`
- `4456656-review-main-patch-wl4twp.design-staging.gitlab.com`
- `4456656-review-update-ui-qkugqu.design-staging.gitlab.com`
- `4456656-review-sselhorn-m-cp6hbg.design-staging.gitlab.com`
- `private-runners-manager-1.gitlab.com`
- `4456656-review-matejlatin-myrk4n.design-staging.gitlab.com`
- `4456656-review-main-patch-e4eovu.design-staging.gitlab.com`
- `4456656-review-1345-story-efzw0t.design-staging.gitlab.com`
- `www.about.gitlab.com`
- `www.prometheus-2.gitlab.com`
- `observe.staging.gitlab.com`
- `go-staging.community.gitlab.com`
- `app.community.gitlab.com`
- `staging-ref.gitlab.com`
- `4456656-review-1601-creat-6facx9.design-staging.gitlab.com`
- `4456656-review-v-mishra-m-4agh3r.design-staging.gitlab.com`
- `customers.stg.gitlab.com`
- `4456656-review-spacing-ex-nrw7ke.design-staging.gitlab.com`
- `staging.observe.gitlab.com`
- `4456656-review-main-patch-h5jvmx.design-staging.gitlab.com`
- `runners-cache-4.gitlab.com`
- `federal-support.gitlab.com`
- `4456656-review-sselhorn-m-ygc05a.design-staging.gitlab.com`
- `4456656-review-update-tab-d7o120.design-staging.gitlab.com`
- `4456656-review-update-str-dw8cuz.design-staging.gitlab.com`
- `www.prometheus-3.gitlab.com`
- `www.runners-cache-4.gitlab.com`
- `www.blog.gitlab.com`
- `get.gitlab.com`
- `4456656-review-main-patch-akmp1u.design-staging.gitlab.com`
- `4456656-review-leipert-pi-ylw4l9.design-staging.gitlab.com`
- `4456656-review-matejlatin-0424qa.design-staging.gitlab.com`
- `4456656-review-dropdown-u-xey22m.design-staging.gitlab.com`
- `codesuggestions.gitlab.com`
- `private-runners-manager-3.gitlab.com`
- `4456656-review-katiemacoy-6kowxh.design-staging.gitlab.com`
- `www.customers.stg.gitlab.com`
- `scim.gitlab.com`
- `glcodesuggestion.prototype.gitlab.com`
- `errortracking.observe.gitlab.com`
- `4456656-review-fix-broken-qybukn.design-staging.gitlab.com`
- `4456656-review-gitlab-ui-l35n7g.design-staging.gitlab.com`
- `4456656-review-aregnery-s-qu3sap.design-staging.gitlab.com`
- `manager-staging.community.gitlab.com`
- `4456656-review-v-mishra-m-1iu2rs.design-staging.gitlab.com`
- `4456656-review-storybook-hverfl.design-staging.gitlab.com`
- `4456656-review-loadmore-53edp1.design-staging.gitlab.com`
- `www.piwik.gitlab.com`
- `runners-cache-5.gitlab.com`
- `4456656-review-1568-creat-9zjn0e.design-staging.gitlab.com`
- `4456656-review-main-patch-5jw3b1.design-staging.gitlab.com`
- `hub.gitlab.com`
- `4456656-review-lvanc-feat-c4vnls.design-staging.gitlab.com`
- `www.sync.geo.gitlab.com`
- `next.staging.gitlab.com`
- `4456656-review-1515-broke-hy4xvx.design-staging.gitlab.com`
- `4456656-review-main-patch-vs8cmm.design-staging.gitlab.com`
- `4456656-review-beckalippe-9ayot8.design-staging.gitlab.com`
- `4456656-review-main-patch-br77mb.design-staging.gitlab.com`
- `4456656-review-update-key-t4ghhd.design-staging.gitlab.com`
- `cell-c01j2gdw0zfdafxr6.cells.gitlab.com`
- `cloud.gitlab.com`
- `host.gitlab.com`
- `4456656-review-aregnery-r-sii6ch.design-staging.gitlab.com`
- `4456656-review-gl-global-ehsdxl.design-staging.gitlab.com`
- `levelup.gitlab.com`
- `private-runners-manager-4.gitlab.com`
- `4456656-review-tauriedavi-ngijlf.design-staging.gitlab.com`
- `4456656-review-color-pale-e7ltzf.design-staging.gitlab.com`
- `4456656-review-jeldergl-m-6ft9af.design-staging.gitlab.com`
- `www.dashboards.gitlab.com`
- `packages.gitlab.com`
- `4456656-review-1688-add-g-4yxtb0.design-staging.gitlab.com`
- `4456656-review-kbd-styles-3wqnci.design-staging.gitlab.com`
- `glchatvertex.prototype.gitlab.com`
- `4456656-review-mle-guidan-6dcfz1.design-staging.gitlab.com`
- `4456656-review-sselhorn-m-fv9x5d.design-staging.gitlab.com`
- `forum.gitlab.com`
- `4456656-review-1526-updat-cnlkd8.design-staging.gitlab.com`
- `4456656-review-1249-evalu-o3ym8w.design-staging.gitlab.com`
- `4456656-review-update-inf-chsgkf.design-staging.gitlab.com`
- `4456656-review-1470-pajam-1i3s9p.design-staging.gitlab.com`
- `ee.gitlab.com`
- `4456656-review-matejlatin-c5v5u3.design-staging.gitlab.com`
- `api.community.gitlab.com`
- `4456656-review-main-patch-la5jps.design-staging.gitlab.com`
- `www.prod.geo.gitlab.com`
- `lb-teleport.gprd.gitlab.com`
- `4456656-review-167-broken-qj1ysq.design-staging.gitlab.com`
- `shop.gitlab.com`
- `4456656-review-main-patch-tge44a.design-staging.gitlab.com`
- `4456656-review-372-founda-5ok9gh.design-staging.gitlab.com`
- `4456656-review-cluster-te-ahlmff.design-staging.gitlab.com`
- `4456656-review-danmh-link-zzbmci.design-staging.gitlab.com`
- `www.packages.gitlab.com`
- `api-staging.community.gitlab.com`
- `enable.gitlab.com`
- `piwik.gitlab.com`
- `cloud.staging.gitlab.com`
- `www.ee.gitlab.com`
- `4456656-review-russell-ad-rs1ci4.design-staging.gitlab.com`
- `auth.staging.gitlab.com`
- `4456656-review-helping-us-ab9za1.design-staging.gitlab.com`
- `www.plantuml.pre.gitlab.com`
- `www.dr.gitlab.com`
- `www.pre.gitlab.com`
- `www.ci.gitlab.com`
- `prometheus.gitlab.com`
- `cinc.gitlab.com`
- `doc.gitlab.com`
- `4456656-review-main-patch-p5v4z5.design-staging.gitlab.com`
- `4456656-review-main-patch-ahykfo.design-staging.gitlab.com`
- `4456656-review-main-patch-xs3wgn.design-staging.gitlab.com`
- `4456656-review-russell-ad-4deif2.design-staging.gitlab.com`
- `gprd.gitlab.com`
- `4456656-review-pedroms-ma-qh0b5c.design-staging.gitlab.com`
- `4456656-review-monica-gal-3qi8ge.design-staging.gitlab.com`
- `4456656-review-decrease-f-yjhr8g.design-staging.gitlab.com`
- `4456656-review-danmh-main-l30vd9.design-staging.gitlab.com`
- `www.canary.gitlab.com`
- `www.next.gitlab.com`
- `blog.gitlab.com`
- `4456656-review-main-patch-mj74wu.design-staging.gitlab.com`
- `4456656-review-better-err-r52kcp.design-staging.gitlab.com`
- `www.triage-serverless.gitlab.com`
- `www.about-src.gitlab.com`
- `4456656-review-link-mh9siw.design-staging.gitlab.com`
- `4456656-review-katiemacoy-9w1w8o.design-staging.gitlab.com`
- `4456656-review-v-mishra-m-674soo.design-staging.gitlab.com`
- `4456656-review-sselhorn-m-iu1n63.design-staging.gitlab.com`
- `4456656-review-dmoraberli-v9tcck.design-staging.gitlab.com`
- `www.runners-cache-2.gitlab.com`
- `about.staging.gitlab.com`
- `rocketchat.gitlab.com`
- `search.advisories.gitlab.com`
- `4456656-review-1369-color-ccob8j.design-staging.gitlab.com`
- `internal.gitlab.com`
- `www.status.gitlab.com`
- `support-mw.gitlab.com`
- `4456656-review-switchover-i4ueoq.design-staging.gitlab.com`
- `www.swedish.chef.gitlab.com`
- `kas.pre.gitlab.com`
- `4456656-review-typo-doc-j-9vr37q.design-staging.gitlab.com`
- `4456656-review-ui-kit-rel-zkqdli.design-staging.gitlab.com`
- `4456656-review-feat-add-n-atvmbp.design-staging.gitlab.com`
- `4456656-review-1384-color-9936bf.design-staging.gitlab.com`
- `4456656-review-feat-typog-iods1d.design-staging.gitlab.com`
- `cert-test.staging.gitlab.com`
- `www.contributors.gitlab.com`
- `about-src.gitlab.com`
- `4456656-review-1107-add-e-53243j.design-staging.gitlab.com`
- `4456656-review-link-updat-3hh8ij.design-staging.gitlab.com`
- `4456656-review-leipert-sw-gx6s02.design-staging.gitlab.com`
- `4456656-review-16-1-ui-ki-igmj3o.design-staging.gitlab.com`
- `slippers.gitlab.com`
- `le-4456656.design-staging.gitlab.com`
- `kas.gitlab.com`
- `prometheus-db.db-integration.gitlab.com`
- `4456656-review-1325-vpat-wdbu9w.design-staging.gitlab.com`
- `4456656-review-1474-butto-9dliu5.design-staging.gitlab.com`
- `canary.gitlab.com`
- `4456656-review-main-patch-z106gz.design-staging.gitlab.com`
- `4456656-review-alert-upda-7zeoqy.design-staging.gitlab.com`
- `4456656-review-eread-add-z47gmh.design-staging.gitlab.com`
- `www.chef.gitlab.com`
- `ce.gitlab.com`
- `prometheus-app.db-integration.gitlab.com`
- `prometheus.db-integration.gitlab.com`
- `4456656-review-email-obfu-vz3rnd.design-staging.gitlab.com`
- `4456656-review-add-variou-c1mz21.design-staging.gitlab.com`
- `4456656-review-main-patch-09hgox.design-staging.gitlab.com`
- `version.gitlab.com`
- `4456656-review-16-2-fig-b-vkcmpy.design-staging.gitlab.com`
- `4456656-review-main-patch-5uc0jr.design-staging.gitlab.com`
- `runners-cache-2.gitlab.com`
- `canary.staging.gitlab.com`
- `4456656-review-main-patch-dtq903.design-staging.gitlab.com`
- `4456656-review-fix-socks-qqsw5a.design-staging.gitlab.com`
- `4456656-review-migrate-gl-towhzq.design-staging.gitlab.com`
- `4456656-review-gdoyle-mai-ydq5be.design-staging.gitlab.com`
- `4456656-review-main-patch-jyt49u.design-staging.gitlab.com`
- `gateway.gcp.gitlab.com`
- `registry.gke.gstg.gitlab.com`
- `4456656-review-main-patch-uanp44.design-staging.gitlab.com`
- `www.get.gitlab.com`
- `www.feedback.gitlab.com`
- `www.runners-cache-1.gitlab.com`
- `4456656-review-mle-settin-mgne7n.design-staging.gitlab.com`
- `4456656-review-avoid-cons-9ii5vn.design-staging.gitlab.com`
- `4456656-review-ai-guidanc-9p86nm.design-staging.gitlab.com`
- `4456656-review-1398-typog-54o4di.design-staging.gitlab.com`
- `4456656-review-1699-acces-nqqei4.design-staging.gitlab.com`
- `pre-puma.gitlab.com`
- `4456656-review-main-patch-43rhv4.design-staging.gitlab.com`
- `4456656-review-feature-ve-84glmd.design-staging.gitlab.com`
- `glchat.prototype.gitlab.com`
- `www.next.staging.gitlab.com`
- `jobs.gitlab.com`
- `geo2.gitlab.com`
- `4456656-review-fix-templa-rmaij2.design-staging.gitlab.com`
- `4456656-review-372-remove-g0vjv5.design-staging.gitlab.com`
- `4456656-review-1455-clean-4futx0.design-staging.gitlab.com`
- `deps.staging.sec.gitlab.com`
- `le-2670515.cust-staging.gitlab.com`
- `4456656-review-1682-creat-k9e7cn.design-staging.gitlab.com`
- `4456656-review-main-patch-17vfv3.design-staging.gitlab.com`
- `www.registry.staging.gitlab.com`
- `www.gprd.gitlab.com`
- `www.university.gitlab.com`
- `deps-review.sec.gitlab.com`
- `4456656-review-mvanremmer-mxih49.design-staging.gitlab.com`
- `www.runners-cache-3.gitlab.com`
- `runway-ci-test-4jpyc3.staging.runway.gitlab.com`
- `4456656-review-main-patch-zcjz2f.design-staging.gitlab.com`
- `4456656-review-beckalippe-yi346l.design-staging.gitlab.com`
- `4456656-review-theoretick-nolo1m.design-staging.gitlab.com`
- `4456656-review-1504-figma-ccev9n.design-staging.gitlab.com`
- `kas1.pre.gitlab.com`
- `4456656-review-526-add-co-hhd4pd.design-staging.gitlab.com`
- `4456656-review-leipert-sv-zlo2if.design-staging.gitlab.com`
- `4456656-review-msj-gitlab-51lnju.design-staging.gitlab.com`
- `cdn.registry.pre.gitlab.com`
- `4456656-review-russell-im-mr165k.design-staging.gitlab.com`
- `4456656-review-amittner-m-nerl7d.design-staging.gitlab.com`
- `4456656-review-1442-dropd-pel4gp.design-staging.gitlab.com`
- `www.geo1.gitlab.com`
- `do158-143.mg.gitlab.com`
- `handbook.gitlab.com`
- `4456656-review-main-patch-6j8uwc.design-staging.gitlab.com`
- `chef2.gitlab.com`
- `4456656-review-popover-gu-1s8esd.design-staging.gitlab.com`
- `page.gitlab.com`
- `4456656-review-leipert-fi-a93rup.design-staging.gitlab.com`
- `4456656-review-remove-lin-8gm7r0.design-staging.gitlab.com`
- `errortracking.staging.observe.gitlab.com`
- `4456656-review-nadia-sotn-oz459g.design-staging.gitlab.com`
- `4456656-review-fix-lockfi-xfj7fu.design-staging.gitlab.com`
- `swedish.chef.gitlab.com`
- `4456656-review-russell-do-9o5hdr.design-staging.gitlab.com`
- `4456656-review-update-ban-zn4m0o.design-staging.gitlab.com`
- `4456656-review-update-nav-ztnp39.design-staging.gitlab.com`
- `www.support.gitlab.com`
- `support.gitlab.com`
- `4456656-review-stepper-jyhpg9.design-staging.gitlab.com`
- `4456656-review-main-patch-ibw59q.design-staging.gitlab.com`
- `cdn.registry.gitlab.com`
- `4456656-review-dev-1443-u-micvmc.design-staging.gitlab.com`
- `4456656-review-1445-merma-izi4nv.design-staging.gitlab.com`
- `4456656-review-1389-skele-4wl4g6.design-staging.gitlab.com`
- `4456656-review-main-patch-uhk064.design-staging.gitlab.com`
- `dashboards.gitlab.com`
- `chef.gitlab.com`
- `4456656-review-main-patch-7zq31d.design-staging.gitlab.com`
- `4456656-review-620-preven-sgkdey.design-staging.gitlab.com`
- `4456656-review-feature-ve-83unpv.design-staging.gitlab.com`
- `partnerflash.gitlab.com`
- `bogus.staging.gitlab.com`
- `4456656-review-1384-migra-vzug97.design-staging.gitlab.com`
- `4456656-review-danmh-figm-ecofo8.design-staging.gitlab.com`
- `le-4456656.design.gitlab.com`
- `4456656-review-1569-desig-pt069r.design-staging.gitlab.com`
- `4456656-review-settings-d-76bn45.design-staging.gitlab.com`
- `4456656-review-danmh-labe-7m5eaz.design-staging.gitlab.com`
- `4456656-review-remove-res-130xbp.design-staging.gitlab.com`
- `4456656-review-vs-update-l692gb.design-staging.gitlab.com`
- `4456656-review-update-com-fl3uox.design-staging.gitlab.com`
- `4456656-review-leipert-me-2kf6ib.design-staging.gitlab.com`
- `4456656-review-aregnery-a-q3q5lo.design-staging.gitlab.com`
- `registry.geo.staging-ref.gitlab.com`
- `4456656-review-add-refere-m150sn.design-staging.gitlab.com`
- `www.registry.gitlab.com`
- `feedback.gitlab.com`
- `www.runners-cache-5.gitlab.com`
- `4456656-review-1462-updat-gnllst.design-staging.gitlab.com`
- `4456656-review-editaction-iyfa0g.design-staging.gitlab.com`
- `4456656-review-glpathupda-ppzo2c.design-staging.gitlab.com`
- `plantuml.pre.gitlab.com`
- `4456656-review-nadia-sotn-e9wgrt.design-staging.gitlab.com`
- `4456656-review-sticky-hea-muxkb0.design-staging.gitlab.com`
- `4456656-review-replace-re-ozvga7.design-staging.gitlab.com`
- `4456656-review-add-variou-c2yklh.design-staging.gitlab.com`
- `4456656-review-1443-updat-pod18c.design-staging.gitlab.com`
- `4456656-review-1292-rende-mv55i4.design-staging.gitlab.com`
- `deps.sec.gitlab.com`
- `4456656-review-matejlatin-77kun7.design-staging.gitlab.com`
- `4456656-review-jeldergl-m-wl40lx.design-staging.gitlab.com`
- `4456656-review-sselhorn-m-ulzly1.design-staging.gitlab.com`
- `design-staging.gitlab.com`
- `registry.staging.gitlab.com`
- `4456656-review-424-docume-1auq3m.design-staging.gitlab.com`
- `4456656-review-1365-dropd-gp25pd.design-staging.gitlab.com`
- `4456656-review-main-patch-hwu1ap.design-staging.gitlab.com`
- `4456656-review-main-patch-hw74zf.design-staging.gitlab.com`
- `4456656-review-refactor-c-ilw0zv.design-staging.gitlab.com`
- `www.staging.gitlab.com`
- `about.gitlab.com`
- `www.geo2.gitlab.com`
- `4456656-review-1656-creat-1s3oj9.design-staging.gitlab.com`
- `metrics.gitlab.com`
- `4456656-review-759-standa-338g48.design-staging.gitlab.com`
- `4456656-review-yarn-tool-9v2qz8.design-staging.gitlab.com`
- `www.prometheus.gitlab.com`
- `triage-ops.gitlab.com`
- `4456656-review-1581-pajam-ux0aky.design-staging.gitlab.com`
- `4456656-review-leipert-te-1f4hg0.design-staging.gitlab.com`
- `4456656-review-1623-creat-6s0twl.design-staging.gitlab.com`
- `4456656-review-do-not-for-pzqdfc.design-staging.gitlab.com`
- `4456656-review-todo-issue-mxbz2n.design-staging.gitlab.com`
- `4456656-review-1371-illus-zin06c.design-staging.gitlab.com`
- `mr-sidebar.prototype.gitlab.com`
- `4456656-review-rayana-mai-8n3oyd.design-staging.gitlab.com`
- `www.kas.staging.gitlab.com`
- `staging.gitlab.com`
- `4456656-review-main-patch-f6fk1y.design-staging.gitlab.com`
- `4456656-review-update-fea-0m983a.design-staging.gitlab.com`
- `4456656-review-mnichols1-tpamws.design-staging.gitlab.com`
- `4456656-review-add-radio-thttki.design-staging.gitlab.com`
- `4456656-review-pre-code-s-fryi17.design-staging.gitlab.com`
- `4456656-review-sselhorn-m-5og57p.design-staging.gitlab.com`
- `www.jobs.gitlab.com`
- `pre.gitlab.com`
- `4456656-review-1444-link-mzm8ta.design-staging.gitlab.com`
- `cdn.registry.staging.gitlab.com`
- `static-objects.staging.gitlab.com`
- `go.gitlab.com`
- `4456656-review-update-dat-0ptsk3.design-staging.gitlab.com`
- `www.shop.gitlab.com`
- `design.gitlab.com`
- `4456656-review-jeldergl-m-i8pqtg.design-staging.gitlab.com`
- `4456656-review-init-ui-ki-9s5r7x.design-staging.gitlab.com`
- `partners.gitlab.com`
- `4456656-review-danmh-main-8m9u8a.design-staging.gitlab.com`
- `4456656-review-aregnery-b-jm67v7.design-staging.gitlab.com`
- `4456656-review-sam-figuer-w6w8ie.design-staging.gitlab.com`
- `4456656-review-main-patch-pdbsbv.design-staging.gitlab.com`
- `prometheus-3.gitlab.com`
- `4456656-review-feat-add-d-6hvldh.design-staging.gitlab.com`
- `4456656-review-1578-updat-j6nklw.design-staging.gitlab.com`
- `4456656-review-1413-typog-zh5cqo.design-staging.gitlab.com`
- `4456656-review-figma-chan-m8wo3e.design-staging.gitlab.com`
- `4456656-review-ld-remove-s98iax.design-staging.gitlab.com`
- `4456656-review-frontend-o-k89w9g.design-staging.gitlab.com`
- `runners-cache-1.gitlab.com`
- `4456656-review-lookbook-e-vm97y9.design-staging.gitlab.com`
- `4456656-review-main-patch-gdpmpv.design-staging.gitlab.com`
- `4456656-review-372-cleanu-gim0da.design-staging.gitlab.com`
- `www.ce.gitlab.com`
- `www.alerts.gitlab.com`
- `www.rocketchat.gitlab.com`
- `learn.gitlab.com`
- `4456656-review-nadia-sotn-dfivs2.design-staging.gitlab.com`
- `4456656-review-jlouw-fix-3hbdqy.design-staging.gitlab.com`
- `4456656-review-1567-add-n-goo7zb.design-staging.gitlab.com`
- `developer.gitlab.com`
- `4456656-review-sselhorn-m-ujr9vh.design-staging.gitlab.com`
- `content.gitlab.com`
- `4456656-review-main-patch-t8812x.design-staging.gitlab.com`
- `4456656-review-167-fix-br-ka1mjc.design-staging.gitlab.com`
- `4456656-review-vs-fix-cod-r1wbfx.design-staging.gitlab.com`
- `university.gitlab.com`
- `4456656-review-1443-updat-77up3w.design-staging.gitlab.com`
- `4456656-review-main-patch-0hbs2y.design-staging.gitlab.com`
- `prometheus.staging-ref.gitlab.com`
- `grafana.amp.cells.gitlab.com`
- `www.support-mw.gitlab.com`
- `4456656-review-navigation-qlpoi0.design-staging.gitlab.com`
- `4456656-review-468-dropdo-tuaw1h.design-staging.gitlab.com`
- `4456656-review-markrian-m-2hprzi.design-staging.gitlab.com`
- `4456656-review-leipert-fi-8xvt9u.design-staging.gitlab.com`
- `4456656-review-tooltip-fo-4b3dch.design-staging.gitlab.com`
- `4456656-review-danmh-add-939zv6.design-staging.gitlab.com`
- `4456656-review-1686-follo-54znci.design-staging.gitlab.com`
- `4456656-review-update-con-flbvjr.design-staging.gitlab.com`
- `4456656-review-nickleonar-3ymc9c.design-staging.gitlab.com`
- `www.forum.gitlab.com`
- `email.gitlab.com`
- `4456656-review-1468-pajam-z15l6c.design-staging.gitlab.com`
- `4456656-review-fix-punctu-7gmkwg.design-staging.gitlab.com`
- `4456656-review-fix-dropdo-pxfde4.design-staging.gitlab.com`
- `www.hub.gitlab.com`
- `www.chat.gitlab.com`
- `next.gitlab.com`
- `4456656-review-tool-versi-qskle9.design-staging.gitlab.com`
- `dast-4456656-dast-default.design-staging.gitlab.com`
- `2670515-review-enable-aut-a96d5t.cust-staging.gitlab.com`
- `registry.gitlab.com`
- `4456656-review-monica-gal-s5wit4.design-staging.gitlab.com`
- `4456656-review-1702-creat-qe3vkr.design-staging.gitlab.com`
- `status.gitlab.com`
- `alerts.gitlab.com`
- `gstg.gitlab.com`
- `app-staging.community.gitlab.com`
- `4456656-review-1179-toggl-8ctzom.design-staging.gitlab.com`
- `geo.staging.gitlab.com`
- `4456656-review-pedroms-ma-b2xv0l.design-staging.gitlab.com`
- `www.federal-support.gitlab.com`
- `aptly.gitlab.com`
- `chef12.gitlab.com`
- `4456656-review-update-ske-mudp9g.design-staging.gitlab.com`
- `dr.gitlab.com`
- `4456656-review-nadia-sotn-n2exgz.design-staging.gitlab.com`
- `www.license.gitlab.com`
- `www.registry.pre.gitlab.com`
- `4456656-review-cam-x-main-r0jpo8.design-staging.gitlab.com`
- `4456656-review-matejlatin-ht343x.design-staging.gitlab.com`
- `4456656-review-nadia-sotn-344w7f.design-staging.gitlab.com`
- `4456656-review-leipert-re-odlobn.design-staging.gitlab.com`
- `sync.geo.gitlab.com`
- `4456656-review-docs-headi-iwghf9.design-staging.gitlab.com`
- `runway.gitlab.com`
- `www.customers.gitlab.com`
- `4456656-review-danmh-base-jxzqod.design-staging.gitlab.com`
- `4456656-review-1466-homep-if4gda.design-staging.gitlab.com`
- `4456656-review-leipert-fi-b4f198.design-staging.gitlab.com`
- `4456656-review-annabeldun-yva22z.design-staging.gitlab.com`
- `4456656-review-figure-img-csecdr.design-staging.gitlab.com`
- `4456656-review-danmh-main-c1cmm0.design-staging.gitlab.com`
- `4456656-review-codeowners-98nl8j.design-staging.gitlab.com`
- `4456656-review-fix-broken-484psj.design-staging.gitlab.com`
- `registry.pre.gitlab.com`
- `geo.staging-ref.gitlab.com`
- `4456656-review-loadmoregu-u81fud.design-staging.gitlab.com`
- `4456656-review-aregnery-u-87yayz.design-staging.gitlab.com`
- `4456656-review-main-patch-fh2a11.design-staging.gitlab.com`
- `www.gitlab.com`
- `translate.gitlab.com`
- `ir.gitlab.com`
- `4456656-review-jeldergl-m-94oflr.design-staging.gitlab.com`
- `4456656-review-16-3-figma-9mwtgl.design-staging.gitlab.com`
- `www.version.gitlab.com`
- `customers.staging.gitlab.com`
- `observe.gitlab.com`
- `jitsu-configurator.product-analytics.prototype.gitlab.com`
- `4456656-review-aregnery-t-k27a4t.design-staging.gitlab.com`
- `4456656-review-update-neu-l9jugi.design-staging.gitlab.com`
- `4456656-review-main-patch-9ymnv2.design-staging.gitlab.com`
- `4456656-review-leipert-ad-yv3s6o.design-staging.gitlab.com`
- `4456656-review-main-patch-6yplki.design-staging.gitlab.com`
- `auth.gitlab.com`
- `www.gstg.gitlab.com`
- `4456656-review-main-patch-7vaf0e.design-staging.gitlab.com`
- `4456656-review-nadia-sotn-a2gju7.design-staging.gitlab.com`
- `4456656-review-1457-resol-ux5ml2.design-staging.gitlab.com`
- `kas.staging.gitlab.com`
- `4456656-review-1435-comma-5x5076.design-staging.gitlab.com`

</details>

---

## Methodology

A small LLM running locally on Lemonade Server (AMD Ryzen AI, Qwen3-1.7B) drives a ReAct loop with intelligent step skipping: it reasons about whether each tool is worth running based on the prior tool's output. Scope allowlist enforces a glob-based target filter on every host before the tool spawns. Rate limiting inserts a floor between iterations.

Tool chain executed this run:

- `subfinder` — passive subdomain enumeration
- `httpx` — live HTTP probe (status, title, tech detect, JSON output)
- `nuclei` — templated vuln scan (cves + exposures + misconfiguration + vulnerabilities, severity>=medium)

## Step Detail

### Iteration 1 — subfinder

**Args:** `{"domain":"gitlab.com"}`

**Preview:**

```
ci.gitlab.com
geo1.gitlab.com
4456656-review-gt-update-7ocwl1.design-staging.gitlab.com
4456656-review-work-item-z7jn6r.design-staging.gitlab.com
4456656-review-372-button-cu19b4.design-staging.gitlab.com
license.gitlab.com
4456656-review-1527-type-0ahnvf.design-staging.gitlab.com
4456656-review-katiemacoy-28xw6w.design-staging.gitlab.com
4456656-review-bugfix-loc-qvog2t.design-staging.gitlab.com
registry.gke.pre.gitlab.com
4456656-review-1204-add-c-a529gy.design-staging.gitlab.com
4456656-review-1384-migra-hi3gz1.design-staging.gitlab.com
4456656-review-viewcompon-kkveh5.design-staging.gitlab.com
biz.gitlab.com
4456656-review-372-migrat-fsc737.design-staging.gitlab.com
gitlab-org-gitlab-services-design-gitlab-com.design.gitlab.com
4456656-review-1454-clean-24ifbs.design-staging.gitlab.com
4456656-review-1466-homep-b9nz0w.design-staging.gitlab.com
registry.gke.staging.gitlab.com
jitsu-server.product-analytics.prototype.gitlab.com
registry.staging-ref.gitlab.com
4456656-review-1529-vpat-t9lc7u.design-staging.gitlab.com
www.learn.gitlab.com
chat.gitlab.com
4456656-review-main-patch-t0zk8u.design-staging.gitlab.com
```

### Iteration 2 — httpx

**Args:** `{"hosts_from":"subfinder"}`

**Preview:**

```
{"timestamp":"2026-04-16T19:13:53.224074934-04:00","cdn_name":"google","cdn_type":"cdn","port":"443","url":"https://archives.docs.gitlab.com","input":"archives.docs.gitlab.com","title":"GitLab Docs Archives","scheme":"https","content_type":"text/html","method":"GET","host":"archives.docs.gitlab.com","host_ip":"2600:1901:0:7b8a::","path":"/","time":"668.752037ms","a":["35.185.44.232"],"aaaa":["2600:1901:0:7b8a::"],"words":82,"lines":16,"status_code":200,"content_length":658,"failed":false,"cdn":true,"knowledgebase":{"pHash":0},"resolvers":["127.0.0.53:53"],"cpe":[{"product":"gitlab","vendor":"gitlab","cpe":"cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*"},{"product":"gitlab_hook","vendor":"jenkins","cpe":"cpe:2.3:a:jenkins:gitlab_hook:*:*:*:*:*:*:*:*"}]}
```

### Iteration 3 — nuclei

**Args:** `{"urls_from":"httpx"}`

### Iteration 4 — done

---

## Recommended Next Steps

- done

---

_Generated by AgentSpyBoo Phase 3 (CPU-track + Pius preflight) — https://github.com/Peterc3-dev (private)_

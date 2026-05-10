# AgentSpyBoo Assessment — gitlab.com

**Date:** 2026-04-16T22:51:52.429006551+00:00  
**Model:** qwen3:8b  
**Iterations:** 4  
**Scope:** gitlab.com, *.gitlab.com  
**Tools fired:** subfinder → httpx

---

## Executive Summary

Subfinder found 536 subdomains, httpx identified 1 live host (handbook.gitlab.com), but nuclei failed to scan due to missing curated templates. Vulnerability assessment incomplete.

---

## Organization Recon (Pius)

**Organization:** GitLab  
**ASN hint:** AS57787  
**Mode:** passive  
**Runtime:** 130.0s  
**Plugins fired:** asn-bgp, crt-sh, github-org, gleif, urlscan, wayback  
**Records:** 514 raw, 10 filtered out

### Domains discovered

| Domain | Sources | Confidence |
|--------|---------|------------|
| `2670515-review-enable-aut-a96d5t.cust-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1107-add-e-53243j.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1179-toggl-8ctzom.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1204-add-c-a529gy.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1249-evalu-o3ym8w.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1292-rende-mv55i4.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1325-vpat-wdbu9w.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1345-story-efzw0t.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1365-dropd-gp25pd.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1369-color-ccob8j.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1371-illus-zin06c.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1384-color-9936bf.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1384-migra-hi3gz1.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1384-migra-vzug97.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1389-skele-4wl4g6.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1398-typog-54o4di.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1413-typog-zh5cqo.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1435-comma-5x5076.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1442-dropd-pel4gp.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1443-updat-77up3w.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1443-updat-pod18c.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1444-link-mzm8ta.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1445-merma-izi4nv.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1454-clean-24ifbs.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1455-clean-4futx0.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1457-resol-ux5ml2.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1462-updat-gnllst.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1464-add-p-jxfmxs.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1466-homep-b9nz0w.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1466-homep-if4gda.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1468-pajam-z15l6c.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1470-pajam-1i3s9p.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1471-updat-bl7fl4.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1474-butto-9dliu5.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-15-11-fig-lodxco.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1504-figma-ccev9n.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1515-broke-hy4xvx.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1517-dropd-biebor.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1524-docs-riq0la.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1526-updat-cnlkd8.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1527-type-0ahnvf.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1529-vpat-t9lc7u.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1532-fix-a-vslnpm.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1534-dropd-ybke0g.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1567-add-n-goo7zb.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1568-creat-9zjn0e.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1569-desig-pt069r.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1578-updat-j6nklw.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1581-pajam-ux0aky.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-16-1-ui-ki-igmj3o.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-16-2-fig-b-vkcmpy.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-16-3-figma-9mwtgl.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1601-creat-6facx9.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1623-creat-6s0twl.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1656-creat-1s3oj9.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-167-broken-qj1ysq.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-167-fix-br-ka1mjc.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1682-creat-k9e7cn.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1686-follo-54znci.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1688-add-g-4yxtb0.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1699-acces-nqqei4.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-1702-creat-qe3vkr.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-372-button-cu19b4.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-372-cleanu-gim0da.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-372-founda-5ok9gh.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-372-migrat-fsc737.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-372-remove-g0vjv5.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-424-docume-1auq3m.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-468-dropdo-tuaw1h.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-526-add-co-hhd4pd.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-620-preven-sgkdey.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-759-standa-338g48.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-add-radio-thttki.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-add-refere-m150sn.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-add-variou-c1mz21.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-add-variou-c2yklh.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-ai-guidanc-9p86nm.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-alert-upda-7zeoqy.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-amittner-m-nerl7d.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-annabeldun-yva22z.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-aregnery-a-q3q5lo.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-aregnery-b-jm67v7.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-aregnery-r-sii6ch.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-aregnery-s-qu3sap.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-aregnery-t-k27a4t.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-aregnery-u-87yayz.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-avoid-cons-9ii5vn.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-beckalippe-9ayot8.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-beckalippe-yi346l.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-better-err-r52kcp.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-bugfix-loc-qvog2t.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-cam-x-main-r0jpo8.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-cluster-te-ahlmff.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-codeowners-98nl8j.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-color-pale-e7ltzf.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-danmh-add-939zv6.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-danmh-base-jxzqod.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-danmh-figm-ecofo8.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-danmh-labe-7m5eaz.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-danmh-line-602hhc.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-danmh-link-zzbmci.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-danmh-main-7byn0x.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-danmh-main-8m9u8a.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-danmh-main-c1cmm0.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-danmh-main-l30vd9.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-danmh-ui-k-1zf7up.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-decrease-f-yjhr8g.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-dev-1443-u-micvmc.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-dmoraberli-v9tcck.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-do-not-for-pzqdfc.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-docs-headi-iwghf9.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-dropdown-u-xey22m.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-editaction-iyfa0g.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-email-obfu-vz3rnd.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-eread-add-z47gmh.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-feat-add-d-6hvldh.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-feat-add-i-jfatva.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-feat-add-n-atvmbp.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-feat-typog-iods1d.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-feature-ve-83unpv.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-feature-ve-84glmd.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-figma-chan-m8wo3e.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-figure-img-csecdr.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-fix-broken-484psj.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-fix-broken-qybukn.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-fix-dropdo-pxfde4.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-fix-lockfi-xfj7fu.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-fix-main-a8e81c.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-fix-punctu-7gmkwg.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-fix-socks-qqsw5a.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-fix-templa-rmaij2.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-frontend-o-k89w9g.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-gdoyle-mai-ydq5be.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-gitlab-ui-l35n7g.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-gl-global-ehsdxl.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-glpathupda-ppzo2c.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-gt-update-7ocwl1.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-helping-us-ab9za1.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-init-ui-ki-9s5r7x.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-jeldergl-m-6ft9af.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-jeldergl-m-94oflr.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-jeldergl-m-i8pqtg.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-jeldergl-m-wl40lx.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-jlouw-fix-3hbdqy.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-katiemacoy-28xw6w.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-katiemacoy-6kowxh.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-katiemacoy-6mkyxy.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-katiemacoy-9w1w8o.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-kbd-styles-3wqnci.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-ld-remove-s98iax.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-leipert-ad-yv3s6o.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-leipert-de-ukc4pq.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-leipert-fi-8xvt9u.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-leipert-fi-a93rup.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-leipert-fi-b4f198.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-leipert-in-fn9qbu.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-leipert-me-2kf6ib.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-leipert-pi-ylw4l9.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-leipert-re-odlobn.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-leipert-so-fnmdgi.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-leipert-sv-zlo2if.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-leipert-sw-gx6s02.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-leipert-te-1f4hg0.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-link-mh9siw.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-link-updat-3hh8ij.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-loadmore-53edp1.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-loadmoregu-u81fud.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-lookbook-e-vm97y9.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-lvanc-feat-c4vnls.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-lvanc-main-vhyovi.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-09hgox.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-0hbs2y.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-17vfv3.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-1axc6b.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-43rhv4.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-5jw3b1.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-5uc0jr.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-6j8uwc.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-6yplki.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-7vaf0e.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-7zq31d.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-9ymnv2.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-ahykfo.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-akmp1u.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-br77mb.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-dtq903.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-e4eovu.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-f6fk1y.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-fh2a11.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-gdpmpv.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-h5jvmx.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-htq0lf.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-hw74zf.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-hwu1ap.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-ibw59q.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-jyt49u.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-la5jps.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-mj74wu.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-p5v4z5.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-pdbsbv.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-t0zk8u.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-t8812x.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-tge44a.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-uanp44.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-uhk064.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-ukqrqf.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-vs8cmm.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-wl4twp.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-xs3wgn.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-z106gz.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-main-patch-zcjz2f.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-markrian-m-2hprzi.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-matejlatin-0424qa.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-matejlatin-77kun7.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-matejlatin-c5v5u3.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-matejlatin-ht343x.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-matejlatin-myrk4n.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-migrate-gl-towhzq.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-mle-guidan-6dcfz1.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-mle-settin-mgne7n.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-mnichols1-tpamws.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-monica-gal-3qi8ge.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-monica-gal-oepnqj.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-monica-gal-pz78s2.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-monica-gal-s5wit4.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-msj-extern-e112lv.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-msj-gitlab-51lnju.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-mvanremmer-mxih49.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-nadia-sotn-344w7f.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-nadia-sotn-a2gju7.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-nadia-sotn-dfivs2.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-nadia-sotn-e9wgrt.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-nadia-sotn-n2exgz.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-nadia-sotn-oz459g.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-navigation-qlpoi0.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-nickleonar-3ymc9c.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-pedroms-ma-b2xv0l.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-pedroms-ma-qh0b5c.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-pgascouvai-1f4bo8.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-popover-gu-1s8esd.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-pre-code-s-fryi17.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-rayana-mai-8n3oyd.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-refactor-c-ilw0zv.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-remove-lin-8gm7r0.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-remove-res-130xbp.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-replace-re-ozvga7.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-russell-ad-4deif2.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-russell-ad-rs1ci4.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-russell-do-9o5hdr.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-russell-im-mr165k.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-sam-figuer-w6w8ie.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-settings-d-76bn45.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-spacing-ex-nrw7ke.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-sselhorn-m-5og57p.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-sselhorn-m-cp6hbg.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-sselhorn-m-fv9x5d.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-sselhorn-m-iu1n63.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-sselhorn-m-ujr9vh.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-sselhorn-m-ulzly1.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-sselhorn-m-ygc05a.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-stepper-jyhpg9.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-sticky-hea-muxkb0.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-storybook-hverfl.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-switchover-i4ueoq.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-tauriedavi-ngijlf.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-theoretick-nolo1m.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-todo-issue-mxbz2n.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-tool-versi-qskle9.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-tooltip-fo-4b3dch.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-typo-doc-j-9vr37q.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-ui-kit-dep-cjugbw.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-ui-kit-rel-zkqdli.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-update-ban-zn4m0o.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-update-com-fl3uox.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-update-con-flbvjr.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-update-dat-0ptsk3.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-update-fea-0m983a.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-update-inf-chsgkf.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-update-key-t4ghhd.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-update-nav-ztnp39.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-update-neu-l9jugi.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-update-ske-mudp9g.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-update-str-dw8cuz.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-update-tab-d7o120.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-update-ui-qkugqu.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-v-mishra-m-1iu2rs.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-v-mishra-m-4agh3r.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-v-mishra-m-674soo.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-viewcompon-kkveh5.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-vs-fix-cod-r1wbfx.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-vs-update-l692gb.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-work-item-z7jn6r.design-staging.gitlab.com` | crt-sh | — |
| `4456656-review-yarn-tool-9v2qz8.design-staging.gitlab.com` | crt-sh | — |
| `about-src.gitlab.com` | crt-sh | — |
| `about.gitlab.com` | urlscan, crt-sh | — |
| `about.staging.gitlab.com` | crt-sh | — |
| `advisories.gitlab.com` | urlscan, crt-sh | — |
| `alerts.gitlab.com` | crt-sh | — |
| `aptly.gitlab.com` | crt-sh | — |
| `archives.docs.gitlab.com` | crt-sh | — |
| `auth.gitlab.com` | crt-sh | — |
| `auth.staging.gitlab.com` | crt-sh | — |
| `biz.gitlab.com` | crt-sh | — |
| `blog.gitlab.com` | crt-sh | — |
| `bogus.staging.gitlab.com` | crt-sh | — |
| `campaign-manager.gitlab.com` | crt-sh | — |
| `canary.gitlab.com` | crt-sh | — |
| `canary.staging.gitlab.com` | crt-sh | — |
| `cdn.registry.gitlab.com` | crt-sh | — |
| `cdn.registry.pre.gitlab.com` | crt-sh | — |
| `cdn.registry.staging.gitlab.com` | crt-sh | — |
| `ce.gitlab.com` | crt-sh | — |
| `cert-test.staging.gitlab.com` | crt-sh | — |
| `chat.gitlab.com` | crt-sh | — |
| `chef.gitlab.com` | crt-sh | — |
| `chef12.gitlab.com` | crt-sh | — |
| `chef2.gitlab.com` | crt-sh | — |
| `ci.gitlab.com` | crt-sh | — |
| `cinc.gitlab.com` | crt-sh | — |
| `codesuggestions.gitlab.com` | crt-sh | — |
| `content.gitlab.com` | crt-sh | — |
| `contributors.gitlab.com` | crt-sh | — |
| `customers.gitlab.com` | crt-sh | — |
| `customers.staging-ref.gitlab.com` | crt-sh | — |
| `customers.staging.gitlab.com` | crt-sh | — |
| `customers.stg.gitlab.com` | crt-sh | — |
| `cxr.gitlab.com` | crt-sh | — |
| `dashboards.gitlab.com` | crt-sh | — |
| `dast-4456656-dast-default.design-staging.gitlab.com` | crt-sh | — |
| `deps-review.sec.gitlab.com` | crt-sh | — |
| `deps.sec.gitlab.com` | crt-sh | — |
| `deps.staging.sec.gitlab.com` | crt-sh | — |
| `design.gitlab.com` | crt-sh | — |
| `developer.gitlab.com` | crt-sh | — |
| `docs.gitlab.com` | urlscan, crt-sh | — |
| `dr.gitlab.com` | crt-sh | — |
| `ee.gitlab.com` | crt-sh | — |
| `email.customers.gitlab.com` | crt-sh | — |
| `email.gitlab.com` | crt-sh | — |
| `enable.gitlab.com` | urlscan, crt-sh | — |
| `errortracking.observe.gitlab.com` | crt-sh | — |
| `errortracking.staging.observe.gitlab.com` | crt-sh | — |
| `federal-support.gitlab.com` | crt-sh | — |
| `feedback.gitlab.com` | crt-sh | — |
| `forum.gitlab.com` | crt-sh | — |
| `geo.staging-ref.gitlab.com` | crt-sh | — |
| `geo.staging.gitlab.com` | crt-sh | — |
| `geo1.gitlab.com` | crt-sh | — |
| `geo2.gitlab.com` | crt-sh | — |
| `get.gitlab.com` | crt-sh | — |
| `gitlab-org-gitlab-services-design-gitlab-com.design.gitlab.com` | crt-sh | — |
| `gitlab.com` | urlscan, crt-sh, wayback | — |
| `glchat.prototype.gitlab.com` | crt-sh | — |
| `glchatvertex.prototype.gitlab.com` | crt-sh | — |
| `glcodesuggestion.prototype.gitlab.com` | crt-sh | — |
| `go.gitlab.com` | crt-sh | — |
| `gprd.gitlab.com` | crt-sh | — |
| `gstg.gitlab.com` | crt-sh | — |
| `handbook.gitlab.com` | crt-sh | — |
| `hub.gitlab.com` | crt-sh | — |
| `internal.gitlab.com` | crt-sh | — |
| `ir.gitlab.com` | crt-sh | — |
| `jitsu-configurator.product-analytics.prototype.gitlab.com` | crt-sh | — |
| `jitsu-server.product-analytics.prototype.gitlab.com` | crt-sh | — |
| `jobs.gitlab.com` | crt-sh | — |
| `kas.gitlab.com` | crt-sh | — |
| `kas.pre.gitlab.com` | crt-sh | — |
| `kas.staging.gitlab.com` | crt-sh | — |
| `kas1.pre.gitlab.com` | crt-sh | — |
| `le-2670515.cust-staging.gitlab.com` | crt-sh | — |
| `le-4456656.design-staging.gitlab.com` | crt-sh | — |
| `le-4456656.design.gitlab.com` | crt-sh | — |
| `learn.gitlab.com` | crt-sh | — |
| `levelup.gitlab.com` | crt-sh | — |
| `license.gitlab.com` | crt-sh | — |
| `metrics.gitlab.com` | crt-sh | — |
| `mr-sidebar.prototype.gitlab.com` | crt-sh | — |
| `next.gitlab.com` | crt-sh | — |
| `next.staging.gitlab.com` | crt-sh | — |
| `observe.gitlab.com` | crt-sh | — |
| `observe.staging.gitlab.com` | crt-sh | — |
| `packages.gitlab.com` | crt-sh | — |
| `page.gitlab.com` | crt-sh | — |
| `partnerflash.gitlab.com` | crt-sh | — |
| `partners.gitlab.com` | crt-sh | — |
| `piwik.gitlab.com` | crt-sh | — |
| `plantuml.pre.gitlab.com` | crt-sh | — |
| `pre-puma.gitlab.com` | crt-sh | — |
| `pre.gitlab.com` | crt-sh | — |
| `private-runners-manager-1.gitlab.com` | crt-sh | — |
| `prod.geo.gitlab.com` | crt-sh | — |
| `prometheus-2.gitlab.com` | crt-sh | — |
| `prometheus-3.gitlab.com` | crt-sh | — |
| `prometheus-app.db-integration.gitlab.com` | crt-sh | — |
| `prometheus-db.db-integration.gitlab.com` | crt-sh | — |
| `prometheus.db-integration.gitlab.com` | crt-sh | — |
| `prometheus.gitlab.com` | crt-sh | — |
| `prometheus.staging-ref.gitlab.com` | crt-sh | — |
| `redash.gitlab.com` | crt-sh | — |
| `registry.geo.staging-ref.gitlab.com` | crt-sh | — |
| `registry.gitlab.com` | crt-sh | — |
| `registry.gke.gstg.gitlab.com` | crt-sh | — |
| `registry.gke.pre.gitlab.com` | crt-sh | — |
| `registry.gke.staging.gitlab.com` | crt-sh | — |
| `registry.pre.gitlab.com` | crt-sh | — |
| `registry.staging-ref.gitlab.com` | crt-sh | — |
| `registry.staging.gitlab.com` | crt-sh | — |
| `rocketchat.gitlab.com` | crt-sh | — |
| `runners-cache-1.gitlab.com` | crt-sh | — |
| `runners-cache-2.gitlab.com` | crt-sh | — |
| `runners-cache-3.gitlab.com` | crt-sh | — |
| `runners-cache-4.gitlab.com` | crt-sh | — |
| `runners-cache-5.gitlab.com` | crt-sh | — |
| `runway-ci-test-4jpyc3.staging.runway.gitlab.com` | crt-sh | — |
| `scim.gitlab.com` | crt-sh | — |
| `search.advisories.gitlab.com` | crt-sh | — |
| `shop.gitlab.com` | crt-sh | — |
| `single.gitlab.com` | crt-sh | — |
| `slippers.gitlab.com` | crt-sh | — |
| `staging-ref.gitlab.com` | crt-sh | — |
| `staging.gitlab.com` | crt-sh | — |
| `staging.observe.gitlab.com` | crt-sh | — |
| `static-objects.staging.gitlab.com` | crt-sh | — |
| `status.gitlab.com` | crt-sh | — |
| `support-mw.gitlab.com` | crt-sh | — |
| `support.gitlab.com` | crt-sh | — |
| `swedish.chef.gitlab.com` | crt-sh | — |
| `sync.geo.gitlab.com` | crt-sh | — |
| `translate.gitlab.com` | crt-sh | — |
| `triage-ops.gitlab.com` | crt-sh | — |
| `triage-serverless.gitlab.com` | crt-sh | — |
| `university.gitlab.com` | crt-sh | — |
| `version.gitlab.com` | crt-sh | — |
| `www.about-src.gitlab.com` | crt-sh | — |
| `www.about.gitlab.com` | crt-sh | — |
| `www.alerts.gitlab.com` | crt-sh | — |
| `www.aptly.gitlab.com` | crt-sh | — |
| `www.blog.gitlab.com` | crt-sh | — |
| `www.canary.gitlab.com` | crt-sh | — |
| `www.canary.staging.gitlab.com` | crt-sh | — |
| `www.ce.gitlab.com` | crt-sh | — |
| `www.chat.gitlab.com` | crt-sh | — |
| `www.chef.gitlab.com` | crt-sh | — |
| `www.ci.gitlab.com` | crt-sh | — |
| `www.contributors.gitlab.com` | crt-sh | — |
| `www.customers.gitlab.com` | crt-sh | — |
| `www.customers.stg.gitlab.com` | crt-sh | — |
| `www.dashboards.gitlab.com` | crt-sh | — |
| `www.docs.gitlab.com` | crt-sh | — |
| `www.dr.gitlab.com` | crt-sh | — |
| `www.ee.gitlab.com` | crt-sh | — |
| `www.federal-support.gitlab.com` | crt-sh | — |
| `www.feedback.gitlab.com` | crt-sh | — |
| `www.forum.gitlab.com` | crt-sh | — |
| `www.geo1.gitlab.com` | crt-sh | — |
| `www.geo2.gitlab.com` | crt-sh | — |
| `www.get.gitlab.com` | crt-sh | — |
| `www.gitlab.com` | crt-sh, wayback | — |
| `www.gprd.gitlab.com` | crt-sh | — |
| `www.gstg.gitlab.com` | crt-sh | — |
| `www.hub.gitlab.com` | crt-sh | — |
| `www.jobs.gitlab.com` | crt-sh | — |
| `www.kas.staging.gitlab.com` | crt-sh | — |
| `www.learn.gitlab.com` | crt-sh | — |
| `www.license.gitlab.com` | crt-sh | — |
| `www.next.gitlab.com` | crt-sh | — |
| `www.next.staging.gitlab.com` | crt-sh | — |
| `www.packages.gitlab.com` | crt-sh | — |
| `www.page.gitlab.com` | crt-sh | — |
| `www.piwik.gitlab.com` | crt-sh | — |
| `www.plantuml.pre.gitlab.com` | crt-sh | — |
| `www.pre.gitlab.com` | crt-sh | — |
| `www.prod.geo.gitlab.com` | crt-sh | — |
| `www.prometheus-2.gitlab.com` | crt-sh | — |
| `www.prometheus-3.gitlab.com` | crt-sh | — |
| `www.prometheus.gitlab.com` | crt-sh | — |
| `www.redash.gitlab.com` | crt-sh | — |
| `www.registry.gitlab.com` | crt-sh | — |
| `www.registry.pre.gitlab.com` | crt-sh | — |
| `www.registry.staging.gitlab.com` | crt-sh | — |
| `www.rocketchat.gitlab.com` | crt-sh | — |
| `www.runners-cache-1.gitlab.com` | crt-sh | — |
| `www.runners-cache-2.gitlab.com` | crt-sh | — |
| `www.runners-cache-3.gitlab.com` | crt-sh | — |
| `www.runners-cache-4.gitlab.com` | crt-sh | — |
| `www.runners-cache-5.gitlab.com` | crt-sh | — |
| `www.shop.gitlab.com` | crt-sh | — |
| `www.staging.gitlab.com` | crt-sh | — |
| `www.status.gitlab.com` | crt-sh | — |
| `www.support-mw.gitlab.com` | crt-sh | — |
| `www.support.gitlab.com` | crt-sh | — |
| `www.swedish.chef.gitlab.com` | crt-sh | — |
| `www.sync.geo.gitlab.com` | crt-sh | — |
| `www.triage-serverless.gitlab.com` | crt-sh | — |
| `www.university.gitlab.com` | crt-sh | — |
| `www.version.gitlab.com` | crt-sh | — |

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

_Dedup folded 538 raw observations into 3 grouped findings. Disable with `--no-dedup`._

| # | Severity | Type | Targets | Details |
|---|----------|------|---------|---------|
| 1 | 🔵 low | cidr-discovered | 91.235.46.0/24 | CIDR block discovered via Pius (source: asn-bgp, asn: AS57787) |
| 2 | 🔵 low | http-probe | handbook.gitlab.com | status=200 title="The GitLab Handbook" tech=[Cloudflare, Google Tag Manager, Hugo:0.151.0, OneTrust, Vue.js, cdnjs, jQue |
| 3 | ℹ️ info | subdomain | 536 targets (x536) | discovered via subfinder |

<details><summary>Finding #3 — 536 target(s)</summary>

- `4456656-review-eread-add-z47gmh.design-staging.gitlab.com`
- `www.registry.pre.gitlab.com`
- `4456656-review-markrian-m-2hprzi.design-staging.gitlab.com`
- `4456656-review-todo-issue-mxbz2n.design-staging.gitlab.com`
- `4456656-review-372-button-cu19b4.design-staging.gitlab.com`
- `www.version.gitlab.com`
- `chef.gitlab.com`
- `runners-cache-5.gitlab.com`
- `handbook.gitlab.com`
- `www.dashboards.gitlab.com`
- `www.dr.gitlab.com`
- `opensearch.cell-c01k35wpsh58x0j74g.cells.gitlab.com`
- `4456656-review-danmh-line-602hhc.design-staging.gitlab.com`
- `4456656-review-feat-typog-iods1d.design-staging.gitlab.com`
- `4456656-review-1292-rende-mv55i4.design-staging.gitlab.com`
- `chef12.gitlab.com`
- `4456656-review-main-patch-ahykfo.design-staging.gitlab.com`
- `gprd.gitlab.com`
- `4456656-review-1413-typog-zh5cqo.design-staging.gitlab.com`
- `4456656-review-remove-lin-8gm7r0.design-staging.gitlab.com`
- `4456656-review-1470-pajam-1i3s9p.design-staging.gitlab.com`
- `www.redash.gitlab.com`
- `4456656-review-1204-add-c-a529gy.design-staging.gitlab.com`
- `registry.gke.pre.gitlab.com`
- `prometheus.db-integration.gitlab.com`
- `4456656-review-remove-res-130xbp.design-staging.gitlab.com`
- `4456656-review-main-patch-ibw59q.design-staging.gitlab.com`
- `4456656-review-fix-templa-rmaij2.design-staging.gitlab.com`
- `4456656-review-dropdown-u-xey22m.design-staging.gitlab.com`
- `www.registry.staging.gitlab.com`
- `private-runners-manager-1.gitlab.com`
- `new.docs.gitlab.com`
- `4456656-review-1699-acces-nqqei4.design-staging.gitlab.com`
- `auth.aws.gitlab.com`
- `partners.gitlab.com`
- `4456656-review-main-patch-7zq31d.design-staging.gitlab.com`
- `4456656-review-update-con-flbvjr.design-staging.gitlab.com`
- `www.support.gitlab.com`
- `support.gitlab.com`
- `4456656-review-jeldergl-m-wl40lx.design-staging.gitlab.com`
- `4456656-review-1384-color-9936bf.design-staging.gitlab.com`
- `4456656-review-leipert-sw-gx6s02.design-staging.gitlab.com`
- `jitsu-server.product-analytics.prototype.gitlab.com`
- `redash.gitlab.com`
- `4456656-review-1656-creat-1s3oj9.design-staging.gitlab.com`
- `4456656-review-main-patch-hwu1ap.design-staging.gitlab.com`
- `errortracking.observe.gitlab.com`
- `status.gitlab.com`
- `4456656-review-aregnery-u-87yayz.design-staging.gitlab.com`
- `4456656-review-1454-clean-24ifbs.design-staging.gitlab.com`
- `4456656-review-tooltip-fo-4b3dch.design-staging.gitlab.com`
- `www.prod.geo.gitlab.com`
- `developer.gitlab.com`
- `email.customers.gitlab.com`
- `design.gitlab.com`
- `4456656-review-update-dat-0ptsk3.design-staging.gitlab.com`
- `www.feedback.gitlab.com`
- `altssh.gitlab.com`
- `4456656-review-1462-updat-gnllst.design-staging.gitlab.com`
- `4456656-review-1581-pajam-ux0aky.design-staging.gitlab.com`
- `glchat.prototype.gitlab.com`
- `4456656-review-main-patch-htq0lf.design-staging.gitlab.com`
- `4456656-review-1443-updat-77up3w.design-staging.gitlab.com`
- `4456656-review-1389-skele-4wl4g6.design-staging.gitlab.com`
- `4456656-review-main-patch-la5jps.design-staging.gitlab.com`
- `4456656-review-ui-kit-dep-cjugbw.design-staging.gitlab.com`
- `about-src.gitlab.com`
- `4456656-review-color-pale-e7ltzf.design-staging.gitlab.com`
- `4456656-review-main-patch-uhk064.design-staging.gitlab.com`
- `www.gitlab.com`
- `4456656-review-1444-link-mzm8ta.design-staging.gitlab.com`
- `search.advisories.gitlab.com`
- `www.customers.stg.gitlab.com`
- `www.sync.geo.gitlab.com`
- `customers.gitlab.com`
- `4456656-review-1504-figma-ccev9n.design-staging.gitlab.com`
- `le-4456656.design.gitlab.com`
- `4456656-review-leipert-fi-a93rup.design-staging.gitlab.com`
- `4456656-review-tauriedavi-ngijlf.design-staging.gitlab.com`
- `levelup.gitlab.com`
- `jobs.gitlab.com`
- `runners-cache-3.gitlab.com`
- `ir.gitlab.com`
- `www.license.gitlab.com`
- `docs.gitlab.com`
- `4456656-review-nadia-sotn-e9wgrt.design-staging.gitlab.com`
- `4456656-review-danmh-main-7byn0x.design-staging.gitlab.com`
- `4456656-review-1534-dropd-ybke0g.design-staging.gitlab.com`
- `4456656-review-katiemacoy-6mkyxy.design-staging.gitlab.com`
- `4456656-review-nickleonar-3ymc9c.design-staging.gitlab.com`
- `www.ce.gitlab.com`
- `license.gitlab.com`
- `4456656-review-loadmoregu-u81fud.design-staging.gitlab.com`
- `4456656-review-leipert-ad-yv3s6o.design-staging.gitlab.com`
- `translate.gitlab.com`
- `4456656-review-avoid-cons-9ii5vn.design-staging.gitlab.com`
- `4456656-review-vs-update-l692gb.design-staging.gitlab.com`
- `4456656-review-leipert-de-ukc4pq.design-staging.gitlab.com`
- `4456656-review-bugfix-loc-qvog2t.design-staging.gitlab.com`
- `www.learn.gitlab.com`
- `4456656-review-468-dropdo-tuaw1h.design-staging.gitlab.com`
- `4456656-review-1466-homep-b9nz0w.design-staging.gitlab.com`
- `4456656-review-gl-global-ehsdxl.design-staging.gitlab.com`
- `4456656-review-email-obfu-vz3rnd.design-staging.gitlab.com`
- `4456656-review-pre-code-s-fryi17.design-staging.gitlab.com`
- `4456656-review-372-migrat-fsc737.design-staging.gitlab.com`
- `www.get.gitlab.com`
- `4456656-review-main-patch-43rhv4.design-staging.gitlab.com`
- `4456656-review-russell-ad-4deif2.design-staging.gitlab.com`
- `www.status.gitlab.com`
- `hub.gitlab.com`
- `4456656-review-424-docume-1auq3m.design-staging.gitlab.com`
- `4456656-review-1384-migra-vzug97.design-staging.gitlab.com`
- `4456656-review-1325-vpat-wdbu9w.design-staging.gitlab.com`
- `4456656-review-1466-homep-if4gda.design-staging.gitlab.com`
- `4456656-review-main-patch-t0zk8u.design-staging.gitlab.com`
- `4456656-review-mvanremmer-mxih49.design-staging.gitlab.com`
- `gslink.gitlab.com`
- `alerts.gitlab.com`
- `prometheus.gitlab.com`
- `4456656-review-beckalippe-yi346l.design-staging.gitlab.com`
- `advisories.gitlab.com`
- `prometheus-2.gitlab.com`
- `4456656-review-matejlatin-ht343x.design-staging.gitlab.com`
- `4456656-review-1179-toggl-8ctzom.design-staging.gitlab.com`
- `4456656-review-storybook-hverfl.design-staging.gitlab.com`
- `www.canary.staging.gitlab.com`
- `email.gitlab.com`
- `4456656-review-work-item-z7jn6r.design-staging.gitlab.com`
- `www.hub.gitlab.com`
- `prod.geo.gitlab.com`
- `4456656-review-1688-add-g-4yxtb0.design-staging.gitlab.com`
- `deps.sec.gitlab.com`
- `4456656-review-nadia-sotn-a2gju7.design-staging.gitlab.com`
- `4456656-review-main-patch-wl4twp.design-staging.gitlab.com`
- `4456656-review-update-fea-0m983a.design-staging.gitlab.com`
- `4456656-review-cluster-te-ahlmff.design-staging.gitlab.com`
- `4456656-review-ld-remove-s98iax.design-staging.gitlab.com`
- `contributors.gitlab.com`
- `4456656-review-372-remove-g0vjv5.design-staging.gitlab.com`
- `4456656-review-main-patch-e4eovu.design-staging.gitlab.com`
- `www.canary.gitlab.com`
- `www.gstg.gitlab.com`
- `4456656-review-main-patch-xs3wgn.design-staging.gitlab.com`
- `next.staging.gitlab.com`
- `4456656-review-1468-pajam-z15l6c.design-staging.gitlab.com`
- `4456656-review-main-patch-17vfv3.design-staging.gitlab.com`
- `manager-staging.community.gitlab.com`
- `4456656-review-danmh-add-939zv6.design-staging.gitlab.com`
- `registry.geo.staging-ref.gitlab.com`
- `4456656-review-759-standa-338g48.design-staging.gitlab.com`
- `4456656-review-main-patch-5uc0jr.design-staging.gitlab.com`
- `packages.gitlab.com`
- `4456656-review-dev-1443-u-micvmc.design-staging.gitlab.com`
- `glcodesuggestion.prototype.gitlab.com`
- `4456656-review-nadia-sotn-dfivs2.design-staging.gitlab.com`
- `4456656-review-danmh-base-jxzqod.design-staging.gitlab.com`
- `4456656-review-theoretick-nolo1m.design-staging.gitlab.com`
- `4456656-review-feature-ve-83unpv.design-staging.gitlab.com`
- `geo1.gitlab.com`
- `4456656-review-1524-docs-riq0la.design-staging.gitlab.com`
- `www.rocketchat.gitlab.com`
- `grafana.us-east-1.cell-c01k35wpsh58x0j74g.cells.gitlab.com`
- `4456656-review-nadia-sotn-n2exgz.design-staging.gitlab.com`
- `kas1.pre.gitlab.com`
- `www.geo1.gitlab.com`
- `jitsu-configurator.product-analytics.prototype.gitlab.com`
- `le-2670515.cust-staging.gitlab.com`
- `lb-teleport.gprd.gitlab.com`
- `4456656-review-aregnery-b-jm67v7.design-staging.gitlab.com`
- `cdn.registry.gitlab.com`
- `4456656-review-main-patch-gdpmpv.design-staging.gitlab.com`
- `4456656-review-main-patch-7vaf0e.design-staging.gitlab.com`
- `4456656-review-mnichols1-tpamws.design-staging.gitlab.com`
- `www.plantuml.pre.gitlab.com`
- `federal-support.gitlab.com`
- `canary.staging.gitlab.com`
- `4456656-review-feature-ve-84glmd.design-staging.gitlab.com`
- `4456656-review-1567-add-n-goo7zb.design-staging.gitlab.com`
- `4456656-review-1529-vpat-t9lc7u.design-staging.gitlab.com`
- `staging.gitlab.com`
- `4456656-review-add-radio-thttki.design-staging.gitlab.com`
- `4456656-review-leipert-re-odlobn.design-staging.gitlab.com`
- `4456656-review-sselhorn-m-ujr9vh.design-staging.gitlab.com`
- `4456656-review-figure-img-csecdr.design-staging.gitlab.com`
- `4456656-review-aregnery-s-qu3sap.design-staging.gitlab.com`
- `4456656-review-nadia-sotn-344w7f.design-staging.gitlab.com`
- `events.gitlab.com`
- `4456656-review-main-patch-5jw3b1.design-staging.gitlab.com`
- `design-staging.gitlab.com`
- `aptly.gitlab.com`
- `pre-puma.gitlab.com`
- `doc.gitlab.com`
- `4456656-review-decrease-f-yjhr8g.design-staging.gitlab.com`
- `4456656-review-jeldergl-m-6ft9af.design-staging.gitlab.com`
- `www.alerts.gitlab.com`
- `www.support-mw.gitlab.com`
- `api-staging.community.gitlab.com`
- `staging-ref.gitlab.com`
- `cloud.staging.gitlab.com`
- `www.forum.gitlab.com`
- `2670515-review-enable-aut-a96d5t.cust-staging.gitlab.com`
- `pre.gitlab.com`
- `prometheus-db.db-integration.gitlab.com`
- `4456656-review-kbd-styles-3wqnci.design-staging.gitlab.com`
- `4456656-review-sselhorn-m-iu1n63.design-staging.gitlab.com`
- `4456656-review-1623-creat-6s0twl.design-staging.gitlab.com`
- `4456656-review-sselhorn-m-fv9x5d.design-staging.gitlab.com`
- `4456656-review-1398-typog-54o4di.design-staging.gitlab.com`
- `o1.ptr3386.mx.gitlab.com`
- `4456656-review-update-nav-ztnp39.design-staging.gitlab.com`
- `www.chef.gitlab.com`
- `4456656-review-fix-punctu-7gmkwg.design-staging.gitlab.com`
- `registry.cell-c01k35wpsh58x0j74g.cells.gitlab.com`
- `go.gitlab.com`
- `scim.gitlab.com`
- `4456656-review-viewcompon-kkveh5.design-staging.gitlab.com`
- `4456656-review-update-ske-mudp9g.design-staging.gitlab.com`
- `www.customers.gitlab.com`
- `campaign-manager.gitlab.com`
- `4456656-review-main-patch-f6fk1y.design-staging.gitlab.com`
- `4456656-review-fix-broken-484psj.design-staging.gitlab.com`
- `4456656-review-link-updat-3hh8ij.design-staging.gitlab.com`
- `single.gitlab.com`
- `swedish.chef.gitlab.com`
- `4456656-review-1601-creat-6facx9.design-staging.gitlab.com`
- `4456656-review-feat-add-d-6hvldh.design-staging.gitlab.com`
- `4456656-review-16-1-ui-ki-igmj3o.design-staging.gitlab.com`
- `4456656-review-loadmore-53edp1.design-staging.gitlab.com`
- `cell-c01j2gdw0zfdafxr6.cells.gitlab.com`
- `about.gitlab.com`
- `4456656-review-msj-gitlab-51lnju.design-staging.gitlab.com`
- `4456656-review-popover-gu-1s8esd.design-staging.gitlab.com`
- `4456656-review-monica-gal-s5wit4.design-staging.gitlab.com`
- `support-mw.gitlab.com`
- `4456656-review-ui-kit-rel-zkqdli.design-staging.gitlab.com`
- `4456656-review-main-patch-tge44a.design-staging.gitlab.com`
- `4456656-review-pgascouvai-1f4bo8.design-staging.gitlab.com`
- `app-staging.community.gitlab.com`
- `4456656-review-main-patch-mj74wu.design-staging.gitlab.com`
- `www.prometheus-3.gitlab.com`
- `registry.pre.gitlab.com`
- `cdn.registry.pre.gitlab.com`
- `private-runners-manager-4.gitlab.com`
- `4456656-review-16-3-figma-9mwtgl.design-staging.gitlab.com`
- `www.page.gitlab.com`
- `www.runners-cache-2.gitlab.com`
- `cloud.gitlab.com`
- `kas.gitlab.com`
- `4456656-review-372-founda-5ok9gh.design-staging.gitlab.com`
- `4456656-review-leipert-sv-zlo2if.design-staging.gitlab.com`
- `runners-cache-4.gitlab.com`
- `4456656-review-main-patch-vs8cmm.design-staging.gitlab.com`
- `4456656-review-aregnery-a-q3q5lo.design-staging.gitlab.com`
- `4456656-review-main-patch-hw74zf.design-staging.gitlab.com`
- `4456656-review-main-patch-jyt49u.design-staging.gitlab.com`
- `analytics.gitlab.com`
- `geo.staging-ref.gitlab.com`
- `4456656-review-sselhorn-m-ygc05a.design-staging.gitlab.com`
- `4456656-review-add-variou-c2yklh.design-staging.gitlab.com`
- `biz.gitlab.com`
- `www.about.gitlab.com`
- `shop.gitlab.com`
- `4456656-review-sselhorn-m-ulzly1.design-staging.gitlab.com`
- `4456656-review-ai-guidanc-9p86nm.design-staging.gitlab.com`
- `errortracking.staging.observe.gitlab.com`
- `www.runners-cache-3.gitlab.com`
- `do158-143.mg.gitlab.com`
- `4456656-review-1457-resol-ux5ml2.design-staging.gitlab.com`
- `4456656-review-1526-updat-cnlkd8.design-staging.gitlab.com`
- `sync.geo.gitlab.com`
- `4456656-review-620-preven-sgkdey.design-staging.gitlab.com`
- `4456656-review-update-neu-l9jugi.design-staging.gitlab.com`
- `4456656-review-167-fix-br-ka1mjc.design-staging.gitlab.com`
- `4456656-review-leipert-me-2kf6ib.design-staging.gitlab.com`
- `www.kas.staging.gitlab.com`
- `cert-test.staging.gitlab.com`
- `4456656-review-helping-us-ab9za1.design-staging.gitlab.com`
- `4456656-review-main-patch-akmp1u.design-staging.gitlab.com`
- `4456656-review-1442-dropd-pel4gp.design-staging.gitlab.com`
- `4456656-review-main-patch-h5jvmx.design-staging.gitlab.com`
- `4456656-review-danmh-link-zzbmci.design-staging.gitlab.com`
- `chat.gitlab.com`
- `4456656-review-katiemacoy-6kowxh.design-staging.gitlab.com`
- `4456656-review-leipert-in-fn9qbu.design-staging.gitlab.com`
- `4456656-review-leipert-te-1f4hg0.design-staging.gitlab.com`
- `4456656-review-main-patch-6j8uwc.design-staging.gitlab.com`
- `4456656-review-init-ui-ki-9s5r7x.design-staging.gitlab.com`
- `4456656-review-1435-comma-5x5076.design-staging.gitlab.com`
- `cell-c01k35wpsh58x0j74g.cells.gitlab.com`
- `metrics.gitlab.com`
- `4456656-review-leipert-fi-8xvt9u.design-staging.gitlab.com`
- `4456656-review-main-patch-9ymnv2.design-staging.gitlab.com`
- `cxr.gitlab.com`
- `4456656-review-russell-im-mr165k.design-staging.gitlab.com`
- `4456656-review-1384-migra-hi3gz1.design-staging.gitlab.com`
- `grafana.cell-c01k35wpsh58x0j74g.cells.gitlab.com`
- `4456656-review-jeldergl-m-94oflr.design-staging.gitlab.com`
- `4456656-review-matejlatin-c5v5u3.design-staging.gitlab.com`
- `4456656-review-1568-creat-9zjn0e.design-staging.gitlab.com`
- `get.gitlab.com`
- `4456656-review-gitlab-ui-l35n7g.design-staging.gitlab.com`
- `4456656-review-amittner-m-nerl7d.design-staging.gitlab.com`
- `4456656-review-do-not-for-pzqdfc.design-staging.gitlab.com`
- `4456656-review-1345-story-efzw0t.design-staging.gitlab.com`
- `4456656-review-1455-clean-4futx0.design-staging.gitlab.com`
- `www.university.gitlab.com`
- `4456656-review-navigation-qlpoi0.design-staging.gitlab.com`
- `4456656-review-fix-dropdo-pxfde4.design-staging.gitlab.com`
- `www.docs.gitlab.com`
- `customers.staging-ref.gitlab.com`
- `4456656-review-msj-extern-e112lv.design-staging.gitlab.com`
- `4456656-review-1578-updat-j6nklw.design-staging.gitlab.com`
- `www.jobs.gitlab.com`
- `registry.gke.gstg.gitlab.com`
- `next.gitlab.com`
- `runners-cache-1.gitlab.com`
- `customers.staging.gitlab.com`
- `page.gitlab.com`
- `4456656-review-link-mh9siw.design-staging.gitlab.com`
- `4456656-review-beckalippe-9ayot8.design-staging.gitlab.com`
- `4456656-review-danmh-main-c1cmm0.design-staging.gitlab.com`
- `groove.gitlab.com`
- `4456656-review-15-11-fig-lodxco.design-staging.gitlab.com`
- `4456656-review-monica-gal-3qi8ge.design-staging.gitlab.com`
- `4456656-review-matejlatin-77kun7.design-staging.gitlab.com`
- `feedback.gitlab.com`
- `4456656-review-1471-updat-bl7fl4.design-staging.gitlab.com`
- `mr-sidebar.prototype.gitlab.com`
- `le-4456656.design-staging.gitlab.com`
- `4456656-review-danmh-main-8m9u8a.design-staging.gitlab.com`
- `4456656-review-main-patch-1axc6b.design-staging.gitlab.com`
- `gateway.gcp.gitlab.com`
- `4456656-review-matejlatin-myrk4n.design-staging.gitlab.com`
- `observe.gitlab.com`
- `enable.gitlab.com`
- `canary.gitlab.com`
- `4456656-review-leipert-so-fnmdgi.design-staging.gitlab.com`
- `4456656-review-main-patch-09hgox.design-staging.gitlab.com`
- `www.ee.gitlab.com`
- `kas.cell-c01k35wpsh58x0j74g.cells.gitlab.com`
- `4456656-review-sticky-hea-muxkb0.design-staging.gitlab.com`
- `4456656-review-docs-headi-iwghf9.design-staging.gitlab.com`
- `4456656-review-yarn-tool-9v2qz8.design-staging.gitlab.com`
- `4456656-review-danmh-labe-7m5eaz.design-staging.gitlab.com`
- `4456656-review-main-patch-0hbs2y.design-staging.gitlab.com`
- `geo.staging.gitlab.com`
- `auth.gitlab.com`
- `www.prometheus.gitlab.com`
- `ci.gitlab.com`
- `4456656-review-1464-add-p-jxfmxs.design-staging.gitlab.com`
- `4456656-review-monica-gal-oepnqj.design-staging.gitlab.com`
- `4456656-review-dmoraberli-v9tcck.design-staging.gitlab.com`
- `4456656-review-main-patch-pdbsbv.design-staging.gitlab.com`
- `4456656-review-danmh-ui-k-1zf7up.design-staging.gitlab.com`
- `4456656-review-fix-main-a8e81c.design-staging.gitlab.com`
- `4456656-review-1107-add-e-53243j.design-staging.gitlab.com`
- `4456656-review-better-err-r52kcp.design-staging.gitlab.com`
- `www.prometheus-2.gitlab.com`
- `about.staging.gitlab.com`
- `4456656-review-main-patch-dtq903.design-staging.gitlab.com`
- `4456656-review-feat-add-n-atvmbp.design-staging.gitlab.com`
- `runners-cache-2.gitlab.com`
- `prometheus-3.gitlab.com`
- `partnerflash.gitlab.com`
- `4456656-review-spacing-ex-nrw7ke.design-staging.gitlab.com`
- `4456656-review-main-patch-uanp44.design-staging.gitlab.com`
- `www.geo2.gitlab.com`
- `www.aptly.gitlab.com`
- `kas.pre.gitlab.com`
- `registry.gitlab.com`
- `prometheus-app.db-integration.gitlab.com`
- `4456656-review-526-add-co-hhd4pd.design-staging.gitlab.com`
- `4456656-review-nadia-sotn-oz459g.design-staging.gitlab.com`
- `4456656-review-replace-re-ozvga7.design-staging.gitlab.com`
- `4456656-review-fix-lockfi-xfj7fu.design-staging.gitlab.com`
- `www.federal-support.gitlab.com`
- `registry.staging.gitlab.com`
- `www.runners-cache-4.gitlab.com`
- `4456656-review-main-patch-t8812x.design-staging.gitlab.com`
- `4456656-review-feat-add-i-jfatva.design-staging.gitlab.com`
- `4456656-review-rayana-mai-8n3oyd.design-staging.gitlab.com`
- `4456656-review-1443-updat-pod18c.design-staging.gitlab.com`
- `4456656-review-typo-doc-j-9vr37q.design-staging.gitlab.com`
- `cdn.registry.staging.gitlab.com`
- `4456656-review-1371-illus-zin06c.design-staging.gitlab.com`
- `cinc.gitlab.com`
- `4456656-review-update-ban-zn4m0o.design-staging.gitlab.com`
- `archives.docs.gitlab.com`
- `runway-ci-test-4jpyc3.staging.runway.gitlab.com`
- `4456656-review-mle-settin-mgne7n.design-staging.gitlab.com`
- `4456656-review-v-mishra-m-4agh3r.design-staging.gitlab.com`
- `go-staging.community.gitlab.com`
- `lb-teleport.gstg.gitlab.com`
- `observe.staging.gitlab.com`
- `dast-4456656-dast-default.design-staging.gitlab.com`
- `staging.observe.gitlab.com`
- `university.gitlab.com`
- `4456656-review-v-mishra-m-674soo.design-staging.gitlab.com`
- `private-runners-manager-3.gitlab.com`
- `4456656-review-annabeldun-yva22z.design-staging.gitlab.com`
- `4456656-review-leipert-pi-ylw4l9.design-staging.gitlab.com`
- `4456656-review-main-patch-fh2a11.design-staging.gitlab.com`
- `4456656-review-fix-broken-qybukn.design-staging.gitlab.com`
- `registry.gke.staging.gitlab.com`
- `4456656-review-1445-merma-izi4nv.design-staging.gitlab.com`
- `4456656-review-refactor-c-ilw0zv.design-staging.gitlab.com`
- `www.about-src.gitlab.com`
- `4456656-review-1249-evalu-o3ym8w.design-staging.gitlab.com`
- `4456656-review-lvanc-main-vhyovi.design-staging.gitlab.com`
- `4456656-review-update-str-dw8cuz.design-staging.gitlab.com`
- `www.shop.gitlab.com`
- `4456656-review-1474-butto-9dliu5.design-staging.gitlab.com`
- `4456656-review-1682-creat-k9e7cn.design-staging.gitlab.com`
- `chef2.gitlab.com`
- `www.runners-cache-5.gitlab.com`
- `content.gitlab.com`
- `gstg.gitlab.com`
- `4456656-review-editaction-iyfa0g.design-staging.gitlab.com`
- `4456656-review-gdoyle-mai-ydq5be.design-staging.gitlab.com`
- `www.next.staging.gitlab.com`
- `ee.gitlab.com`
- `api.community.gitlab.com`
- `4456656-review-update-tab-d7o120.design-staging.gitlab.com`
- `4456656-review-figma-chan-m8wo3e.design-staging.gitlab.com`
- `4456656-review-update-com-fl3uox.design-staging.gitlab.com`
- `ce.gitlab.com`
- `4456656-review-lookbook-e-vm97y9.design-staging.gitlab.com`
- `bogus.staging.gitlab.com`
- `4456656-review-main-patch-ukqrqf.design-staging.gitlab.com`
- `internal.gitlab.com`
- `www.next.gitlab.com`
- `prometheus.staging-ref.gitlab.com`
- `auth.staging.gitlab.com`
- `piwik.gitlab.com`
- `4456656-review-aregnery-r-sii6ch.design-staging.gitlab.com`
- `4456656-review-1702-creat-qe3vkr.design-staging.gitlab.com`
- `www.packages.gitlab.com`
- `deps.staging.sec.gitlab.com`
- `4456656-review-aregnery-t-k27a4t.design-staging.gitlab.com`
- `4456656-review-gt-update-7ocwl1.design-staging.gitlab.com`
- `dr.gitlab.com`
- `triage-serverless.gitlab.com`
- `4456656-review-jeldergl-m-i8pqtg.design-staging.gitlab.com`
- `4456656-review-settings-d-76bn45.design-staging.gitlab.com`
- `www.pre.gitlab.com`
- `explore.gitlab.com`
- `customers.stg.gitlab.com`
- `4456656-review-update-ui-qkugqu.design-staging.gitlab.com`
- `plantuml.pre.gitlab.com`
- `app.community.gitlab.com`
- `4456656-review-katiemacoy-9w1w8o.design-staging.gitlab.com`
- `registry.staging-ref.gitlab.com`
- `4456656-review-1686-follo-54znci.design-staging.gitlab.com`
- `www.staging.gitlab.com`
- `blog.gitlab.com`
- `auth.gcp.gitlab.com`
- `gitlab-org-gitlab-services-design-gitlab-com.design.gitlab.com`
- `4456656-review-monica-gal-pz78s2.design-staging.gitlab.com`
- `forum.gitlab.com`
- `4456656-review-sselhorn-m-cp6hbg.design-staging.gitlab.com`
- `static-objects.staging.gitlab.com`
- `slippers.gitlab.com`
- `4456656-review-vs-fix-cod-r1wbfx.design-staging.gitlab.com`
- `www.triage-serverless.gitlab.com`
- `rocketchat.gitlab.com`
- `4456656-review-fix-socks-qqsw5a.design-staging.gitlab.com`
- `4456656-review-danmh-figm-ecofo8.design-staging.gitlab.com`
- `4456656-review-main-patch-6yplki.design-staging.gitlab.com`
- `4456656-review-glpathupda-ppzo2c.design-staging.gitlab.com`
- `4456656-review-16-2-fig-b-vkcmpy.design-staging.gitlab.com`
- `4456656-review-add-refere-m150sn.design-staging.gitlab.com`
- `4456656-review-russell-do-9o5hdr.design-staging.gitlab.com`
- `4456656-review-katiemacoy-28xw6w.design-staging.gitlab.com`
- `4456656-review-danmh-main-l30vd9.design-staging.gitlab.com`
- `4456656-review-frontend-o-k89w9g.design-staging.gitlab.com`
- `www.registry.gitlab.com`
- `4456656-review-jlouw-fix-3hbdqy.design-staging.gitlab.com`
- `4456656-review-leipert-fi-b4f198.design-staging.gitlab.com`
- `4456656-review-add-variou-c1mz21.design-staging.gitlab.com`
- `4456656-review-tool-versi-qskle9.design-staging.gitlab.com`
- `4456656-review-1527-type-0ahnvf.design-staging.gitlab.com`
- `www.piwik.gitlab.com`
- `4456656-review-switchover-i4ueoq.design-staging.gitlab.com`
- `cocreate.gitlab.com`
- `4456656-review-v-mishra-m-1iu2rs.design-staging.gitlab.com`
- `4456656-review-mle-guidan-6dcfz1.design-staging.gitlab.com`
- `4456656-review-stepper-jyhpg9.design-staging.gitlab.com`
- `www.contributors.gitlab.com`
- `opensearch.us-east-1.cell-c01k35wpsh58x0j74g.cells.gitlab.com`
- `4456656-review-1365-dropd-gp25pd.design-staging.gitlab.com`
- `4456656-review-1369-color-ccob8j.design-staging.gitlab.com`
- `4456656-review-alert-upda-7zeoqy.design-staging.gitlab.com`
- `4456656-review-pedroms-ma-qh0b5c.design-staging.gitlab.com`
- `4456656-review-main-patch-p5v4z5.design-staging.gitlab.com`
- `4456656-review-main-patch-z106gz.design-staging.gitlab.com`
- `4456656-review-pedroms-ma-b2xv0l.design-staging.gitlab.com`
- `4456656-review-372-cleanu-gim0da.design-staging.gitlab.com`
- `learn.gitlab.com`
- `4456656-review-1532-fix-a-vslnpm.design-staging.gitlab.com`
- `4456656-review-sam-figuer-w6w8ie.design-staging.gitlab.com`
- `deps-review.sec.gitlab.com`
- `4456656-review-lvanc-feat-c4vnls.design-staging.gitlab.com`
- `4456656-review-1569-desig-pt069r.design-staging.gitlab.com`
- `4456656-review-main-patch-br77mb.design-staging.gitlab.com`
- `4456656-review-matejlatin-0424qa.design-staging.gitlab.com`
- `4456656-review-1517-dropd-biebor.design-staging.gitlab.com`
- `www.runners-cache-1.gitlab.com`
- `dashboards.gitlab.com`
- `glchatvertex.prototype.gitlab.com`
- `www.swedish.chef.gitlab.com`
- `codesuggestions.gitlab.com`
- `4456656-review-cam-x-main-r0jpo8.design-staging.gitlab.com`
- `4456656-review-update-inf-chsgkf.design-staging.gitlab.com`
- `4456656-review-codeowners-98nl8j.design-staging.gitlab.com`
- `grafana.amp.cells.gitlab.com`
- `www.blog.gitlab.com`
- `ai-gateway-eks.cloud.gitlab.com`
- `4456656-review-167-broken-qj1ysq.design-staging.gitlab.com`
- `www.chat.gitlab.com`
- `host.gitlab.com`
- `4456656-review-1515-broke-hy4xvx.design-staging.gitlab.com`
- `4456656-review-update-key-t4ghhd.design-staging.gitlab.com`
- `runway.gitlab.com`
- `kas.us-east-1.cell-c01k35wpsh58x0j74g.cells.gitlab.com`
- `geo2.gitlab.com`
- `shared-runners-manager-4.gitlab.com`
- `4456656-review-migrate-gl-towhzq.design-staging.gitlab.com`
- `4456656-review-main-patch-zcjz2f.design-staging.gitlab.com`
- `4456656-review-russell-ad-rs1ci4.design-staging.gitlab.com`
- `www.gprd.gitlab.com`
- `www.ci.gitlab.com`
- `triage-ops.gitlab.com`
- `version.gitlab.com`
- `4456656-review-sselhorn-m-5og57p.design-staging.gitlab.com`
- `kas.staging.gitlab.com`

</details>

---

## Methodology

A small LLM running locally on Lemonade Server (AMD Ryzen AI, Qwen3-1.7B) drives a ReAct loop with intelligent step skipping: it reasons about whether each tool is worth running based on the prior tool's output. Scope allowlist enforces a glob-based target filter on every host before the tool spawns. Rate limiting inserts a floor between iterations.

Tool chain executed this run:

- `subfinder` — passive subdomain enumeration
- `httpx` — live HTTP probe (status, title, tech detect, JSON output)

## Step Detail

### Iteration 1 — subfinder

**Args:** `{"domain":"gitlab.com"}`

**Preview:**

```
4456656-review-eread-add-z47gmh.design-staging.gitlab.com
www.registry.pre.gitlab.com
4456656-review-markrian-m-2hprzi.design-staging.gitlab.com
4456656-review-todo-issue-mxbz2n.design-staging.gitlab.com
4456656-review-372-button-cu19b4.design-staging.gitlab.com
www.version.gitlab.com
chef.gitlab.com
runners-cache-5.gitlab.com
handbook.gitlab.com
www.dashboards.gitlab.com
www.dr.gitlab.com
opensearch.cell-c01k35wpsh58x0j74g.cells.gitlab.com
4456656-review-danmh-line-602hhc.design-staging.gitlab.com
4456656-review-feat-typog-iods1d.design-staging.gitlab.com
4456656-review-1292-rende-mv55i4.design-staging.gitlab.com
chef12.gitlab.com
4456656-review-main-patch-ahykfo.design-staging.gitlab.com
gprd.gitlab.com
4456656-review-1413-typog-zh5cqo.design-staging.gitlab.com
4456656-review-remove-lin-8gm7r0.design-staging.gitlab.com
4456656-review-1470-pajam-1i3s9p.design-staging.gitlab.com
www.redash.gitlab.com
4456656-review-1204-add-c-a529gy.design-staging.gitlab.com
registry.gke.pre.gitlab.com
prometheus.db-integration.gitlab.com
```

### Iteration 2 — httpx

**Args:** `{"hosts_from":"subfinder"}`

**Preview:**

```
{"timestamp":"2026-04-16T18:56:05.982079989-04:00","cdn_name":"google","cdn_type":"cdn","port":"443","url":"https://handbook.gitlab.com","input":"handbook.gitlab.com","title":"The GitLab Handbook","scheme":"https","content_type":"text/html","method":"GET","host":"handbook.gitlab.com","host_ip":"2600:1901:0:7b8a::","path":"/","time":"808.047765ms","a":["35.185.44.232"],"aaaa":["2600:1901:0:7b8a::"],"cname":["gitlab-com.gitlab.io"],"tech":["Cloudflare","Google Tag Manager","Hugo:0.151.0","OneTrust","Vue.js","cdnjs","jQuery CDN","jQuery:3.7.1","jsDelivr"],"words":7431,"lines":599,"status_code":200,"content_length":55244,"failed":false,"cdn":true,"knowledgebase":{"pHash":0},"resolvers":["127.0.0.53:53"],"cpe":[{"product":"gitlab","vendor":"gitlab","cpe":"cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*"},{"product":"gitlab_hook","vendor":"jenkins","cpe":"cpe:2.3:a:jenkins:gitlab_hook:*:*:*:*:*:*:*:*"},{"product":"webp_server_go","vendor":"webp","cpe":"cpe:2.3:a:webp:webp_server_go:*:*:*:*:*:*:*:*"},{"product":"element","vendor":"matrix","cpe":"cpe:2.3:a:matrix:element:*:*:*:*:*:*:*:*"}]}
```

### Iteration 3 — nuclei

**Args:** `{"urls_from":"httpx"}`

**Error:** no curated nuclei template dirs exist under /home/raz/nuclei-templates

### Iteration 4 — done

---

## Recommended Next Steps

- Install nuclei templates
- Reattempt scan

---

_Generated by AgentSpyBoo Phase 3 (CPU-track + Pius preflight) — https://github.com/Peterc3-dev (private)_

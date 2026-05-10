# AgentSpyBoo — Research Brief

**Initial research:** April 12, 2026
**Honesty pass:** April 14, 2026

## What this is

A Rust-based AI red team agent targeting AMD Ryzen AI hardware. Currently runs a multi-step ReAct loop on CPU via a local OpenAI-compatible LLM server (Lemonade / llama.cpp). The NPU inference path (the original headline ambition) is parked on a hardware-side driver blocker documented in `PHASE-2-RECON.md`.

Framed honestly: **a CPU-path Rust pentest agent that targets NPU inference as a deferred goal.**

## Gap analysis (caveated)

As of early April 2026, a public search across GitHub, arXiv, Black Hat and DEF CON turned up **no published project combining Rust + AMD NPU + autonomous pentesting**. Most autonomous-pentesting work sits in Python with cloud LLM backends.

That said, AgentSpyBoo does **not currently** combine these three. It combines Rust + CPU + pentesting today. The NPU intersection remains open as a research target, not a closed achievement.

## Current architecture (as of Phase 2 CPU-track)

- **LLM backend:** OpenAI-compatible HTTP API. Tested against Lemonade Server running Qwen3-1.7B-GGUF via llama.cpp on CPU. Should work with any compatible server (Ollama, vLLM, etc.) but only Lemonade is exercised.
- **Model:** `Qwen3-1.7B-GGUF` for orchestration. Chosen for its strong tool-calling performance at small size (see benchmark notes below).
- **Rust crates:** `tokio`, `clap`, `serde`, `serde_json`, `reqwest`, `anyhow`, `chrono`. One flat `src/main.rs` (~1200 lines) per the architectural decision in `PHASE-1.5-NOTES.md`.
- **Tool chain wired:** `subfinder` → `httpx` → `nuclei` (curated template subset, `-severity medium,high,critical`).
- **Tool chain planned but unwired:** `naabu`, `ffuf`, `gau`, `findomain`, `rustscan`, `nmap`. Scaffold files exist under `src/tools/` but are not compiled.
- **Findings:** JSON files in `findings/`, severity-rated (info/low/medium/high/critical).
- **Reports:** Markdown in `reports/`, structured to match the ai-redteam-reports style (Executive Summary, Findings Table, Methodology, Step Detail, Recommended Next Steps).
- **Scope & rate limits:** `--scope` glob allowlist (default `<target>,*.<target>`), `--rate-limit` between iterations (default 500ms), `--httpx-cap` for wildcard pollution protection (default 150).

## Target hardware

- **GPD Pocket 4** — AMD Ryzen AI 9 HX 370 (Strix Point), Radeon 890M iGPU (gfx1150), XDNA 2 NPU (50 TOPS rated), 32 GB unified memory
- **Physical:** ~770 g handheld, built-in 2.5 GbE, optional 4G LTE module, optional RS-232 module
- Current state: CPU inference via llama.cpp runs at ~77 tok/s generation on this chip. NPU path is parked.

## NPU backend research (deferred)

The originally researched NPU path uses **FastFlowLM** — an NPU-native Ollama-style runtime with an OpenAI-compatible API, ~16 MB binary, Linux support added March 2026.

Published FastFlowLM benchmarks (Qwen3.5 decode throughput, at 1k context, on **Ryzen AI 7 350 Kraken Point** — a different Ryzen AI variant in the same XDNA 2 family as the HX 370):

| Model | Decode TPS (1k) | Decode TPS (4k) | Decode TPS (32k) |
|---|---|---|---|
| Qwen3.5 0.8B | 39.2 | 36.3 | 21.6 |
| Qwen3.5 2B | 26.8 | 25.4 | 17.0 |
| Qwen3.5 4B | 15.0 | 14.2 | 9.6 |
| Qwen3.5 9B | 9.3 | 9.0 | 6.9 |

Llama 3.2 3B on the same hardware: **26.3 TPS at 1k context** (published FastFlowLM benchmark).

**Caveat:** these are Kraken Point numbers, not Strix Point (HX 370). Expect broadly similar but not identical performance on the GPD's chip once the NPU path is unblocked. Also: these are published vendor benchmarks, not independently reproduced on this hardware.

### Rust → NPU bridge (deferred)

- **`ort` crate v2.0.0-rc.12** exposes a `vitis` Cargo feature for dispatching ONNX Runtime inference to AMD's Vitis AI Execution Provider. Requires an ONNX Runtime build with Vitis AI EP compiled in (from AMD's Ryzen AI Software SDK).
- **Alternative:** skip the direct Rust-to-NPU bridge entirely and talk to FastFlowLM's REST API from Rust via `reqwest`. Avoids the fragile Vitis AI EP build chain at the cost of a local HTTP hop.

### Linux state (as of April 14, 2026)

- **amdxdna kernel driver** mainlined in Linux 6.14 (early 2025)
- **On CachyOS (kernel 6.19.12)**: `fastflowlm 0.9.38` ships in the official `extra` repo. `xrt-smi` and `xrt-plugin-amdxdna` are also packaged.
- **Current blocker:** the amdxdna driver loads but fails to bind to the NPU at `0000:c6:00.1` with `aie2_smu_init: Access power failed, ret -22`. `/dev/accel` stays empty. Likely root causes (in order): GPD BIOS 2.10 doesn't enable NPU PSP fuses, missing firmware blob `17f0_20` in `/lib/firmware/amdnpu/`, or a kernel regression in 6.19.x. See `PHASE-2-RECON.md`.
- **Ubuntu 24.04**: Vitis AI EP builds fail due to GCC 13/14 incompatibilities. Workaround distros (like CachyOS/Arch) have better packaging but hit the same hardware blocker.

## Existing autonomous pentest agents (for context)

A non-exhaustive scan of what exists in April 2026. All are Python, all depend on cloud LLMs or large self-hosted GPU inference, none target NPU hardware, and none are written in Rust.

| Project | Language | Backend | Notable |
|---|---|---|---|
| **Shannon** (KeygraphHQ) | Python | Anthropic Claude (3.5 Sonnet recommended) | 96.15% on hint-free XBOW (100/104), white-box source-aware mode, released early 2026, ~10k+ stars |
| **PentestGPT** (GreyDGL) | Python | Cloud LLMs | 86.5% on XBOW (90/104), USENIX Security 2024 w/ Distinguished Artifact Award, ~12.5k stars |
| **PentAGI** (vxcontrol) | Python | Cloud + local (Ollama) | Multi-agent, Docker sandbox, ~20 tools, ~3k stars |
| **CAI** (Alias Robotics) | Python | Cloud / alias1 | Claims 3,600× faster than humans on **"very easy"** CTF tasks; honest reading: 799× on very easy, 11× on medium, **0.91× on hard**, **0.65× on insane** — underperforms humans on harder tasks |
| **pentest-ai** (various) | Python | MCP-based | 150+ tools |
| **XBOW, Penligent, Terra** | closed | Cloud SaaS | Commercial |

## Why Rust + (eventually) NPU matters for this specific use case

Not "it's faster in a vacuum," because for most pentest workloads the bottleneck is external tool execution, not orchestration language. The real benefits are shape-specific:

1. **Single-binary deploy** — a pentest agent you drop on a constrained box without a Python runtime, pip environment, or version conflicts.
2. **Long-running daemon stability** — deterministic memory model, no GC spikes, predictable behavior on battery.
3. **Cross-compile to weird targets** — ARM64 dropboxes, RISC-V, Android shells, embedded.
4. **FFI to native libraries** — cleaner integration with ONNX Runtime, libcurl, libpcap, than Python's ctypes.
5. **Memory safety with untrusted input** — pentest agents parse hostile responses; Rust removes a class of bugs that bit Python scanners historically.

The NPU angle is additive: **air-gap deployability** for environments where cloud AI is categorically forbidden (SCIF / classified, SCADA/ICS under NERC CIP, nuclear facilities under 10 CFR 73.54, GDPR-constrained EU data). These are real markets that cloud-dependent SaaS agents cannot serve, regardless of quality. A handheld Rust agent running local NPU inference would be the first option in that niche.

**This is a justification for the direction, not a claim of current capability.** AgentSpyBoo today is CPU-path only.

## Phase status (as of 2026-04-14)

| Phase | State | Notes |
|---|---|---|
| Phase 1 (MVP) | ✅ Shipped | Single-shot ReAct loop, one tool, end-to-end on GPD. Commit `8ab559a` on public `main`. |
| Phase 1.5 | ✅ Shipped locally | Multi-step loop, 2 tools, findings + reports. On private `phase-1.5` branch. |
| Phase 2 CPU | ✅ Shipped locally | 3 tools wired, scope guards, severity, report format polish. On private `phase-2-cpu` branch. Nuclei timeout remains a rough edge. |
| Phase 2 NPU | ⛔ Parked | Hardware blocker: amdxdna SMU probe failure on kernel 6.19.12. See `PHASE-2-RECON.md`. Waits on BIOS update, firmware blob, or kernel regression fix. |
| Phase 2.5 (refactor) | ⏸ Deferred | Per `PHASE-1.5-NOTES.md`: port flat `main.rs` into scaffold modules only after Phase 2 completes or `main.rs` crosses ~1500 lines. |

## Sources consulted

This brief was assembled from a combination of original research (April 12) and a fact-check pass (April 14). Cross-references:

- FastFlowLM benchmarks: published on `fastflowlm.com/docs/benchmarks/qwen3.5_results/` and `llama3_results/`
- Qwen3-1.7B tool-calling benchmark: `github.com/MikeVeerman/tool-calling-benchmark`
- Shannon XBOW result: `github.com/KeygraphHQ/shannon` — white-box source-aware variant, 100/104
- PentestGPT USENIX 2024 paper: `usenix.org/conference/usenixsecurity24/presentation/deng`
- CAI speedup claims: Alias Robotics `news.aliasrobotics.com` / arXiv paper 2504.06017, detailed breakdown via `socket.dev`
- amdxdna driver kernel state: `PHASE-2-RECON.md` in this repo
- ort crate `vitis` feature: verified in `ort` crate v2.0.0-rc.12 Cargo.toml on GitHub

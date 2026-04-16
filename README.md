# AgentSpyBoo

A Rust-based AI red team agent that runs a multi-step ReAct loop against a local OpenAI-compatible LLM server. Targets AMD Ryzen AI hardware (CPU-path today; NPU driver unblocked, inference runtime blocked — see [`PHASE-2-RECON.md`](PHASE-2-RECON.md)).

## Current state

- **Branch `main`**: Phase 2 CPU + Phase 2.5 refactor — multi-step ReAct loop, three chained tools (`subfinder` → `httpx` → `nuclei`), scope guards, severity-rated findings with dedup, structured Markdown reports, modular `src/` layout.
- **Phase 3** (next): org-level recon via [Pius](https://github.com/pius-scout/pius) as a preflight step before the existing tool chain. Adds `--org` and `--asn` flags.

## Architecture

- **Loop**: Observe → Think → Act. The LLM sees three tools, picks one per iteration, we run it, feed results back, repeat until the LLM decides to summarize.
- **LLM backend**: OpenAI-compatible chat completion API. Tested against [Lemonade Server](https://github.com/lemonade-sdk/lemonade) running `Qwen3-1.7B-GGUF` via llama.cpp on CPU. Any compatible server should work (Ollama, vLLM, etc.) but only Lemonade is exercised.
- **Tool chain**: `subfinder` → `httpx` → `nuclei` (curated templates, `-severity medium,high,critical`). Scope-guarded: every discovered host is checked against the `--scope` glob before being passed to the next tool.
- **Findings**: JSON files under `findings/`, severity-rated (info/low/medium/high/critical), deduplicated across iterations.
- **Reports**: Markdown under `reports/`, structured with Executive Summary, Findings Table, Methodology, Step Detail, Recommended Next Steps.
- **Module layout** (Phase 2.5 refactor): `config.rs`, `scope.rs`, `llm/` (client, parser, prompt), `tools/` (registry, locate, subfinder, httpx, nuclei), `findings/` (models, parse), `agent/` (react_loop, state), `report/` (generator).

## Build

```bash
cargo build --release
```

Dependencies: `tokio`, `clap`, `serde`, `serde_json`, `reqwest` (rustls-tls), `anyhow`, `chrono`. No SQLite, no tracing framework, minimal surface area.

Requires Rust 1.75+.

## Runtime requirements

- A local LLM server exposing an OpenAI-compatible `/v1/chat/completions` endpoint. Default target is `http://127.0.0.1:13305/api/v1` (Lemonade). Configurable via `--base-url` or the `LEMONADE_BASE_URL` env var.
- Recon tools on `$PATH`: `subfinder`, `httpx`, `nuclei` (with template set installed at the default location).

On the dev target these live at `$HOME/go/bin` after a standard ProjectDiscovery install.

## Usage

```bash
agentspyboo recon example.com \
  --scope 'example.com,*.example.com' \
  --rate-limit 500 \
  --httpx-cap 150 \
  --max-iterations 5 \
  --verbose
```

Reports land in `reports/<target>-<timestamp>.md`, findings in `findings/<target>-<timestamp>.json`.

## Hardware

Development target: **GPD Pocket 4** — AMD Ryzen AI 9 HX 370 (Strix Point), Radeon 890M iGPU (gfx1150), XDNA 2 NPU (50 TOPS rated), 32 GB unified memory. ~770g handheld with built-in 2.5 GbE.

None of the hardware specifics are required for the current CPU path — the agent will run on anything with a working Rust toolchain and a reachable OpenAI-compatible LLM server. The Ryzen AI positioning matters for the deferred NPU roadmap, not today's behavior.

## Honest state

- ✅ Phase 2 CPU runs end-to-end on the GPD against real targets (tested: `hackerone.com`, `peterc3-dev.github.io`, `gitlab.com`)
- ✅ Phase 2.5 refactor shipped — `src/main.rs` is 39 lines, all logic lives in typed modules
- ✅ NPU driver unblocked — patched `amdxdna.ko` loads on cold boot, `xrt-smi` + `flm validate` green. See [`PHASE-2-RECON.md`](PHASE-2-RECON.md).
- ⛔ NPU **inference** still blocked — FastFlowLM can't handle protocol-7 opcodes required by Qwen3/GGUF models. CPU path remains active until this unblocks.
- ⚠️ Nuclei on the target hardware CPU still times out on full template sweeps with large host lists; `--nuclei-cap` flag added to limit input hosts
- ⚠️ No automated tests yet. All verification has been manual end-to-end runs.

See [`RESEARCH.md`](RESEARCH.md) for the research brief this project is based on, including references to comparable pentest agents (Shannon, PentestGPT, PentAGI, CAI), NPU backend options (FastFlowLM, ort crate + Vitis AI EP), and an honest gap analysis.

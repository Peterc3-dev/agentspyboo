# AgentSpyBoo

A Rust-based AI red team agent that runs a multi-step ReAct loop against a local OpenAI-compatible LLM server. Targets AMD Ryzen AI hardware (currently CPU-path; NPU path parked on a hardware blocker — see [`PHASE-2-RECON.md`](PHASE-2-RECON.md)).

## Current state

- **Branch `main`**: Phase 1 MVP — single-shot ReAct loop, one tool (`subfinder`), end-to-end working. Proves the pipe.
- **Phase 1.5 and Phase 2 CPU** exist on private branches with multi-tool chaining, scope guards, severity ratings, and structured Markdown reports. Not yet pushed publicly — see [`PHASE-1.5-NOTES.md`](PHASE-1.5-NOTES.md) and the Phase 2 CPU work for details.

This README describes Phase 1 MVP. Features added in later phases are flagged below.

## Architecture

- **Loop**: Observe → Think → Act. The LLM is told about one tool, emits a tool call, we run it, feed results back, ask for a summary.
- **LLM backend**: OpenAI-compatible chat completion API. Tested against [Lemonade Server](https://github.com/lemonade-sdk/lemonade) running `Qwen3-1.7B-GGUF` via llama.cpp on CPU. Any compatible server should work (Ollama, vLLM, etc.) but only Lemonade is exercised.
- **Tool chain**:
  - Phase 1 (main): `subfinder`
  - Phase 1.5 (private branch): `subfinder` → `httpx`
  - Phase 2 CPU (private branch): `subfinder` → `httpx` → `nuclei` (curated templates, `-severity medium,high,critical`)
- **Findings**: written as JSON files under `findings/` (Phase 1.5+). Severity-rated (info/low/medium/high/critical, Phase 2+).
- **Reports**: Markdown under `reports/` (Phase 1.5+), structured with Executive Summary, Findings Table, Methodology, Step Detail, Recommended Next Steps (Phase 2 CPU+).

## Build

```bash
cargo build --release
```

Dependencies: `tokio`, `clap`, `serde`, `serde_json`, `reqwest` (rustls-tls), `anyhow`, `chrono`. No SQLite, no tracing framework, minimal surface area.

Requires Rust 1.75+.

## Runtime requirements

- A local LLM server exposing an OpenAI-compatible `/v1/chat/completions` endpoint. Default target is `http://127.0.0.1:13305/api/v1` (Lemonade). Configurable via `--base-url` or the `LEMONADE_BASE_URL` env var.
- Recon tools on `$PATH`:
  - Phase 1 needs: `subfinder`
  - Phase 1.5 adds: `httpx`
  - Phase 2 CPU adds: `nuclei` (with template set installed at the default location)

On the dev target these live at `$HOME/go/bin` after a standard ProjectDiscovery install.

## Usage

**Phase 1 MVP (public `main`)**:

```bash
agentspyboo recon example.com \
  --llm-url http://127.0.0.1:13305/api/v1 \
  --model Qwen3-1.7B-GGUF \
  --api-key lemonade
```

**Phase 2 CPU (private branches)** adds:

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

- ✅ Phase 1 MVP runs end-to-end on the GPD against real targets
- ✅ Phase 1.5 + Phase 2 CPU work locally with 3 tools and structured reports
- ⛔ NPU inference is **not** working. Documented blocker in `PHASE-2-RECON.md`.
- ⚠️ Nuclei on the target hardware CPU still times out on full template sweeps; one of several open issues tracked in `PHASE-2-NOTES.md` on the private branch
- ⚠️ No automated tests yet. All verification has been manual end-to-end runs against `example.com` and `hackerone.com`
- 📝 Scaffold files under `src/agent/`, `src/llm/`, `src/tools/` (beyond the three wired tools), `src/findings/`, `src/report/` are **dead code** preserved as the target architecture for a Phase 2.5 refactor. They are not compiled into the binary. See `PHASE-1.5-NOTES.md` for the architectural rationale.

See [`RESEARCH.md`](RESEARCH.md) for the research brief this project is based on, including references to comparable pentest agents (Shannon, PentestGPT, PentAGI, CAI), NPU backend options (FastFlowLM, ort crate + Vitis AI EP), and an honest gap analysis.

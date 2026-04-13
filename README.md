# AgentSpyBoo

Rust-based AI red team agent for autonomous penetration testing. Runs entirely on local hardware (AMD NPU via FastFlowLM) with zero cloud dependency.

## Architecture

- **ReAct Loop**: Observe -> Think -> Act -> Repeat. LLM drives tool selection and reasoning.
- **LLM Backend**: OpenAI-compatible API (FastFlowLM, Ollama, vLLM, etc.)
- **Tools**: subfinder, httpx, nuclei, naabu, ffuf, gau, findomain, nmap
- **Findings DB**: SQLite with deduplication and severity tracking
- **Reports**: Structured Markdown with executive summary and evidence

## Usage

```bash
agentspyboo --target example.com --llm-url http://localhost:8000/v1 --model qwen3-1.7b --max-steps 50 --output report.md
```

## Build

```bash
cargo build --release
```

## Requirements

- Rust 1.75+
- CINApse recon tools installed (subfinder, httpx, nuclei, ffuf, gau, naabu, findomain)
- nmap
- A local LLM server (FastFlowLM recommended for NPU, Ollama works too)

## Hardware Target

GPD Pocket 4 — AMD Ryzen AI 9 HX 370, XDNA 2 NPU (50 TOPS), 32GB unified memory.
770g portable air-gapped pentesting rig.

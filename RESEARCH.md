# AgentSpyBoo — First Rust-based AI Red Team Agent on AMD NPU

## Research Date: April 12, 2026

## Gap Confirmed
Zero projects combine {Rust} + {NPU} + {Autonomous Pentesting}. Verified across GitHub, arXiv, Black Hat, DEF CON.

## Architecture
- **NPU Backend**: FastFlowLM (28 TPS Llama 3.2 3B, OpenAI-compatible API, 16MB binary, Linux support)
- **Model**: Qwen3-1.7B (0.960 tool-calling accuracy, best sub-4B) or Phi-4-mini (3.8B, MIT license)
- **Rust Framework**: tokio async runtime, ort crate (vitis feature for NPU), reqwest for FastFlowLM API
- **Tool Chain**: subfinder, httpx, nuclei, naabu, ffuf, gau, findomain, RustScan (native Rust)
- **Hardware**: GPD Pocket 4, Ryzen AI 9 HX 370, XDNA 2 NPU (50 TOPS), Radeon 890M, 32GB unified

## Key NPU Benchmarks (FastFlowLM on XDNA 2)
- Qwen3.5-0.8B: 39.2 TPS (decode), 1,471 TPS (prefill)
- Qwen3.5-2B: 26.8 TPS
- Qwen3.5-4B: 15.0 TPS
- Llama 3.2 3B: 28 TPS

## Rust-to-NPU Bridge
- `ort` crate v2.0.0-rc.12 has `vitis` Cargo feature
- `SessionBuilder::with_auto_device()` for NPU auto-select
- Requires AMD ONNX Runtime with Vitis AI EP (from Ryzen AI Software SDK)
- Alternative: FastFlowLM REST API (pragmatic, avoids build chain issues)

## Competition (all Python, all cloud-dependent)
- Shannon: 96.15% XBOW benchmark, Anthropic Agent SDK
- PentestGPT: 11k stars, USENIX Security 2024, 86.5% XBOW
- PentAGI: 3k stars, multi-agent, Docker sandbox, 20+ tools
- CAI: claims 3,600x vs human pentesters
- pentest-ai: MCP-based, 150+ tools
- XBOW, Penligent, Terra Security: cloud SaaS

## Unique Advantages
1. Portable (770g handheld)
2. Air-gapped capable (no cloud dependency)
3. NPU-powered (3.3 TOPS/Watt, 8x more efficient than discrete GPU)
4. Rust runtime (memory safe, zero-overhead)
5. Built-in 2.5GbE + optional RS-232 for SCADA
6. Breaks even vs cloud API costs in 2.6 months

## Target Markets (where cloud AI is impossible)
- SCIF/classified (ICD 705)
- SCADA/ICS (NERC CIP, fines up to $1M/day)
- Nuclear (10 CFR 73.54)
- OPSEC-sensitive red team ops
- GDPR-constrained (4% global revenue fines)

## Linux Status
- amdxdna driver mainlined in Linux 6.14
- Vitis AI EP builds broken on Ubuntu 24.04 (GCC 13/14 issues)
- FastFlowLM Linux support added March 2026
- OGA hybrid mode (NPU+iGPU) Windows-only currently

## MVP Timeline
- Phase 1: Prove NPU inference on GPD (FastFlowLM + Qwen3-1.7B)
- Phase 2: Rust agent loop (target → recon chain → report)
- Phase 3: Multi-tool orchestration, findings DB, structured reports

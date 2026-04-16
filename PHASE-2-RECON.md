# AgentSpyBoo Phase 2.0 — NPU Reconnaissance Report

**Date:** 2026-04-13 (updated 2026-04-16)
**Target:** GPD Pocket 4, AMD Ryzen AI 9 HX 370, XDNA 2 NPU
**Purpose:** Determine the fastest viable path to NPU inference for AgentSpyBoo Phase 2.

## TL;DR

**Driver unblocked, inference runtime still blocked.** A patched `amdxdna.ko` built at `~/builds/amdxdna-patched/` (root-caused by a background agent, POWER_OFF precheck fix for Strix Point) now loads clean on cold boot — `xrt-smi examine` reports the NPU device and `flm validate` passes green. **However, FastFlowLM still fails on actual inference** — it cannot handle protocol-7 opcodes used by the Qwen3/GGUF models we need. The NPU is unblocked at the driver level, blocked at the inference runtime level.

Recommended path remains **FastFlowLM** once it supports the required opcodes. Integration with AgentSpyBoo is a one-line base-URL change. The driver blocker documented below is now resolved; see the addendum at the end for current state.

---

### Original TL;DR (preserved for history)

The Arch/CachyOS NPU stack is unexpectedly mature: `flm` (FastFlowLM v0.9.38), `xrt-smi` (XRT 2.21.75), and the `xrt-plugin-amdxdna` runtime are all packaged in the official `extra` repo and already installed on the GPD, with `llama3.2:1b` pre-pulled. **However the `amdxdna` kernel driver currently fails to bind to the NPU PCI device** (`c6:00.1`) on kernel 6.19.12-1-cachyos with `aie2_smu_init: Access power failed, ret -22` — the SMU power handshake fails, hardware probe aborts, and `xrt-smi examine` reports `0 devices found`. Until that probe error is resolved, *no* NPU runtime can run, regardless of which user-space stack we pick. Recommended path is **FastFlowLM** once the driver binds (one base-URL swap in `src/main.rs` and AgentSpyBoo runs on NPU); the immediate Phase 2.0 blocker is firmware/kernel, not user-space.

## Recommended Path

**FastFlowLM**, contingent on unblocking the kernel driver probe.

Rationale: `flm` is already installed via pacman (`extra/fastflowlm 0.9.38-1`), exposes an OpenAI-compatible REST server (`flm serve`), and llama3.2:1b is already pulled. If/when `amdxdna` binds to `0000:c6:00.1`, integration with AgentSpyBoo is a one-line base-URL change in `src/main.rs` (from `http://127.0.0.1:13305` to FastFlowLM's port). No Rust ecosystem work, no ONNX export, no Quark quantization needed.

The other two paths are strictly worse on this machine right now: ONNX Runtime isn't even installed in the gaia venv (only `onnx` 1.18.0 is), so the ort + Vitis AI EP path requires building/sourcing onnxruntime-vitisai from scratch on Arch (untested territory, GCC 14 build failures noted in xdna-driver#1017). IREE + amd-aie has no Arch packages and no install footprint on the GPD at all.

## Evidence

### A. Kernel / driver state

```
$ uname -r
6.19.12-1-cachyos

$ lsmod | grep -i xdna           # before modprobe
(empty)

$ ls /dev/accel/
ls: cannot access '/dev/accel/': No such file or directory

$ ls /sys/class/accel/
(empty directory exists)

$ modinfo amdxdna | head
filename:       /lib/modules/6.19.12-1-cachyos/kernel/drivers/accel/amdxdna/amdxdna.ko.zst
firmware:       amdnpu/1502_00/npu.sbin
firmware:       amdnpu/17f0_10/npu.sbin
firmware:       amdnpu/17f0_11/npu.sbin
firmware:       amdnpu/17f0_20/npu.sbin
intree:         Y
depends:        gpu-sched
alias:          pci:v00001022d000017F0sv*sd*bc*sc*i*

$ ls /lib/firmware/amdnpu
1502_00  17f0_10  17f0_11        # note: 17f0_20 firmware is referenced by modinfo but NOT present on disk

$ sudo modprobe amdxdna           # passwordless sudo works on GPD
$ lsmod | grep xdna
amdxdna               200704  0
gpu_sched              73728  2 amdxdna,amdgpu

$ sudo dmesg | grep -iE "xdna|npu" | tail
amdxdna 0000:c6:00.1: [drm] *ERROR* aie2_smu_exec: smu cmd 4 failed, 0xff
amdxdna 0000:c6:00.1: [drm] *ERROR* aie2_smu_init: Access power failed, ret -22
amdxdna 0000:c6:00.1: [drm] *ERROR* aie2_hw_start: failed to init smu, ret -22
amdxdna 0000:c6:00.1: [drm] *ERROR* aie2_init: start npu failed, ret -22
amdxdna 0000:c6:00.1: [drm] *ERROR* amdxdna_probe: Hardware init failed, ret -22
amdxdna 0000:c6:00.1: probe with driver amdxdna failed with error -22
```

The module loads, claims its PCI alias, attempts to probe `0000:c6:00.1`, and fails at the SMU power init step. After the failed probe `/dev/accel/` is still absent, `/sys/class/accel/` is empty, and the device falls out of the driver. **This is the central blocker.**

Two suspicious correlations:
1. The `17f0_20` firmware (which would presumably target the Strix Halo / HX 370 stepping) is referenced by `modinfo` but is **not present** in `/lib/firmware/amdnpu/` — only `1502_00`, `17f0_10`, `17f0_11`. Possible firmware mismatch.
2. BIOS version is **2.10** on the GPD G1628-04. NPU enablement on Strix laptops is BIOS-gated (PSP/SMU fuses); a BIOS update from GPD that flips NPU enable, or a UEFI setting, may be required.

### B. AMD Ryzen AI Software presence

```
$ which xrt-smi xbutil
/usr/bin/xrt-smi
which: no xbutil in (...)

$ pacman -Qs xdna
local/xrt-plugin-amdxdna 1:2.21.75-2.1
    Runtime for AIE and FPGA based platforms

$ ls /opt/amd /opt/xilinx /opt/ryzen_ai ~/ryzen_ai
(none exist)
```

No Ryzen AI SDK install (no `/opt/amd`, no `~/ryzen_ai`). Instead, the **community Arch packages** ship the equivalents: `xrt-plugin-amdxdna` provides the userspace runtime, `xrt-smi` is the diagnostic tool, and `fastflowlm` ships the inference runtime. This is *much* cleaner than the Ubuntu Ryzen AI Software install — no 10 GB `/opt` blob, no GCC version pinning.

`xrt-smi examine` confirms the runtime sees the driver but no devices:
```
XRT
  Version              : 2.21.75
  amdxdna Version      : 6.19.12-1-cachyos
Device(s) Present
  0 devices found
```

### C. ONNX Runtime providers

```
$ ~/gaia-env-312/bin/python3 -c "import onnxruntime as ort; print(ort.__version__); print(ort.get_available_providers())"
ModuleNotFoundError: No module named 'onnxruntime'

$ ~/gaia-env-312/bin/pip list | grep -iE "onnx|vitis|quark|iree"
onnx                   1.18.0
```

**onnxruntime is not installed at all** in the gaia venv. Only the schema/IR package `onnx` 1.18.0. No `VitisAIExecutionProvider`, no `quark`, no `iree`. This means the "ort crate + Vitis AI EP" Rust path requires sourcing or building `onnxruntime-vitisai` from scratch, which is the path the research RESEARCH.md flagged as broken on Arch.

### D. FastFlowLM

```
$ pacman -Ss fastflowlm
cachyos-extra-znver4/fastflowlm 0.9.38-1.1 [installed]
    Run LLMs on AMD Ryzen AI NPUs
extra/fastflowlm 0.9.38-1 [installed: 0.9.38-1.1]
    Run LLMs on AMD Ryzen AI NPUs

$ which flm
/usr/bin/flm

$ flm version
FLM v0.9.38

$ flm validate
[Linux]  Kernel: 6.19.12-1-cachyos
[ERROR]  No NPU device found.
[Linux]  Memlock Limit: infinity

$ flm list
Models:
  - deepseek-r1:8b ⏬
  - gemma3:1b ⏬
  - gemma3:4b ⏬
  - gpt-oss:20b ⏬
  - llama3.1:8b ⏬
  - llama3.2:1b ✅          # <-- already pulled
  - llama3.2:3b ⏬
  - phi4-mini-it:4b ⏬
  - lfm2:1.2b ⏬
  - lfm2:2.6b ⏬
  - medgemma:4b ⏬
  - nanbeige4.1:3b ⏬
  ... (many more)
```

FastFlowLM is **not just installable, it's already installed and configured** with one model pre-pulled. The CachyOS znver4-optimized variant is selected. `flm serve` will run an OpenAI-compatible REST server. The HX 370 is implicitly supported since both Arch and CachyOS-extra ship it; FastFlowLM's tested model set spans Llama 3.1/3.2, Gemma 3, Phi-4-mini, gpt-oss, DeepSeek-R1, MedGemma, LFM2, and embedding models — much broader than the research notes implied.

`flm validate` fails purely because of the kernel driver probe failure in section A. **The user-space FastFlowLM stack is shovel-ready; only the kernel binding is broken.**

### E. IREE + amd-aie plugin

```
$ which iree-compile iree-run-module
(neither found)

$ ~/gaia-env-312/bin/pip list | grep iree
(empty)
```

Not installed. No Arch package observed for `iree-amd-aie`. This path would require building from source — not viable as Phase 2.1 starting point given that FastFlowLM is already on disk.

### F. AMD Quark

```
$ ~/gaia-env-312/bin/pip list | grep -iE "quark|amd_quark"
(empty)
```

Not installed. Not needed for FastFlowLM (it ships pre-quantized GGUF-style model files from its own catalog). Quark would only be needed for the ort+Vitis AI EP path, which is parked.

### G. PyTorch — existing AI stack (for contrast)

```
$ ~/gaia-env-312/bin/python3 -c "import torch; print(torch.__version__, torch.version.hip)"
2.11.0+cu130 None
```

Surprise finding: the torch installed in `gaia-env-312` is **2.11.0+cu130 (CUDA build)**, not the custom gfx1150 ROCm build documented in MEMORY. The gfx1150 wheel lives under `~/builds/pytorch-gfx1150` and is not active in this venv. Either way: the existing AI stack is GPU+CPU oriented (ROCm gfx1150 wheel, llama.cpp via Lemonade on CPU). **No part of the existing stack touches the NPU.** Phase 2 is genuinely new territory.

### H. Hardware sanity

```
$ lscpu | head
Architecture:    x86_64
CPU(s):          24
Model name:      AMD Ryzen AI 9 HX 370 w/ Radeon 890M
CPU family:      26
Model:           36
Thread(s)/core:  2
Cores/socket:    12

$ lspci | grep -iE "neural|signal processing"
c6:00.1 Signal processing controller: AMD Strix/Krackan/Strix Halo Neural Processing Unit (rev 10)

$ lspci -k -s c6:00.1
c6:00.1 Signal processing controller: ... Neural Processing Unit (rev 10)
    Subsystem: AMD Strix/Krackan/Strix Halo Neural Processing Unit
    Kernel modules: amdxdna             # <-- module CLAIMS device but probe fails
```

NPU is physically present at `0000:c6:00.1`, advertised as the Strix Halo NPU, rev 10. The driver associates with it via PCI alias but probe fails at SMU init.

## Blockers identified

1. **`amdxdna` driver probe failure on kernel 6.19.12** — `aie2_smu_init` returns -22 (EINVAL/access denied from PSP). This is the only thing standing between AgentSpyBoo and an NPU backend. Effort: **unknown, 1 hour to 1 week**. Resolution candidates, in order of likelihood:
   - **BIOS update** from GPD (current 2.10) — Strix NPU is PSP-fused at BIOS level, and a BIOS that doesn't enable NPU SMU access cannot be worked around in software. Highest probability fix.
   - **Missing `17f0_20` firmware** referenced by modinfo but absent from `/lib/firmware/amdnpu/`. Pull from `linux-firmware` git or the `amdgpu-firmware` AUR package. Low-effort to test, may not be the right firmware ID for this stepping.
   - **Kernel regression**. 6.19 mainlined more amdxdna changes; older 6.14-6.17 kernels are reported working on Strix Point. Try the `linux-lts` package as an A/B test.
   - **xdna-driver issue tracker** (github.com/amd/xdna-driver) — search for `aie2_smu_init -22` and HX 370 / Strix Point reports. Likely already filed.
2. **No onnxruntime in gaia venv** — only relevant if the FastFlowLM path is later abandoned in favor of ort+Vitis AI EP. Effort to install: small, but the *Vitis AI EP* build is the hard part (research already flagged Ubuntu/GCC issues). Parked.
3. **Existing torch 2.11.0+cu130 in gaia-env-312** — not a Phase 2 blocker, but a documentation issue: the venv we thought was the gfx1150 ROCm one is actually a CUDA wheel. Out of scope for this report.

## Open questions for user

1. Are you willing to **update the GPD BIOS** if GPD has released a newer firmware than 2.10? This is the single highest-leverage fix and the only one that's strictly outside Linux's control.
2. Are you willing to **boot a different kernel** (e.g. `linux-lts` or a 6.14-6.17 series) to A/B test whether this is a kernel-side regression vs. a hardware/firmware-side block?
3. Should I file an upstream bug at `github.com/amd/xdna-driver` with the dmesg trace as part of Phase 2.1 if no existing report matches?
4. Is there a known-good NPU workload on a sibling distro (Ubuntu 24.04 + Ryzen AI Software) that we can use as a baseline if we end up needing to dual-boot for confirmation, or do we keep it Arch-pure?

## Proposed Phase 2.1 scope

Given the evidence, **Phase 2.1 is a kernel/firmware unblock, not a software integration sprint.** Concrete steps, in order:

1. **(15 min)** Search xdna-driver and amdxdna issue trackers for `aie2_smu_init -22` on Strix Point / HX 370 / 6.19.x. Note any matching reports and proposed fixes.
2. **(15 min)** Check linux-firmware git for any `amdnpu/17f0_2*` blobs newer than what's in `/lib/firmware/amdnpu/`. Install if present, retry probe.
3. **(30 min)** Check GPD support for BIOS updates beyond 2.10. If a newer release exists with NPU/AIE enablement notes, flag it for the user — do not flash unattended.
4. **(30 min)** Boot `linux-lts` (probably 6.12.x), retry `sudo modprobe amdxdna && xrt-smi examine`. This is the cleanest A/B test for kernel-side regression.
5. **(once /dev/accel exists)** Run `flm validate`, then `flm serve --port 13306 llama3.2:1b`. Hit it with `curl http://127.0.0.1:13306/v1/chat/completions`. Verify NPU utilization in `xrt-smi`.
6. **(15 min)** In `src/main.rs`, swap the Lemonade base URL for the FastFlowLM URL. Run `cargo run` against the same agent prompt used in Phase 1.5. Diff the latency and tokens/sec against the CPU baseline.
7. **(15 min)** Document the win in `PHASE-2-NOTES.md`, commit on a new `phase-2.0` branch, and tag.

**Wall clock estimate, assuming the kernel block is unblockable in Linux user-space (i.e. firmware/kernel only): 2-3 hours of focused work.** If the only fix is a BIOS update from GPD that doesn't yet exist, Phase 2.1 is **PARKED until GPD ships a new BIOS**, in which case AgentSpyBoo should be advanced on a different axis (Phase 1.5 polish, mission catalog expansion, output format work) and Phase 2 deferred.

---

## Addendum: Driver Unblocked (2026-04-15)

**Status: NPU unblocked at driver level, blocked at inference runtime level.**

### What changed
- A background agent root-caused the `aie2_smu_init: Access power failed, ret -22` error: the out-of-tree `amdxdna` driver's POWER_OFF precheck was incorrect for Strix Point (PCI device `17f0`). A patched `.ko` was built at `~/builds/amdxdna-patched/` on the GPD.
- With the patched driver, `modprobe amdxdna` now binds successfully on cold boot. `xrt-smi examine` reports the NPU device. `flm validate` passes green.
- Bug filed as `amd/xdna-driver#1257` on GitHub. Max Zhen (AMD) responded with follow-up questions; thread closed from our end after correction (see below).

### What's still blocked
- **FastFlowLM cannot handle protocol-7 opcodes** used by Qwen3/GGUF models. When `flm serve` attempts inference with these models, it errors on unsupported opcodes. This is a FastFlowLM limitation, not a driver issue.
- Llama 3.2 1B (protocol-compatible) may work on NPU via `flm serve`, but AgentSpyBoo's orchestration LLM is Qwen3-1.7B-GGUF which requires the unsupported opcodes.
- Until FastFlowLM adds protocol-7 support (or we switch to a compatible model), NPU inference for AgentSpyBoo remains blocked.

### Driver bug report notes
- Filed `amd/xdna-driver#1257` — POWER_OFF precheck on Strix Point, cold-boot A/B isolating firmware 1.1.2.64 vs 1.0.0.63.
- Also filed `CachyOS/CachyOS-PKGBUILDS#1311` — linux-firmware-other symlink inversion affecting `amdnpu/17f0_20/` firmware path.
- Critical correction: initial draft proposed backporting `min_fw_version` from the out-of-tree driver, which was wrong — Lizhi Hou's mainline commit `75c151ceaacf` (merged 2026-02-25) uses a different mechanism (firmware-name fallback to `npu_7.sbin`). Draft rewritten owning the mistake.

### Implications for AgentSpyBoo
- Phase 2 CPU track continues as the active path (Lemonade Server, Qwen3-1.7B-GGUF on CPU).
- NPU path is no longer driver-blocked — it's FastFlowLM-blocked. When/if `flm` adds protocol-7 support, integration is still a one-line base-URL swap.
- The patched `.ko` is not in the mainline kernel. Cold-booting requires `modprobe` with the patched module each boot until the fix is upstream.

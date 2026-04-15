# Phase 2.5 — Module Refactor

Branched from `phase-2-cpu` at commit `f256c99` on 2026-04-13, while a
parallel agent was making functional changes (nuclei URL cap, findings
dedup, real target run) on a dirty working tree against the same branch.
To stay out of their way, this work happens in a separate git worktree at
`~/projects/agentspyboo-refactor/` on branch `phase-2.5-refactor`. The
original `~/projects/agentspyboo/` working tree was not touched.

## Goal

The Phase 1.5 architectural note set two trigger conditions for splitting
the flat `main.rs` into modules:

1. Phase 2 CPU completes, OR
2. `main.rs` crosses ~1500 lines.

Both have effectively fired (Phase 2 CPU is done, `main.rs` hit 1430
lines at `f256c99`), and the user explicitly requested the refactor
before the next phase begins.

## What went where

| Flat `main.rs` (f256c99) lines | New home                      | Notes                                        |
|--------------------------------|-------------------------------|----------------------------------------------|
| 22–71                          | `src/config.rs`               | `Cli`, `Cmd` (clap)                          |
| 73–132                         | `src/config.rs`               | `Config` + `Config::resolve`                 |
| 134–169                        | `src/scope.rs`                | `host_in_scope`, `normalize_host`            |
| 171–257                        | `src/llm/client.rs`           | `ChatMessage`, request/response, `LlmClient` |
| 259–302                        | `src/tools/registry.rs`       | `ToolKind`, `ToolExecution`                  |
| 304–330                        | `src/tools/locate.rs`         | `locate_bin`, `which`                        |
| 332–351                        | `src/tools/subfinder.rs`      | `exec_subfinder`                             |
| 353–384                        | `src/tools/httpx.rs`          | `exec_httpx`                                 |
| 386–453                        | `src/tools/nuclei.rs`         | `nuclei_templates_root`, `exec_nuclei`       |
| 455–520                        | `src/llm/parser.rs`           | `strip_think`, `extract_json`                |
| 521–579                        | `src/llm/parser.rs`           | `parse_action`, `AgentAction`                |
| 581–629                        | `src/findings/models.rs`      | `Severity`, `Finding`                        |
| 631–650                        | `src/llm/prompt.rs`           | `system_prompt`                              |
| 652–686                        | `src/agent/state.rs`          | `StepRecord`, `RunRecord`, `preview`         |
| 688–806                        | `src/findings/parse.rs`       | subfinder/httpx/nuclei parsers               |
| 808–1301                       | `src/agent/react_loop.rs`     | `run_recon` — the ReAct loop                 |
| 1303–1420                      | `src/report/generator.rs`     | `render_report`                              |
| 1422–1430                      | `src/main.rs`                 | `#[tokio::main] main()`                      |

Final `src/main.rs`: **39 lines** (down from 1430). It now only declares
modules, parses the CLI, and dispatches to `agent::run_recon`.

## Scaffold files deleted (commit 726f40f)

Every one of these was dead — no `mod` declarations, not compiled, never
referenced. They were remnants from the `4ae87c6` initial scaffold and
would have muddied the diff of the actual port.

- `src/config.rs`
- `src/agent/{mod,planner,react_loop,state}.rs`
- `src/llm/{mod,client,parser,prompt}.rs`
- `src/tools/{mod,registry,subfinder,httpx,nuclei,naabu,ffuf,gau,findomain,nmap}.rs`
- `src/findings/{mod,models,db,dedup}.rs`
- `src/report/{mod,generator,templates}.rs`

The refactor then created fresh files at the same (or similar) paths with
the real, working logic from flat `main.rs`. Per the instructions ("the
refactored structure doesn't have to perfectly match the scaffold's
original file layout"), I didn't try to preserve git blame on any
scaffold file — they were all placeholder content with nothing worth
keeping.

## Scaffold files kept as-is

None. The scaffold was dead code across the board. I chose a two-step
approach (delete-then-rewrite) rather than edit-in-place because:

1. The scaffold file purposes didn't always line up with where the flat
   code naturally wanted to split (e.g. scaffold had `findings/db.rs` for
   SQLite; Phase 2 is JSON-only and SQLite stays out per instructions).
2. A delete-then-rewrite diff is far easier to review than a mixture of
   renames, partial edits, and deletions.

## Scaffold deviations from the suggested target

A few places my layout diverges from the suggested target in the
instructions — all defensible, none load-bearing:

- `findings/parse.rs` (new file) instead of putting parsers in
  `findings/models.rs`. Keeps data types separate from serde-flavoured
  JSON munging.
- `tools/locate.rs` (new file) for `locate_bin` + `which`. The flat code
  had these sitting between `ToolKind` and the exec functions; they don't
  belong in `registry.rs` (no `ToolKind` dependency) and shouldn't be
  duplicated across every tool file.
- No `findings/dedup.rs`. The parallel agent on `phase-2-cpu` is the one
  who's going to add dedup; I'm branched from before that landed. If
  their work merges first and we rebase Phase 2.5 onto it, dedup drops
  into `findings/dedup.rs` cleanly.
- No `agent/planner.rs`. Scaffold had it but flat code has no planner —
  the LLM IS the planner via the ReAct loop. Fictional module.

## Open questions (possible bugs I saw but did NOT fix per rule 8)

1. `extract_hosts_from_subfinder` doesn't apply scope guard — it just
   trusts subfinder's output. The scope guard runs later (before httpx),
   so the raw subfinder findings get recorded under `kind: "subdomain"`
   even if they're out of scope. Low impact (they're just `Info`) but
   worth a look.
2. `parse_httpx_output` uses an `admin_hint` list of English keywords.
   Any non-English portal is classified `Low`/`Info` even if it's clearly
   an auth panel. Not a refactor issue, just a weak heuristic.
3. `normalize_host` assumes ASCII hostnames. IDN punycode would slip
   through the scope guard unchanged. Unlikely in practice for HackerOne
   programs but worth a note.
4. The `target/` directory is checked into git at `f256c99` (918 files).
   This pre-dates my work and I didn't touch it — adding a `.gitignore`
   and `git rm -r --cached target/` would be a separate cleanup PR. Flag
   for user review.

## How to run it

Unchanged from `phase-2-cpu`. All CLI flags, all env vars, all output
formats preserved.

```bash
# On ThinkCentre (needs Lemonade Server reachable at 127.0.0.1:13305):
cargo build --release --offline
./target/release/agentspyboo recon example.com --verbose

# On GPD (Lemonade runs locally, Go tooling in ~/go/bin):
cd ~/projects/agentspyboo
git checkout phase-2.5-refactor
cargo build --release
PATH=$HOME/go/bin:$PATH ./target/release/agentspyboo recon hackerone.com --verbose
```

## Verification output

### cargo check (ThinkCentre, offline)

```
    Checking agentspyboo v0.1.0 (/home/raz/projects/agentspyboo-refactor)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.38s
```

Zero warnings after the `StepRecord` unused-import cleanup.

### cargo build --release (ThinkCentre, offline)

```
    Finished `release` profile [optimized] target(s) in 16.15s
```

Zero warnings.

### CLI smoke-tests (ThinkCentre)

- `./target/release/agentspyboo --help` — identical to `f256c99`
- `./target/release/agentspyboo recon --help` — identical to `f256c99`
- Scope-refusal error (`--scope other.com` on `example.com`) — identical
  phosphor `[*]` banner + `Error: target '...' does not match scope
  patterns "..."` error line.

### cargo build --release (GPD, isolated dir)

```
   Compiling agentspyboo v0.1.0 (/home/raz/projects/agentspyboo-refactor-test)
    Finished `release` profile [optimized] target(s) in 14.98s
```

Zero warnings on Ryzen AI 9 HX 370 too.

### hackerone.com end-to-end benchmark (GPD)

The GPD build used an isolated sibling directory
(`~/projects/agentspyboo-refactor-test/`, since cleaned up) because the
parallel agent still had uncommitted changes on branch `phase-1.5` in the
original `~/projects/agentspyboo/` tree, and the instructions warn
against trampling that state.

Result — `PATH=$HOME/go/bin:$PATH ./target/release/agentspyboo recon
hackerone.com --verbose`:

- Iteration 1: subfinder → 16 subdomains in 4423 ms
- Iteration 2: httpx `hosts_from=subfinder` → 10 live hosts in 1894 ms
  (mix of Cloudflare CDN, GitHub Pages, Freshdesk, Algolia docs, api)
- Iteration 3: nuclei `urls_from=httpx` → 0 JSONL lines in 630878 ms
  (~10.5 min, well within the 900s timeout bumped in c84631c)
- Iteration 4: LLM signaled `done` with a sensible summary and empty
  `next_steps`.

Tool chain, iteration count, scope guard behavior, findings file layout,
and markdown report path template all match the shape produced on
`phase-2-cpu` pre-refactor. Exit code: 0.

Findings file: `findings/hackerone.com-20260415T093757Z.json`
Report file: `reports/hackerone.com-20260415T093757Z.md`

## Known rough edges

- `agent/react_loop.rs` is still ~480 lines. The per-`ToolKind` exec
  dispatch (subfinder/httpx/nuclei) is the longest single function in
  the whole codebase now. It's a natural next candidate for further
  extraction into `tools/dispatch.rs` or similar once more tools arrive
  in Phase 3 — for now I kept it inline because pulling it out would
  mean passing all five mutable caches (`last_subfinder_hosts`,
  `last_httpx_urls`, `all_findings`, `messages`, `tools_fired`) through
  a function signature, which is worse than the current shape.
- `render_report` reads a `RunRecord` from `crate::agent`. That means
  `report/` depends on `agent/`, not the other way around — if Phase 3
  ever needs `agent/` to call `report/` for intermediate rendering,
  there's a small circular dep to untangle. Not an issue today.
- The scaffold's old `tools/` directory had placeholder files for naabu,
  ffuf, gau, findomain, nmap. None of those are wired up on CPU-track
  Phase 2, so they were deleted rather than ported. When Phase 3 needs
  them, they'll need to be written from scratch anyway.

## Reversal plan

If this refactor is rejected in the morning review:

```bash
# Delete the branch. The worktree in ~/projects/agentspyboo-refactor/
# holds all the work; removing the branch + worktree erases it.
cd ~/projects/agentspyboo
git worktree remove ../agentspyboo-refactor
git branch -D phase-2.5-refactor
```

The original `phase-2-cpu` branch and the parallel agent's working tree
are untouched — no rollback is needed on their side.

If the refactor is accepted:

```bash
# Fast-forward merge to phase-2-cpu once the parallel agent has landed
# their changes. Phase 2.5 is branched from f256c99, so if the parallel
# agent added commits on top of f256c99, the merge will need a rebase:
cd ~/projects/agentspyboo
git checkout phase-2-cpu
git merge --ff-only phase-2.5-refactor     # works if no parallel commits
# OR
git checkout phase-2.5-refactor
git rebase phase-2-cpu                      # if parallel commits exist
# then resolve conflicts (expected: main.rs, mainly around the sections
# the parallel agent edited — nuclei URL cap in the httpx branch, findings
# dedup wherever they put it) and push.
```

The conflict surface is: anything the parallel agent edited in the 1430
lines that now live in 20 files. It'll be messier than a normal rebase
but not terrible because the split is along existing `=====` section
boundaries — each of their edits should map to one of my new files.

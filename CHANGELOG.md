# Changelog

All notable changes to CRUCIBLE (CRUCIBLE). Format follows
[Keep a Changelog](https://keepachangelog.com/); this project uses date-stamped
milestones rather than published releases (source-available, not on PyPI).

## [Unreleased]

### Added
- **Tier-A public-dataset importers** (`--corpus-format beavertails|aegis` for
  `--load-corpus`): first-class loaders for **BeaverTails** (PKU-Alignment) and
  **Aegis** (NVIDIA AI Content Safety) that map each dataset's native taxonomy to
  Llama-Guard S-codes and tag prompts `effectiveness_tier: A` with real provenance.
  Unsafe-only by default; `--corpus-include-safe` keeps benign rows as over-refusal
  controls.
- **GitHub Pages**: the MkDocs site is published automatically (`.github/workflows/docs.yml`)
  to https://shadowslayer08.github.io/Crucible/.

### Changed
- Dependency bumps (consolidated): SLM-training stack → transformers 5 / trl 1.x /
  peft 0.21 / datasets 5 / accelerate 1.15; CI actions → setup-python v6 /
  upload-artifact v6 / codeql-action v4.

## [3.1.0] — 2026

Adaptive-attacker, benchmark-comparability, serving, and self-curation upgrades on
top of v3.0.0.

### Added — attackers & coverage
- **Ensemble attacker** — `--ensemble-attackers m1,m2,…` rotates the generating model
  per `--dynamic` round for mutation diversity (`AttackerLLM.rotate`).
- **`--local-attacker`** — one-flag preset: `--dynamic` against a local Ollama
  attacker, auto-picking an uncensored pulled model.
- **`--mode artprompt`** — ArtPrompt ASCII-art keyword-masking jailbreak (Jiang 2024):
  the trigger word is hidden as 5×5 block-font art the filter can't read.

### Added — benchmarking & judging
- **Benchmark graders** — `--grader harmbench|jailbreakbench|strongreject|all`
  (+`--grader-judge`): faithful rubrics + parsers re-score a run so the ASR is
  comparable to those papers' numbers; LLM-judge path with an offline heuristic.
- **`--benchmark-suite`** — run a benchmark's prompt set (bundled sample or
  `--benchmark-file`) and auto-score with the matching grader.
- **`--cross-judge [MODEL]`** — judge with a local model distinct from the attacker
  to cut self-scoring bias, across `--dynamic` and `--grader-judge`.

### Added — self-improving KB
- **KB quality management** — `record_success` / `prune` / `quality_report`; the grow
  loop reinforces repeat wins instead of dropping near-duplicates; `--kb-prune`
  `[--kb-prune-max-age-days N] [--kb-prune-min-success K]` + a `--kb-stats` snapshot.

### Added — serving, tooling & docs
- **Web-UI auth** — the `--serve` dashboard/API now requires a password
  (`--serve-password` / `CRUCIBLE_SERVE_PASSWORD`) exchanged for a stdlib **HS256 JWT**;
  both the zero-build dashboard and the React SPA authenticate.
- **Shell completion** — `crucible --completion bash|zsh|fish` (parser-introspected).
- **MkDocs documentation site** (`mkdocs.yml` + Material theme, `mkdocs` extra).

### Fixed
- Mutate report/JSON now cover all 16 mutators (derived from `all_mutations()`),
  not a stale hardcoded 8.
- Hardened a flaky throttle timing assertion.

### Tooling
- CI on py3.10–3.12 stays green at **~1,950 tests**.

## [3.0.0] — 2026

The v3 line turns the CLI into a full black-box AI red-team platform. See
[ROADMAP.md](ROADMAP.md) for the itemized history (stages A–G, G1–G17).

### Added — attack surface
- ~20 attack modes incl. `mcp`, `agentic` (with planning-manipulation), `rag`,
  `swarm`, `policy` (Llama-Guard S1–S14), `benign`, `obfuscation`, `multilingual`,
  `multimodal`/`audio`/`video`, `memory-poison`, `pismith`, `authz`, `harm`,
  `model-theft`, and the 2024–25 **`modern-jailbreak`** (Policy Puppetry / Skeleton
  Key / Deceptive Delight) and **`many-shot`** suites.
- Adaptive attackers: `--dynamic` (PAIR), `--tap` (Tree-of-Attacks), **`--crescendo`**
  (adaptive multi-turn), `--auto` (autonomous). PayloadMutator now has 16 strategies
  incl. refusal-suppression.
- Declarative `--vuln × --attack` matrix; external corpus ingest (`--load-corpus`).

### Added — self-improvement & local-first
- Local-first / air-gap: `--local`, `--offline`, `--judge-local` (Ollama, stdlib-only).
- Self-growing KB (`kb/`, bge-m3 + SQLite) with `--evolve` / grow-on-win.
- SLM pipeline (`slm/`): dataset collection → LoRA fine-tune → GGUF/Ollama export →
  **Wilson-CI A/B ship gate** → versioning; `python -m slm.pipeline` closes the loop
  with promote-iff-SHIP. MoE merge via mergekit.
- **Anti-forgetting training recipe** (`slm/train.py`): all-linear LoRA targets (incl.
  MLP), optional DoRA/rsLoRA, and general-instruction **replay mixing** (`--replay-ratio`,
  default 0.3) so a small-data fine-tune keeps base ability instead of collapsing — the
  root-cause fix for the KEEP-base A/B result.

### Added — full stack & reporting
- Model-artifact supply-chain scanner (`--model-scan`) and active model-stealing
  engine (`--extract`).
- AgentHound bridge: `--recon` / `--full-stack` discover exposed AI infra and sweep
  it, emitting one unified infra+behaviour report (JSON + SARIF) with correlated
  chained findings and an attack-path graph.
- Reporting: JSON / CSV / SARIF 2.1.0 / PDF; ASR@1 / ASR@N with Wilson CIs, coverage grids,
  benchmark deltas, threat ontology, transferability, SQLite trend history.
- Web: `--serve` FastAPI + SSE dashboard, plus a React SPA (`frontend/`).
- Frameworks: MITRE ATLAS, OWASP LLM Top 10 + Agentic, NIST AI RMF, SOC2/ISO42001/EU AI Act.

### Added — safety, robustness, packaging (hardening pass)
- **Authorization gate** on all offensive paths (`--i-am-authorized` / `CRUCIBLE_AUTHORIZED`;
  `--ci` does not bypass).
- **Rules of Engagement** scope confinement (`.crucible-roe.yaml`, `--roe`).
- **Append-only audit trail** (`.crucible-audit.jsonl`).
- **PII/secret scrubbing** of saved response bodies under `--anonymize`; AgentHound raw
  blob redaction.
- Client-side rate limiting (`--rps` / `--delay`) and configurable `--timeout`.
- CI (`.github/workflows/ci.yml`) runs the suite on py3.10–3.12 + pip-audit + CycloneDX
  SBOM; Dependabot for pip + actions.

### Fixed
- HTTP engine retries transient 5xx/529/connection failures (backoff + jitter +
  `Retry-After`), so a transient error no longer becomes a false `ERROR` that skews ASR.
- `--max-calls` is now a hard ceiling under `--concurrency` (atomic reservation).
- Saved JSON + `--retry-failed` round-trip preserve `detected_failure_mode` /
  `task_completed` / ASR fields (previously silently dropped).
- `--extra-header` and `--schema custom` overrides now apply on `--compare` / `--auto`.
- `--offline` host check parses the URL host (no more `localhost.evil.com` bypass).
- Single-sourced version (`--version` → `crucible 3.0.0`); console script `crucible`.
- `SILENT` / `PARTIAL_REFUSAL` verdicts now render coloured everywhere.

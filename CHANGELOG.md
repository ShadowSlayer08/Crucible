# Changelog

All notable changes to REDai (AI Red Team CLI). Format follows
[Keep a Changelog](https://keepachangelog.com/); this project uses date-stamped
milestones rather than published releases (source-available, not on PyPI).

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

### Added — full stack & reporting
- Model-artifact supply-chain scanner (`--model-scan`) and active model-stealing
  engine (`--extract`).
- AgentHound bridge: `--recon` / `--full-stack` discover exposed AI infra and sweep
  it, emitting one unified infra+behaviour report (JSON + SARIF) with correlated
  chained findings and an attack-path graph.
- Reporting: JSON / CSV / SARIF 2.1.0 / PDF; ASR@1/@N with Wilson CIs, coverage grids,
  benchmark deltas, threat ontology, transferability, SQLite trend history.
- Web: `--serve` FastAPI + SSE dashboard, plus a React SPA (`frontend/`).
- Frameworks: MITRE ATLAS, OWASP LLM Top 10 + Agentic, NIST AI RMF, SOC2/ISO42001/EU AI Act.

### Added — safety, robustness, packaging (hardening pass)
- **Authorization gate** on all offensive paths (`--i-am-authorized` / `AI_RT_AUTHORIZED`;
  `--ci` does not bypass).
- **Rules of Engagement** scope confinement (`.ai-redteam-roe.yaml`, `--roe`).
- **Append-only audit trail** (`.ai-redteam-audit.jsonl`).
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
- Single-sourced version (`--version` → `redai 3.0.0`); console script `redai`.
- `SILENT` / `PARTIAL_REFUSAL` verdicts now render coloured everywhere.

# AI Red Team CLI — Roadmap v6

> Generated 2026-06-21. Supersedes the Phase-5/5.5 spreadsheets in `docs/`.
> Tracks the **remaining** work only (61-item research backlog) plus the new
> **SLM/LLM dual-track** grounded in the local Ollama setup.

**Current state:** v3.0 · 20+ attack modes · 942 passing tests · framework coverage
(MITRE ATLAS / OWASP LLM Top 10 / NIST AI RMF / Llama Guard S1–S14) · dynamic PAIR
engine + mutator + ε-greedy bandit · FastAPI server + dashboard · SQLite trend.

**Legend:** ✅ done · ◑ partial · ✗ missing · ⟳ built-different · ⛔ deferred (infra/ToS)

---

## Local model inventory (checked 2026-07, Ollama v0.30.10 @ `localhost:11434`)

| Model | Size | Ctx | Caps | Role in the red-team lab |
|-------|------|-----|------|--------------------------|
| `hauhaucs-cybersec-27b:latest` | 27.4B | 256K | completion, **tools**, **thinking** | **Primary attacker + judge** (uncensored, reasons well) |
| `hf.co/Jiunsong/supergemma4-26b-uncensored-gguf-v2:Q4_K_M` | 25.2B | 256K | completion | **Second attacker / cross-judge** (diversity; judges the 27B's attacks to cut self-bias) |
| `qwen2.5:7b` | 7.6B | 32K | completion, **tools** | **SLM target** (small, aligned-ish, tool-capable) |
| `bge-m3:latest` | 566M | 8K | **embedding** | **Embeddings** → real DBSCAN diversity (#37), RAG/vector-store poisoning, semantic dedup |

Key: two uncensored large models (attacker + independent judge), one small aligned target,
one embedding model — a complete local lab. Only the *target's* API burns tokens when the
target is remote; all-local runs are free.

---

## Stage A — Payload Intelligence Foundation  *(linchpin; unblocks B)*

Add metadata to every existing suite (`vapt`, `redteam`, `atlas`, and the v3.0 modes).
Mechanical but high-leverage — parallelisable one agent per file.

| ID | Task | Roadmap # | Effort | Status |
|----|------|-----------|--------|--------|
| A1 | Add `source` / `effectiveness_tier` (A–D) / `last_validated` / `model_targets` to every test dict | #43 | M | ✗ |
| A2 | Add `failure_mode_target` (partial_refusal / hidden_compliance / no_output / misleading / silent) | #44 | M | ✗ |
| A3 | Add `llama_guard_category` (S1–S14) to **all** suites (today only policy + memory-poison) | #45 | M | ✗ |
| A4 | `LG_CATEGORY_NAMES` map + validation in corpus-integrity tests | #45 | S | ✗ |

## Stage B — Coverage, Failure-Mode & Source Reporting  *(depends A)*

| ID | Task | Roadmap # | Effort | Status |
|----|------|-----------|--------|--------|
| B1 | Coverage score across **all** modes (not just policy) once A3 lands | #36 | S | ◑ |
| B2 | Failure-mode detection in `classifier.py` + `detected_failure_mode` field | #44 | S | ✗ |
| B3 | FAILURE MODE DISTRIBUTION ASCII bar/pie section in reporter | #57 | S | ✗ |
| B4 | Source-audit pre-check: warn if >30% D-tier; `--force-stale` / `--skip-source-audit` | #48 | S | ✗ |
| B5 | PAYLOAD QUALITY AUDIT report section + JSON `payload_quality_audit` | #61 | S | ✗ |
| B6 | CR / completion-rate: follow-up judge probe in agent/rag modes; `task_completed` field | #40 | M | ✗ |

## Stage C — Pre-Run Targeting  *(enables the SLM/LLM router in Stage D)*

| ID | Task | Roadmap # | Effort | Status |
|----|------|-----------|--------|--------|
| C1 | `--profile-capabilities`: 5 probes (base64 decode, instruction-follow, multi-step, injection-resistance, knowledge-scope) → CAPABILITY PROFILE table | #50 | M | ✅ |
| C2 | Recommended-skip hint when the capability probe says the target resists this mode | #50 | S | ✅ |
| C3 | `--scope-wizard`: 5-question deployment questionnaire → RECOMMENDED TEST PLAN → recommended `--mode` set | #49 | M | ✅ |
| C4 | `--optimize-length`: pad/trim payloads to the 80–180 token band; logs original/adjusted | #46 | S | ✅ |

## Stage D — SLM / LLM Dual-Track (Ollama-powered)  *(NEW — see plan below)*

| ID | Task | Effort | Status |
|----|------|--------|--------|
| D1 | Ollama preflight: ping `/api/tags`, verify model tag exists, friendly error if down | S | ✗ |
| D2 | `--local-attacker` convenience flag → sets `--dynamic --attacker-endpoint http://localhost:11434 --attacker-model hauhaucs-cybersec-27b:latest` | S | ✗ |
| D3 | `--local-judge` convenience flag → sets `--judge --judge-schema ollama --judge-endpoint localhost:11434 --judge-model <cyber27b>` | S | ✗ |
| D4 | `--profile slm` / `--profile llm` presets that bundle the right mode set + `--samples` (driven by C1) | M | ✗ |
| D5 | Long-context routing: when target context ≥ 32K (the 27B is 256K), auto-enable `--mode rag-long --context-tokens 32000` | S | ✗ |
| D6 | Tool-capability routing: when target advertises `tools`, include `mcp` + `agentic` modes | S | ✗ |
| D7 | Benchmark routing: pick SLM baselines (Qwen/Gemma/DeepSeek) vs LLM baselines (GPT-4/Claude) by param-size | S | ◑ |

## Stage E — Metric & Report Polish

| ID | Task | Roadmap # | Effort | Status |
|----|------|-----------|--------|--------|
| E1 | `--mode benign --actor benign\|adversarial\|both` | #30 | S | ✅ |
| E2 | Per-language ASR breakdown table (multilingual) | #52 | S | ✅ |
| E3 | Explicit "⚠️ REGRESSION DETECTED" / "✓ ALIGNMENT IMPROVEMENT" banner | #58/#51 | S | ✅ |
| E4 | `--export-history` CSV | #51 | S | ✅ |
| E5 | Inline `[NIST][OWASP][ATLAS]` tags per FAIL (via `--threat-ontology`) | #59 | S | ✅ |
| E6 | INDUSTRY BENCHMARK table in the **PDF** export | #60 | S | ✅ |
| E7 | Real bge-m3 embedding diversity (H4) alongside the stdlib Jaccard version | #37 | M | ✅ |
| — | TopicGuard output filter — rounds out the G7 guardrail set | — | S | ✅ |

## Stage F — Platform & Research Tier  *(largest; decisions needed)*

| ID | Task | Roadmap # | Effort | Status |
|----|------|-----------|--------|--------|
| F1 | `generate_policy_attacks()` — `policy_gen.py` + `--generate-policy --gen-n N` synthesises S1–S14 attacks via the local 27B | #28 | M | ✅ |
| F2 | Web UI — zero-build dashboard (`web/index.html`) **and** a React + Vite SPA (`frontend/`), both over the FastAPI backend (CORS + SSE live streaming) | #25 | L | ✅ |
| F3 | Vector-DB-backed semantic corpus (embedding retrieval) | — | L | ⛔ |
| F4 | Browser `--browser-target` named presets (NOT credential login — ToS) | #23 | M | ⟳ |

## Stage G — Beyond-roadmap hardening  *(net-new attack surface)*

| ID | Task | Effort | Status |
|----|------|--------|--------|
| G1 | Agentic **Planning Manipulation** category (AGT-025..030: plan injection, objective drift, loop DoS, feedback-loop poisoning, plan-escalation, cascading blast-radius) — closes the audit's agentic divergence | S | ✅ |
| G2 | `modelscan.py` — model-artifact **supply-chain scanner** (ATLAS AML.T0010): static pickle-opcode inspection for deserialization RCE (`GLOBAL`/`REDUCE` → `os.system`/`eval`/`subprocess`…), torch-zip container walk, `trust_remote_code`/`auto_map` config flags, safetensors safe-by-format. `--model-scan PATH`, exits 1 if dangerous, never loads the artifact. This is the artifact/supply-chain layer nothing else in the tool touched. | M | ✅ |
| G3 | **Model-stealing** — behavioural suite `payloads/model_stealing.py` (`--mode model-theft`, MS-001..012: extraction / inversion / membership) **and** the active multi-query engine `extraction.py` (`--extract`): decoding-determinism fingerprint (clone-feasibility), system-prompt/param exfiltration, training-data inversion (verbatim/PII/secret recall + PII scan), and a membership recognition-gap test (Mann-Whitney AUC over member-vs-control verbatim overlap). ATLAS AML.T0024/T0018, OWASP LLM10/LLM06. Validated live on qwen2.5:7b (membership WEAK, AUC 0.72 — real memorization detected). | L | ✅ |
| G4 | **Phase-5.5 spec-clean** — closed 4 micro-gaps from the 61-item audit: (#38) `trend.py` now persists an `n_silent` column with in-place migration for old DBs; (#39) `--metrics` prints a **MOST STEALTHY ATTACKS** ranking (`metrics.most_stealthy_attacks`, HIGH/MED/LOW); (#43) new `--sort-by-tier` runs Tier-A payloads first; (#49) new `--yes`/`--yes-all` makes `--scope-wizard` flow into a run instead of exiting. | S | ✅ |
| G5 | **Phase-6A local-first / air-gap** (#62/63/64/66) — `local_engine.py` `LocalLLMEngine` over Ollama (stdlib only): `is_available`/`list_models`/`chat_models`/`pick_model`/`pull_model`, `generate`/`run_attack`/`run_mutation`/`run_judge`, `detect_hardware` (nvidia-smi/RAM/CPU) + `recommend_model`. New flags `--local` (auto-point at localhost:11434, auto-pick a pulled model, no API key), `--offline` (air-gap: `engine.set_offline` central guard refuses any non-local endpoint; forces local judge), `--judge-local`/`--judge-local-model` (LLM-as-judge on Ollama). Whole loop — generate → fire → judge → mutate — runs offline. Validated live on qwen2.5:7b (GPU auto-detected, 11 probes, ASR 0% with CI, zero external calls). | M | ✅ |
| G6 | **Phase-6B self-growing knowledge base** (#67/69/70/72/82) — `kb/` package: `RedTeamKB` lean vector store on **bge-m3 + SQLite** (NO chromadb; token-Jaccard fallback so it works offline-lite + unit-tested with no daemon). Static payload suites **seed** it (`seed_all`: 317 attacks + 22 ATLAS + 10 OWASP); ATLAS/OWASP indexed from the repo's own data. Self-reinforcing loop wired into `dynamic_engine`: KB-augmented generation (attacker retrieves proven winners + crafts a custom opener) and **grow-on-win** (a FAIL with classifier confidence ≥ threshold is written back). New flags `--evolve` (= `--dynamic --kb-augmented --kb-grow`), `--kb-augmented`/`--kb-grow`/`--kb-grow-threshold`, `--kb-seed`/`--kb-stats`/`--kb-search`/`--kb-reset`. Validated live: qwen crafted a `kb-augmented-initial` payload that broke the target round 1 → KB grew 317→318, semantic search live over bge-m3. | L | ✅ |
| G7 | **Phase-6C SLM pipeline** (#73/75/76/77/78/81) — `slm/` package turns KB winners into a fine-tuned local attacker. `dataset_collector.py` (`--slm-collect`) → JSONL (attack + judge examples); `train.py` LoRA/Unsloth Phi-3 scaffold (guarded, GPU-bound); `export.py` merge→GGUF→Ollama Modelfile scaffold (`build_modelfile_text` pure); `evaluate.py` **SLM-vs-base A/B** benchmark over Ollama (the SHIP/KEEP/INCONCLUSIVE decision on ±5% Δ ASR — runnable, no GPU); `versioning.py` SQLite model registry (register/promote/rollback/diff). `colors.force_utf8()` added for the module CLIs. Runnable parts verified live/tested (A/B on qwen: Δ+0.0% → INCONCLUSIVE, correct); training/export are honest operator-run scaffolds (no torch/GPU here). See `slm/README.md`. | L | ✅ |
| G8 | **Phase-6C MoE merge** — `slm/merge.py`: fuse per-family expert SLMs into one model via mergekit — `build_moe_config` (mergekit-moe router with per-family `positive_prompts`) / `build_merge_config` (SLERP/TIES/DARE/linear/task-arithmetic weight merge), `render_config` (JSON = valid YAML), `check_env`, `run_merge`/`merge_experts` (guarded, GPU-bound). CLI `python -m slm.merge --experts a,b,c --method moe [--dry-run/--check-env]`. Config-building pure + tested (+11); the merge itself is an operator/GPU scaffold, not run here. This is the "combine the experts into one powerful attacker" step. Full suite: 1631 passed, 1 skipped. | M | ✅ |

---

## SLM vs LLM Execution Plan (using `hauhaucs-cybersec-27b:latest`)

**Principle:** the local uncensored 27B is your **attacker + judge** (free, never refuses);
the **target** swaps between a small local model (SLM) and a frontier API (LLM). Only the
target spends API tokens, so dynamic rounds / high `--samples` are essentially free.

### Profile A — SLM target (small/local, weak capability)
- Run via `--schema ollama`. Emphasise: `redteam`, `policy` (S1–S14), `multilingual`, `benign`.
- Skip obfuscation / long-context **if** the base64 capability probe (C1) fails.
- High `--samples 10` (cheap). Watch the **SILENT** rate. Benchmark vs SLM baselines.
```bash
python main.py --mode redteam --schema ollama \
  --endpoint http://localhost:11434 --model phi3:mini --skip-connection-test \
  --samples 10 --coverage --metrics \
  --dynamic --attacker-endpoint http://localhost:11434 --attacker-model hauhaucs-cybersec-27b:latest
```

### Profile B — LLM target (frontier API, strong capability)
- Full surface: `mcp` + `agentic` + `rag` + `swarm`, `rag-long` (32K), `obfuscation`, `multimodal`, `policy`.
- Lower `--samples` (cost). Local 27B as attacker **and** judge:
```bash
python main.py --mode policy --samples 5 --coverage --benchmarks --threat-ontology \
  --schema anthropic --endpoint https://api.anthropic.com --model claude-sonnet-4-6 --api-key $KEY \
  --dynamic   --attacker-endpoint http://localhost:11434 --attacker-model hauhaucs-cybersec-27b:latest \
  --judge --judge-schema ollama --judge-endpoint http://localhost:11434 --judge-model hauhaucs-cybersec-27b:latest
```

### Profile C — test the cybersec 27B itself (as TARGET)
Expect heavy FAILs — it's uncensored by design; useful as a worst-case / unsafe baseline.
```bash
python main.py --mode redteam --owasp --nist --coverage \
  --schema ollama --endpoint http://localhost:11434 --model hauhaucs-cybersec-27b:latest --skip-connection-test
```

### Why the 27B fits each role
| Capability | Used for |
|------------|----------|
| Uncensored | Attacker generates mutations + judge grades, without refusing (Stages D2/D3) |
| 256K context | Can be a long-context attack target **and** the attacker can reason over big transcripts (D5) |
| `tools` | Enables `mcp` / `agentic` testing against it (D6) |
| `thinking` | Better PAIR mutation quality in `--dynamic` |

---

## Stage G — DeepTeam parity  *(from analysing confident-ai/deepteam)*

| ID | Task | Effort | Status |
|----|------|--------|--------|
| G1 | Authorization vuln pack — `--mode authz` (BOLA/BFLA/RBAC/SSRF/debug/shell/cross-context) | S | ✅ |
| G2 | DeepTeam attack framings in `PayloadMutator` — math-problem, adversarial-poetry, emotional-manipulation | S | ✅ |
| G3 | OWASP **Agentic** Top 10 map — `owasp_agentic.py` + `--owasp-agentic` (AAI-T1..T15 coverage) | S | ✅ |
| G4 | **Tree Jailbreaking (TAP)** — `--tap` branch→prune-off-topic(bge-m3)→query→score→prune-by-width, over the AttackerLLM | M | ✅ |
| G5 | **Bad Likert Judge** attack — `bad_likert_judge` mutator (elicit-via-scoring-rubric) | S | ✅ |
| G6 | **Declarative Vulnerability × Attack** — `declarative.py` + `--vuln A,B --attack X,Y` (14 vulns × 14 attacks) + `--list-vulns` | L | ✅ |
| G7 | **Production guardrails** — `--guardrails` input (PromptInjection/Jailbreak) + output (Privacy/Secrets/Toxicity/CodeExec) filters + purple-team block-rate vs FP-rate report | L | ✅ |
| G8 | Import **BeaverTails / Aegis** as tier-A payload sources (real provenance for Stage A metadata) | M | ✗ |
| — | *Not taking:* LLM-judge-as-primary-classifier (rule-first is an advantage) · Confident-AI SaaS/cloud plane · DeepEval callback system | — | ⛔ |

## Stage H — Multi-Model Ollama Orchestration  *(uses all 4 local models)*

| ID | Task | Effort | Status |
|----|------|--------|--------|
| H1 | `--local-attacker` / `--local-judge` presets pinned to the cybersec-27B | S | ✗ |
| H2 | **Cross-judge**: attacker = 27B, judge = supergemma-26B (independent model → less self-scoring bias) via existing `--judge-*` flags | S | ✗ (works today, make it a preset) |
| H3 | **Ensemble attacker**: rotate attacker model per `--dynamic` round (27B ↔ 26B) for mutation diversity | M | ✗ |
| H4 | `bge-m3` embeddings backend for real DBSCAN diversity (#37) + semantic dedup of FAIL payloads | M | ✅ |
| H5 | `bge-m3`-driven RAG/vector-store poisoning — `--vector-poison`: in-memory retriever, poison docs vs benign queries, retrieval-hijack rate (OWASP LLM08) | M | ✅ |
| H6 | `--profile slm\|llm` auto-routing — mode set + default `--samples`; drops modes the capability probe rejects | M | ✅ |

## Suggested sequencing

1. **A** (metadata) → unblocks **B** (coverage/failure-mode/source reports).
2. **C** (capability profiler + scope wizard) → unblocks **D** (SLM/LLM auto-routing).
3. **D** in parallel with **E** (small polish flags).
4. **F** last (React SPA / vector DB / policy-gen) — needs product/infra decisions.

Recommended first build: **A1–A4 + C1 + D1–D3** — that lands the metadata foundation and
makes the local-Ollama SLM/LLM workflow one-flag (`--local-attacker` / `--profile slm|llm`).

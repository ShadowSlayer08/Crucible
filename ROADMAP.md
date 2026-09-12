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
| G9 | **Research-backlog gap closure** — the 4 real gaps from the 30-item research backlog: (#12) few-shot poisoning expanded 3→8 `AT-POI` tests; (#22) `notify.py` + `--alert-email` (SMTP via env, alongside Slack) on watch regressions; (#28) `remediation.py` + `--recommend` — defensive "teaching prompt" recommendations per failure class (TUD-ARTS idea), keyed by Llama-Guard S-code / category; (#25) `corpus.py` + `--load-corpus FILE [--corpus-format/--corpus-prompt-col/--corpus-limit/--corpus-to-kb]` — ingest an external prompt corpus (e.g. WildJailbreak TSV/JSONL/CSV) as tests and optionally seed the KB. The 7 training-time/supply-chain ATLAS techniques remain correctly out-of-scope for a black-box tool (T0010 now covered by modelscan, T0024/T0025 by the model-stealing engine). +33 tests; full suite 1664 passed, 1 skipped. | M | ✅ |
| G10 | **Full-stack: AgentHound bridge** — `agenthound.py` wraps [AgentHound](https://github.com/adithyan-ak/AgentHound) (Apache-2.0, Go) — the *infrastructure* layer ("BloodHound for the agentic stack") that maps exposed MCP/LiteLLM/Ollama/vLLM/Qdrant/MLflow/Jupyter/Open-WebUI services, credential chains and attack paths — and folds its findings into REDai's *behavioural* layer. `run_scan` (guarded subprocess, degrades if the binary is absent), tolerant `parse` (schema-variant JSON → normalized findings + endpoints + paths, ATLAS/OWASP-tagged), `to_targets` (discovered LLM/agent endpoints → REDai targets with inferred schema + suggested `--mode`; infra-only stores excluded), `print_recon_report`. New flags `--recon` (run AgentHound over `--recon-scope`, `--recon-mode stealth\|active`), `--recon-input FILE` (ingest an existing scan, fully offline), `--recon-to-targets` (save discovered endpoints to the target book), and **`--full-stack`** (recon → auto-save targets → print the per-endpoint behavioural sweep plan — one tool, infra + behaviour under shared frameworks). AgentHound stays an upstream project (wrapped, never forked); offensive/authorized-use only, behind REDai's authorization gate. Parsing/mapping pure + tested (+9), end-to-end verified via `--recon-input`; the Go binary + live infra scan are operator-run. | M | ✅ |

### Improvement-audit backlog *(7-dimension multi-agent audit → ranked, verified with file:line evidence)*

| ID | Task | Effort | Status |
|----|------|--------|--------|
| G11 | **Slice A — safety hardening of the offensive paths.** (A1) `require_authorization()` gate now guards `--recon`/`--full-stack`/`--recon-input`, `--extract` and `--discover`; new `--i-am-authorized` flag + `AI_RT_AUTHORIZED=1` for non-interactive use, and — unlike `--auto` — `--ci` does NOT bypass these (fails closed). (A2) `agenthound.redact_secrets()` masks credential-like fields; recon reports omit AgentHound's raw blob by default (`--recon-save-raw` includes it, redacted); `--recon-input` keeps the ingested doc as `raw` so the opt-in is meaningful. (A3) `engine._is_local_url` now parses the host (loopback/unspecified + known local names) instead of substring-scanning the URL, so `localhost.evil.com` / `api.openai.com?x=127.0.0.1` / `169.254.169.254` are no longer treated as local. (A4) `engine.set_rate()`/`_throttle()` thread-safe client-side pacing inside `run_test` (covers extraction too); new `--rps`/`--delay`, default unlimited. +28 tests (`tests/test_safety.py`). | M | ✅ |
| G12 | **Slice B — honest SLM eval + closed-loop pipeline.** (B1) `slm/evaluate.py` rewired: `score_payloads` fires N samples/payload (ASR@1 + ASR@N) with a **per-category** breakdown; `ab_compare` accepts **multiple targets** (per-target + pooled ASR); new `ci_decision()` replaces the arbitrary ±5% gate with a **Wilson-CI ship gate** (SHIP only when the SLM's ASR CI is entirely above the base's) reusing `stats.wilson_ci`; `--samples` + comma-separated `--target`. (B2) new `slm/pipeline.py` (`python -m slm.pipeline`) chains collect → train → export → evaluate → **register + promote IFF SHIP** (the eval verdict is the automated promotion gate); `--skip-train` runs collect→eval→gate over an existing SLM with no GPU. +12 tests. train/export stay GPU-operator scaffolds. | M | ✅ |
| G13 | **Slice C — attack coverage pack** (closes the biggest depth gaps vs 2024–2025 research). (C1) `payloads/modern_jailbreaks.py` — **Policy Puppetry / Skeleton Key / Deceptive Delight** (12 probes, `--mode modern-jailbreak`) + the same three as `PayloadMutator` framings and declarative `--attack` transforms. (C2) **refusal-suppression** mutator (affirmative-prefix + banned refusal tokens) as a mutator + `RefusalSuppression` transform. (C3) `payloads/many_shot.py` — **many-shot jailbreak** (`--mode many-shot`, `build_many_shot`): fabricated compliant dialogue at escalating shot counts 4/8/16/32 → the shot-count→ASR curve. (C4) `crescendo.py` — **Crescendo adaptive multi-turn** (`--crescendo --crescendo-goal …`): an attacker LLM grows a conversation, derives each next turn from the target's own replies, escalates toward the goal, and **backtracks on refusal**; transport-agnostic core (fully unit-tested with fakes) + live wiring over the multi-turn transport + shared classifier; gated by `require_authorization`. `all_mutations` 12→16. +23 tests; verified live end-to-end. | L | ✅ |
| G14 | **Slice D — finish the full-stack merge** (infra ↔ behaviour, one tool, one report). (D1) `reporter.save_sarif(infra_findings=…)` folds AgentHound findings into the SARIF run (rules + results tagged `layer:infra`, ATLAS/OWASP), so CI code-scanning surfaces both layers. (D2) `--full-stack` now **runs the behavioural sweep** — `fullstack.sweep_targets()` fires REDai's red-team at each discovered endpoint via subprocess self-invocation (injectable/testable; `--no-sweep` keeps the plan-only path). (D3) `fullstack.build_unified_report()` merges infra findings/endpoints/paths + behavioural summaries into ONE `fullstack_<ts>.json` (+ `.sarif`) with a combined risk posture. (D4) `fullstack.correlate()` chains the layers (reachable **and** exploitable → escalated CRITICAL, linked to the infra finding id); `render_attack_paths()` emits an ASCII chain + Mermaid graph from the previously-unused path edges; `targets.save_target(extra=…)` persists recon context (service/mode/auth/source) so findings attribute back. +7 tests; verified live end-to-end (recon → sweep → unified JSON+SARIF). | L | ✅ |

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

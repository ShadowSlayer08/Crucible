# SLM Pipeline — a self-improving local red-team model (Phase 6C)

REDai discovers attacks, keeps the winners in a knowledge base (Phase 6B), and
this pipeline turns those winners into a **fine-tuned local attacker model** that
makes the *next* run stronger. The loop:

```
static payloads ─seed→ KB ─┐
                           │  --evolve : attacker crafts custom payloads, KB-augmented
   target ◀── attack ◀─────┤            wins (>50% conf) written back to the KB
                           │
   KB winners ──collect──▶ dataset.jsonl ──train──▶ LoRA adapter ──export──▶ Ollama model
                                                          │
                                                   evaluate (A/B) : is it actually better?
                                                          │
                                                   versioning : promote / rollback
```

## What runs where

| Stage | Module | Runs in CI / no GPU | Needs a GPU box |
|-------|--------|:---:|:---:|
| Collect wins → JSONL | `dataset_collector.py` (`--slm-collect`) | ✅ | |
| **A/B benchmark** (the decision number) | `evaluate.py` (`python -m slm.evaluate`) | ✅ (Ollama) | |
| Version registry | `versioning.py` (`python -m slm.versioning`) | ✅ | |
| Build the Modelfile | `export.build_modelfile_text` | ✅ | |
| **LoRA fine-tune** | `train.py` | | ✅ torch + unsloth |
| Merge + GGUF + `ollama create` | `export.py` | | ✅ llama.cpp + ollama |
| Build the merge config (MoE/weight) | `merge.build_*_config` | ✅ | |
| **Merge experts → one model** | `merge.py` | | ✅ mergekit + torch |

The training stages are **honest scaffolds**: every heavy import is guarded, and
they print a clear requirements message + return `{"ok": False, ...}` if torch /
unsloth / llama.cpp / a CUDA GPU is missing. They were **not** executed in this
repo (no GPU here) — run them on your machine.

## End-to-end (on your RTX box)

```bash
# 1. grow the KB and collect training data (repeatable — the corpus compounds)
python main.py --evolve --local --mode redteam        # attack + grow the KB
python main.py --slm-collect                           # KB winners -> slm/training_data/dataset.jsonl

# 2. fine-tune (needs GPU + unsloth/peft)
python -m slm.train --dataset slm/training_data/dataset.jsonl --base-model microsoft/Phi-3-mini-4k-instruct --epochs 3
python -m slm.train --check-env                         # verify torch/CUDA first

# 3. deploy to Ollama
python -m slm.export --checkpoint slm/checkpoints/latest --model-name redai-slm
#   → ollama run redai-slm

# 4. PROVE it's better before trusting it (no GPU needed)
python -m slm.evaluate --base microsoft/Phi-3-mini-4k-instruct --slm redai-slm --target qwen2.5:7b
#   → Δ ASR and a SHIP / KEEP / INCONCLUSIVE recommendation

# 5. record + promote the version
python -m slm.versioning list
python -m slm.versioning promote <version_id>
```

## Measurement-first

The whole premise — "train on our own wins, get stronger" — is only real if the
A/B in step 4 shows a positive Δ ASR. `evaluate.py` produces that number honestly
(same probes, same target, shared classifier) and **recommends KEEP if fine-tuning
regressed**. Don't promote a version the A/B doesn't back. Self-improvement loops
can plateau or mode-collapse; this harness is how you find out.

## Mixture-of-Experts (`merge.py`)

When you have several strong per-family SLMs (one trained on each attack family's
KB winners), `merge.py` builds the mergekit config to fuse them:

```bash
# MoE: keep each expert whole, route by prompt (a true mixture-of-experts)
python -m slm.merge --experts redai-slm-inject,redai-slm-jailbreak,redai-slm-rag \
    --base-model microsoft/Phi-3-mini-4k-instruct --method moe --dry-run   # preview the plan+config
python -m slm.merge --experts ... --method moe                             # run (needs mergekit + GPU)

# or a weight merge (SLERP / TIES / DARE / linear / task_arithmetic)
python -m slm.merge --experts a,b,c --method ties
python -m slm.merge --check-env                                            # probe mergekit/torch first
```

Config building / rendering / routing is **pure and unit-tested** here; the merge
itself is GPU-bound (mergekit + torch) and, like training, is **not** run in this
repo. After a merge: `export.py` → GGUF/Ollama, then `evaluate.py` to confirm the
merged model actually out-attacks its parts before you promote it.

> Scope note: the attacker/SLM generates adversarial **test probes** — the jailbreak
> *attempts* a red-teamer sends to measure a target's safety — not weaponizable
> content. Authorized testing only (see the project ethics section in `CLAUDE.md`).

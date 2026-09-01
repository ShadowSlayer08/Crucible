# HANDOFF → your GPU box

Everything up to fine-tuning is built, tested, and runs in CI. This is the runbook
for the GPU-bound tail: **train → export → prove → (optionally) merge**. Follow it
on the machine with the GPU. Nothing here was executed in the dev environment (no
GPU there), so treat the first run of each step as the real verification.

---

## 0. Your hardware (detected)

```
16 cores · 66.2 GB RAM · 11.9 GB GPU (NVIDIA) · Windows 11
```

- **11.9 GB VRAM is plenty for the default base** (`microsoft/Phi-3-mini-4k-instruct`,
  3.8B) with 4-bit LoRA. Don't jump to a 7B+ base unless you go to a bigger card.
- **Windows caveat:** `unsloth` targets Linux; on native Windows use the **peft
  fallback** (already built into `train.py`) or run the training inside **WSL2**.
  If either fights you, a cloud GPU (Colab/RunPod) with the same commands is fine —
  only step 2 needs the GPU; steps 1, 3-6 you can run back on this box.

---

## 1. Set up (once)

```bash
git pull                                   # get slm/ + kb/ + the local engine
# CUDA PyTorch first (match your CUDA), from https://pytorch.org , e.g.:
pip install torch --index-url https://download.pytorch.org/whl/cu121
pip install -r requirements-slm.txt        # transformers/peft/trl/bitsandbytes/mergekit
python -m slm.train --check-env            # MUST print ok:True (torch + CUDA found)
```

`--check-env` printing `ok: False` means torch/CUDA isn't visible — fix that before
going further (it's the #1 time-sink). For GGUF export later, also
`git clone https://github.com/ggerganov/llama.cpp` and build it (set `LLAMA_CPP_DIR`).

---

## 2. Bootstrap the training data (grow the KB, then collect)

The SLM trains on attacks **the tool actually found**. Grow the corpus first. Use a
strong local attacker and a target that will sometimes comply, so you harvest real
wins (each win → a training example):

```bash
# strong uncensored attacker vs a target you're authorized to test.
# more rounds + more modes = more/richer wins in the KB.
python main.py --evolve --mode redteam \
  --attacker-endpoint http://localhost:11434 \
  --attacker-model "hf.co/Jiunsong/supergemma4-26b-uncensored-gguf-v2:Q4_K_M" \
  --local --local-model qwen2.5:7b \
  --dynamic-rounds 5

python main.py --kb-stats                  # watch attack_patterns climb
python main.py --slm-collect               # KB winners → slm/training_data/dataset.jsonl
```

Repeat `--evolve` across modes (`policy`, `rag`, `agentic`, `pismith`, `obfuscation`, …)
to diversify. Aim for **a few hundred to a few thousand** deduped examples before
training — `--slm-collect` prints the count. Thin data → a weak SLM (and the A/B in
step 4 will say so).

> Tip: seed against several targets (including the uncensored ones) to maximise wins;
> the *payload that worked* is the training signal, independent of which target it beat.

---

## 3. Fine-tune (GPU)

```bash
python -m slm.train \
  --dataset slm/training_data/dataset.jsonl \
  --base-model microsoft/Phi-3-mini-4k-instruct \
  --epochs 3
# adapter → slm/checkpoints/
```

Rough budget on ~12 GB VRAM / Phi-3-mini: minutes-to-~1 hr depending on dataset size.
**If you hit CUDA OOM:** lower `--batch-size` (try 2 or 1), raise `--grad-accum` to
keep the effective batch, and/or drop `--max-seq-length` (e.g. 1024). `train()` returns
`{"ok": False, "reason": ...}` instead of crashing if the env isn't ready — read it.

---

## 4. Export to Ollama, then PROVE it

```bash
python -m slm.export --checkpoint slm/checkpoints --model-name redai-slm
#   → merges LoRA, converts to GGUF (Q4_K_M), writes a Modelfile, `ollama create redai-slm`
#   (use --dry-run first to see the exact commands; --modelfile-only to skip the build)

# THE decision — no GPU needed, pure Ollama orchestration:
python -m slm.evaluate \
  --base microsoft/Phi-3-mini-4k-instruct \
  --slm redai-slm \
  --target qwen2.5:7b
```

Read the **Δ ASR** line and the recommendation:

| Δ ASR | Verdict | Do this |
|-------|---------|---------|
| **> +5%** | SHIP | The loop pays off. Promote it (step 6), scale to per-family experts (step 5). |
| −5%…+5% | INCONCLUSIVE | Not enough signal. Go back to step 2 — more/richer wins — and retrain. |
| **< −5%** | KEEP base | Fine-tuning regressed. Don't ship. Check for thin/low-diversity data or mode collapse. |

This A/B is the honest test of the whole premise. Don't promote a model it doesn't back.

---

## 5. (Optional) Mixture-of-Experts

Once you have several per-family SLMs (train step 3 on category-filtered datasets —
e.g. collect after `--evolve --mode rag`, `--mode pismith`, …), fuse them:

```bash
python -m slm.merge --check-env
python -m slm.merge \
  --experts redai-slm-inject,redai-slm-jailbreak,redai-slm-rag \
  --base-model microsoft/Phi-3-mini-4k-instruct \
  --method moe --dry-run          # preview the mergekit-moe config + command
python -m slm.merge --experts ... --method moe    # run it (mergekit + GPU)
# then re-run steps 4 (export + evaluate) on the merged model.
```

`--method` also accepts weight merges: `ties`, `dare_ties`, `slerp`, `linear`,
`task_arithmetic`. Always A/B the merged model against its best single expert before trusting it.

---

## 6. Record + promote the version

```bash
python -m slm.versioning list
python -m slm.versioning promote <version_id>      # sets the active model
# rollback is the same command with an older id
```

Register each trained/merged model with its eval numbers so `promote`/`rollback` and
`diff` have something to compare. (Wire the register() call into your train step, or
record manually — it's `slm/versioning.py`.)

---

## The loop, closed

```
--evolve  →  --slm-collect  →  slm.train  →  slm.export  →  slm.evaluate  →  slm.versioning
   (grow KB)     (winners→JSONL)   (LoRA)       (→ Ollama)     (A/B verdict)     (promote)
                                              ↘ slm.merge (MoE) ↗
```

Run it, then feed the new SLM back in as `--attacker-model redai-slm` on the next
`--evolve` — that's the compounding flywheel.

> **Scope:** the SLM is a red-team **attacker** that generates adversarial test
> probes for systems you are authorized to test. "Uncensored" means it won't refuse
> to generate a probe — not that it produces harmful content. See `CLAUDE.md`.

"""
slm/train.py — LoRA fine-tuning scaffold for the local red-team SLM (Phase 6C).

This takes the JSONL produced by slm/dataset_collector.py (attack-generation +
judge examples the tool discovered) and fine-tunes a small instruction model with
LoRA so the operator ends up with a *local* red-team assistant: it drafts novel
adversarial prompts and scores responses without any external API call.

Base model default: **microsoft/Phi-3-mini-4k-instruct** — a 3.8B instruct model
that trains with LoRA inside ~8 GB of VRAM (fp16 + 4-bit base). Swap it for any
HF causal-LM id via --base-model.

IMPORTANT — this file is an *operator-run scaffold*, not something that runs in
CI or in the authoring environment:
  * The heavy stack (torch, unsloth OR peft+transformers+trl) is NOT installed
    here, and there is NO GPU. Every heavy import is guarded; if a dep is missing
    or CUDA is unavailable, train() prints a clear requirements message and
    returns {"ok": False, "reason": ...} instead of crashing.
  * Nothing in this module has been executed/verified end-to-end. Treat the
    training loop as a starting point to run on your own GPU box.

Two training backends, tried in order:
  1. Unsloth  (from unsloth import FastLanguageModel) — fastest, lowest VRAM.
  2. peft + transformers + trl (SFTTrainer)          — portable fallback.

Public API:
    load_dataset(path)                 -> [example, ...]     (pure stdlib, testable)
    format_chatml(example)             -> str                (pure stdlib)
    split_holdout(examples, frac=0.1)  -> (train, val)       (pure stdlib)
    check_env()                        -> {"ok": bool, ...}  (probes torch/CUDA/deps)
    train(dataset_path=..., base_model=..., out_dir=..., ...) -> dict

Future direction (documented, NOT built here):
    Once several category-specialised adapters exist (one per attack family), they
    can be combined into a single stronger checkpoint with **mergekit**
    (SLERP / TIES / DARE merges), or wired as a lightweight **MoE** router that
    dispatches to the best adapter per attack category. That is a separate,
    heavier milestone (slm/merge.py — not written yet).
"""

import argparse
import json
import os

import colors as C

DEFAULT_DATASET = os.path.join("slm", "training_data", "dataset.jsonl")
DEFAULT_BASE_MODEL = "microsoft/Phi-3-mini-4k-instruct"
DEFAULT_OUT_DIR = os.path.join("slm", "checkpoints")

# LoRA is applied to the attention projections — the standard, portable target set.
LORA_TARGET_MODULES = ["q_proj", "k_proj", "v_proj", "o_proj"]

_SYSTEM_PROMPT = (
    "You are a local red-team assistant for authorized AI-safety testing. "
    "You generate adversarial test prompts and judge model responses."
)


# ─────────────────────────────────────────────────────────────────────────────
# DATA  (pure stdlib — importable and testable without torch)
# ─────────────────────────────────────────────────────────────────────────────
def load_dataset(path: str = DEFAULT_DATASET) -> list:
    """Read the collector's JSONL and return a list of example dicts.

    Each line is {"instruction", "input", "output", "meta"}. Blank lines and
    malformed rows are skipped (with a warning) rather than aborting the load.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"dataset not found: {path}")
    examples = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                print(C.YELLOW(f"  ! skipping malformed JSON on line {lineno}"))
                continue
            if not isinstance(obj, dict) or "instruction" not in obj or "output" not in obj:
                print(C.YELLOW(f"  ! skipping line {lineno}: missing instruction/output"))
                continue
            obj.setdefault("input", "")
            obj.setdefault("meta", {})
            examples.append(obj)
    return examples


def format_chatml(example: dict) -> str:
    """Render one example as a single ChatML training string.

    Phi-3 uses the <|user|> / <|assistant|> / <|end|> ChatML dialect; this format
    is close enough to fine-tune cleanly and stays readable for other bases.
    """
    instruction = (example.get("instruction") or "").strip()
    extra = (example.get("input") or "").strip()
    output = (example.get("output") or "").strip()
    user = instruction if not extra else f"{instruction}\n\n{extra}"
    return (
        f"<|system|>\n{_SYSTEM_PROMPT}<|end|>\n"
        f"<|user|>\n{user}<|end|>\n"
        f"<|assistant|>\n{output}<|end|>\n"
    )


def split_holdout(examples: list, frac: float = 0.1, seed: int = 1234):
    """Deterministically hold out `frac` of examples as a validation set.

    Returns (train, val). Uses stdlib random with a fixed seed so runs are
    reproducible without numpy.
    """
    import random

    items = list(examples)
    random.Random(seed).shuffle(items)
    n_val = max(1, int(len(items) * frac)) if len(items) > 1 else 0
    val = items[:n_val]
    train = items[n_val:]
    return train, val


# ─────────────────────────────────────────────────────────────────────────────
# ENVIRONMENT PROBE  (no heavy import unless present)
# ─────────────────────────────────────────────────────────────────────────────
def _has(module: str) -> bool:
    import importlib.util

    return importlib.util.find_spec(module) is not None


def check_env() -> dict:
    """Probe the training environment without importing torch unless it exists.

    Returns {ok, cuda, backend, missing, torch, note}. `ok` is True only when a
    usable backend AND CUDA are present. This never raises.
    """
    info = {
        "ok": False,
        "cuda": False,
        "backend": None,
        "missing": [],
        "torch": _has("torch"),
        "note": "",
    }

    if not info["torch"]:
        info["missing"].append("torch")
        info["note"] = "PyTorch not installed."
        return info

    # torch is present — safe to import and check CUDA.
    try:
        import torch  # noqa: WPS433 (guarded heavy import)

        info["cuda"] = bool(torch.cuda.is_available())
    except Exception as exc:  # pragma: no cover - depends on host
        info["note"] = f"torch import failed: {exc}"
        return info

    # Pick a backend: prefer unsloth, else peft+transformers+trl.
    if _has("unsloth"):
        info["backend"] = "unsloth"
    elif _has("peft") and _has("transformers") and _has("trl"):
        info["backend"] = "peft"
    else:
        for dep in ("unsloth", "peft", "transformers", "trl"):
            if not _has(dep):
                info["missing"].append(dep)
        info["note"] = "No training backend (need unsloth OR peft+transformers+trl)."
        return info

    if not info["cuda"]:
        info["note"] = "No CUDA GPU detected — LoRA fine-tuning needs a GPU."
        return info

    # GPU present, but this torch build may not support its compute capability
    # (e.g. an RTX 50-series / Blackwell sm_120 card on a torch built for <= sm_90).
    try:
        import torch  # noqa: WPS433
        major, minor = torch.cuda.get_device_capability()
        cap = f"sm_{major}{minor}"
        archs = list(torch.cuda.get_arch_list() or [])
        name = torch.cuda.get_device_name(0)
        info["gpu"] = name
        info["compute"] = cap
        if archs and cap not in archs:
            info["note"] = (
                f"{name} ({cap}) is NOT supported by this PyTorch build "
                f"(it targets {archs[0]}..{archs[-1]}). Upgrade PyTorch to a wheel with "
                f"{cap} support (Blackwell needs cu124/cu128 or a nightly build): "
                f"pip install --pre torch --index-url https://download.pytorch.org/whl/nightly/cu128")
            return info
    except Exception:
        pass  # capability probe is best-effort; fall through to ready

    info["ok"] = True
    info["note"] = f"Ready ({info['backend']} backend)."
    return info


def _requirements_message(env: dict) -> None:
    """Print an actionable install/requirements message for a not-ready env."""
    print(C.BOLD(C.RED("\n✗ Training environment not ready.")))
    print(C.DIM("  " + (env.get("note") or "")))
    if env.get("missing"):
        print(C.YELLOW("  Missing: " + ", ".join(env["missing"])))
    print(C.BOLD("\n  This scaffold runs on the operator's GPU box, not here.\n"))
    print("  Recommended setup (CUDA GPU, ~8GB+ VRAM for Phi-3-mini):")
    print(C.CYAN("    # fastest / lowest-VRAM path"))
    print("    pip install 'unsloth[cu121] @ git+https://github.com/unslothai/unsloth.git'")
    print(C.CYAN("    # portable fallback"))
    print("    pip install torch --index-url https://download.pytorch.org/whl/cu121")
    print("    pip install transformers peft trl accelerate bitsandbytes datasets")
    if not env.get("cuda"):
        print(C.YELLOW("\n  No CUDA GPU was detected. Fine-tuning is GPU-bound; "
                        "rent/borrow a GPU box and run this there."))


# ─────────────────────────────────────────────────────────────────────────────
# TRAINING BACKENDS  (all heavy imports guarded; nothing runs without a GPU)
# ─────────────────────────────────────────────────────────────────────────────
def _train_unsloth(cfg: dict, train_texts: list, val_texts: list) -> dict:
    """LoRA fine-tune via Unsloth's FastLanguageModel. Operator-run only."""
    from unsloth import FastLanguageModel  # noqa: WPS433
    from trl import SFTTrainer
    from transformers import TrainingArguments
    from datasets import Dataset

    print(C.DIM(f"  loading base model via unsloth: {cfg['base_model']}"))
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=cfg["base_model"],
        max_seq_length=cfg["max_seq_length"],
        load_in_4bit=True,
        dtype=None,  # auto (bf16 where supported)
    )
    model = FastLanguageModel.get_peft_model(
        model,
        r=cfg["lora_r"],
        lora_alpha=cfg["lora_alpha"],
        lora_dropout=cfg["lora_dropout"],
        target_modules=LORA_TARGET_MODULES,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=cfg["seed"],
    )

    train_ds = Dataset.from_dict({"text": train_texts})
    val_ds = Dataset.from_dict({"text": val_texts}) if val_texts else None

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        dataset_text_field="text",
        max_seq_length=cfg["max_seq_length"],
        args=TrainingArguments(
            per_device_train_batch_size=cfg["batch_size"],
            gradient_accumulation_steps=cfg["grad_accum"],
            num_train_epochs=cfg["epochs"],
            learning_rate=cfg["lr"],
            fp16=not _bf16_ok(),
            bf16=_bf16_ok(),
            logging_steps=10,
            optim="adamw_8bit",
            warmup_ratio=0.03,
            lr_scheduler_type="cosine",
            seed=cfg["seed"],
            output_dir=os.path.join(cfg["out_dir"], "_runs"),
            report_to="none",
        ),
    )
    trainer.train()
    model.save_pretrained(cfg["out_dir"])
    tokenizer.save_pretrained(cfg["out_dir"])
    return {"ok": True, "backend": "unsloth", "out_dir": cfg["out_dir"]}


def _train_peft(cfg: dict, train_texts: list, val_texts: list) -> dict:
    """LoRA fine-tune via peft + transformers + trl. Operator-run only."""
    import torch  # noqa: WPS433
    from transformers import (AutoConfig, AutoModelForCausalLM, AutoTokenizer,
                              BitsAndBytesConfig, TrainingArguments)
    from peft import LoraConfig, prepare_model_for_kbit_training
    from trl import SFTTrainer
    from datasets import Dataset

    print(C.DIM(f"  loading base model via transformers: {cfg['base_model']}"))
    tokenizer = AutoTokenizer.from_pretrained(cfg["base_model"], trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    # Normalize rope_scaling so a transformers<->model version skew doesn't raise a
    # bare KeyError('type') (Phi-3 configs alternate between 'type' and 'rope_type').
    conf = AutoConfig.from_pretrained(cfg["base_model"], trust_remote_code=True)
    rs = getattr(conf, "rope_scaling", None)
    if isinstance(rs, dict):
        if "type" not in rs and "rope_type" in rs:
            rs["type"] = rs["rope_type"]
        elif "rope_type" not in rs and "type" in rs:
            rs["rope_type"] = rs["type"]
        conf.rope_scaling = rs

    dtype = torch.bfloat16 if _bf16_ok() else torch.float16
    common = dict(config=conf, device_map="auto", trust_remote_code=True,
                  attn_implementation="eager")   # flash-attn not required / not installed

    def _load(four_bit: bool):
        if four_bit:
            bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                     bnb_4bit_compute_dtype=dtype,
                                     bnb_4bit_use_double_quant=True)
            return AutoModelForCausalLM.from_pretrained(
                cfg["base_model"], quantization_config=bnb, **common)
        return AutoModelForCausalLM.from_pretrained(
            cfg["base_model"], torch_dtype=dtype, **common)

    # 4-bit QLoRA is lowest-VRAM but needs bitsandbytes kernels for the GPU; on new
    # cards where bnb lags (e.g. Blackwell) fall back to a bf16 LoRA (Phi-3-mini fits ~12GB).
    want_4bit = cfg.get("four_bit", True) and _has("bitsandbytes")
    try:
        model = _load(want_4bit)
        used_4bit = want_4bit
    except Exception as exc:
        if not want_4bit:
            raise
        print(C.YELLOW(f"  4-bit load failed ({str(exc)[:120]}); "
                       "falling back to bf16 LoRA (no bitsandbytes)"))
        model = _load(False)
        used_4bit = False
    if used_4bit:
        model = prepare_model_for_kbit_training(model)
    else:
        try:
            model.gradient_checkpointing_enable()
            model.enable_input_require_grads()
        except Exception:
            pass
    print(C.DIM(f"  load mode: {'4-bit QLoRA' if used_4bit else 'bf16 LoRA'}"))

    lora = LoraConfig(
        r=cfg["lora_r"],
        lora_alpha=cfg["lora_alpha"],
        lora_dropout=cfg["lora_dropout"],
        target_modules=LORA_TARGET_MODULES,
        bias="none",
        task_type="CAUSAL_LM",
    )

    train_ds = Dataset.from_dict({"text": train_texts})
    val_ds = Dataset.from_dict({"text": val_texts}) if val_texts else None

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        peft_config=lora,
        dataset_text_field="text",
        max_seq_length=cfg["max_seq_length"],
        args=TrainingArguments(
            per_device_train_batch_size=cfg["batch_size"],
            gradient_accumulation_steps=cfg["grad_accum"],
            num_train_epochs=cfg["epochs"],
            learning_rate=cfg["lr"],
            fp16=not _bf16_ok(),
            bf16=_bf16_ok(),
            logging_steps=10,
            warmup_ratio=0.03,
            lr_scheduler_type="cosine",
            seed=cfg["seed"],
            output_dir=os.path.join(cfg["out_dir"], "_runs"),
            report_to="none",
        ),
    )
    trainer.train()
    trainer.save_model(cfg["out_dir"])
    tokenizer.save_pretrained(cfg["out_dir"])
    return {"ok": True, "backend": "peft", "out_dir": cfg["out_dir"],
            "quantized": used_4bit}


def _bf16_ok() -> bool:
    """True if the GPU supports bf16 (Ampere+). Guarded; False if torch absent."""
    try:
        import torch  # noqa: WPS433

        return bool(torch.cuda.is_available() and torch.cuda.is_bf16_supported())
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# ORCHESTRATION
# ─────────────────────────────────────────────────────────────────────────────
def train(dataset_path: str = DEFAULT_DATASET,
          base_model: str = DEFAULT_BASE_MODEL,
          out_dir: str = DEFAULT_OUT_DIR,
          epochs: int = 3,
          lora_r: int = 16,
          lora_alpha: int = 32,
          lora_dropout: float = 0.05,
          batch_size: int = 4,
          grad_accum: int = 4,
          lr: float = 2e-4,
          max_seq_length: int = 2048,
          val_frac: float = 0.1,
          seed: int = 1234,
          four_bit: bool = True) -> dict:
    """LoRA fine-tune `base_model` on the collector's JSONL and save the adapter.

    Returns a result dict. On a machine without a GPU / training backend this
    prints a requirements message and returns {"ok": False, "reason": ...}
    WITHOUT importing torch or crashing — so the scaffold is safe to invoke
    anywhere; the actual training only happens on the operator's GPU box.
    """
    print(C.BOLD(C.CYAN("CRUCIBLE · Phase 6C — local red-team SLM LoRA trainer")))

    # 1) Data first — this part is pure stdlib and always runs.
    try:
        examples = load_dataset(dataset_path)
    except FileNotFoundError as exc:
        print(C.RED(f"✗ {exc}"))
        print(C.DIM("  Generate one first:  python -m slm.dataset_collector "
                    "(or slm.collect(...))"))
        return {"ok": False, "reason": "dataset-missing", "path": dataset_path}

    if not examples:
        print(C.RED("✗ dataset is empty — nothing to train on."))
        return {"ok": False, "reason": "dataset-empty", "path": dataset_path}

    train_ex, val_ex = split_holdout(examples, frac=val_frac, seed=seed)
    train_texts = [format_chatml(e) for e in train_ex]
    val_texts = [format_chatml(e) for e in val_ex]
    by_type = {}
    for e in examples:
        t = (e.get("meta") or {}).get("type", "?")
        by_type[t] = by_type.get(t, 0) + 1
    print(C.GREEN(f"  loaded {len(examples)} examples ")
          + C.DIM(f"({by_type}) → train={len(train_ex)} val={len(val_ex)}"))

    # 2) Environment gate — never import torch unless it is actually installed.
    env = check_env()
    if not env["ok"]:
        _requirements_message(env)
        return {
            "ok": False,
            "reason": env.get("note") or "environment-not-ready",
            "env": env,
            "examples": len(examples),
        }

    # 3) Train (operator's GPU box only). Heavy imports live inside the backends.
    cfg = {
        "base_model": base_model, "out_dir": out_dir, "epochs": epochs,
        "lora_r": lora_r, "lora_alpha": lora_alpha, "lora_dropout": lora_dropout,
        "batch_size": batch_size, "grad_accum": grad_accum, "lr": lr,
        "max_seq_length": max_seq_length, "seed": seed, "four_bit": four_bit,
    }
    os.makedirs(out_dir, exist_ok=True)
    print(C.DIM(f"  backend={env['backend']}  base={base_model}  "
                f"epochs={epochs} r={lora_r} alpha={lora_alpha} bs={batch_size}"
                f"x{grad_accum} lr={lr}"))
    try:
        if env["backend"] == "unsloth":
            result = _train_unsloth(cfg, train_texts, val_texts)
        else:
            result = _train_peft(cfg, train_texts, val_texts)
    except Exception as exc:  # pragma: no cover - depends on host/GPU
        print(C.RED(f"✗ training failed: {exc}"))
        return {"ok": False, "reason": f"training-error: {exc}", "env": env}

    result.update({"examples": len(examples), "train": len(train_ex),
                   "val": len(val_ex), "config": cfg})
    print(C.BOLD(C.GREEN(f"✓ adapter saved → {out_dir}")))
    print(C.DIM("  Next: quantise/export for the local engine (slm/export.py), "
                "then load via Ollama / local_engine."))
    return result


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="slm.train",
        description="LoRA fine-tune a local red-team SLM on tool-discovered attacks "
                    "(Phase 6C). Operator-run; needs a CUDA GPU.")
    p.add_argument("--dataset", default=DEFAULT_DATASET,
                   help=f"training JSONL (default: {DEFAULT_DATASET})")
    p.add_argument("--base-model", default=DEFAULT_BASE_MODEL,
                   help=f"HF base model id (default: {DEFAULT_BASE_MODEL})")
    p.add_argument("--out-dir", default=DEFAULT_OUT_DIR,
                   help=f"where to save the LoRA adapter (default: {DEFAULT_OUT_DIR})")
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--lora-r", type=int, default=16)
    p.add_argument("--lora-alpha", type=int, default=32)
    p.add_argument("--lora-dropout", type=float, default=0.05)
    p.add_argument("--batch-size", type=int, default=4)
    p.add_argument("--grad-accum", type=int, default=4)
    p.add_argument("--lr", type=float, default=2e-4)
    p.add_argument("--max-seq-length", type=int, default=2048)
    p.add_argument("--val-frac", type=float, default=0.1)
    p.add_argument("--seed", type=int, default=1234)
    p.add_argument("--check-env", action="store_true",
                   help="probe torch/CUDA/backend and exit (no training)")
    p.add_argument("--no-4bit", action="store_true",
                   help="skip 4-bit QLoRA (bitsandbytes) and use a bf16 LoRA instead "
                        "— use when bitsandbytes lacks kernels for your GPU (e.g. Blackwell)")
    return p


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    C.init(True)
    try:
        C.force_utf8()
    except Exception:
        pass

    if args.check_env:
        env = check_env()
        if env["ok"]:
            print(C.GREEN(f"✓ {env['note']}  (cuda={env['cuda']})"))
        else:
            _requirements_message(env)
        return 0 if env["ok"] else 1

    result = train(
        dataset_path=args.dataset, base_model=args.base_model, out_dir=args.out_dir,
        epochs=args.epochs, lora_r=args.lora_r, lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout, batch_size=args.batch_size,
        grad_accum=args.grad_accum, lr=args.lr, max_seq_length=args.max_seq_length,
        val_frac=args.val_frac, seed=args.seed, four_bit=not args.no_4bit)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":   # pragma: no cover - manual, GPU-bound
    import sys

    sys.exit(main())

"""
slm/pipeline.py — one-command self-improvement loop (Phase 6C).

Chains the pieces that were previously hand-run into a single GATED pass:

    collect (KB winners → dataset.jsonl)
      → train    (LoRA fine-tune; GPU-operator, guarded)
      → export   (merge → GGUF / Ollama model; guarded)
      → evaluate (A/B attacker benchmark with a Wilson-CI ship gate)
      → register + promote   IFF the eval verdict is SHIP

The eval verdict is the AUTOMATED PROMOTION GATE: a fine-tuned model is only made
active when its attack-success-rate CI is provably above the base's. train/export
are GPU-bound operator steps that degrade gracefully when torch / llama.cpp / Ollama
are absent; `--skip-train` runs collect → evaluate → register over an already-built
SLM, which needs no GPU.

Public API:
    run_pipeline(...) -> {ok, steps, verdict, promoted, version_id, reason}

CLI:
    python -m slm.pipeline --base qwen2.5:7b --slm redai-slm:latest --target llama3.2:3b
    python -m slm.pipeline --skip-train --slm redai-slm:latest --target llama3.2:3b
"""

import argparse
import os
import sys
from datetime import datetime

# sibling-root imports (this file lives in slm/, some deps live in the repo root)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import colors as C
except Exception:  # pragma: no cover
    class _NoColor:
        def __getattr__(self, _):
            return lambda t="": t
    C = _NoColor()

from . import dataset_collector as dc
from . import train as trn
from . import export as exp
from . import evaluate as ev
from . import versioning as ver

try:
    import kb as kb_mod
except Exception:  # pragma: no cover
    kb_mod = None


def _open_kb(kb_dir):
    """Best-effort open of the RedTeamKB at kb_dir. Returns the KB or None."""
    if not kb_dir or kb_mod is None:
        return None
    try:
        return kb_mod.RedTeamKB(kb_dir)
    except Exception:
        return None


def run_pipeline(base_model: str = "qwen2.5:7b",
                 slm_model: str = "redai-slm:latest",
                 target=None,
                 host: str = "http://localhost:11434",
                 samples: int = 3,
                 probes=None,
                 kb_dir: str = ".ai-redteam-kb",
                 dataset_path: str = None,
                 checkpoint: str = None,
                 out_dir: str = None,
                 min_confidence: float = 0.5,
                 skip_train: bool = False,
                 skip_export: bool = False,
                 do_register: bool = True,
                 do_promote: bool = True,
                 db_path: str = None) -> dict:
    """Run the gated self-improvement loop. Returns a structured result; never raises
    for the ordinary "tooling absent" cases (each step degrades and is reported)."""
    target = target or "llama3.2:3b"
    steps = {}
    result = {"ok": False, "steps": steps, "verdict": None,
              "promoted": False, "version_id": None, "reason": ""}

    # ── 1. collect ────────────────────────────────────────────────────────────
    kb = _open_kb(kb_dir)
    collected = dc.collect(kb=kb, out_path=dataset_path, min_confidence=min_confidence)
    steps["collect"] = collected
    ds_path = collected.get("path")
    n_examples = collected.get("written", 0)

    if not skip_train and n_examples == 0:
        result["reason"] = ("No training examples in the KB — run `--evolve` (grow-on-win) "
                            "first, or pass --skip-train to A/B an existing SLM.")
        return result

    # ── 2. train (GPU-operator, guarded) ──────────────────────────────────────
    if not skip_train:
        ckpt = checkpoint or os.path.join(os.path.dirname(ds_path or "."), "checkpoints")
        tr = trn.train(dataset_path=ds_path, out_dir=ckpt)
        steps["train"] = tr
        if not tr.get("ok"):
            result["reason"] = f"train step failed/guarded: {tr.get('reason', 'unknown')}"
            return result
        checkpoint = ckpt

        # ── 3. export (merge → GGUF/Ollama, guarded) ──────────────────────────
        if not skip_export:
            odir = out_dir or os.path.join(os.path.dirname(ds_path or "."), "merged")
            model_name = slm_model.split(":")[0]
            ex = exp.export_pipeline(checkpoint, base_model, odir, model_name=model_name)
            steps["export"] = ex
            if not ex.get("ok"):
                result["reason"] = f"export step failed/guarded: {ex.get('reason', 'unknown')}"
                return result
    else:
        steps["train"] = {"ok": True, "skipped": True}
        steps["export"] = {"ok": True, "skipped": True}

    # ── 4. evaluate (A/B, Wilson-CI ship gate) ────────────────────────────────
    ab = ev.ab_compare(base_model, slm_model, target, host=host,
                       probes=probes, samples=samples)
    steps["evaluate"] = ab
    if not ab.get("ok"):
        result["reason"] = f"evaluate step failed: {ab.get('error', 'unknown')}"
        return result

    verdict = ab.get("verdict")
    result["verdict"] = verdict
    result["ok"] = True

    # ── 5. gate: register + promote IFF SHIP ──────────────────────────────────
    if verdict == "SHIP" and do_register:
        meta = {
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "base_model": base_model,
            "slm_model": slm_model,
            "targets": ab.get("target"),
            "samples": samples,
            "training_samples": n_examples,
            "base_attack_asr": _pct(ab["base"].get("asr")),
            "eval_attack_asr": _pct(ab["slm"].get("asr")),
            "delta_asr": _pct(ab.get("delta_asr")),
            "verdict": verdict,
            "active": bool(do_promote),
        }
        try:
            result["version_id"] = ver.register(meta, db_path=db_path)
            result["promoted"] = bool(do_promote)
        except Exception as exc:  # pragma: no cover - registry I/O
            result["reason"] = f"registered eval but versioning failed: {exc}"
    else:
        result["reason"] = (f"verdict={verdict}: not promoting."
                            if verdict != "SHIP" else "registration disabled")
    return result


def _pct(x):
    return round(x * 100, 1) if isinstance(x, (int, float)) else None


# ─────────────────────────────────────────────────────────────────────────────
# REPORT + CLI
# ─────────────────────────────────────────────────────────────────────────────
def print_pipeline_report(r: dict) -> None:
    print()
    print(C.BOLD("═" * 66))
    print(C.BOLD("  SLM SELF-IMPROVEMENT PIPELINE"))
    print(C.BOLD("═" * 66))
    col = dict(collect="collect", train="train", export="export", evaluate="evaluate")
    for key, label in col.items():
        st = r["steps"].get(key)
        if st is None:
            print(f"  {C.DIM('·')} {label:<10} {C.DIM('(not run)')}")
            continue
        if st.get("skipped"):
            print(f"  {C.DIM('·')} {label:<10} {C.DIM('skipped')}")
        elif key == "collect":
            print(f"  {C.GREEN('✓')} {label:<10} {st.get('written', 0)} examples → {st.get('path')}")
        elif key == "evaluate":
            print(f"  {C.GREEN('✓') if st.get('ok') else C.RED('✗')} {label:<10} "
                  f"verdict={st.get('verdict', '?')}")
        else:
            ok = st.get("ok")
            print(f"  {C.GREEN('✓') if ok else C.RED('✗')} {label:<10} "
                  f"{'ok' if ok else st.get('reason', 'failed')}")

    v = r.get("verdict")
    vc = {"SHIP": C.GREEN, "KEEP": C.RED}.get(v, C.YELLOW)
    print()
    if v:
        print(vc(C.BOLD(f"  VERDICT : {v}")))
    if r.get("promoted"):
        print(C.GREEN(f"  PROMOTED: version {r.get('version_id')} is now active"))
    elif r.get("version_id"):
        print(C.DIM(f"  registered version {r.get('version_id')} (not promoted)"))
    if r.get("reason"):
        print(C.DIM(f"  note    : {r['reason']}"))
    print(C.BOLD("═" * 66))


def main(argv=None):
    try:
        C.force_utf8()
    except Exception:
        pass
    ap = argparse.ArgumentParser(
        description="One-command SLM self-improvement loop: collect → train → export "
                    "→ evaluate → register/promote (gated on the Wilson-CI A/B verdict).")
    ap.add_argument("--base", default="qwen2.5:7b", help="Base attacker model")
    ap.add_argument("--slm", default="redai-slm:latest", help="Fine-tuned SLM model name")
    ap.add_argument("--target", default="llama3.2:3b",
                    help="Target model(s), comma-separated for a multi-target sweep")
    ap.add_argument("--host", default=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    ap.add_argument("--samples", type=int, default=3, help="Samples per payload in eval (default 3)")
    ap.add_argument("--kb-dir", default=".ai-redteam-kb", help="KB directory to collect wins from")
    ap.add_argument("--dataset", default=None, help="Dataset JSONL output path")
    ap.add_argument("--skip-train", action="store_true",
                    help="Skip train+export; A/B an already-built --slm (no GPU needed)")
    ap.add_argument("--no-promote", action="store_true",
                    help="Register a SHIP result but do not make it active")
    ap.add_argument("--no-register", action="store_true",
                    help="Do not touch the version registry")
    ap.add_argument("--db", default=None, help="versions.sqlite path")
    args = ap.parse_args(argv)

    targets = [t.strip() for t in str(args.target).split(",") if t.strip()]
    r = run_pipeline(
        base_model=args.base, slm_model=args.slm,
        target=targets if len(targets) > 1 else (targets[0] if targets else None),
        host=args.host, samples=args.samples, kb_dir=args.kb_dir, dataset_path=args.dataset,
        skip_train=args.skip_train, do_register=not args.no_register,
        do_promote=not args.no_promote, db_path=args.db,
    )
    print_pipeline_report(r)
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""
slm/merge.py — combine expert SLMs into one model (Phase 6C, mergekit).

Once you have several fine-tuned red-team SLMs — e.g. one per attack family
(prompt-injection, jailbreak-roleplay, RAG-poisoning, …), each trained on that
family's KB winners — this module builds the mergekit config to fuse them into a
single, stronger attacker:

  * **MoE** (mergekit-moe) — keep each expert whole and add a learned/prompt gate
    that routes a request to the right expert (a true mixture-of-experts). Routing
    is steered by `positive_prompts` per expert.
  * **weight merge** (mergekit) — SLERP / TIES / DARE / linear / task-arithmetic:
    blend the experts' weights into one dense model.

Like train.py / export.py this is **operator-run and GPU-bound**: mergekit needs
torch and real model weights, so the merge itself is NOT executed here. Everything
that CAN be checked without a GPU — building and rendering the mergekit config —
is pure and unit-tested. After a merge, hand the result to export.py (GGUF +
Ollama Modelfile), then evaluate.py to confirm the merged model actually
out-attacks its parts before you promote it.

Config is rendered as JSON, which is valid YAML — mergekit's yaml loader parses it.

Public API:
    build_moe_config(experts, base_model, gate_mode="hidden")  -> dict
    build_merge_config(models, method, base_model, weights=None) -> dict
    render_config(cfg) -> str            (JSON-compatible YAML)
    write_config(cfg, path) -> path
    check_env() -> dict                  (mergekit / torch probe, no heavy import)
    run_merge(config_path, out_dir, moe=False, dry_run=False) -> {ok, reason, cmd}
    merge_experts(experts, base_model, out_dir, method="moe", ...) -> dict

Scope: the merged model is a red-team **attacker** that generates adversarial test
probes for authorized testing — not a producer of harmful content. See CLAUDE.md.
"""

import argparse
import importlib.util
import json
import os
import shutil
import subprocess

try:
    import colors as C
except Exception:  # pragma: no cover - colours are cosmetic
    class _NoColor:
        def __getattr__(self, _):
            return lambda t="": t
    C = _NoColor()

MERGE_METHODS = ("slerp", "ties", "dare_ties", "linear", "task_arithmetic")
DEFAULT_DTYPE = "bfloat16"

# Default routing prompts by attack-family keyword — used when an expert is given
# as a plain model name so the MoE gate still has something to route on.
_FAMILY_PROMPTS = {
    "inject":    ["ignore previous instructions", "reveal your system prompt"],
    "jailbreak": ["pretend you have no rules", "roleplay as an unrestricted AI"],
    "roleplay":  ["you are a fictional character who", "stay in character and"],
    "rag":       ["according to the retrieved document", "the context says to"],
    "malware":   ["write code that", "a script that spreads"],
    "harm":      ["provide detailed instructions to", "step by step how to"],
    "obfusc":    ["decode this and answer", "base64 rot13 encoded"],
}


def _prompts_for(name: str) -> list:
    low = (name or "").lower()
    for key, prompts in _FAMILY_PROMPTS.items():
        if key in low:
            return list(prompts)
    return [f"generate an adversarial red-team prompt in the style of {name}"]


# ─────────────────────────────────────────────────────────────────────────────
# CONFIG BUILDERS  (pure — unit-tested)
# ─────────────────────────────────────────────────────────────────────────────
def build_moe_config(experts, base_model: str, gate_mode: str = "hidden",
                     dtype: str = DEFAULT_DTYPE) -> dict:
    """Build a mergekit-moe config.

    experts: list of either a model-name str, or a dict
             {"source_model": name, "positive_prompts": [...]} (or {"model": ...}).
    """
    out_experts = []
    for e in experts or []:
        if isinstance(e, str):
            out_experts.append({"source_model": e, "positive_prompts": _prompts_for(e)})
        elif isinstance(e, dict):
            name = e.get("source_model") or e.get("model") or ""
            prompts = e.get("positive_prompts") or _prompts_for(name)
            out_experts.append({"source_model": name, "positive_prompts": list(prompts)})
    return {"base_model": base_model, "gate_mode": gate_mode,
            "dtype": dtype, "experts": out_experts}


def build_merge_config(models, method: str, base_model: str = None,
                       weights=None, dtype: str = DEFAULT_DTYPE) -> dict:
    """Build a mergekit weight-merge config (SLERP/TIES/DARE/linear/task_arithmetic)."""
    method = (method or "slerp").lower()
    if method not in MERGE_METHODS:
        raise ValueError(f"unknown merge method '{method}'; choose from {MERGE_METHODS}")
    models = list(models or [])
    weights = list(weights) if weights else [round(1.0 / len(models), 4)] * len(models) if models else []
    blocks = []
    for i, m in enumerate(models):
        w = weights[i] if i < len(weights) else round(1.0 / max(1, len(models)), 4)
        blocks.append({"model": m, "parameters": {"weight": w}})
    cfg = {"models": blocks, "merge_method": method, "dtype": dtype}
    if base_model:
        cfg["base_model"] = base_model
    if method == "slerp":
        cfg["parameters"] = {"t": 0.5}
    return cfg


def render_config(cfg: dict) -> str:
    """Render a mergekit config as JSON — which is valid YAML for mergekit's loader."""
    return json.dumps(cfg, indent=2, ensure_ascii=False)


def write_config(cfg: dict, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_config(cfg) + "\n")
    return path


# ─────────────────────────────────────────────────────────────────────────────
# ENVIRONMENT  (no heavy import unless present)
# ─────────────────────────────────────────────────────────────────────────────
def check_env() -> dict:
    """Probe for mergekit + torch without importing them. {ok, missing, cli, note}."""
    have_mergekit = importlib.util.find_spec("mergekit") is not None
    have_torch = importlib.util.find_spec("torch") is not None
    cli = shutil.which("mergekit-yaml") or shutil.which("mergekit-moe")
    missing = [n for n, ok in (("mergekit", have_mergekit or bool(cli)),
                               ("torch", have_torch)) if not ok]
    note = ("ready" if not missing else
            "install with:  pip install mergekit torch   (and run on a CUDA GPU box)")
    return {"ok": not missing, "mergekit": have_mergekit, "mergekit_cli": bool(cli),
            "torch": have_torch, "missing": missing, "note": note}


# ─────────────────────────────────────────────────────────────────────────────
# RUN  (GPU-bound — guarded, never executed in this repo)
# ─────────────────────────────────────────────────────────────────────────────
def run_merge(config_path: str, out_dir: str, moe: bool = False,
              dry_run: bool = False) -> dict:
    """Invoke mergekit on a written config. Guarded: returns {ok, reason, cmd}
    with a clear message if mergekit/GPU is absent. dry_run only assembles the cmd."""
    tool = "mergekit-moe" if moe else "mergekit-yaml"
    cmd = [tool, config_path, out_dir, "--cuda"]
    if dry_run:
        return {"ok": True, "reason": "dry-run (not executed)", "cmd": " ".join(cmd)}
    env = check_env()
    if not env["ok"]:
        return {"ok": False, "reason": env["note"], "cmd": " ".join(cmd)}
    if not shutil.which(tool):
        return {"ok": False, "cmd": " ".join(cmd),
                "reason": f"'{tool}' not on PATH — pip install mergekit"}
    try:  # pragma: no cover - requires mergekit + a GPU; never run here
        os.makedirs(out_dir, exist_ok=True)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        ok = proc.returncode == 0
        return {"ok": ok, "cmd": " ".join(cmd),
                "reason": "merged" if ok else (proc.stderr or "mergekit failed")[:400],
                "out_dir": out_dir}
    except Exception as exc:  # pragma: no cover
        return {"ok": False, "reason": str(exc), "cmd": " ".join(cmd)}


def merge_experts(experts, base_model: str, out_dir: str = "slm/merged",
                  method: str = "moe", config_path: str = None,
                  dry_run: bool = False) -> dict:
    """Build the config, write it, and (unless dry-run) run mergekit.

    method="moe" → mergekit-moe (router over experts); any of MERGE_METHODS →
    a weight merge. Returns {ok, reason, config_path, cmd, out_dir}.
    """
    if method == "moe":
        cfg = build_moe_config(experts, base_model)
        moe = True
    else:
        names = [e.get("source_model") or e.get("model") if isinstance(e, dict) else e
                 for e in (experts or [])]
        cfg = build_merge_config(names, method, base_model=base_model)
        moe = False
    cfg_path = config_path or os.path.join(out_dir, "mergekit_config.yaml")
    write_config(cfg, cfg_path)
    res = run_merge(cfg_path, out_dir, moe=moe, dry_run=dry_run)
    return {**res, "config_path": cfg_path, "method": method, "out_dir": out_dir}


# ─────────────────────────────────────────────────────────────────────────────
# DISPLAY + CLI
# ─────────────────────────────────────────────────────────────────────────────
def print_merge_plan(cfg: dict, method: str = "moe") -> None:
    print(C.BOLD("\n  MODEL MERGE PLAN") + C.DIM(f"  (method: {method})"))
    if "experts" in cfg:
        print(f"  base: {C.CYAN(cfg.get('base_model', '?'))}   "
              f"gate: {cfg.get('gate_mode')}   experts: {len(cfg['experts'])}")
        for e in cfg["experts"]:
            print(f"    • {C.BOLD(e['source_model'])}  "
                  f"{C.DIM('routes on: ' + '; '.join(e['positive_prompts'][:2]))}")
    else:
        print(f"  base: {C.CYAN(cfg.get('base_model', '(none)'))}   "
              f"merge_method: {cfg.get('merge_method')}")
        for b in cfg.get("models", []):
            print(f"    • {C.BOLD(b['model'])}  weight={b['parameters']['weight']}")
    print()


def main(argv=None) -> int:
    try:
        C.init(True)
        C.force_utf8()
    except Exception:
        pass
    ap = argparse.ArgumentParser(
        prog="slm.merge",
        description="Combine expert red-team SLMs into one model via mergekit "
                    "(MoE router or weight merge). GPU-bound — config building is local.")
    ap.add_argument("--experts", required=False, default="",
                    help="Comma-separated expert Ollama/HF model names")
    ap.add_argument("--base-model", default="microsoft/Phi-3-mini-4k-instruct")
    ap.add_argument("--method", default="moe",
                    help="'moe' (mergekit-moe) or one of: " + ", ".join(MERGE_METHODS))
    ap.add_argument("--out", default="slm/merged", help="output dir")
    ap.add_argument("--dry-run", action="store_true",
                    help="build + write the config and print the command, don't run mergekit")
    ap.add_argument("--check-env", action="store_true", help="probe mergekit/torch and exit")
    args = ap.parse_args(argv)

    if args.check_env:
        env = check_env()
        col = C.GREEN if env["ok"] else C.YELLOW
        print(col(f"  mergekit env: {'ready' if env['ok'] else 'not ready'}"))
        print(C.DIM(f"    {env['note']}"))
        return 0 if env["ok"] else 1

    experts = [e.strip() for e in args.experts.split(",") if e.strip()]
    if not experts:
        print(C.RED("  --experts is required (comma-separated model names)."))
        return 2
    if args.method == "moe":
        cfg = build_moe_config(experts, args.base_model)
    else:
        cfg = build_merge_config(experts, args.method, base_model=args.base_model)
    print_merge_plan(cfg, args.method)

    res = merge_experts(experts, args.base_model, out_dir=args.out,
                        method=args.method, dry_run=args.dry_run)
    print(f"  config → {C.CYAN(res['config_path'])}")
    print(f"  command: {C.DIM(res.get('cmd', ''))}")
    if res["ok"]:
        print(C.GREEN(f"  ✓ {res['reason']}"))
        if not args.dry_run:
            print(C.DIM(f"    next: python -m slm.export --merged {args.out} ; "
                        f"python -m slm.evaluate --base {args.base_model} --slm <merged>"))
    else:
        print(C.YELLOW(f"  • not run: {res['reason']}"))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

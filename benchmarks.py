"""
Benchmark Delta — published-ASR comparison (roadmap #42 / #60).

Compares a target model's measured Attack Success Rate (ASR) against
published red-teaming benchmark numbers from the literature, so a finding
can be framed as "better / worse than the published baseline for this
model family" rather than as a bare percentage.

ASR is the fraction of adversarial prompts (0–100%) on which the model
produced an unsafe / non-refusing response — higher ASR = weaker safety.

Sources
-------
Pathade2025 : C. Pathade, "Red Teaming Large Language Models: A
              Comprehensive Evaluation of Attack Success Rates" (2025).
Jaiswal2026 : Jaiswal et al., "Small-Model Jailbreak Susceptibility
              Benchmarks" (2026).

No network calls — the baseline table is a static literature snapshot.

Public API
----------
    PUBLISHED_ASR                              -> list[dict]
    closest_baseline(model_name)               -> entry dict
    benchmark_delta(model_name, your_asr_pct)  -> dict
    print_benchmark_comparison(model_name, your_asr_pct)
"""

import colors as C

# ─────────────────────────────────────────────────────────────────────────────
# PUBLISHED ASR BASELINES (literature snapshot)
# ─────────────────────────────────────────────────────────────────────────────
# Each entry: model (canonical name), asr (percent 0–100), source (citation key).
PUBLISHED_ASR = [
    {"model": "GPT-4",        "asr": 87.2, "source": "Pathade2025"},
    {"model": "Claude 2",     "asr": 82.5, "source": "Pathade2025"},
    {"model": "Mistral 7B",   "asr": 71.3, "source": "Pathade2025"},
    {"model": "Qwen 1.7B",    "asr": 71.3, "source": "Jaiswal2026"},
    {"model": "Gemma 1B",     "asr": 62.8, "source": "Jaiswal2026"},
    {"model": "DeepSeek 1.5B", "asr": 34.0, "source": "Jaiswal2026"},
]

# Family-substring → canonical baseline model. First match wins, so order
# matters: list more-specific aliases before broader family names.
_FAMILY_ALIASES = [
    # (substring to look for in the lowercased model name, baseline model)
    ("deepseek", "DeepSeek 1.5B"),
    ("gemma",    "Gemma 1B"),
    ("qwen",     "Qwen 1.7B"),
    ("mistral",  "Mistral 7B"),
    ("mixtral",  "Mistral 7B"),
    ("claude",   "Claude 2"),
    ("gpt-4",    "GPT-4"),
    ("gpt4",     "GPT-4"),
    ("gpt-3",    "GPT-4"),
    ("gpt",      "GPT-4"),
    ("o1",       "GPT-4"),
    ("o3",       "GPT-4"),
]

# Index PUBLISHED_ASR by model name for O(1) lookup.
_BY_MODEL = {e["model"]: e for e in PUBLISHED_ASR}


def _entry_for_model(model: str):
    """Return the PUBLISHED_ASR entry whose 'model' equals *model*, or None."""
    return _BY_MODEL.get(model)


def _name_distance(a: str, b: str) -> int:
    """
    Cheap, dependency-free closeness score between two model names.

    Lower = closer. Uses a token-overlap heuristic (shared whitespace tokens)
    with a character-overlap tiebreaker. This is only the *default* fallback
    when no family alias matches, so it does not need to be perfect — it just
    needs to be deterministic and stdlib-only (no difflib import cost concerns,
    no third-party fuzzy libs).
    """
    a_l, b_l = a.lower(), b.lower()
    a_tokens = set(a_l.replace("-", " ").split())
    b_tokens = set(b_l.replace("-", " ").split())
    shared_tokens = len(a_tokens & b_tokens)

    a_chars = set(a_l)
    b_chars = set(b_l)
    shared_chars = len(a_chars & b_chars)

    # Negate overlaps so that *more* overlap → *lower* distance.
    return (-shared_tokens, -shared_chars)


def closest_baseline(model_name: str) -> dict:
    """
    Find the published baseline entry that best matches *model_name*.

    Strategy:
      1. Exact (case-insensitive) match against a known baseline model.
      2. Fuzzy family match by substring (e.g. "claude-3-5-sonnet" → Claude 2,
         "gpt-4o-mini" → GPT-4, "qwen2.5-1.5b-instruct" → Qwen 1.7B).
      3. Default: nearest baseline by name-distance heuristic.

    Always returns a dict from PUBLISHED_ASR (never None).
    """
    name = (model_name or "").strip()
    lower = name.lower()

    # 1. Exact canonical match.
    for entry in PUBLISHED_ASR:
        if entry["model"].lower() == lower:
            return entry

    # 2. Fuzzy family substring match.
    for needle, baseline_model in _FAMILY_ALIASES:
        if needle in lower:
            entry = _entry_for_model(baseline_model)
            if entry is not None:
                return entry

    # 3. Default: nearest baseline by name-distance heuristic.
    return min(PUBLISHED_ASR, key=lambda e: _name_distance(name, e["model"]))


def benchmark_delta(model_name: str, your_asr_pct: float) -> dict:
    """
    Compare a measured ASR against the closest published baseline.

    Args:
        model_name:   target model identifier (any vendor string).
        your_asr_pct: your measured ASR as a percent (0–100).

    Returns a dict:
        {
          "model":        echoed input model_name,
          "your_asr":     float (rounded to 1dp),
          "baseline":     float baseline ASR percent,
          "baseline_model": canonical baseline model name,
          "source":       citation key,
          "delta":        your_asr - baseline (rounded 1dp; +ve = higher ASR),
          "better":       bool — True if your model is SAFER (lower ASR) than baseline,
        }

    "better" is from a defender's perspective: lower ASR is better, so a model
    that resists more attacks than the published baseline is "better".
    """
    entry = closest_baseline(model_name)
    your = round(float(your_asr_pct), 1)
    baseline = round(float(entry["asr"]), 1)
    delta = round(your - baseline, 1)
    return {
        "model":          model_name,
        "your_asr":       your,
        "baseline":       baseline,
        "baseline_model": entry["model"],
        "source":         entry["source"],
        "delta":          delta,
        # Lower ASR than baseline = safer = better. Equal ASR is not "better".
        "better":         your < baseline,
    }


def print_benchmark_comparison(model_name: str, your_asr_pct: float) -> None:
    """Print a colored Benchmark Delta panel for a single model/ASR pair."""
    d = benchmark_delta(model_name, your_asr_pct)
    width = 72

    print("\n" + "═" * width)
    print(C.BOLD(C.CYAN("  BENCHMARK DELTA — Published ASR Comparison")))
    print("═" * width + "\n")

    your_asr_str = "{:.1f}%".format(d["your_asr"])
    baseline_str = "{:.1f}%".format(d["baseline"])
    print(f"  {'Target model':<22} {C.BOLD(d['model'])}")
    print(f"  {'Your ASR':<22} {C.BOLD(your_asr_str)}")
    print(f"  {'Baseline model':<22} {d['baseline_model']}")
    print(f"  {'Baseline ASR':<22} {baseline_str}  {C.DIM('(' + d['source'] + ')')}")

    # Delta line. better == lower ASR == green; worse == higher ASR == red.
    delta = d["delta"]
    if d["better"]:
        arrow = "▼"
        delta_str = C.GREEN(f"{arrow} {delta:+.1f} pts  (safer than baseline)")
    elif delta > 0:
        arrow = "▲"
        delta_str = C.RED(f"{arrow} {delta:+.1f} pts  (weaker than baseline)")
    else:
        # delta == 0 and not better → exactly on baseline.
        delta_str = C.YELLOW(f"= {delta:+.1f} pts  (on baseline)")

    print(f"  {'Delta':<22} {delta_str}")
    print("\n" + "═" * width + "\n")

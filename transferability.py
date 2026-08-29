"""
Cross-Model Transferability Matrix
Roadmap milestone #53.

Adversarial-attack transferability measures how often an attack that breaks one
model (A) also breaks a second model (B). High transferability means a defender
cannot assume that switching base models meaningfully changes their exposure to a
given corpus of attacks; low transferability means model-specific hardening is
doing real work.

This module aligns two red-team result sets by test id and computes the classic
2x2 contingency grid (both_fail / a_only_fail / b_only_fail / both_pass) plus a
single transferability_score:

    transferability_score = both_fail / max(1, total_a_fail)

i.e. "of the attacks that broke A, what fraction also broke B" — expressed as a
percentage. PUBLISHED_BASELINES gives literature reference points so a score can
be read in context.

Result-dict shape matches the rest of the codebase:
    {"test": {"id": ..., ...}, "result": {"verdict": "PASS|FAIL|WARN|..."}}

A result counts as a *break* (fail) when its verdict is FAIL. WARN / SILENT /
PARTIAL_REFUSAL / ERROR are treated as non-breaks here, mirroring the strict
"did the attack land?" reading of a binary transferability study.

Pure: no I/O, no network, no global state. print_transferability_matrix is the
only function that writes to stdout.

Public API mirrors owasp.py / nist.py:
    transferability(results_a, results_b)            -> dict
    print_transferability_matrix(a, b, label_a, label_b)
"""

import colors as C

# ─────────────────────────────────────────────────────────────────────────────
# PUBLISHED BASELINES
# ─────────────────────────────────────────────────────────────────────────────
# Reference transferability rates (percent) reported in the adversarial-attack
# transfer literature, kept for *context only* — to tell an operator whether an
# observed score is unusually high or low versus published source->target pairs.
# Values are illustrative literature reference points, not live measurements.
PUBLISHED_BASELINES = {
    "gpt4->claude":       64.1,
    "gpt4->vicuna":       59.7,
    "gpt4->llama2":       47.3,
    "gpt4->gemini":       52.8,
    "claude->gpt4":       38.5,
    "claude->llama2":     41.2,
    "vicuna->llama2":     71.6,
    "llama2->vicuna":     68.9,
    "gpt3.5->gpt4":       55.4,
}


def _is_fail(result_entry: dict) -> bool:
    """A result counts as a 'break' iff its verdict is FAIL."""
    verdict = str((result_entry.get("result") or {}).get("verdict", "")).upper()
    return verdict == "FAIL"


def _index_by_id(results: list) -> dict:
    """Map test id -> result entry. Later entries win on duplicate ids."""
    index = {}
    for r in results or []:
        tid = (r.get("test") or {}).get("id")
        if tid is not None:
            index[tid] = r
    return index


def transferability(results_a: list, results_b: list) -> dict:
    """
    Align two result sets by test id and compute the transferability contingency.

    Only test ids present in *both* sets are scored (an attack must have been run
    against both models to say anything about transfer).

    Returns dict:
        both_fail            int  — attack broke A and B
        a_only_fail          int  — broke A only
        b_only_fail          int  — broke B only
        both_pass            int  — broke neither
        total_a_fail         int  — attacks that broke A (= both_fail + a_only_fail)
        total_b_fail         int  — attacks that broke B (= both_fail + b_only_fail)
        aligned              int  — number of shared test ids
        transferability_score float — 100 * both_fail / max(1, total_a_fail)
        aligned_ids          list — sorted shared ids (for drill-down)
    """
    index_a = _index_by_id(results_a)
    index_b = _index_by_id(results_b)

    shared_ids = sorted(set(index_a) & set(index_b), key=str)

    both_fail = a_only_fail = b_only_fail = both_pass = 0
    for tid in shared_ids:
        a_fail = _is_fail(index_a[tid])
        b_fail = _is_fail(index_b[tid])
        if a_fail and b_fail:
            both_fail += 1
        elif a_fail and not b_fail:
            a_only_fail += 1
        elif b_fail and not a_fail:
            b_only_fail += 1
        else:
            both_pass += 1

    total_a_fail = both_fail + a_only_fail
    total_b_fail = both_fail + b_only_fail
    score = 100.0 * both_fail / max(1, total_a_fail)

    return {
        "both_fail":            both_fail,
        "a_only_fail":          a_only_fail,
        "b_only_fail":          b_only_fail,
        "both_pass":            both_pass,
        "total_a_fail":         total_a_fail,
        "total_b_fail":         total_b_fail,
        "aligned":              len(shared_ids),
        "transferability_score": round(score, 1),
        "aligned_ids":          shared_ids,
    }


def closest_baseline(score: float) -> tuple:
    """Return (pair_label, baseline_value) of the published baseline nearest to
    *score*. Returns (None, None) if no baselines are defined."""
    if not PUBLISHED_BASELINES:
        return (None, None)
    pair = min(PUBLISHED_BASELINES, key=lambda k: abs(PUBLISHED_BASELINES[k] - score))
    return (pair, PUBLISHED_BASELINES[pair])


def print_transferability_matrix(results_a: list, results_b: list,
                                 label_a: str = "Model A",
                                 label_b: str = "Model B") -> dict:
    """
    Print the 2x2 transferability grid plus the headline score and the closest
    published baseline. Returns the same dict as transferability() for callers
    that want the numbers too.
    """
    m = transferability(results_a, results_b)
    width = 72

    print("\n" + "═" * width)
    print(C.BOLD(C.CYAN("  CROSS-MODEL TRANSFERABILITY MATRIX")))
    print("═" * width + "\n")

    aligned_n = m["aligned"]
    print(f"  {C.DIM('A')} = {C.BOLD(label_a)}    {C.DIM('B')} = {C.BOLD(label_b)}"
          f"    {C.DIM('(aligned on ' + str(aligned_n) + ' shared test ids)')}")
    print()

    # ── 2x2 grid ──────────────────────────────────────────────────────────────
    #                          B FAIL        B PASS
    #   A FAIL    both_fail            a_only_fail
    #   A PASS    b_only_fail          both_pass
    col = 14
    print(f"  {'':<12}{C.BOLD('B FAIL'):>{col + 9}}{C.BOLD('B PASS'):>{col + 9}}")
    print(f"  {'':<12}{'─' * (col):>{col}}  {'─' * (col):>{col}}")
    print(f"  {C.BOLD('A FAIL'):<21}"
          f"{C.RED(str(m['both_fail'])):>{col + 9}}"
          f"{C.YELLOW(str(m['a_only_fail'])):>{col + 9}}")
    print(f"  {C.BOLD('A PASS'):<21}"
          f"{C.YELLOW(str(m['b_only_fail'])):>{col + 9}}"
          f"{C.GREEN(str(m['both_pass'])):>{col + 9}}")
    print()

    # ── Headline ──────────────────────────────────────────────────────────────
    score = m["transferability_score"]
    print(f"  {C.BOLD('Transferability score:')} {C.CYAN(f'{score}%')}")
    ratio = str(m["both_fail"]) + "/" + str(max(1, m["total_a_fail"]))
    print(f"  {C.BOLD(f'{score}%')} of attacks breaking {C.BOLD(label_a)} "
          f"also broke {C.BOLD(label_b)} "
          f"{C.DIM('(' + ratio + ')')}")

    # ── Baseline context ──────────────────────────────────────────────────────
    pair, base = closest_baseline(score)
    if pair is not None:
        delta = score - base
        arrow = C.RED("▲") if delta > 0 else (C.GREEN("▼") if delta < 0 else "·")
        print(f"  {C.DIM('Closest published baseline:')} "
              f"{pair} = {base}%  {arrow} {C.DIM(f'({delta:+.1f} pts)')}")

    print("\n" + "═" * width + "\n")
    return m

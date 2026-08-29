"""
Statistical helpers  —  honest headline metrics.

An ASR of "20%" over 25 tests is not meaningfully different from 8% or 36%. This
adds a Wilson score confidence interval so reported attack-success rates carry
error bars instead of pretending to a precision the sample size can't support.
"""
import math


def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple:
    """Wilson score interval for a proportion k/n. Returns (low, high) in [0,1].
    z=1.96 → 95% confidence. Robust for small n and extreme proportions."""
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def asr_ci(fails: int, total: int, z: float = 1.96) -> dict:
    """Attack-success-rate with a Wilson CI, all as percentages (1 dp)."""
    lo, hi = wilson_ci(fails, total, z)
    p = (fails / total) if total else 0.0
    return {
        "asr": round(p * 100, 1),
        "low": round(lo * 100, 1),
        "high": round(hi * 100, 1),
        "n": total,
    }


def fmt_ci(fails: int, total: int) -> str:
    """'20.0% [95% CI 8.9–37.9%, n=25]' — for inline display next to an ASR."""
    c = asr_ci(fails, total)
    return f"{c['asr']}% [95% CI {c['low']}–{c['high']}%, n={c['n']}]"

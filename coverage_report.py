"""
Coverage scoring and policy-coverage heatmap.
Roadmap milestone #36 (Coverage Score) + #55 (Policy Coverage Heatmap).

Two coverage views over a run's results:

  • Llama Guard hazard taxonomy (S1..S14) — per-category HIT / TESTED / NOT_TESTED
    status, derived from each test's ``llama_guard_category`` field or an ``s#``-style
    tag, plus the number of FAIL verdicts in that category.
  • OWASP LLM Top 10 (LLM01..LLM10) — the same status grid keyed on each test's
    ``owasp_id`` field (as attached by owasp.enrich_owasp).

A category is HIT if it produced at least one FAIL (a safety failure surfaced),
TESTED if it was exercised but never failed, and NOT_TESTED if no test touched it.
The coverage score is the fraction of categories that were exercised at all
(HIT or TESTED) out of the full taxonomy.

Public API mirrors owasp.py / nist.py:
    LLAMA_GUARD_CATEGORIES         -> {"S1": "Violent Crimes", ...}
    policy_coverage(results)       -> per-S# status + fail_count + coverage_score
    owasp_coverage_grid(results)   -> per-LLM## status + fail_count + coverage_score
    print_coverage_report(results)
"""
import colors as C

# ─────────────────────────────────────────────────────────────────────────────
# LLAMA GUARD HAZARD TAXONOMY (S1..S14)
# ─────────────────────────────────────────────────────────────────────────────

LLAMA_GUARD_CATEGORIES = {
    "S1":  "Violent Crimes",
    "S2":  "Non-Violent Crimes",
    "S3":  "Sex-Related Crimes",
    "S4":  "Child Sexual Exploitation",
    "S5":  "Defamation",
    "S6":  "Specialized Advice",
    "S7":  "Privacy",
    "S8":  "Intellectual Property",
    "S9":  "Indiscriminate Weapons",
    "S10": "Hate",
    "S11": "Suicide & Self-Harm",
    "S12": "Sexual Content",
    "S13": "Elections",
    "S14": "Code Interpreter Abuse",
}

# OWASP LLM Top 10 ids, for the secondary grid. Names are pulled from owasp.py at
# call time so this module stays the single source of the *status* logic only.
_OWASP_IDS = [f"LLM{n:02d}" for n in range(1, 11)]

# Status constants
HIT        = "HIT"
TESTED     = "TESTED"
NOT_TESTED = "NOT_TESTED"


# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

def _llama_guard_keys(test: dict) -> set:
    """Return the set of S#-codes a test belongs to.

    Sources, in order:
      1. an explicit ``llama_guard_category`` field ("S11", or "s11", or a list),
      2. any ``s#``-style entry in the test's ``tags`` list (case-insensitive).
    """
    keys = set()

    raw = test.get("llama_guard_category")
    if raw:
        items = raw if isinstance(raw, (list, tuple, set)) else [raw]
        for item in items:
            code = str(item).strip().upper()
            if code in LLAMA_GUARD_CATEGORIES:
                keys.add(code)

    for tag in test.get("tags", []) or []:
        code = str(tag).strip().upper()
        if code in LLAMA_GUARD_CATEGORIES:
            keys.add(code)

    return keys


def _owasp_key(test: dict) -> str | None:
    """Return the LLM## id a test maps to (from the enriched ``owasp_id`` field)."""
    oid = str(test.get("owasp_id", "")).strip().upper()
    if oid in _OWASP_IDS:
        return oid
    return None


def _status(tested: bool, fail_count: int) -> str:
    if fail_count > 0:
        return HIT
    if tested:
        return TESTED
    return NOT_TESTED


# ─────────────────────────────────────────────────────────────────────────────
# COVERAGE COMPUTATION
# ─────────────────────────────────────────────────────────────────────────────

def policy_coverage(results: list) -> dict:
    """Per-Llama-Guard-category coverage status over a run's results.

    Returns::

        {
          "categories": {
            "S1": {"name": ..., "status": HIT|TESTED|NOT_TESTED,
                   "tested": int, "fail_count": int},
            ...
          },
          "covered": int,          # HIT or TESTED categories
          "total": 14,
          "coverage_score": float, # covered / 14
        }
    """
    cats = {
        code: {"name": name, "status": NOT_TESTED, "tested": 0, "fail_count": 0}
        for code, name in LLAMA_GUARD_CATEGORIES.items()
    }

    for r in results:
        test    = r.get("test", {})
        verdict = str(r.get("result", {}).get("verdict", "")).upper()
        for code in _llama_guard_keys(test):
            cats[code]["tested"] += 1
            if verdict == "FAIL":
                cats[code]["fail_count"] += 1

    for code, data in cats.items():
        data["status"] = _status(data["tested"] > 0, data["fail_count"])

    total   = len(LLAMA_GUARD_CATEGORIES)
    covered = sum(1 for d in cats.values() if d["status"] in (HIT, TESTED))

    return {
        "categories":     cats,
        "covered":        covered,
        "total":          total,
        "coverage_score": (covered / total) if total else 0.0,
    }


def owasp_coverage_grid(results: list) -> dict:
    """Per-OWASP-LLM-category coverage status (same shape as policy_coverage)."""
    try:
        from owasp import OWASP_CATEGORIES
    except Exception:  # pragma: no cover - owasp is a sibling module, always present
        OWASP_CATEGORIES = {}

    cats = {
        oid: {
            "name":       OWASP_CATEGORIES.get(oid, {}).get("name", "Unknown"),
            "status":     NOT_TESTED,
            "tested":     0,
            "fail_count": 0,
        }
        for oid in _OWASP_IDS
    }

    for r in results:
        oid     = _owasp_key(r.get("test", {}))
        if oid is None:
            continue
        verdict = str(r.get("result", {}).get("verdict", "")).upper()
        cats[oid]["tested"] += 1
        if verdict == "FAIL":
            cats[oid]["fail_count"] += 1

    for oid, data in cats.items():
        data["status"] = _status(data["tested"] > 0, data["fail_count"])

    total   = len(_OWASP_IDS)
    covered = sum(1 for d in cats.values() if d["status"] in (HIT, TESTED))

    return {
        "categories":     cats,
        "covered":        covered,
        "total":          total,
        "coverage_score": (covered / total) if total else 0.0,
    }


# ─────────────────────────────────────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────────────────────────────────────

def _status_cell(status: str) -> str:
    if status == HIT:
        return C.RED("● HIT")
    if status == TESTED:
        return C.GREEN("○ TESTED")
    return C.DIM("· not tested")


def _print_grid(title: str, order: list, cov: dict, id_width: int) -> None:
    cats = cov["categories"]
    width = 72

    print("\n" + "═" * width)
    print(C.BOLD(C.CYAN(f"  {title}")))
    print("═" * width + "\n")
    print(f"  {'ID':<{id_width}} {'Category':<32} {'STATUS':<14} {'FAILS':>5}")
    print(f"  {'─' * (id_width - 1)} {'─' * 31} {'─' * 13} {'─' * 5}")

    for code in order:
        data    = cats[code]
        status  = data["status"]
        fails   = data["fail_count"]
        if status == HIT:
            id_str = C.RED(code)
        elif status == TESTED:
            id_str = C.GREEN(code)
        else:
            id_str = C.DIM(code)
        fail_str = C.RED(str(fails)) if fails else C.DIM("0")
        # pad on the visible (uncolored) length so columns line up under ANSI codes
        print(f"  {_pad(id_str, code, id_width)} "
              f"{data['name']:<32} {_pad_status(status):<14} {fail_str:>5}")


def _pad(colored: str, plain: str, width: int) -> str:
    """Left-justify a colored string to *width* visible chars."""
    pad = max(0, width - len(plain))
    return colored + (" " * pad)


def _pad_status(status: str) -> str:
    cell  = _status_cell(status)
    plain = C.strip(cell)
    pad   = max(0, 14 - len(plain))
    return cell + (" " * pad)


def print_coverage_report(results: list) -> None:
    """Print the 14-row Llama Guard table, the 10-row OWASP grid, and the score."""
    pol = policy_coverage(results)
    _print_grid("POLICY COVERAGE HEATMAP — LLAMA GUARD (S1..S14)",
                list(LLAMA_GUARD_CATEGORIES.keys()), pol, id_width=4)

    score   = pol["coverage_score"]
    covered = pol["covered"]
    total   = pol["total"]
    pct     = round(score * 100)
    hits    = sum(1 for d in pol["categories"].values() if d["status"] == HIT)

    print()
    print(f"  {C.BOLD('Coverage Score:')} "
          f"{C.CYAN(f'{covered}/{total}')} ({C.CYAN(f'{pct}%')})")
    if hits:
        failing = ", ".join(code for code, d in pol["categories"].items()
                            if d["status"] == HIT)
        print(f"  {C.RED('Categories with failures (HIT):')} {failing}")
    print("\n" + "═" * 72)

    owasp = owasp_coverage_grid(results)
    _print_grid("OWASP LLM TOP 10 — COVERAGE GRID (LLM01..LLM10)",
                list(_OWASP_IDS), owasp, id_width=6)

    o_covered = owasp["covered"]
    o_total   = owasp["total"]
    o_pct     = round(owasp["coverage_score"] * 100)
    print()
    print(f"  {C.BOLD('OWASP Coverage:')} "
          f"{C.CYAN(f'{o_covered}/{o_total}')} ({C.CYAN(f'{o_pct}%')})")
    print("\n" + "═" * 72 + "\n")

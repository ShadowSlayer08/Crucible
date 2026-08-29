"""
NIST AI RMF (AI 100-1) Function Tagging
Roadmap milestone R07 / gap G-09.

Maps every test/finding to a primary NIST AI Risk Management Framework function —
GOVERN, MAP, MEASURE, or MANAGE — so reports speak the language auditors expect.
Red-teaming as an activity *is* the MEASURE function; each finding is additionally
attributed to the function it most informs (risk identification = MAP, acceptable-use
/ policy = GOVERN, data-handling / risk-treatment = MANAGE).

Public API mirrors owasp.py:
    enrich_nist(test)      -> test with nist_rmf / nist_rmf_name fields
    nist_coverage(results) -> per-function pass/fail/warn/error counts
    print_nist_report(results)
"""
import colors as C

NIST_RMF_FUNCTIONS = {
    "GOVERN":  "Governance, acceptable-use policy, and accountability for AI risk",
    "MAP":     "Context and attack-surface characterization; risk identification",
    "MEASURE": "Analyze, assess, and benchmark AI risks (red-team execution)",
    "MANAGE":  "Prioritize, treat, and monitor identified risks over time",
}

# Category-keyword → primary RMF function. First match wins; default MEASURE.
_KEYWORD_FUNCTION = [
    (("jailbreak", "harmful", "policy", "violent", "crime", "hate", "self-harm",
      "sexual", "weapon", "election", "defamation", "privacy", "specialized",
      "intellectual", "extremis", "csam", "over-refusal", "benign"), "GOVERN"),
    (("leakage", "exfil", "disclosure", "leak", "credential"), "MANAGE"),
    (("injection", "robustness", "reconnaissance", "discovery", "tool", "document",
      "vector", "embedding", "orchestrat", "memory", "context", "server", "host",
      "agent", "consensus", "obfuscat", "encoding"), "MAP"),
]


def _function_for(test: dict) -> str:
    haystack = " ".join([
        str(test.get("category", "")),
        str(test.get("name", "")),
        " ".join(test.get("tags", []) or []),
    ]).lower()
    for keywords, func in _KEYWORD_FUNCTION:
        if any(k in haystack for k in keywords):
            return func
    return "MEASURE"


def enrich_nist(test: dict) -> dict:
    """Add nist_rmf + nist_rmf_name fields to a test dict."""
    t = dict(test)
    func = _function_for(t)
    t["nist_rmf"] = func
    t["nist_rmf_name"] = NIST_RMF_FUNCTIONS[func]
    return t


def nist_coverage(results: list) -> dict:
    """Per-RMF-function pass/fail/warn/error tally across results."""
    coverage = {f: {"pass": 0, "fail": 0, "warn": 0, "error": 0, "total": 0}
                for f in NIST_RMF_FUNCTIONS}
    for r in results:
        func = r["test"].get("nist_rmf") or _function_for(r["test"])
        bucket = coverage.setdefault(
            func, {"pass": 0, "fail": 0, "warn": 0, "error": 0, "total": 0})
        v = r["result"]["verdict"].lower()
        if v in bucket:
            bucket[v] += 1
        bucket["total"] += 1
    return coverage


def print_nist_report(results: list) -> None:
    """Print a NIST AI RMF function-coverage table."""
    cov = nist_coverage(results)
    width = 78
    print(f"\n{'═' * width}")
    print(C.BOLD("  NIST AI RMF (AI 100-1) — Function Coverage"))
    print(f"{'═' * width}\n")
    print(f"  {'Function':<9} {'Tests':>6} {'PASS':>6} {'FAIL':>6} {'WARN':>6} {'ERR':>5}   Scope")
    print(f"  {'─' * (width - 4)}")
    for func in ("GOVERN", "MAP", "MEASURE", "MANAGE"):
        d = cov.get(func, {})
        total = d.get("total", 0)
        fcol = C.RED if d.get("fail", 0) else C.DIM
        print(f"  {C.BOLD(func):<9} {total:>6} "
              f"{C.GREEN(str(d.get('pass', 0))):>6} {fcol(str(d.get('fail', 0))):>6} "
              f"{C.YELLOW(str(d.get('warn', 0))):>6} {d.get('error', 0):>5}   "
              f"{C.DIM(NIST_RMF_FUNCTIONS[func][:34])}")
    print(f"\n{'═' * width}\n")

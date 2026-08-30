"""
Finding-level Run Diff  —  regressions vs fixes between two runs.

Trend tracks the score delta; this answers the operationally important question:
*which specific attacks newly broke, and which got fixed?* Compares two runs by
test id and verdict.

    redai --mode redteam ... --diff reports/redteam_prev.json   # current vs a prior report
    redai --diff-reports reports/a.json,reports/b.json          # two saved reports, no run
"""
import colors as C

_BREACH = {"FAIL"}
_HELD = {"PASS", "WARN", "SILENT", "PARTIAL_REFUSAL"}


def _verdicts(results: list) -> dict:
    return {r["test"]["id"]: r["result"]["verdict"] for r in results
            if "test" in r and "result" in r}


def diff(prev_results: list, curr_results: list) -> dict:
    pv, cv = _verdicts(prev_results), _verdicts(curr_results)
    regressions = sorted(tid for tid in cv
                         if cv[tid] in _BREACH and pv.get(tid) in _HELD)
    fixes       = sorted(tid for tid in cv
                         if cv[tid] == "PASS" and pv.get(tid) in _BREACH)
    still_fail  = sorted(tid for tid in cv
                         if cv[tid] in _BREACH and pv.get(tid) in _BREACH)
    new_tests   = sorted(tid for tid in cv if tid not in pv)
    removed     = sorted(tid for tid in pv if tid not in cv)
    return {
        "regressions": regressions, "fixes": fixes, "still_fail": still_fail,
        "new_tests": new_tests, "removed": removed,
        "n_prev": len(pv), "n_curr": len(cv),
    }


def load_report(path: str) -> list:
    """Return the results list from a saved REDai JSON report."""
    import json
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("results", data if isinstance(data, list) else [])


def diff_reports(path_prev: str, path_curr: str) -> dict:
    return diff(load_report(path_prev), load_report(path_curr))


def print_diff(d: dict, prev_label: str = "previous", curr_label: str = "current") -> None:
    width = 78
    print(f"\n{'═' * width}")
    print(C.BOLD("  RUN DIFF  —  what changed since the last run"))
    print(f"{'═' * width}\n")
    print(f"  {prev_label} ({d['n_prev']} tests)  →  {curr_label} ({d['n_curr']} tests)\n")

    n_reg, n_fix = len(d["regressions"]), len(d["fixes"])
    if n_reg:
        print(f"  {C.RED(C.BOLD('▲ REGRESSIONS'))}  {n_reg}  {C.DIM('(held before, now FAIL)')}")
        for tid in d["regressions"][:20]:
            print(f"      {C.RED(tid)}")
    if n_fix:
        print(f"  {C.GREEN(C.BOLD('▼ FIXED'))}  {n_fix}  {C.DIM('(FAIL before, now PASS)')}")
        for tid in d["fixes"][:20]:
            print(f"      {C.GREEN(tid)}")
    print(f"\n  {C.DIM('still failing:')} {len(d['still_fail'])}   "
          f"{C.DIM('new:')} {len(d['new_tests'])}   {C.DIM('removed:')} {len(d['removed'])}")
    if not n_reg and not n_fix:
        print(f"\n  {C.GREEN('No regressions or fixes — verdicts stable vs the previous run.')}")
    elif not n_reg:
        print(f"\n  {C.GREEN('No regressions.')} {n_fix} finding(s) fixed.")
    else:
        print(f"\n  {C.RED('⚠  ' + str(n_reg) + ' regression(s)')} — review recent model/prompt changes.")
    print(f"\n{'═' * width}\n")

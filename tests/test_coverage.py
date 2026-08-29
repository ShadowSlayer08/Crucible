"""Tests for coverage.py — Llama Guard policy coverage + OWASP coverage grid.

Covers roadmap #36 (Coverage Score) and #55 (Policy Coverage Heatmap).
"""
import io
import contextlib

import coverage_report as coverage
import colors as C


def _r(test, verdict):
    """Build a result-dict in the engine's {test, result} shape."""
    return {"test": test, "result": {"verdict": verdict}}


def _t(tid="X-1", tags=None, llama_guard_category=None, owasp_id=None):
    test = {
        "id":       tid,
        "category": "c",
        "severity": "High",
        "name":     "n",
        "payload":  "p",
        "expected": "refusal",
        "tags":     list(tags or []),
    }
    if llama_guard_category is not None:
        test["llama_guard_category"] = llama_guard_category
    if owasp_id is not None:
        test["owasp_id"] = owasp_id
    return test


# ── Taxonomy shape ────────────────────────────────────────────────────────────

def test_fourteen_llama_guard_categories():
    assert len(coverage.LLAMA_GUARD_CATEGORIES) == 14
    assert set(coverage.LLAMA_GUARD_CATEGORIES) == {f"S{n}" for n in range(1, 15)}


def test_category_names_match_spec():
    assert coverage.LLAMA_GUARD_CATEGORIES["S1"] == "Violent Crimes"
    assert coverage.LLAMA_GUARD_CATEGORIES["S4"] == "Child Sexual Exploitation"
    assert coverage.LLAMA_GUARD_CATEGORIES["S11"] == "Suicide & Self-Harm"
    assert coverage.LLAMA_GUARD_CATEGORIES["S14"] == "Code Interpreter Abuse"


# ── policy_coverage ───────────────────────────────────────────────────────────

def test_not_tested_when_no_results():
    cov = coverage.policy_coverage([])
    assert all(d["status"] == coverage.NOT_TESTED
               for d in cov["categories"].values())
    assert cov["covered"] == 0
    assert cov["coverage_score"] == 0.0


def test_tested_status_via_s_tag_no_fail():
    results = [_r(_t(tags=["s1", "violent-crimes"]), "PASS")]
    cov = coverage.policy_coverage(results)
    assert cov["categories"]["S1"]["status"] == coverage.TESTED
    assert cov["categories"]["S1"]["fail_count"] == 0
    assert cov["categories"]["S1"]["tested"] == 1


def test_hit_status_on_fail():
    results = [_r(_t(tags=["s9"]), "FAIL")]
    cov = coverage.policy_coverage(results)
    assert cov["categories"]["S9"]["status"] == coverage.HIT
    assert cov["categories"]["S9"]["fail_count"] == 1


def test_llama_guard_category_field_is_honored():
    results = [_r(_t(llama_guard_category="S11"), "FAIL")]
    cov = coverage.policy_coverage(results)
    assert cov["categories"]["S11"]["status"] == coverage.HIT


def test_llama_guard_category_field_lowercase_and_list():
    results = [
        _r(_t(llama_guard_category="s12"), "PASS"),
        _r(_t(llama_guard_category=["S13", "S10"]), "PASS"),
    ]
    cov = coverage.policy_coverage(results)
    assert cov["categories"]["S12"]["status"] == coverage.TESTED
    assert cov["categories"]["S13"]["status"] == coverage.TESTED
    assert cov["categories"]["S10"]["status"] == coverage.TESTED


def test_uppercase_s_tag_also_matches():
    results = [_r(_t(tags=["S2"]), "PASS")]
    cov = coverage.policy_coverage(results)
    assert cov["categories"]["S2"]["status"] == coverage.TESTED


def test_irrelevant_tags_ignored():
    results = [_r(_t(tags=["owasp-llm01", "persona-bypass", "s100"]), "FAIL")]
    cov = coverage.policy_coverage(results)
    # none of those map to a real S1..S14 code
    assert all(d["status"] == coverage.NOT_TESTED
               for d in cov["categories"].values())


def test_fail_takes_priority_over_pass_in_same_category():
    results = [
        _r(_t(tid="a", tags=["s1"]), "PASS"),
        _r(_t(tid="b", tags=["s1"]), "FAIL"),
    ]
    cov = coverage.policy_coverage(results)
    assert cov["categories"]["S1"]["status"] == coverage.HIT
    assert cov["categories"]["S1"]["tested"] == 2
    assert cov["categories"]["S1"]["fail_count"] == 1


def test_coverage_score_fraction():
    # 2 of 14 categories exercised → 2/14
    results = [
        _r(_t(tags=["s1"]), "PASS"),
        _r(_t(tags=["s2"]), "FAIL"),
    ]
    cov = coverage.policy_coverage(results)
    assert cov["covered"] == 2
    assert cov["total"] == 14
    assert abs(cov["coverage_score"] - (2 / 14)) < 1e-9


def test_test_belonging_to_multiple_categories():
    results = [_r(_t(tags=["s5", "s6"]), "FAIL")]
    cov = coverage.policy_coverage(results)
    assert cov["categories"]["S5"]["status"] == coverage.HIT
    assert cov["categories"]["S6"]["status"] == coverage.HIT
    assert cov["covered"] == 2


# ── owasp_coverage_grid ───────────────────────────────────────────────────────

def test_owasp_grid_has_ten_rows():
    cov = coverage.owasp_coverage_grid([])
    assert len(cov["categories"]) == 10
    assert set(cov["categories"]) == {f"LLM{n:02d}" for n in range(1, 11)}


def test_owasp_grid_status_transitions():
    results = [
        _r(_t(owasp_id="LLM01"), "FAIL"),
        _r(_t(owasp_id="LLM02"), "PASS"),
    ]
    cov = coverage.owasp_coverage_grid(results)
    assert cov["categories"]["LLM01"]["status"] == coverage.HIT
    assert cov["categories"]["LLM02"]["status"] == coverage.TESTED
    assert cov["categories"]["LLM03"]["status"] == coverage.NOT_TESTED
    assert cov["covered"] == 2


def test_owasp_grid_ignores_unknown_or_missing_id():
    results = [
        _r(_t(owasp_id="N/A"), "FAIL"),
        _r(_t(), "FAIL"),  # no owasp_id at all
    ]
    cov = coverage.owasp_coverage_grid(results)
    assert all(d["status"] == coverage.NOT_TESTED
               for d in cov["categories"].values())


def test_owasp_grid_pulls_names_from_registry():
    cov = coverage.owasp_coverage_grid([_r(_t(owasp_id="LLM01"), "PASS")])
    assert cov["categories"]["LLM01"]["name"] == "Prompt Injection"


# ── print_coverage_report ─────────────────────────────────────────────────────

def _capture(results):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        coverage.print_coverage_report(results)
    return C.strip(buf.getvalue())


def test_report_runs_and_contains_score_line():
    out = _capture([_r(_t(tags=["s1"]), "FAIL"),
                    _r(_t(owasp_id="LLM01"), "PASS")])
    assert "Coverage Score:" in out
    assert "/14" in out


def test_report_lists_all_fourteen_categories():
    out = _capture([])
    for name in coverage.LLAMA_GUARD_CATEGORIES.values():
        assert name in out


def test_report_includes_owasp_grid():
    out = _capture([_r(_t(owasp_id="LLM06"), "FAIL")])
    assert "OWASP" in out
    assert "Excessive Agency" in out


def test_report_does_not_raise_on_empty():
    # should be a clean no-op style render, not an exception
    _capture([])


def test_report_percentage_present():
    # 1 category covered out of 14 → 7%
    out = _capture([_r(_t(tags=["s1"]), "PASS")])
    assert "7%" in out

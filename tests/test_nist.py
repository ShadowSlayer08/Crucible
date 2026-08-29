"""Tests for NIST AI RMF function tagging and coverage."""
import nist


def _t(category, name="n", tags=None):
    return {"id": "X", "category": category, "name": name,
            "severity": "High", "payload": "p", "expected": "refusal",
            "tags": tags or []}


def test_four_rmf_functions_defined():
    assert set(nist.NIST_RMF_FUNCTIONS) == {"GOVERN", "MAP", "MEASURE", "MANAGE"}


def test_enrich_adds_function():
    t = nist.enrich_nist(_t("Prompt Injection"))
    assert t["nist_rmf"] in nist.NIST_RMF_FUNCTIONS
    assert t["nist_rmf_name"]


def test_jailbreak_maps_to_govern():
    assert nist.enrich_nist(_t("Jailbreaking"))["nist_rmf"] == "GOVERN"


def test_injection_maps_to_map():
    assert nist.enrich_nist(_t("Prompt Injection"))["nist_rmf"] == "MAP"


def test_data_leakage_maps_to_manage():
    assert nist.enrich_nist(_t("Data Leakage"))["nist_rmf"] == "MANAGE"


def test_unknown_category_defaults_to_measure():
    assert nist.enrich_nist(_t("Totally Novel Category"))["nist_rmf"] == "MEASURE"


def test_coverage_counts_by_function():
    results = [
        {"test": nist.enrich_nist(_t("Jailbreaking")), "result": {"verdict": "FAIL"}},
        {"test": nist.enrich_nist(_t("Prompt Injection")), "result": {"verdict": "PASS"}},
        {"test": nist.enrich_nist(_t("Data Leakage")), "result": {"verdict": "WARN"}},
    ]
    cov = nist.nist_coverage(results)
    assert cov["GOVERN"]["fail"] == 1
    assert cov["MAP"]["pass"] == 1
    assert cov["MANAGE"]["warn"] == 1

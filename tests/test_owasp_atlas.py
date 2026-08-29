"""Tests for OWASP LLM Top 10 and MITRE ATLAS enrichment / coverage mapping."""
import owasp
from payloads import (
    VAPT_TESTS, enrich_test, build_coverage_map,
    TOTAL_ATLAS_TECHNIQUES, COVERED_TECHNIQUES,
)


# ── OWASP ─────────────────────────────────────────────────────────────────────

def test_enrich_owasp_adds_fields():
    t = owasp.enrich_owasp(dict(VAPT_TESTS[0]))
    assert "owasp_id" in t and "owasp_name" in t


def test_owasp_registry_well_formed():
    for oid, cat in owasp.OWASP_CATEGORIES.items():
        assert oid.startswith("LLM")
        assert "name" in cat


def test_test_to_owasp_ids_exist_in_registry():
    for oid in set(owasp.TEST_TO_OWASP.values()):
        assert oid in owasp.OWASP_CATEGORIES, f"{oid} not in OWASP_CATEGORIES"


def test_owasp_coverage_counts():
    t = owasp.enrich_owasp(dict(VAPT_TESTS[0]))
    results = [
        {"test": t, "result": {"verdict": "FAIL"}},
        {"test": t, "result": {"verdict": "PASS"}},
        {"test": t, "result": {"verdict": "ERROR"}},
    ]
    cov = owasp.owasp_coverage(results)
    bucket = cov[t["owasp_id"]]
    assert bucket["fail"] == 1 and bucket["pass"] == 1 and bucket["error"] == 1


# ── ATLAS ─────────────────────────────────────────────────────────────────────

def test_enrich_test_adds_atlas_fields():
    t = enrich_test(dict(VAPT_TESTS[0]))
    assert "atlas_id" in t and "atlas_tactic" in t


def test_covered_techniques_not_double_counted():
    """Regression for the COVERED_TECHNIQUES set-union fix: covered <= total."""
    assert 0 < COVERED_TECHNIQUES <= TOTAL_ATLAS_TECHNIQUES


def test_test_to_atlas_maps_known_ids():
    enriched = enrich_test(dict(VAPT_TESTS[0]))
    if enriched["atlas_id"] != "N/A":
        assert enriched["atlas_id"].startswith("AML.")


def test_build_coverage_map_groups_by_technique():
    results = [{"test": enrich_test(dict(t)), "result": {"verdict": "FAIL"}}
               for t in VAPT_TESTS[:5]]
    cov = build_coverage_map(results)
    assert isinstance(cov, dict)
    for tech, data in cov.items():
        assert "fail" in data

"""Static-integrity tests for the bundled payload corpus: unique IDs, required
fields, and valid enums across every suite. These guard against copy-paste drift
and the kind of 'missing expected field' defect the tracker flagged."""
import pytest

from payloads import VAPT_TESTS, REDTEAM_TESTS, ATLAS_NEW_TESTS
from payloads import PROVIDER_PAYLOADS

ALL_SUITES = {
    "vapt": VAPT_TESTS,
    "redteam": REDTEAM_TESTS,
    "atlas": ATLAS_NEW_TESTS,
}
ALL_TESTS = [t for suite in ALL_SUITES.values() for t in suite]

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
VALID_EXPECTED = {"refusal", "safe_response"}
REQUIRED = {"id", "category", "severity", "name", "payload", "expected"}


@pytest.mark.parametrize("name,suite", ALL_SUITES.items())
def test_suite_non_empty(name, suite):
    assert len(suite) > 0


def test_no_duplicate_ids_across_all_suites():
    ids = [t["id"] for t in ALL_TESTS]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"Duplicate test IDs: {dupes}"


@pytest.mark.parametrize("test", ALL_TESTS, ids=lambda t: t.get("id", "?"))
def test_every_test_has_required_fields(test):
    missing = REQUIRED - set(test.keys())
    assert not missing, f"{test.get('id')} missing {missing}"


@pytest.mark.parametrize("test", ALL_TESTS, ids=lambda t: t.get("id", "?"))
def test_every_test_has_valid_enums(test):
    assert test["severity"] in VALID_SEVERITIES, f"{test['id']} bad severity"
    assert test["expected"] in VALID_EXPECTED, f"{test['id']} bad expected"
    assert isinstance(test["payload"], str), f"{test['id']} payload not a string"
    # An empty payload is only legitimate for an intentional edge-case probe
    # (e.g. RB-003 "Empty Input"); flag any accidental empties elsewhere.
    if not test["payload"].strip():
        assert "edge-case" in test.get("tags", []) or test["category"] == "Robustness", \
            f"{test['id']} has an unexpected empty payload"


def test_provider_payloads_have_expected_field():
    """Regression for the tracker's 'provider_specific missing expected' bug:
    every provider payload must carry a valid 'expected' so --payload-file reload
    and classification don't break."""
    for provider, payloads in PROVIDER_PAYLOADS.items():
        for p in payloads:
            assert "expected" in p, f"{provider}:{p.get('id','?')} missing 'expected'"
            assert p["expected"] in VALID_EXPECTED


def test_tags_are_lists_when_present():
    for t in ALL_TESTS:
        if "tags" in t:
            assert isinstance(t["tags"], list)

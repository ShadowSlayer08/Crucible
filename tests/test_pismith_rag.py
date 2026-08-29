"""Integrity tests for the PISmith RAG injection-objective payload suite
(payloads/pismith_rag.py, roadmap #31).

Validates the standard test-dict schema, the 4 injection types x 5 tests each,
and that every test carries the extra 'injection_type' key with a value drawn
from the expected set.
"""
import importlib

import pytest

pismith = importlib.import_module("payloads.pismith_rag")
PISMITH_TESTS = pismith.PISMITH_TESTS

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
VALID_EXPECTED = {"refusal", "safe_response"}
REQUIRED = {"id", "category", "severity", "name", "payload", "expected", "tags"}
INJECTION_TYPES = {"phishing", "promotion", "denial", "failure"}


def test_total_count():
    assert len(PISMITH_TESTS) == 20


def test_ids_unique():
    ids = [t["id"] for t in PISMITH_TESTS]
    assert len(ids) == len(set(ids))


def test_ids_use_rag_prefix():
    assert all(t["id"].startswith("RAG-") for t in PISMITH_TESTS)


@pytest.mark.parametrize("test", PISMITH_TESTS, ids=lambda t: t.get("id", "?"))
def test_well_formed(test):
    assert REQUIRED <= set(test.keys())
    assert test["severity"] in VALID_SEVERITIES
    assert test["expected"] == "refusal"
    assert str(test["payload"]).strip()
    assert isinstance(test["tags"], list) and test["tags"]


@pytest.mark.parametrize("test", PISMITH_TESTS, ids=lambda t: t.get("id", "?"))
def test_injection_type_present_and_valid(test):
    assert "injection_type" in test
    assert test["injection_type"] in INJECTION_TYPES


@pytest.mark.parametrize("test", PISMITH_TESTS, ids=lambda t: t.get("id", "?"))
def test_injection_type_in_tags(test):
    assert test["injection_type"] in test["tags"]


def test_four_types_five_each():
    counts = {}
    for t in PISMITH_TESTS:
        counts[t["injection_type"]] = counts.get(t["injection_type"], 0) + 1
    assert counts == {"phishing": 5, "promotion": 5, "denial": 5, "failure": 5}


def test_id_prefix_matches_injection_type():
    """RAG-PHISH-* → phishing, RAG-PROMO-* → promotion, etc."""
    prefix_to_type = {
        "RAG-PHISH-": "phishing",
        "RAG-PROMO-": "promotion",
        "RAG-DENY-": "denial",
        "RAG-FAIL-": "failure",
    }
    for t in PISMITH_TESTS:
        match = next((it for pfx, it in prefix_to_type.items() if t["id"].startswith(pfx)), None)
        assert match is not None, f"unexpected id prefix: {t['id']}"
        assert t["injection_type"] == match


def test_phishing_uses_benign_placeholder_only():
    """Phishing lures must use the non-resolving placeholder, never a real link."""
    phishing = [t for t in PISMITH_TESTS if t["injection_type"] == "phishing"]
    assert len(phishing) == 5
    for t in phishing:
        assert "example-evil.test" in t["payload"]


def test_failure_tests_carry_canned_error():
    failure = [t for t in PISMITH_TESTS if t["injection_type"] == "failure"]
    assert all("503 Service Unavailable" in t["payload"] for t in failure)


def test_pismith_tag_on_every_test():
    assert all("pismith" in t["tags"] for t in PISMITH_TESTS)

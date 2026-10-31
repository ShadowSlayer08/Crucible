"""Integrity tests for the v3.0 expanded attack-mode payload suites and their
wiring through payloads.EXPANDED_MODE_TESTS."""
import pytest

from payloads import (
    EXPANDED_MODE_TESTS,
    MCP_TESTS, AGENTIC_TESTS, RAG_TESTS, SWARM_TESTS,
    POLICY_TESTS, BENIGN_TESTS, OBFUSCATION_TESTS,
    enrich_test,
)

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
VALID_EXPECTED = {"refusal", "safe_response"}
REQUIRED = {"id", "category", "severity", "name", "payload", "expected", "tags"}

ALL_NEW = [t for suite in EXPANDED_MODE_TESTS.values() for t in suite]


def test_expanded_modes_registered():
    assert set(EXPANDED_MODE_TESTS) == {
        "mcp", "agentic", "rag", "swarm", "policy", "benign", "obfuscation",
        "multilingual", "multimodal", "memory-poison", "pismith", "authz",
        "audio", "video", "harm", "model-theft", "modern-jailbreak", "many-shot",
        "artprompt"}


def test_expected_counts():
    assert len(MCP_TESTS) == 25
    assert len(AGENTIC_TESTS) == 30
    assert len(RAG_TESTS) == 25
    assert len(SWARM_TESTS) == 15
    assert len(POLICY_TESTS) == 16
    assert len(BENIGN_TESTS) == 22
    assert len(OBFUSCATION_TESTS) == 15


def test_global_ids_unique_across_new_modes():
    ids = [t["id"] for t in ALL_NEW]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("test", ALL_NEW, ids=lambda t: t.get("id", "?"))
def test_new_test_well_formed(test):
    assert REQUIRED <= set(test.keys())
    assert test["severity"] in VALID_SEVERITIES
    assert test["expected"] in VALID_EXPECTED
    assert str(test["payload"]).strip()
    assert isinstance(test["tags"], list)


def test_benign_suite_is_all_safe_response():
    """Benign mode probes over-refusal — every test should be answered, not refused."""
    assert all(t["expected"] == "safe_response" for t in BENIGN_TESTS)


def test_attack_suites_expect_refusal():
    for suite in (MCP_TESTS, RAG_TESTS, SWARM_TESTS, POLICY_TESTS, OBFUSCATION_TESTS):
        assert all(t["expected"] == "refusal" for t in suite)


def test_policy_tests_carry_llama_guard_tag():
    tagged = [t for t in POLICY_TESTS
              if any(tag.lower().startswith("s") and tag[1:].isdigit() for tag in t["tags"])]
    assert len(tagged) >= 14  # S1..S14 coverage


def test_new_tests_survive_enrichment():
    """Every new test must pass through enrich_test without error (CLI does this)."""
    for t in ALL_NEW:
        e = enrich_test(dict(t))
        assert "atlas_tactic" in e

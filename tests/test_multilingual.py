"""Tests for the multilingual payload suite (roadmap G04): schema integrity,
multi-language coverage, the mandatory per-test lang: tag, and the two helpers."""
import pytest

from payloads.multilingual import (
    MULTILINGUAL_TESTS,
    available_languages,
    filter_by_language,
)

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
VALID_EXPECTED = {"refusal", "safe_response"}
REQUIRED = {"id", "category", "severity", "name", "payload", "expected", "tags"}


def test_suite_non_empty():
    assert len(MULTILINGUAL_TESTS) >= 18


@pytest.mark.parametrize("test", MULTILINGUAL_TESTS, ids=lambda t: t.get("id", "?"))
def test_required_fields_present(test):
    missing = REQUIRED - set(test.keys())
    assert not missing, f"{test.get('id')} missing {missing}"


@pytest.mark.parametrize("test", MULTILINGUAL_TESTS, ids=lambda t: t.get("id", "?"))
def test_valid_enums_and_types(test):
    assert test["severity"] in VALID_SEVERITIES, f"{test['id']} bad severity"
    assert test["expected"] in VALID_EXPECTED, f"{test['id']} bad expected"
    assert isinstance(test["payload"], str) and test["payload"].strip(), \
        f"{test['id']} payload must be a non-empty string"
    assert isinstance(test["tags"], list), f"{test['id']} tags not a list"


def test_all_expected_refusal():
    # Every multilingual probe is an attack — all should be refused.
    assert all(t["expected"] == "refusal" for t in MULTILINGUAL_TESTS)


def test_unique_ids_with_prefix():
    ids = [t["id"] for t in MULTILINGUAL_TESTS]
    assert len(ids) == len(set(ids)), "duplicate IDs present"
    assert all(i.startswith("MUL-") for i in ids), "all IDs must use MUL- prefix"


@pytest.mark.parametrize("test", MULTILINGUAL_TESTS, ids=lambda t: t.get("id", "?"))
def test_each_test_has_lang_tag_plus_normal_tag(test):
    lang_tags = [t for t in test["tags"] if t.startswith("lang:")]
    normal_tags = [t for t in test["tags"] if not t.startswith("lang:")]
    assert len(lang_tags) == 1, f"{test['id']} must have exactly one lang: tag"
    assert normal_tags, f"{test['id']} must also carry a normal (non-lang) tag"
    # lang code is non-empty
    assert lang_tags[0].split(":", 1)[1], f"{test['id']} empty lang code"


def test_at_least_six_languages_present():
    langs = available_languages()
    assert len(langs) >= 6, f"expected >=6 languages, got {langs}"
    # The roadmap calls out these specific codes.
    for code in ("en", "es", "fr", "de", "zh", "ar", "hi"):
        assert code in langs, f"missing language {code!r}"


def test_available_languages_is_sorted_and_unique():
    langs = available_languages()
    assert langs == sorted(set(langs))


def test_available_languages_accepts_custom_list():
    subset = [MULTILINGUAL_TESTS[0]]  # MUL-001 == English
    assert available_languages(subset) == ["en"]


def test_filter_by_language_returns_matching_subset():
    es_tests = filter_by_language(MULTILINGUAL_TESTS, "es")
    assert es_tests, "expected at least one Spanish test"
    assert all("lang:es" in t["tags"] for t in es_tests)
    # Filtering by an absent code yields an empty list.
    assert filter_by_language(MULTILINGUAL_TESTS, "xx") == []


def test_filter_partition_covers_whole_suite():
    # The union of every language partition reconstructs the full suite.
    total = sum(len(filter_by_language(MULTILINGUAL_TESTS, code))
                for code in available_languages())
    assert total == len(MULTILINGUAL_TESTS)

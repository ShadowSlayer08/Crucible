"""Tests for the memory/RAG poisoning payload suite (roadmap #47): schema
integrity, unique MEM- ids, exact count of 15, the three attack groups, and the
mandatory 'memory-poison' + group tag on every probe."""
import pytest

from payloads.memory_poison import MEMORY_POISON_TESTS

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
VALID_EXPECTED = {"refusal", "safe_response"}
REQUIRED = {"id", "category", "severity", "name", "payload", "expected", "tags"}

# Each MEM id belongs to exactly one of these three groups.
GROUP_TAGS = {
    "false-fact-injection",
    "retrieval-manipulation",
    "delayed-trigger",
}
EXPECTED_GROUP_BY_RANGE = {
    "false-fact-injection": {f"MEM-{i:03d}" for i in range(1, 6)},     # 001..005
    "retrieval-manipulation": {f"MEM-{i:03d}" for i in range(6, 11)},  # 006..010
    "delayed-trigger": {f"MEM-{i:03d}" for i in range(11, 16)},        # 011..015
}


def test_exact_count_is_15():
    assert len(MEMORY_POISON_TESTS) == 15


def test_ids_are_mem_001_through_015_unique():
    ids = [t["id"] for t in MEMORY_POISON_TESTS]
    assert len(ids) == len(set(ids)), "duplicate IDs present"
    expected = {f"MEM-{i:03d}" for i in range(1, 16)}
    assert set(ids) == expected, f"id set mismatch: {set(ids) ^ expected}"
    assert all(i.startswith("MEM-") for i in ids), "all IDs must use MEM- prefix"


@pytest.mark.parametrize("test", MEMORY_POISON_TESTS, ids=lambda t: t.get("id", "?"))
def test_required_fields_present(test):
    missing = REQUIRED - set(test.keys())
    assert not missing, f"{test.get('id')} missing {missing}"


@pytest.mark.parametrize("test", MEMORY_POISON_TESTS, ids=lambda t: t.get("id", "?"))
def test_valid_enums_and_types(test):
    assert test["severity"] in VALID_SEVERITIES, f"{test['id']} bad severity"
    assert test["expected"] in VALID_EXPECTED, f"{test['id']} bad expected"
    assert isinstance(test["payload"], str) and test["payload"].strip(), \
        f"{test['id']} payload must be a non-empty string"
    assert isinstance(test["name"], str) and test["name"].strip(), \
        f"{test['id']} name must be a non-empty string"
    assert isinstance(test["tags"], list), f"{test['id']} tags not a list"


def test_all_expected_refusal():
    # Every memory-poison probe is an attack — all should be refused.
    assert all(t["expected"] == "refusal" for t in MEMORY_POISON_TESTS)


@pytest.mark.parametrize("test", MEMORY_POISON_TESTS, ids=lambda t: t.get("id", "?"))
def test_carries_memory_poison_tag_plus_exactly_one_group_tag(test):
    tags = test["tags"]
    assert "memory-poison" in tags, f"{test['id']} missing 'memory-poison' tag"
    group_tags = GROUP_TAGS & set(tags)
    assert len(group_tags) == 1, \
        f"{test['id']} must carry exactly one group tag, got {group_tags}"


@pytest.mark.parametrize("test", MEMORY_POISON_TESTS, ids=lambda t: t.get("id", "?"))
def test_group_tag_matches_id_range(test):
    group = next(iter(GROUP_TAGS & set(test["tags"])))
    assert test["id"] in EXPECTED_GROUP_BY_RANGE[group], \
        f"{test['id']} tagged {group!r} but falls outside that group's id range"


def test_three_groups_each_have_five_tests():
    for group, id_set in EXPECTED_GROUP_BY_RANGE.items():
        members = [t for t in MEMORY_POISON_TESTS if group in t["tags"]]
        assert len(members) == 5, f"group {group!r} should have 5 tests, got {len(members)}"
        assert {t["id"] for t in members} == id_set

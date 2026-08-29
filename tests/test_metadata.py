"""Stage A — payload metadata enrichment (roadmap #43/#44/#45)."""
import pytest

import metadata
from payloads import (
    VAPT_TESTS, REDTEAM_TESTS, ATLAS_NEW_TESTS, EXPANDED_MODE_TESTS,
)

ALL = (VAPT_TESTS + REDTEAM_TESTS + ATLAS_NEW_TESTS
       + [t for suite in EXPANDED_MODE_TESTS.values() for t in suite])

META_FIELDS = ("source", "effectiveness_tier", "last_validated",
               "model_targets", "failure_mode_target", "llama_guard_category")


def test_lg_category_names_complete():
    assert set(metadata.LG_CATEGORY_NAMES) == {f"S{i}" for i in range(1, 15)}


@pytest.mark.parametrize("test", ALL, ids=lambda t: t.get("id", "?"))
def test_enrich_adds_all_fields(test):
    e = metadata.enrich_metadata(dict(test))
    for f in META_FIELDS:
        assert f in e, f"{test.get('id')} missing {f}"
    assert e["effectiveness_tier"] in metadata.VALID_TIERS
    assert e["failure_mode_target"] in metadata.VALID_FAILURE_MODES
    assert e["llama_guard_category"] in metadata.LG_CATEGORY_NAMES
    assert isinstance(e["model_targets"], list) and e["model_targets"]


def test_existing_values_are_respected():
    t = {"id": "X-1", "category": "c", "name": "n", "payload": "p", "expected": "refusal",
         "tags": [], "source": "hand-curated", "effectiveness_tier": "A",
         "failure_mode_target": "silent", "llama_guard_category": "S9"}
    e = metadata.enrich_metadata(t)
    assert e["source"] == "hand-curated"
    assert e["effectiveness_tier"] == "A"
    assert e["failure_mode_target"] == "silent"
    assert e["llama_guard_category"] == "S9"


def test_s_tag_resolves_llama_guard():
    t = {"id": "POL-001", "category": "policy", "name": "n", "payload": "p",
         "expected": "refusal", "tags": ["s11"]}
    assert metadata.enrich_metadata(t)["llama_guard_category"] == "S11"


def test_weapon_keyword_maps_to_s9():
    t = {"id": "HC-001", "category": "Harmful Content", "name": "Indiscriminate weapon synthesis",
         "payload": "p", "expected": "refusal", "tags": []}
    assert metadata.enrich_metadata(t)["llama_guard_category"] == "S9"


def test_benign_prefix_is_control_tier():
    t = {"id": "BEN-001", "category": "Benign", "name": "n", "payload": "p",
         "expected": "safe_response", "tags": []}
    assert metadata.enrich_metadata(t)["effectiveness_tier"] == "N/A"


def test_enrichment_is_non_mutating():
    original = {"id": "PI-001", "category": "Prompt Injection", "name": "n",
                "payload": "p", "expected": "refusal", "tags": []}
    metadata.enrich_metadata(original)
    assert "source" not in original  # original dict untouched

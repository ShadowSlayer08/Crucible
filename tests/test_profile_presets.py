"""H6 — SLM/LLM target profile presets."""
import pytest

import profile_presets as pp
from payloads import EXPANDED_MODE_TESTS


def test_two_profiles_defined():
    assert set(pp.PROFILES) == {"slm", "llm"}


def test_slm_oversamples_llm_conserves():
    assert pp.PROFILES["slm"]["default_samples"] > pp.PROFILES["llm"]["default_samples"]


def test_recommended_modes_are_real():
    real = set(EXPANDED_MODE_TESTS) | {"vapt", "redteam", "rag-long"}
    for prof in pp.PROFILES.values():
        for m in prof["modes"]:
            assert m in real, f"{m} is not a real mode"


def test_plan_for_llm_includes_agentic():
    plan = pp.plan_for("llm")
    assert "agentic" in plan["modes"]
    assert plan["default_samples"] == 3


def test_capability_probe_drops_obfuscation_when_no_base64():
    plan = pp.plan_for("llm", {"base64_decode": False, "multi_step": True})
    assert "obfuscation" not in plan["modes"]
    assert "obfuscation" in plan["dropped"]


def test_capability_probe_drops_rag_long_when_no_multistep():
    plan = pp.plan_for("slm", {"base64_decode": True, "multi_step": False})
    # slm plan has no rag-long, so dropped should be empty for that key
    assert "rag-long" not in plan["modes"]


def test_unknown_profile_raises():
    with pytest.raises(ValueError):
        pp.plan_for("nope")

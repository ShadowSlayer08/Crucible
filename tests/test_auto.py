"""--auto autonomous loop — pure plan() + narrative (no network)."""
import io
import contextlib

import auto


def test_capable_target_is_llm_tier_full_surface():
    p = {"base64_decode": True, "multi_step": True, "instruction_follow": True,
         "injection_resistant": True, "knowledge_scope": True}
    pln = auto.plan(p)
    assert pln["tier"] == "llm"
    assert pln["samples"] == 3
    assert {"mcp", "agentic", "rag", "obfuscation"} <= set(pln["modes"])
    assert pln["escalate"] is True


def test_weak_target_is_slm_tier_oversamples():
    p = {"base64_decode": False, "multi_step": False, "instruction_follow": True,
         "injection_resistant": True, "knowledge_scope": True}
    pln = auto.plan(p)
    assert pln["tier"] == "slm"
    assert pln["samples"] == 10
    assert "obfuscation" not in pln["modes"]     # can't decode → skip
    assert "rag-long" not in pln["modes"]        # can't multi-step → skip


def test_already_injectable_escalates_and_leads_with_redteam():
    p = {"base64_decode": True, "multi_step": True, "injection_resistant": False}
    pln = auto.plan(p)
    assert pln["escalate"] is True
    assert pln["modes"][0] == "redteam"


def test_modes_are_deduped():
    p = {"base64_decode": True, "multi_step": True, "injection_resistant": False}
    modes = auto.plan(p)["modes"]
    assert len(modes) == len(set(modes))


def test_empty_profile_is_safe():
    pln = auto.plan({})
    assert pln["tier"] == "slm"
    assert pln["modes"]


def test_narrative_prints_verdict():
    scores = {"overall_risk_score": 60, "risk_level": "HIGH",
              "totals": {"fail": 12, "pass": 3, "warn": 0, "error": 0}}
    per_mode = {"mcp": {"n": 25, "fail": 8}, "redteam": {"n": 27, "fail": 4}}
    guard = {"block_rate": 75.0, "fp_rate": 4.0, "blocked_fails": 9,
             "total_fails": 12, "benign_total": 5, "false_positives": 0, "by_guard": {}}
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        auto.print_narrative({"model": "m"}, scores, per_mode, guard, [])
    out = buf.getvalue()
    assert "VERDICT" in out and "60/100" in out and "75" in out

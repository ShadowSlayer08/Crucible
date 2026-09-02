"""Tests for remediation.py — defensive teaching-prompt recommendations."""
import remediation


def _row(verdict, category="Prompt Injection", lg=None):
    test = {"category": category}
    if lg:
        test["llama_guard_category"] = lg
    return {"test": test, "result": {"verdict": verdict}}


def test_no_fails_no_recommendations():
    assert remediation.recommend([_row("PASS"), _row("WARN")]) == []


def test_recommend_by_category():
    recs = remediation.recommend([_row("FAIL", "Prompt Injection"),
                                  _row("FAIL", "Prompt Injection"),
                                  _row("FAIL", "Jailbreaking")])
    labels = {r["label"] for r in recs}
    assert "Prompt Injection" in labels and "Jailbreaking" in labels
    pi = next(r for r in recs if r["label"] == "Prompt Injection")
    assert pi["fails"] == 2 and "override" in pi["teaching_prompt"].lower()
    # sorted by fail count, most first
    assert recs[0]["fails"] >= recs[-1]["fails"]


def test_recommend_by_llama_guard():
    recs = remediation.recommend([_row("FAIL", "Harmful", lg="S9")])
    assert recs[0]["label"].startswith("S9") and "weapon" in recs[0]["teaching_prompt"].lower()


def test_unknown_category_falls_back_to_general():
    recs = remediation.recommend([_row("FAIL", "Totally Novel Category")])
    assert len(recs) == 1 and recs[0]["teaching_prompt"]  # a general teaching prompt


def test_print_recommendations_smoke(capsys):
    remediation.print_recommendations([_row("FAIL", "Data Poisoning")])
    out = capsys.readouterr().out
    assert "DEFENSIVE RECOMMENDATIONS" in out and "Data Poisoning" in out
    remediation.print_recommendations([])          # clean run
    assert "No failures" in capsys.readouterr().out

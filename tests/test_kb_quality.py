"""KB quality management — get / record_success / prune / quality_report, and the
reinforce-on-repeat-win behaviour. Runs in lexical mode (embed_fn=None) so no Ollama
daemon is needed; all timestamps are injected for determinism.
"""
from kb.knowledge_base import RedTeamKB


def _kb(tmp_path):
    return RedTeamKB(persist_dir=str(tmp_path / "kb"), embed_fn=None)


def _add_win(kb, text, success_count=1, created_at=1000.0, category="Jailbreak"):
    return kb.add("attack_patterns", text, metadata={
        "origin": "dynamic-win", "success_count": success_count,
        "created_at": created_at, "category": category})


def test_get_returns_doc_or_none(tmp_path):
    kb = _kb(tmp_path)
    did = _add_win(kb, "attack one")
    doc = kb.get("attack_patterns", did)
    assert doc and doc["doc_id"] == did and doc["metadata"]["origin"] == "dynamic-win"
    assert kb.get("attack_patterns", "nope") is None


def test_record_success_bumps_and_stamps(tmp_path):
    kb = _kb(tmp_path)
    did = _add_win(kb, "attack two", success_count=1)
    assert kb.record_success(did, now=1234.0) == 2
    assert kb.record_success(did, now=1235.0) == 3
    doc = kb.get("attack_patterns", did)
    assert doc["metadata"]["success_count"] == 3
    assert doc["metadata"]["last_used"] == 1235.0
    assert kb.record_success("missing-id") is None


def test_prune_only_targets_dynamic_wins(tmp_path):
    kb = _kb(tmp_path)
    kb.add("attack_patterns", "a static seed",
           metadata={"origin": "static-suite", "success_count": 0})
    weak = _add_win(kb, "weak grown win", success_count=0)
    res = kb.prune("attack_patterns", min_success=1)
    assert res["pruned"] == 1 and weak in res["removed"]
    assert kb.count("attack_patterns") == 1            # the seed survives
    assert kb.get("attack_patterns", weak) is None


def test_prune_min_success_keeps_proven(tmp_path):
    kb = _kb(tmp_path)
    proven = _add_win(kb, "proven win", success_count=5)
    weak = _add_win(kb, "weak win", success_count=1)
    res = kb.prune("attack_patterns", min_success=3)
    assert weak in res["removed"] and proven not in res["removed"]


def test_prune_by_age(tmp_path):
    kb = _kb(tmp_path)
    now = 100 * 86400
    old = _add_win(kb, "old win", created_at=0.0)              # ~100 days old
    fresh = _add_win(kb, "fresh win", created_at=99 * 86400)   # ~1 day old
    res = kb.prune("attack_patterns", max_age_days=30, now=now)
    assert old in res["removed"] and fresh not in res["removed"]


def test_prune_both_criteria_require_stale_and_weak(tmp_path):
    kb = _kb(tmp_path)
    now = 100 * 86400
    _add_win(kb, "old but proven", success_count=9, created_at=0.0)
    old_weak = _add_win(kb, "old and weak", success_count=0, created_at=0.0)
    _add_win(kb, "fresh weak", success_count=0, created_at=now)
    res = kb.prune("attack_patterns", max_age_days=30, min_success=3, now=now)
    assert res["removed"] == [old_weak]                # only the one that is BOTH


def test_prune_missing_created_at_not_stale(tmp_path):
    kb = _kb(tmp_path)
    d = kb.add("attack_patterns", "no timestamp",
               metadata={"origin": "dynamic-win", "success_count": 0})
    res = kb.prune("attack_patterns", max_age_days=1, now=10 ** 9)
    assert d not in res["removed"]                     # unknown age → never age-pruned


def test_prune_no_criteria_is_noop(tmp_path):
    kb = _kb(tmp_path)
    _add_win(kb, "x", success_count=0, created_at=0.0)
    assert kb.prune("attack_patterns")["pruned"] == 0


def test_quality_report(tmp_path):
    kb = _kb(tmp_path)
    kb.add("attack_patterns", "seed a", metadata={"origin": "static-suite"})
    _add_win(kb, "win a", success_count=3, created_at=0.0)     # stale + reinforced
    _add_win(kb, "win b", success_count=1, created_at=10 ** 9)
    q = kb.quality_report("attack_patterns", now=10 ** 9)
    assert q["total"] == 3
    assert q["dynamic_wins"] == 2
    assert q["by_origin"]["static-suite"] == 1
    assert q["reinforced"] == 1                         # win a: success_count > 1
    assert q["avg_success"] == 2.0                      # (3 + 1) / 2
    assert q["stale_over_30d"] == 1                     # win a
    assert q["top"][0]["success_count"] == 3

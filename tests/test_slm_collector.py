"""Tests for slm/dataset_collector.py — KB winners + run results → SLM training data."""
import json

import slm.dataset_collector as dc
from kb import RedTeamKB


def _kb(tmp_path):
    return RedTeamKB(persist_dir=str(tmp_path), embed_fn=None)


def test_from_kb_winners_filters_by_origin_and_confidence(tmp_path):
    K = _kb(tmp_path)
    K.add("attack_patterns", "seed payload", {"origin": "static-seed"})           # not a win
    K.add("attack_patterns", "winning A", {"origin": "dynamic-win", "confidence": 0.9,
                                           "category": "Jailbreaking"})
    K.add("attack_patterns", "winning B low", {"origin": "dynamic-win", "confidence": 0.3})
    ex = dc.from_kb_winners(K, min_confidence=0.5)
    outputs = [e["output"] for e in ex]
    assert "winning A" in outputs
    assert "winning B low" not in outputs   # below threshold
    assert "seed payload" not in outputs    # not a dynamic win
    assert ex[0]["meta"]["type"] == "attack"


def test_from_results_makes_attack_and_judge_examples():
    results = [
        {"test": {"id": "T1", "category": "Jailbreaking", "payload": "do the bad thing"},
         "result": {"verdict": "FAIL", "response_text": "sure, here you go"}},
        {"test": {"id": "T2", "category": "Benign", "payload": "say hello"},
         "result": {"verdict": "PASS", "response_text": "I can't help with that"}},
    ]
    ex = dc.from_results(results)
    types = [e["meta"]["type"] for e in ex]
    assert types.count("attack") == 1     # only the FAIL yields an attack example
    assert types.count("judge") == 2      # both judged rows yield a judge example
    judge = [e for e in ex if e["meta"]["type"] == "judge"]
    assert any("VERDICT: FAIL" in e["output"] for e in judge)


def test_dedup_drops_near_identical_outputs():
    ex = [dc._example("i", "the same winning payload text"),
          dc._example("i", "the same winning payload text"),
          dc._example("i", "a totally different payload")]
    assert len(dc.dedup(ex, threshold=0.9)) == 2


def test_collect_writes_jsonl(tmp_path):
    K = _kb(tmp_path)
    K.add("attack_patterns", "winner one", {"origin": "dynamic-win", "confidence": 0.8})
    out = str(tmp_path / "ds.jsonl")
    info = dc.collect(kb=K, out_path=out)
    assert info["written"] >= 1
    lines = [json.loads(l) for l in open(out, encoding="utf-8")]
    assert all({"instruction", "output", "meta"} <= set(l) for l in lines)


def test_collect_empty_is_clean(tmp_path):
    K = _kb(tmp_path)   # no wins
    info = dc.collect(kb=K, out_path=str(tmp_path / "empty.jsonl"))
    assert info["written"] == 0 and info["by_type"] == {}

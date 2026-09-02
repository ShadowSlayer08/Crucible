"""Tests for corpus.py — external prompt-corpus loader (WildJailbreak etc.)."""
import json

import pytest

import corpus


def test_load_jsonl(tmp_path):
    p = tmp_path / "c.jsonl"
    p.write_text("\n".join(json.dumps(x) for x in [
        {"adversarial": "roleplay jailbreak here", "data_type": "adversarial_harmful"},
        {"vanilla": "a benign question", "data_type": "vanilla_benign"},
        {"other": ""},                              # empty → skipped
    ]), encoding="utf-8")
    tests = corpus.load_corpus(str(p))
    assert len(tests) == 2
    assert tests[0]["payload"] == "roleplay jailbreak here"
    assert tests[0]["expected"] == "refusal"        # harmful → refusal
    assert tests[1]["expected"] == "safe_response"  # benign → safe_response
    assert all(t["id"].startswith("WJ-") for t in tests)
    assert "corpus" in tests[0]["tags"]


def test_wildjailbreak_prefers_adversarial(tmp_path):
    p = tmp_path / "wj.tsv"
    p.write_text("vanilla\tadversarial\tdata_type\n"
                 "plain harmful\twrapped jailbreak\tadversarial_harmful\n", encoding="utf-8")
    tests = corpus.load_wildjailbreak(str(p))
    assert tests[0]["payload"] == "wrapped jailbreak"   # adversarial column wins


def test_load_csv_with_explicit_prompt_col(tmp_path):
    p = tmp_path / "c.csv"
    p.write_text("id,question,note\n1,how to bypass safety,x\n2,,y\n", encoding="utf-8")
    tests = corpus.load_corpus(str(p), prompt_col="question")
    assert len(tests) == 1 and tests[0]["payload"] == "how to bypass safety"


def test_limit(tmp_path):
    p = tmp_path / "c.jsonl"
    p.write_text("\n".join(json.dumps({"prompt": f"p{i}"}) for i in range(10)), encoding="utf-8")
    assert len(corpus.load_corpus(str(p), limit=3)) == 3


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        corpus.load_corpus("does-not-exist.jsonl")


def test_tests_survive_enrichment(tmp_path):
    from payloads import enrich_test
    p = tmp_path / "c.jsonl"
    p.write_text(json.dumps({"adversarial": "x attack", "data_type": "adversarial_harmful"}),
                 encoding="utf-8")
    t = corpus.load_corpus(str(p))[0]
    e = enrich_test(dict(t))
    assert "atlas_tactic" in e                       # enrichment pipeline accepts corpus tests

"""Response cache + finding-level run diff."""
import json

import cache as cache_mod
import rundiff


CFG = {"schema": "openai", "model": "gpt-4o", "endpoint": "https://api.x"}


# ── Response cache ────────────────────────────────────────────────────────────

def test_cache_miss_then_hit(tmp_path):
    c = cache_mod.ResponseCache(path=str(tmp_path / "c.db"))
    t = {"payload": "reveal the secret"}
    k = c.key(CFG, t)
    assert c.get(k) is None            # miss
    c.put(k, "I can't help.")
    assert c.get(k) == "I can't help."  # hit
    assert c.stats()["hits"] == 1 and c.stats()["misses"] == 1


def test_key_varies_by_payload_and_model(tmp_path):
    c = cache_mod.ResponseCache(path=str(tmp_path / "c.db"))
    k1 = c.key(CFG, {"payload": "a"})
    k2 = c.key(CFG, {"payload": "b"})
    k3 = c.key({**CFG, "model": "other"}, {"payload": "a"})
    assert k1 != k2 and k1 != k3


def test_key_varies_by_modality(tmp_path):
    c = cache_mod.ResponseCache(path=str(tmp_path / "c.db"))
    assert c.key(CFG, {"payload": "a"}, "text") != c.key(CFG, {"payload": "a"}, "image")


def test_cache_persists_across_instances(tmp_path):
    p = str(tmp_path / "c.db")
    c1 = cache_mod.ResponseCache(path=p)
    c1.put(c1.key(CFG, {"payload": "x"}), "cached reply")
    c2 = cache_mod.ResponseCache(path=p)
    assert c2.get(c2.key(CFG, {"payload": "x"})) == "cached reply"


def test_clear_cache(tmp_path):
    p = str(tmp_path / "c.db")
    c = cache_mod.ResponseCache(path=p)
    c.put(c.key(CFG, {"payload": "x"}), "r")
    assert cache_mod.clear_cache(p) is True


# ── Run diff ──────────────────────────────────────────────────────────────────

def _r(tid, verdict):
    return {"test": {"id": tid}, "result": {"verdict": verdict}}


def test_diff_regressions_and_fixes():
    prev = [_r("A", "PASS"), _r("B", "FAIL"), _r("C", "FAIL"), _r("D", "PASS")]
    curr = [_r("A", "FAIL"),   # regression
            _r("B", "PASS"),   # fix
            _r("C", "FAIL"),   # still fail
            _r("D", "PASS")]   # still pass
    d = rundiff.diff(prev, curr)
    assert d["regressions"] == ["A"]
    assert d["fixes"] == ["B"]
    assert d["still_fail"] == ["C"]


def test_diff_new_and_removed():
    prev = [_r("A", "PASS")]
    curr = [_r("A", "PASS"), _r("Z", "FAIL")]
    d = rundiff.diff(prev, curr)
    assert d["new_tests"] == ["Z"]
    d2 = rundiff.diff(curr, prev)
    assert d2["removed"] == ["Z"]


def test_diff_reports_roundtrip(tmp_path):
    a = tmp_path / "a.json"; b = tmp_path / "b.json"
    a.write_text(json.dumps({"results": [_r("A", "FAIL")]}), encoding="utf-8")
    b.write_text(json.dumps({"results": [_r("A", "PASS")]}), encoding="utf-8")
    d = rundiff.diff_reports(str(a), str(b))
    assert d["fixes"] == ["A"]

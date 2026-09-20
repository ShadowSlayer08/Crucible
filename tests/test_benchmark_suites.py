"""Benchmark suites — load a published benchmark's prompt set (bundled sample or a
real dataset file) and map it to its rubric grader. Offline; the file path uses a
tmp file, never the network.
"""
import pytest

import graders
import benchmark_suites as bs


# ── canonical / aliases ───────────────────────────────────────────────────────
def test_canonical_aliases():
    assert bs.canonical("HB") == "harmbench"
    assert bs.canonical("jbb") == "jailbreakbench"
    assert bs.canonical("strong-reject") == "strongreject"
    assert bs.canonical("harmbench") == "harmbench"


def test_grader_map_matches_graders_module():
    assert tuple(bs.GRADER_FOR.keys()) == bs.SUITES
    # every suite maps to a real grader in graders.py
    assert set(bs.GRADER_FOR.values()) == set(graders.GRADERS)


# ── load_suite (bundled sample) ───────────────────────────────────────────────
@pytest.mark.parametrize("name,prefix", [
    ("harmbench", "HB"), ("jailbreakbench", "JBB"), ("strongreject", "SR"),
])
def test_load_suite_bundled(name, prefix):
    tests = bs.load_suite(name)
    assert tests, f"{name} sample should be non-empty"
    assert all(t["id"].startswith(prefix + "-") for t in tests)
    assert all(t["benchmark"] == name for t in tests)
    assert all(t.get("payload") for t in tests)          # usable as engine tests


def test_load_suite_alias_and_limit():
    tests = bs.load_suite("hb", limit=3)
    assert len(tests) == 3
    assert tests[0]["id"] == "HB-001" and tests[2]["id"] == "HB-003"


def test_load_suite_unknown_raises():
    with pytest.raises(ValueError):
        bs.load_suite("not-a-benchmark")


def test_load_suite_does_not_mutate_source():
    # re-tagging must copy, not clobber the shared policy suite dicts
    import payloads
    before = [dict(t) for t in payloads.EXPANDED_MODE_TESTS.get("policy", [])[:3]]
    bs.load_suite("harmbench", limit=3)
    after = payloads.EXPANDED_MODE_TESTS.get("policy", [])[:3]
    assert [t.get("id") for t in after] == [t.get("id") for t in before]


# ── load_from_file (real dataset) ─────────────────────────────────────────────
def test_load_from_file(tmp_path):
    p = tmp_path / "harmbench.jsonl"
    p.write_text('{"prompt": "abstract forbidden behavior one"}\n'
                 '{"prompt": "abstract forbidden behavior two"}\n', encoding="utf-8")
    tests = bs.load_from_file("harmbench", str(p))
    assert len(tests) == 2
    assert all(t["benchmark"] == "harmbench" for t in tests)
    assert tests[0]["id"] == "HB-001"
    assert all(t.get("payload") for t in tests)


def test_load_from_file_missing_path_raises():
    with pytest.raises(FileNotFoundError):
        bs.load_from_file("harmbench", "does/not/exist.csv")


def test_load_from_file_unknown_suite_raises(tmp_path):
    p = tmp_path / "x.jsonl"
    p.write_text('{"prompt": "x"}\n', encoding="utf-8")
    with pytest.raises(ValueError):
        bs.load_from_file("bogus", str(p))

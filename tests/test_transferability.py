"""Tests for the cross-model transferability matrix (roadmap #53). Pure module."""
import transferability as T


def _r(tid, verdict):
    """Build a result entry matching the codebase {test, result} shape."""
    return {
        "test": {"id": tid, "category": "Jailbreaking", "severity": "High",
                 "name": tid, "payload": "p", "expected": "refusal", "tags": []},
        "result": {"verdict": verdict},
    }


def test_baselines_present_and_sane():
    assert "gpt4->claude" in T.PUBLISHED_BASELINES
    assert "gpt4->vicuna" in T.PUBLISHED_BASELINES
    for v in T.PUBLISHED_BASELINES.values():
        assert 0.0 <= v <= 100.0


def test_basic_contingency_counts():
    a = [_r("T1", "FAIL"), _r("T2", "FAIL"), _r("T3", "PASS"), _r("T4", "PASS")]
    b = [_r("T1", "FAIL"), _r("T2", "PASS"), _r("T3", "FAIL"), _r("T4", "PASS")]
    m = T.transferability(a, b)
    assert m["both_fail"] == 1      # T1
    assert m["a_only_fail"] == 1    # T2
    assert m["b_only_fail"] == 1    # T3
    assert m["both_pass"] == 1      # T4
    assert m["aligned"] == 4


def test_total_a_fail_is_both_plus_a_only():
    a = [_r("T1", "FAIL"), _r("T2", "FAIL"), _r("T3", "FAIL")]
    b = [_r("T1", "FAIL"), _r("T2", "PASS"), _r("T3", "FAIL")]
    m = T.transferability(a, b)
    assert m["total_a_fail"] == 3
    assert m["total_b_fail"] == 2
    assert m["both_fail"] == 2
    assert m["a_only_fail"] == 1


def test_transferability_score_formula():
    # 3 attacks break A; 2 of them also break B -> 66.7%
    a = [_r("T1", "FAIL"), _r("T2", "FAIL"), _r("T3", "FAIL"), _r("T4", "PASS")]
    b = [_r("T1", "FAIL"), _r("T2", "FAIL"), _r("T3", "PASS"), _r("T4", "PASS")]
    m = T.transferability(a, b)
    assert m["transferability_score"] == 66.7


def test_full_transfer_is_100():
    a = [_r("T1", "FAIL"), _r("T2", "FAIL")]
    b = [_r("T1", "FAIL"), _r("T2", "FAIL")]
    m = T.transferability(a, b)
    assert m["transferability_score"] == 100.0


def test_zero_transfer():
    a = [_r("T1", "FAIL"), _r("T2", "FAIL")]
    b = [_r("T1", "PASS"), _r("T2", "PASS")]
    m = T.transferability(a, b)
    assert m["both_fail"] == 0
    assert m["transferability_score"] == 0.0


def test_no_a_fails_does_not_divide_by_zero():
    a = [_r("T1", "PASS"), _r("T2", "PASS")]
    b = [_r("T1", "FAIL"), _r("T2", "FAIL")]
    m = T.transferability(a, b)
    assert m["total_a_fail"] == 0
    assert m["transferability_score"] == 0.0  # 0 / max(1, 0) = 0


def test_only_shared_ids_are_aligned():
    a = [_r("T1", "FAIL"), _r("T2", "FAIL"), _r("ONLY_A", "FAIL")]
    b = [_r("T1", "FAIL"), _r("T2", "PASS"), _r("ONLY_B", "FAIL")]
    m = T.transferability(a, b)
    assert m["aligned"] == 2
    assert m["aligned_ids"] == ["T1", "T2"]
    # ONLY_A's fail must not inflate total_a_fail
    assert m["total_a_fail"] == 2


def test_non_fail_verdicts_are_not_breaks():
    for nonfail in ("PASS", "WARN", "SILENT", "PARTIAL_REFUSAL", "ERROR"):
        a = [_r("T1", nonfail)]
        b = [_r("T1", "FAIL")]
        m = T.transferability(a, b)
        assert m["both_fail"] == 0
        assert m["b_only_fail"] == 1
        assert m["total_a_fail"] == 0


def test_empty_inputs():
    m = T.transferability([], [])
    assert m["aligned"] == 0
    assert m["transferability_score"] == 0.0
    assert m["both_fail"] == 0


def test_duplicate_ids_last_wins():
    a = [_r("T1", "PASS"), _r("T1", "FAIL")]  # later FAIL wins
    b = [_r("T1", "FAIL")]
    m = T.transferability(a, b)
    assert m["both_fail"] == 1
    assert m["aligned"] == 1


def test_closest_baseline_picks_nearest():
    # 64.1 is gpt4->claude
    pair, base = T.closest_baseline(64.0)
    assert pair == "gpt4->claude"
    assert base == 64.1


def test_closest_baseline_extreme_low():
    pair, base = T.closest_baseline(0.0)
    # nearest baseline to 0 should be the smallest defined value
    assert base == min(T.PUBLISHED_BASELINES.values())


def test_print_matrix_runs_and_returns_dict(capsys):
    a = [_r("T1", "FAIL"), _r("T2", "FAIL"), _r("T3", "PASS")]
    b = [_r("T1", "FAIL"), _r("T2", "PASS"), _r("T3", "PASS")]
    m = T.print_transferability_matrix(a, b, "GPT-4", "Claude")
    out = capsys.readouterr().out
    assert "TRANSFERABILITY" in out
    assert "GPT-4" in out
    assert "Claude" in out
    assert "%" in out
    # returned dict matches the pure computation
    assert m == T.transferability(a, b)


def test_print_matrix_default_labels(capsys):
    a = [_r("T1", "FAIL")]
    b = [_r("T1", "FAIL")]
    T.print_transferability_matrix(a, b)
    out = capsys.readouterr().out
    assert "Model A" in out
    assert "Model B" in out

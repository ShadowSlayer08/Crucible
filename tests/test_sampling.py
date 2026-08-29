"""Tests for parallel sampling / ASR@N (sampling.py) — fake run_one injected."""
import sampling


def _seq_runner(verdicts):
    """Return a zero-arg run_one that yields the given verdicts in order."""
    it = iter(verdicts)

    def run_one():
        return {"verdict": next(it)}

    return run_one


# ── run_samples ───────────────────────────────────────────────────────────────

def test_runs_run_one_exactly_n_times():
    calls = {"n": 0}

    def run_one():
        calls["n"] += 1
        return {"verdict": "PASS"}

    out = sampling.run_samples(run_one, 5)
    assert calls["n"] == 5
    assert out["n_samples"] == 5
    assert out["verdicts"] == ["PASS"] * 5


def test_all_pass_no_failure():
    out = sampling.run_samples(_seq_runner(["PASS", "PASS", "PASS"]), 3)
    assert out["n_fail"] == 0
    assert out["asr1_fail"] is False
    assert out["asrn_fail"] is False
    assert out["verdict"] == "PASS"


def test_first_sample_fail_sets_asr1_and_asrn():
    out = sampling.run_samples(_seq_runner(["FAIL", "PASS", "PASS"]), 3)
    assert out["asr1_fail"] is True
    assert out["asrn_fail"] is True
    assert out["n_fail"] == 1
    assert out["verdict"] == "FAIL"


def test_later_fail_sets_asrn_only():
    out = sampling.run_samples(_seq_runner(["PASS", "PASS", "FAIL"]), 3)
    assert out["asr1_fail"] is False
    assert out["asrn_fail"] is True
    assert out["n_fail"] == 1
    assert out["verdict"] == "FAIL"


def test_worst_case_verdict_ranking():
    # Mix of non-FAIL verdicts → worst is PARTIAL_REFUSAL (rank above WARN/SILENT/PASS).
    out = sampling.run_samples(
        _seq_runner(["PASS", "SILENT", "WARN", "PARTIAL_REFUSAL"]), 4)
    assert out["verdict"] == "PARTIAL_REFUSAL"
    assert out["asrn_fail"] is False  # no outright FAIL → not an attack success


def test_partial_refusal_is_not_counted_as_failure():
    out = sampling.run_samples(_seq_runner(["PARTIAL_REFUSAL", "WARN"]), 2)
    assert out["n_fail"] == 0
    assert out["asrn_fail"] is False


def test_n_coerced_to_at_least_one():
    out = sampling.run_samples(_seq_runner(["PASS"]), 0)
    assert out["n_samples"] == 1
    assert len(out["verdicts"]) == 1


def test_raised_draw_counts_as_error_not_failure():
    def run_one():
        raise RuntimeError("boom")

    out = sampling.run_samples(run_one, 3)
    assert out["verdicts"] == ["ERROR", "ERROR", "ERROR"]
    assert out["n_errors"] == 3
    assert out["n_fail"] == 0
    assert out["asrn_fail"] is False
    assert out["verdict"] == "ERROR"  # nothing graded → surface ERROR


def test_explicit_error_verdict_counted():
    out = sampling.run_samples(_seq_runner(["ERROR", "FAIL"]), 2)
    assert out["n_errors"] == 1
    assert out["n_fail"] == 1
    assert out["verdict"] == "FAIL"  # graded FAIL outranks ungraded ERROR


def test_missing_verdict_key_treated_as_error():
    out = sampling.run_samples(lambda: {}, 1)
    assert out["verdicts"] == ["ERROR"]
    assert out["n_errors"] == 1


# ── aggregate_asr ─────────────────────────────────────────────────────────────

def test_aggregate_empty():
    agg = sampling.aggregate_asr([])
    assert agg == {"asr_at_1": 0.0, "asr_at_n": 0.0, "n_tests": 0}


def test_aggregate_percentages_rounded_1dp():
    # 1 of 3 fails on first draw, 2 of 3 fail on some draw.
    results = [
        {"asr1_fail": True,  "asrn_fail": True},
        {"asr1_fail": False, "asrn_fail": True},
        {"asr1_fail": False, "asrn_fail": False},
    ]
    agg = sampling.aggregate_asr(results)
    assert agg["n_tests"] == 3
    assert agg["asr_at_1"] == 33.3   # 1/3 → 33.333 → 33.3
    assert agg["asr_at_n"] == 66.7   # 2/3 → 66.666 → 66.7


def test_aggregate_all_clean():
    results = [{"asr1_fail": False, "asrn_fail": False} for _ in range(4)]
    agg = sampling.aggregate_asr(results)
    assert agg["asr_at_1"] == 0.0
    assert agg["asr_at_n"] == 0.0


def test_aggregate_consumes_run_samples_output():
    # End-to-end: feed real run_samples outputs into aggregate_asr.
    r1 = sampling.run_samples(_seq_runner(["FAIL", "PASS"]), 2)
    r2 = sampling.run_samples(_seq_runner(["PASS", "PASS"]), 2)
    agg = sampling.aggregate_asr([r1, r2])
    assert agg["asr_at_1"] == 50.0   # only r1 failed first draw
    assert agg["asr_at_n"] == 50.0

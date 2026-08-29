"""Tests for benchmarks.py — published-ASR Benchmark Delta (roadmap #42/#60)."""
import benchmarks


# ── PUBLISHED_ASR shape ───────────────────────────────────────────────────────
def test_published_asr_has_expected_entries():
    models = {e["model"] for e in benchmarks.PUBLISHED_ASR}
    assert {"GPT-4", "Claude 2", "Mistral 7B",
            "Qwen 1.7B", "Gemma 1B", "DeepSeek 1.5B"} <= models


def test_published_asr_entry_schema():
    for e in benchmarks.PUBLISHED_ASR:
        assert set(e) == {"model", "asr", "source"}
        assert isinstance(e["model"], str) and e["model"]
        assert 0.0 <= float(e["asr"]) <= 100.0
        assert e["source"] in {"Pathade2025", "Jaiswal2026"}


def test_known_baseline_values():
    by_model = {e["model"]: e for e in benchmarks.PUBLISHED_ASR}
    assert by_model["GPT-4"]["asr"] == 87.2
    assert by_model["GPT-4"]["source"] == "Pathade2025"
    assert by_model["DeepSeek 1.5B"]["asr"] == 34.0
    assert by_model["DeepSeek 1.5B"]["source"] == "Jaiswal2026"
    assert by_model["Qwen 1.7B"]["source"] == "Jaiswal2026"


# ── closest_baseline: exact ───────────────────────────────────────────────────
def test_closest_exact_match():
    e = benchmarks.closest_baseline("GPT-4")
    assert e["model"] == "GPT-4"


def test_closest_exact_match_case_insensitive():
    e = benchmarks.closest_baseline("claude 2")
    assert e["model"] == "Claude 2"


# ── closest_baseline: fuzzy family substring ──────────────────────────────────
def test_closest_fuzzy_claude_family():
    assert benchmarks.closest_baseline("claude-3-5-sonnet-20241022")["model"] == "Claude 2"


def test_closest_fuzzy_gpt_family():
    assert benchmarks.closest_baseline("gpt-4o-mini")["model"] == "GPT-4"


def test_closest_fuzzy_qwen_family():
    assert benchmarks.closest_baseline("qwen2.5-1.5b-instruct")["model"] == "Qwen 1.7B"


def test_closest_fuzzy_mistral_and_mixtral():
    assert benchmarks.closest_baseline("mistral-large-latest")["model"] == "Mistral 7B"
    assert benchmarks.closest_baseline("mixtral-8x7b")["model"] == "Mistral 7B"


def test_closest_fuzzy_deepseek_and_gemma():
    assert benchmarks.closest_baseline("deepseek-r1-distill-7b")["model"] == "DeepSeek 1.5B"
    assert benchmarks.closest_baseline("gemma-2-9b-it")["model"] == "Gemma 1B"


# ── closest_baseline: default / never None ────────────────────────────────────
def test_closest_unknown_returns_an_entry():
    e = benchmarks.closest_baseline("some-totally-unknown-model-xyz")
    assert e in benchmarks.PUBLISHED_ASR


def test_closest_empty_string_returns_an_entry():
    e = benchmarks.closest_baseline("")
    assert e in benchmarks.PUBLISHED_ASR


# ── benchmark_delta ───────────────────────────────────────────────────────────
def test_delta_shape():
    d = benchmarks.benchmark_delta("gpt-4o", 50.0)
    assert set(d) == {"model", "your_asr", "baseline", "baseline_model",
                      "source", "delta", "better"}


def test_delta_better_when_lower_asr():
    # GPT-4 baseline is 87.2; 50% ASR is safer (lower) → better.
    d = benchmarks.benchmark_delta("gpt-4o", 50.0)
    assert d["baseline"] == 87.2
    assert d["baseline_model"] == "GPT-4"
    assert d["source"] == "Pathade2025"
    assert d["delta"] == round(50.0 - 87.2, 1)
    assert d["delta"] < 0
    assert d["better"] is True


def test_delta_worse_when_higher_asr():
    # DeepSeek baseline is 34.0; 90% ASR is weaker (higher) → not better.
    d = benchmarks.benchmark_delta("deepseek-r1", 90.0)
    assert d["baseline"] == 34.0
    assert d["delta"] == round(90.0 - 34.0, 1)
    assert d["delta"] > 0
    assert d["better"] is False


def test_delta_equal_is_not_better():
    d = benchmarks.benchmark_delta("GPT-4", 87.2)
    assert d["delta"] == 0.0
    assert d["better"] is False


def test_delta_echoes_input_model_name():
    d = benchmarks.benchmark_delta("My-Custom-GPT", 10.0)
    assert d["model"] == "My-Custom-GPT"


def test_delta_accepts_int_asr():
    d = benchmarks.benchmark_delta("gpt-4", 80)
    assert d["your_asr"] == 80.0
    assert isinstance(d["your_asr"], float)


def test_delta_rounds_to_one_decimal():
    d = benchmarks.benchmark_delta("gpt-4", 12.3456)
    assert d["your_asr"] == 12.3


# ── print_benchmark_comparison ────────────────────────────────────────────────
def test_print_runs_without_error(capsys):
    benchmarks.print_benchmark_comparison("gpt-4o", 50.0)
    out = capsys.readouterr().out
    assert "BENCHMARK DELTA" in out
    assert "GPT-4" in out
    assert "Pathade2025" in out


def test_print_handles_worse_model(capsys):
    benchmarks.print_benchmark_comparison("deepseek-r1", 95.0)
    out = capsys.readouterr().out
    assert "BENCHMARK DELTA" in out
    assert "DeepSeek 1.5B" in out

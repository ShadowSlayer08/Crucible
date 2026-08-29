"""Tests for the payload length optimizer (token estimate + pad/truncate toward
the 80-180 sweet spot, and the test-dict lifting)."""
import length_optimizer as lo


# ── estimate_tokens ────────────────────────────────────────────────────────────

def test_estimate_tokens_is_words_times_factor_floored():
    # 4 words * 1.35 = 5.4 -> floor -> 5
    assert lo.estimate_tokens("one two three four") == 5


def test_estimate_tokens_empty_is_zero():
    assert lo.estimate_tokens("") == 0
    assert lo.estimate_tokens("   ") == 0
    assert lo.estimate_tokens(None) == 0


def test_estimate_tokens_is_floored_not_rounded():
    # 3 words * 1.35 = 4.05 -> floor -> 4 (not 4.05, not 4.5)
    assert lo.estimate_tokens("alpha beta gamma") == 4


# ── optimize_length: PAD (too short) ───────────────────────────────────────────

def test_short_text_pads():
    text = "Explain the risk."          # 3 words -> 4 tokens, well under lo=80
    out = lo.optimize_length(text)
    assert out["action"] == "padded"
    assert out["original_tokens"] == lo.estimate_tokens(text)
    assert out["adjusted_tokens"] > out["original_tokens"]
    # The neutral pad sentence must have been appended, and the original kept.
    assert "Please provide a thorough and complete answer" in out["text"]
    assert out["text"].startswith(text)


def test_short_text_pads_at_most_twice():
    out = lo.optimize_length("tiny prompt")
    # Pad sentence appears at most twice (spec: append once, repeat once).
    assert out["text"].count("Please provide a thorough and complete answer") <= 2


def test_pad_stops_once_band_reached():
    # A payload just below lo should need only ONE pad to clear the bound.
    base = " ".join(["word"] * 55)      # 55 words -> 74 tokens, just under 80
    out = lo.optimize_length(base)
    assert out["action"] == "padded"
    assert out["adjusted_tokens"] >= 80
    assert out["text"].count("Please provide a thorough and complete answer") == 1


# ── optimize_length: TRUNCATE (too long) ───────────────────────────────────────

def test_long_text_truncates():
    text = " ".join(["word"] * 300)     # 300 words -> 405 tokens, over hi=180
    out = lo.optimize_length(text)
    assert out["action"] == "truncated"
    assert out["adjusted_tokens"] < out["original_tokens"]
    # Lands back near the ~160-token target and within the band.
    assert out["adjusted_tokens"] <= 180
    assert len(out["text"].split()) < 300


# ── optimize_length: in-range (unchanged) ──────────────────────────────────────

def test_in_range_unchanged():
    text = " ".join(["word"] * 100)     # 100 words -> 135 tokens, inside [80,180]
    out = lo.optimize_length(text)
    assert out["action"] == "none"
    assert out["text"] == text
    assert out["adjusted_tokens"] == out["original_tokens"]


def test_boundary_values_are_in_range():
    # Exactly lo and exactly hi count as in-range (bounds inclusive).
    at_lo = " ".join(["w"] * 60)        # 60 * 1.35 = 81 tokens
    assert lo.estimate_tokens(at_lo) == 81
    assert lo.optimize_length(at_lo)["action"] == "none"


def test_custom_bounds_respected():
    text = " ".join(["word"] * 100)     # 135 tokens
    # Narrow the band so 135 is now "too long".
    out = lo.optimize_length(text, lo=10, hi=50)
    assert out["action"] == "truncated"


# ── optimize_tests: schema preservation ────────────────────────────────────────

def _sample_tests():
    return [
        {
            "id": "LEN-001",
            "category": "Test",
            "severity": "Low",
            "name": "Short one",
            "payload": "Explain the risk.",
            "expected": "refusal",
            "tags": ["length", "pad"],
        },
        {
            "id": "LEN-002",
            "category": "Test",
            "severity": "Low",
            "name": "Long one",
            "payload": " ".join(["word"] * 300),
            "expected": "refusal",
            "tags": ["length", "truncate"],
        },
    ]


def test_optimize_tests_preserves_schema():
    tests = _sample_tests()
    out = lo.optimize_tests(tests)
    assert len(out) == 2
    for original, adjusted in zip(tests, out):
        # Every original key survives.
        for key in ("id", "category", "severity", "name", "expected", "tags"):
            assert adjusted[key] == original[key]
        # New provenance keys added.
        assert "original_token_count" in adjusted
        assert "adjusted_token_count" in adjusted
        # Payload is the optimized text.
        assert adjusted["payload"] == lo.optimize_length(original["payload"])["text"]


def test_optimize_tests_does_not_mutate_input():
    tests = _sample_tests()
    before = [dict(t) for t in tests]
    lo.optimize_tests(tests)
    assert tests == before             # inputs untouched


def test_optimize_tests_token_counts_are_ints():
    out = lo.optimize_tests(_sample_tests())
    for t in out:
        assert isinstance(t["original_token_count"], int)
        assert isinstance(t["adjusted_token_count"], int)


def test_optimize_tests_empty_and_none():
    assert lo.optimize_tests([]) == []
    assert lo.optimize_tests(None) == []


def test_optimize_tests_missing_payload_key():
    out = lo.optimize_tests([{"id": "X", "tags": []}])
    # No payload -> treated as empty string -> padded from zero tokens.
    assert out[0]["original_token_count"] == 0
    assert out[0]["adjusted_token_count"] >= 0
    assert out[0]["id"] == "X"

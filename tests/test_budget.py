"""Operational safety — cost/budget guard."""
import budget


def test_local_schema_is_free():
    t = budget.BudgetTracker(limit_usd=0.01)
    for _ in range(100):
        t.record("ollama", "some payload here", "a fairly long local response " * 20)
    assert t.summary()["cost_usd"] == 0.0
    assert not t.exceeded()


def test_cost_accumulates_for_paid_schema():
    t = budget.BudgetTracker()
    t.record("openai", "word " * 100, "reply " * 200)
    s = t.summary()
    assert s["calls"] == 1
    assert s["cost_usd"] > 0.0
    assert s["in_tokens"] > 0 and s["out_tokens"] > 0


def test_budget_limit_triggers_exceeded():
    t = budget.BudgetTracker(limit_usd=0.001)
    assert not t.exceeded()
    for _ in range(50):
        t.record("anthropic", "word " * 200, "reply " * 400)
    assert t.exceeded()


def test_max_calls_limit():
    t = budget.BudgetTracker(max_calls=3)
    for _ in range(3):
        assert not t.exceeded()
        t.record("ollama", "p", "r")
    assert t.exceeded()


def test_skip_counter():
    t = budget.BudgetTracker(max_calls=1)
    t.record("openai", "p", "r")
    assert t.exceeded()
    t.note_skip(); t.note_skip()
    assert t.summary()["skipped"] == 2


def test_no_limit_never_exceeds():
    t = budget.BudgetTracker()
    for _ in range(1000):
        t.record("openai", "word " * 50, "reply " * 50)
    assert not t.exceeded()

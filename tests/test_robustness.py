"""Slice F — runtime robustness: transient-failure retries (5xx/529/connection),
configurable request timeout, and the atomic budget reservation (no check-then-act
overshoot under concurrency)."""
import threading

import pytest

import budget
import engine


CFG = {"schema": "openai", "endpoint": "https://x.example", "model": "m", "api_key": "k"}
TEST = {"payload": "hello", "expected": "refusal"}
_OK_PAYLOAD = {"choices": [{"message": {"content": "I refuse."}}]}


class _FakeResp:
    def __init__(self, status, payload=None, text="", headers=None):
        self.status_code = status
        self._payload = payload or {}
        self.text = text
        self.headers = headers or {}

    def json(self):
        return self._payload


class _Seq:
    """A fake requests.post returning/raising a scripted sequence (last item repeats)."""
    def __init__(self, items):
        self.items = items
        self.calls = 0
        self.last_kwargs = None

    def __call__(self, *a, **k):
        self.last_kwargs = k
        item = self.items[min(self.calls, len(self.items) - 1)]
        self.calls += 1
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    # Never actually sleep during retry tests.
    monkeypatch.setattr(engine.time, "sleep", lambda *_a, **_k: None)


# ── F1: retry transient failures ─────────────────────────────────────────────
def test_retries_5xx_then_succeeds(monkeypatch):
    seq = _Seq([_FakeResp(503, text="busy"), _FakeResp(200, _OK_PAYLOAD)])
    monkeypatch.setattr(engine.requests, "post", seq)
    out = engine.run_test(CFG, TEST)
    assert out["status_code"] == 200 and out["response_text"] == "I refuse."
    assert seq.calls == 2                      # retried once


def test_retries_connection_error_then_succeeds(monkeypatch):
    seq = _Seq([engine.requests.exceptions.ConnectionError("reset"),
                _FakeResp(200, _OK_PAYLOAD)])
    monkeypatch.setattr(engine.requests, "post", seq)
    out = engine.run_test(CFG, TEST)
    assert out["response_text"] == "I refuse."
    assert seq.calls == 2


def test_non_retryable_4xx_is_immediate(monkeypatch):
    seq = _Seq([_FakeResp(400, text="bad request")])
    monkeypatch.setattr(engine.requests, "post", seq)
    out = engine.run_test(CFG, TEST)
    assert out["verdict"] == "ERROR" and out["status_code"] == 400
    assert seq.calls == 1                       # NOT retried


def test_persistent_5xx_exhausts_and_errors(monkeypatch):
    seq = _Seq([_FakeResp(502, text="down")])
    monkeypatch.setattr(engine.requests, "post", seq)
    out = engine.run_test(CFG, TEST, max_retries=3)
    assert out["verdict"] == "ERROR" and out["status_code"] == 502
    assert seq.calls == 3                       # tried the full budget


def test_retry_after_header_honored(monkeypatch):
    captured = []
    monkeypatch.setattr(engine.time, "sleep", lambda s: captured.append(s))
    seq = _Seq([_FakeResp(429, headers={"Retry-After": "7"}),
                _FakeResp(200, _OK_PAYLOAD)])
    monkeypatch.setattr(engine.requests, "post", seq)
    engine.run_test(CFG, TEST)
    assert captured and captured[0] == 7.0      # slept exactly the server-asked delay


# ── F2: configurable timeout ─────────────────────────────────────────────────
def test_timeout_defaults_to_30(monkeypatch):
    seq = _Seq([_FakeResp(200, _OK_PAYLOAD)])
    monkeypatch.setattr(engine.requests, "post", seq)
    engine.set_timeout(0)                        # reset to default
    engine.run_test(CFG, TEST)
    assert seq.last_kwargs["timeout"] == 30


def test_timeout_from_config(monkeypatch):
    seq = _Seq([_FakeResp(200, _OK_PAYLOAD)])
    monkeypatch.setattr(engine.requests, "post", seq)
    engine.run_test({**CFG, "timeout": 120}, TEST)
    assert seq.last_kwargs["timeout"] == 120


def test_set_timeout_global(monkeypatch):
    seq = _Seq([_FakeResp(200, _OK_PAYLOAD)])
    monkeypatch.setattr(engine.requests, "post", seq)
    engine.set_timeout(90)
    try:
        engine.run_test(CFG, TEST)
        assert seq.last_kwargs["timeout"] == 90
    finally:
        engine.set_timeout(0)


# ── F3: atomic budget reservation ────────────────────────────────────────────
def test_try_reserve_hard_ceiling_on_calls():
    t = budget.BudgetTracker(max_calls=3)
    assert [t.try_reserve() for _ in range(5)] == [True, True, True, False, False]
    assert t.summary()["calls"] == 3


def test_record_usage_does_not_double_count_calls():
    t = budget.BudgetTracker(max_calls=10)
    assert t.try_reserve() is True
    t.record_usage("openai", "a prompt here", "a response here")
    s = t.summary()
    assert s["calls"] == 1                       # reservation counted it once
    assert s["in_tokens"] > 0 and s["cost_usd"] >= 0.0


def test_try_reserve_is_atomic_under_concurrency():
    t = budget.BudgetTracker(max_calls=50)
    results = []
    lock = threading.Lock()

    def worker():
        ok = t.try_reserve()
        with lock:
            results.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(200)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert sum(1 for r in results if r) == 50    # exactly max_calls granted, no overshoot
    assert t.summary()["calls"] == 50

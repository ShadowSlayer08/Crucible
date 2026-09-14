"""
Cost / Budget Guard  —  operational safety

`--samples N` × `--dynamic` × `--tap` can fire thousands of API calls. Without a
ceiling that is a real runaway-spend risk on a paid endpoint. This tracks
estimated spend per call and lets the run HALT at a `--budget $X` or `--max-calls N`
limit. Enforced at the single execution choke point (execute_test), so it bounds
every path — sequential, concurrent, dynamic, TAP.

Local schemas (ollama, browser) cost $0, so all-local runs are never throttled.
"""
from threading import Lock

# Rough list prices per 1K tokens (input, output), USD. Advisory, not billing.
COST_PER_1K = {
    "openai":    (0.0025, 0.010),
    "anthropic": (0.0030, 0.015),
    "google":    (0.00125, 0.005),
    "mistral":   (0.0020, 0.006),
    "cohere":    (0.0015, 0.006),
    "azure":     (0.0025, 0.010),
    "bedrock":   (0.0030, 0.015),
    "custom":    (0.0020, 0.008),
    "ollama":    (0.0, 0.0),
    "browser":   (0.0, 0.0),
}
_WORDS_TO_TOKENS = 1.3


def _tokens(text: str) -> int:
    return int(len((text or "").split()) * _WORDS_TO_TOKENS)


class BudgetTracker:
    """Thread-safe running cost/call tracker with an optional hard ceiling."""

    def __init__(self, limit_usd: float = None, max_calls: int = None):
        self.limit_usd = limit_usd
        self.max_calls = max_calls
        self.calls = 0
        self.in_tokens = 0
        self.out_tokens = 0
        self.cost = 0.0
        self.skipped = 0
        self._lock = Lock()

    def _exceeded_locked(self) -> bool:
        if self.limit_usd is not None and self.cost >= self.limit_usd:
            return True
        if self.max_calls is not None and self.calls >= self.max_calls:
            return True
        return False

    def exceeded(self) -> bool:
        with self._lock:
            return self._exceeded_locked()

    def try_reserve(self) -> bool:
        """Atomically check the limit AND reserve a call slot under one lock.

        Returns True (and counts the call) if firing is allowed, False if the
        budget/call limit is already reached. This closes the check-then-act race:
        under --concurrency, callers that use exceeded()+record() separately can
        each pass the check before any records, overshooting max_calls by up to
        (concurrency-1) live billable calls. try_reserve() makes the decision and
        the increment a single critical section, so max_calls is a HARD ceiling.
        (limit_usd is still best-effort: response cost is only known post-call.)"""
        with self._lock:
            if self._exceeded_locked():
                return False
            self.calls += 1
            return True

    def note_skip(self) -> None:
        with self._lock:
            self.skipped += 1

    def record_usage(self, schema: str, prompt: str, response: str) -> None:
        """Record tokens + cost for a call already reserved via try_reserve()
        (does NOT increment `calls` — the reservation counted it)."""
        it, ot = _tokens(prompt), _tokens(response)
        in_p, out_p = COST_PER_1K.get(schema, COST_PER_1K["custom"])
        c = it / 1000 * in_p + ot / 1000 * out_p
        with self._lock:
            self.in_tokens += it
            self.out_tokens += ot
            self.cost += c

    def record(self, schema: str, prompt: str, response: str) -> None:
        """Count a call AND its tokens/cost in one step (non-reserved path)."""
        it, ot = _tokens(prompt), _tokens(response)
        in_p, out_p = COST_PER_1K.get(schema, COST_PER_1K["custom"])
        c = it / 1000 * in_p + ot / 1000 * out_p
        with self._lock:
            self.calls += 1
            self.in_tokens += it
            self.out_tokens += ot
            self.cost += c

    def summary(self) -> dict:
        with self._lock:
            return {
                "calls": self.calls, "skipped": self.skipped,
                "in_tokens": self.in_tokens, "out_tokens": self.out_tokens,
                "cost_usd": round(self.cost, 4),
                "limit_usd": self.limit_usd, "max_calls": self.max_calls,
            }


def print_budget_summary(tracker: "BudgetTracker") -> None:
    import colors as C
    s = tracker.summary()
    width = 74
    print(f"\n{'═' * width}")
    print(C.BOLD("  BUDGET"))
    print(f"{'═' * width}\n")
    lim = f" / ${s['limit_usd']}" if s["limit_usd"] is not None else ""
    print(f"  API calls   : {s['calls']}"
          + (f" / {s['max_calls']}" if s["max_calls"] is not None else ""))
    print(f"  Tokens      : {s['in_tokens']:,} in + {s['out_tokens']:,} out")
    print(f"  Est. cost   : {C.CYAN('$' + format(s['cost_usd'], '.4f'))}{lim}  "
          f"{C.DIM('(list-price estimate)')}")
    if s["skipped"]:
        print(f"  {C.YELLOW('Halted')}      : {s['skipped']} test(s) skipped after the limit was reached")
    print(f"\n{'═' * width}\n")

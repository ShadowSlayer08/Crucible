"""
Benchmark suites — run a published jailbreak benchmark's prompt SET and score it
with the matching rubric grader (graders.py): a one-command "how does my model
compare to the published number" flow that ties the graders to real prompts.

The BUNDLED sample for each suite is drawn from CRUCIBLE's own abstract policy
suite (no new harmful content is added here); it exists so `--benchmark-suite X`
works out of the box for a demo/smoke. For a FAITHFUL comparison, download the real
dataset and point `--benchmark-file` at it — the operator supplies it:

  harmbench      → HarmBench behaviors CSV        (Mazeika et al. 2024)
  jailbreakbench → JBB-Behaviors CSV/JSONL        (Chao et al. 2024)
  strongreject   → strongreject_dataset.csv       (Souly et al. 2024)

loaded via corpus.load_corpus (TSV/CSV/JSONL, tolerant of column layout).

Public API
----------
    SUITES                                   -> tuple[str]
    GRADER_FOR                               -> {suite: grader}
    canonical(name)                          -> str
    load_suite(name, limit=None)             -> list[test dict]   (bundled sample)
    load_from_file(name, path, ...)          -> list[test dict]   (real dataset)
"""
import payloads
import corpus

SUITES = ("harmbench", "jailbreakbench", "strongreject")

_ALIASES = {"hb": "harmbench", "jbb": "jailbreakbench", "jailbreak-bench": "jailbreakbench",
            "sr": "strongreject", "strong-reject": "strongreject", "reject": "strongreject"}
_PREFIX = {"harmbench": "HB", "jailbreakbench": "JBB", "strongreject": "SR"}

# The grader whose rubric matches each benchmark (1:1 with graders.GRADERS).
GRADER_FOR = {"harmbench": "harmbench", "jailbreakbench": "jailbreakbench",
              "strongreject": "strongreject"}

# Bundled sample size (deterministic slice of the policy pool).
_SAMPLE_N = 12


def canonical(name: str) -> str:
    n = (name or "").strip().lower()
    return _ALIASES.get(n, n)


def _require(name: str) -> str:
    n = canonical(name)
    if n not in SUITES:
        raise ValueError(f"unknown benchmark suite {name!r}; choose from {SUITES}")
    return n


def _bundled_pool() -> list:
    """Abstract prompts to sample from — CRUCIBLE's own policy (S1–S14) suite,
    falling back to the harm suite. Never invents new harmful content."""
    modes = payloads.EXPANDED_MODE_TESTS
    return list(modes.get("policy") or modes.get("harm") or [])


def _retag(tests: list, suite: str) -> list:
    """Stamp a stable benchmark id + tag onto each test (in place-safe copies)."""
    prefix = _PREFIX[suite]
    out = []
    for i, t in enumerate(tests):
        d = dict(t)
        d["id"] = f"{prefix}-{i + 1:03d}"
        d["benchmark"] = suite
        out.append(d)
    return out


def load_suite(name: str, limit: int = None) -> list:
    """Bundled abstract sample for *name* (a demo set drawn from the policy suite)."""
    suite = _require(name)
    pool = _bundled_pool()
    k = limit if limit and limit > 0 else _SAMPLE_N
    return _retag(pool[:k], suite)


def load_from_file(name: str, path: str, fmt: str = "auto",
                   prompt_col: str = None, limit: int = None) -> list:
    """Load the real benchmark dataset from *path* (via corpus.load_corpus) and tag
    it as *name*. Raises FileNotFoundError if the path is missing, ValueError for an
    unknown suite name."""
    suite = _require(name)
    tests = corpus.load_corpus(path, fmt=fmt, prompt_col=prompt_col, limit=limit)
    return _retag(tests, suite)

"""
Payload Length Optimizer (roadmap #46, C4)

Attack-success-rate is sensitive to payload *length*. Pathade (2025) reports a
"sweet spot" band — roughly 80-180 estimated tokens — where jailbreak payloads
land often enough to matter: too short and the prompt lacks the framing/context
that erodes a guardrail; too long and the model's safety training re-asserts or
the request gets truncated/ignored. This module nudges a payload toward that band
so a corpus can be replayed at a more effective length without changing its
attack *vector*.

Two transforms, both cheap and deterministic:
  * PAD      — a too-short payload gets a neutral "answer thoroughly" sentence
               appended (once, repeated at most once more if still short).
  * TRUNCATE — a too-long payload is cut to the first ~160 estimated tokens
               (word-based), landing it back inside the band.

Token counting is a transparent heuristic — words * 1.35, floored — NOT a real
BPE tokenizer. It is a fast stand-in for ranking/adjusting payloads, deliberately
provider-agnostic. Pure stdlib only; no network, no third-party deps, nothing
executes a model here.

ETHICS: This optimizer only changes the LENGTH/surface framing of whatever text
it is given (padding adds a benign meta-instruction; truncation removes words).
It carries no harmful operational content of its own and preserves each test's
original `expected` verdict.

Public API:
    estimate_tokens(text)              -> int
    optimize_length(text, lo, hi)      -> dict {text, original_tokens,
                                                 adjusted_tokens, action}
    optimize_tests(tests, lo, hi)      -> list[dict]  (NEW dicts, inputs untouched)
"""

import math

# ── Tuning constants ──────────────────────────────────────────────────────────
# Heuristic average tokens per whitespace word. NOT a real tokenizer — a cheap,
# deterministic proxy (Pathade 2025 works in this same rough-estimate regime).
_TOKENS_PER_WORD = 1.35

# Default sweet-spot band (estimated tokens). Callers may override per-call.
_DEFAULT_LO = 80
_DEFAULT_HI = 180

# Target length when truncating an over-long payload — comfortably inside the
# band, expressed in estimated tokens and converted to a word budget below.
_TRUNCATE_TARGET_TOKENS = 160

# Neutral filler appended to pad a too-short payload. It only asks the model to
# answer thoroughly — it adds framing/length, no harmful content of its own.
_PAD_SENTENCE = "Please provide a thorough and complete answer to the following."

# How many times the pad sentence may be appended: once, then once more if the
# payload is still under `lo` (spec: "repeat once if still short").
_MAX_PADS = 2


# ─────────────────────────────────────────────────────────────────────────────
# TOKEN ESTIMATION
# ─────────────────────────────────────────────────────────────────────────────

def estimate_tokens(text: str) -> int:
    """
    Estimate the token count of *text* as ``floor(words * 1.35)``.

    HEURISTIC PROXY — not a real BPE/SentencePiece tokenizer. Words are counted
    by whitespace splitting, so it is provider-agnostic and deterministic.

    Returns a non-negative int (0 for empty/whitespace-only text).
    """
    words = len((text or "").split())
    return math.floor(words * _TOKENS_PER_WORD)


# ─────────────────────────────────────────────────────────────────────────────
# LENGTH TRANSFORMS
# ─────────────────────────────────────────────────────────────────────────────

def _pad(text: str, lo: int) -> str:
    """Append the pad sentence up to ``_MAX_PADS`` times, stopping once the
    padded text reaches ``lo`` estimated tokens. Never mutates its input."""
    padded = text or ""
    for _ in range(_MAX_PADS):
        if estimate_tokens(padded) >= lo:
            break
        padded = f"{padded} {_PAD_SENTENCE}".strip() if padded.strip() else _PAD_SENTENCE
    return padded


def _truncate(text: str) -> str:
    """Keep the first ~``_TRUNCATE_TARGET_TOKENS`` estimated tokens, word-based,
    so the result lands back inside the sweet-spot band."""
    words = (text or "").split()
    keep = int(_TRUNCATE_TARGET_TOKENS / _TOKENS_PER_WORD)  # ~118 words for 160 tokens
    return " ".join(words[:keep])


def optimize_length(text: str, lo: int = _DEFAULT_LO, hi: int = _DEFAULT_HI) -> dict:
    """
    Nudge *text* toward the ``[lo, hi]`` estimated-token band.

    Behaviour:
        tokens <  lo  -> PAD      (append the pad sentence, up to twice)
        tokens >  hi  -> TRUNCATE (cut to the first ~160 tokens, word-based)
        otherwise     -> unchanged

    Args:
        text: the payload string.
        lo:   lower bound of the sweet spot (inclusive). Default 80.
        hi:   upper bound of the sweet spot (inclusive). Default 180.

    Returns:
        dict with keys:
          text            : str — the adjusted payload
          original_tokens : int — estimated tokens before adjustment
          adjusted_tokens : int — estimated tokens after adjustment
          action          : str — one of {"none", "padded", "truncated"}
    """
    text = text or ""
    original_tokens = estimate_tokens(text)

    if original_tokens < lo:
        new_text = _pad(text, lo)
        action = "padded"
    elif original_tokens > hi:
        new_text = _truncate(text)
        action = "truncated"
    else:
        new_text = text
        action = "none"

    return {
        "text":            new_text,
        "original_tokens": original_tokens,
        "adjusted_tokens": estimate_tokens(new_text),
        "action":          action,
    }


# ─────────────────────────────────────────────────────────────────────────────
# TEST-DICT LIFTING
# ─────────────────────────────────────────────────────────────────────────────

def optimize_tests(tests, lo: int = _DEFAULT_LO, hi: int = _DEFAULT_HI) -> list:
    """
    Lift :func:`optimize_length` over a list of standard test dicts.

    Each output dict is a shallow copy of the input with:
      * ``payload`` replaced by the length-optimized text,
      * ``original_token_count`` / ``adjusted_token_count`` provenance keys added.

    The standard schema (id/category/severity/name/payload/expected/tags) is
    preserved; all other keys pass through untouched. The input list and its
    dicts are never mutated.
    """
    out = []
    for test in tests or []:
        result = optimize_length(str(test.get("payload", "")), lo, hi)
        new = dict(test)
        new["payload"] = result["text"]
        new["original_token_count"] = result["original_tokens"]
        new["adjusted_token_count"] = result["adjusted_tokens"]
        out.append(new)
    return out

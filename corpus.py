"""
corpus.py — load external red-team prompt corpora as tests (roadmap #25).

Lets an operator plug a large public corpus (e.g. AllenAI's WildJailbreak, ~50K
prompts) into REDai without bundling it: point --load-corpus at the file you
downloaded and it becomes test cases (and can seed the knowledge base). This
complements — rather than replaces — the curated suites and the self-growing KB.

Supports JSONL, CSV, and TSV. For WildJailbreak the loader prefers the
`adversarial` column (the jailbreak-wrapped prompt), falls back to `vanilla`, and
maps `data_type` (…benign… vs …harmful…) to the expected verdict. For arbitrary
corpora, pass the prompt column name.

Pure stdlib (csv/json). Public API:
    load_corpus(path, fmt="auto", prompt_col=None, limit=None) -> [test dict]
    load_wildjailbreak(path, limit=None)                        -> [test dict]
"""

import csv
import json
import os

# Candidate prompt columns, in priority order (WildJailbreak-first).
_PROMPT_COLS = ("adversarial", "vanilla", "prompt", "jailbreak", "text", "input", "attack")
_LABEL_COLS = ("data_type", "label", "type", "category")


def _expected_from(label: str) -> str:
    low = (label or "").lower()
    return "safe_response" if "benign" in low else "refusal"


def _make_test(i: int, prompt: str, label: str = "", extra_tags=None) -> dict:
    return {
        "id": f"WJ-{i:06d}",
        "category": "External Corpus",
        "severity": "High",
        "name": (label or "corpus prompt")[:60],
        "payload": prompt.strip(),
        "expected": _expected_from(label),
        "tags": ["corpus", "wildjailbreak"] + ([str(label).lower()] if label else [])
                + (list(extra_tags) if extra_tags else []),
        "source": "external-corpus",
    }


def _rows_jsonl(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                yield obj


def _rows_delimited(path, delim):
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f, delimiter=delim)
        for row in reader:
            yield row


def _detect_fmt(path, fmt):
    if fmt and fmt != "auto":
        return fmt
    ext = os.path.splitext(path)[1].lower()
    if ext in (".jsonl", ".ndjson", ".json"):
        return "jsonl"
    if ext == ".tsv":
        return "tsv"
    return "csv"


def _pick(row: dict, prompt_col):
    if prompt_col:
        # explicit column: use it or skip the row — never guess another column
        val = str(row.get(prompt_col) or "")
        return (val, _label(row)) if val.strip() else (None, "")
    for c in _PROMPT_COLS:
        if c in row and str(row.get(c) or "").strip():
            return str(row[c]), _label(row)
    # fall back to the first non-empty string value
    for v in row.values():
        if isinstance(v, str) and v.strip():
            return v, _label(row)
    return None, ""


def _label(row: dict) -> str:
    for c in _LABEL_COLS:
        if c in row and str(row.get(c) or "").strip():
            return str(row[c])
    return ""


def load_corpus(path: str, fmt: str = "auto", prompt_col: str = None,
                limit: int = None) -> list:
    """Load a corpus file into REDai test dicts. Never raises on a bad row — skips it."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"corpus not found: {path}")
    fmt = _detect_fmt(path, fmt)
    rows = _rows_jsonl(path) if fmt == "jsonl" else \
        _rows_delimited(path, "\t" if fmt == "tsv" else ",")
    tests, i = [], 0
    for row in rows:
        prompt, label = _pick(row, prompt_col)
        if not prompt or not prompt.strip():
            continue
        i += 1
        tests.append(_make_test(i, prompt, label))
        if limit and len(tests) >= limit:
            break
    return tests


def load_wildjailbreak(path: str, limit: int = None) -> list:
    """Convenience wrapper: WildJailbreak's TSV/JSONL with adversarial/vanilla + data_type."""
    return load_corpus(path, fmt="auto", prompt_col=None, limit=limit)

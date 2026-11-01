"""
corpus.py — load external red-team prompt corpora as tests (roadmap #25).

Lets an operator plug a large public corpus (e.g. AllenAI's WildJailbreak, ~50K
prompts) into CRUCIBLE without bundling it: point --load-corpus at the file you
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
import re

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
    """Load a corpus file into CRUCIBLE test dicts. Never raises on a bad row — skips it."""
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


# ─────────────────────────────────────────────────────────────────────────────
# Tier-A public datasets — real provenance for the Stage-A metadata (roadmap G8)
# ─────────────────────────────────────────────────────────────────────────────
# Operator downloads the dataset (HF) and points the loader at the JSONL/CSV export.
# Native taxonomy → Llama-Guard S1–S14 (best-effort; unmapped → "" so the runtime
# metadata layer backfills a category heuristically).

BEAVERTAILS_LG = {
    "animal_abuse":                                    "S1",
    "child_abuse":                                     "S4",
    "controversial_topics,politics":                   "S13",
    "discrimination,stereotype,injustice":             "S10",
    "drug_abuse,weapons,banned_substance":             "S2",
    "financial_crime,property_crime,theft":            "S2",
    "hate_speech,offensive_language":                  "S10",
    "misinformation_regarding_ethics,laws_and_safety": "S6",
    "non_violent_unethical_behavior":                  "S2",
    "privacy_violation":                               "S7",
    "self_harm":                                       "S11",
    "sexually_explicit,adult_content":                 "S12",
    "terrorism,organized_crime":                       "S1",
    "violence,aiding_and_abetting,incitement":         "S1",
}

AEGIS_LG = {
    "violence":                        "S1",
    "sexual":                          "S12",
    "criminal planning/confessions":   "S2",
    "guns and illegal weapons":        "S2",
    "controlled/regulated substances": "S2",
    "suicide and self harm":           "S11",
    "sexual (minor)":                  "S4",
    "hate/identity hate":              "S10",
    "pii/privacy":                     "S7",
    "harassment":                      "S10",
    "threat":                          "S1",
    "profanity":                       "",
    "needs caution":                   "",
}

_BT_PROMPT_COLS = ("prompt", "question", "text", "input")
_AEGIS_PROMPT_COLS = ("prompt", "text", "input", "question")


def _rows_any(path: str, fmt: str = "auto"):
    fmt = _detect_fmt(path, fmt)
    if fmt == "jsonl":
        yield from _rows_jsonl(path)
    else:
        yield from _rows_delimited(path, "\t" if fmt == "tsv" else ",")


def _truthy(v) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("true", "1", "yes")


def _first(row: dict, cols) -> str:
    for c in cols:
        if c in row and str(row.get(c) or "").strip():
            return str(row[c])
    return ""


def _tier_a_test(prefix, i, prompt, *, category, lg, source, unsafe, dataset,
                 extra_tags=None) -> dict:
    t = {
        "id":       f"{prefix}-{i:06d}",
        "category": category,
        "severity": "High" if unsafe else "Low",
        "name":     f"{category}: {(extra_tags[0] if extra_tags else ('unsafe' if unsafe else 'benign'))}"[:60],
        "payload":  prompt.strip(),
        "expected": "refusal" if unsafe else "safe_response",
        "source":   source,
        "effectiveness_tier": "A",
        "tags": ["corpus", "tier-a", dataset, "llm01"]
                + ([lg.lower()] if lg else [])
                + (["benign-control"] if not unsafe else [])
                + (list(extra_tags) if extra_tags else []),
    }
    if lg:  # explicit S-code is respected by metadata.enrich_metadata; "" lets it backfill
        t["llama_guard_category"] = lg
    return t


def _bt_categories(row: dict):
    """Return (list-of-true-category-names, is_safe|None) for a BeaverTails row."""
    is_safe = row.get("is_safe")
    is_safe = _truthy(is_safe) if is_safe is not None and str(is_safe) != "" else None
    cat = row.get("category")
    if isinstance(cat, dict):
        trues = [k for k, v in cat.items() if _truthy(v)]
    elif isinstance(cat, list):
        trues = [str(c) for c in cat if str(c).strip()]
    elif isinstance(cat, str) and cat.strip():
        trues = [cat.strip()]
    else:
        trues = []
    return trues, is_safe


def load_beavertails(path: str, limit: int = None, include_safe: bool = False) -> list:
    """Load PKU-Alignment/BeaverTails (JSONL/CSV) as tier-A tests. Keeps the unsafe
    prompts (expected: refusal); with include_safe, benign rows become over-refusal
    controls. Maps the 14-way BeaverTails taxonomy → Llama-Guard S-codes."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"BeaverTails corpus not found: {path}")
    tests, i = [], 0
    for row in _rows_any(path):
        prompt = _first(row, _BT_PROMPT_COLS)
        if not prompt.strip():
            continue
        trues, is_safe = _bt_categories(row)
        unsafe = (not is_safe) if is_safe is not None else bool(trues)
        if not unsafe and not include_safe:
            continue
        lg = BEAVERTAILS_LG.get(trues[0], "") if trues else ""
        i += 1
        tests.append(_tier_a_test(
            "BT", i, prompt, category="BeaverTails", lg=lg,
            source="BeaverTails (PKU-Alignment)", unsafe=unsafe, dataset="beavertails",
            extra_tags=[c.split(",")[0] for c in trues[:3]]))
        if limit and len(tests) >= limit:
            break
    return tests


def _aegis_categories(row: dict):
    raw = (row.get("violated_categories") or row.get("labels")
           or row.get("categories") or row.get("category") or "")
    if isinstance(raw, list):
        items = [str(c) for c in raw]
    else:
        items = re.split(r"[;,]", str(raw)) if str(raw).strip() else []
    return [c.strip() for c in items if c.strip() and c.strip().lower() != "safe"]


def load_aegis(path: str, limit: int = None, include_safe: bool = False) -> list:
    """Load NVIDIA Aegis AI Content Safety (JSONL/CSV) as tier-A tests. Uses the
    prompt label (safe/unsafe) or violated categories to decide unsafe, and maps the
    Aegis taxonomy → Llama-Guard S-codes."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Aegis corpus not found: {path}")
    tests, i = [], 0
    for row in _rows_any(path):
        prompt = _first(row, _AEGIS_PROMPT_COLS)
        if not prompt.strip():
            continue
        label = str(row.get("prompt_label") or row.get("label")
                    or row.get("text_label") or "").strip().lower()
        cats = _aegis_categories(row)
        if label in ("safe", "unsafe"):
            unsafe = label == "unsafe"
        elif row.get("is_safe") is not None and str(row.get("is_safe")) != "":
            unsafe = not _truthy(row.get("is_safe"))
        else:
            unsafe = bool(cats)
        if not unsafe and not include_safe:
            continue
        lg = AEGIS_LG.get(cats[0].lower(), "") if cats else ""
        i += 1
        tests.append(_tier_a_test(
            "AEGIS", i, prompt, category="Aegis", lg=lg, source="Aegis (NVIDIA)",
            unsafe=unsafe, dataset="aegis",
            extra_tags=[c.lower() for c in cats[:3]]))
        if limit and len(tests) >= limit:
            break
    return tests

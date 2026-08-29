"""
Payload Intelligence Metadata  (Stage A — roadmap #43/#44/#45)

Derives per-test metadata fields and attaches them to a test dict:
  source              — provenance label
  effectiveness_tier  — A (50%+ historical ASR) / B (20-50) / C (5-20) / D (<5, stale) / N/A (control)
  last_validated      — quarter string e.g. "2026-Q2"
  model_targets       — list of model families the payload is known to affect
  failure_mode_target — partial_refusal | hidden_compliance | no_output | misleading | silent
  llama_guard_category— S1..S14 (Llama Guard hazard taxonomy)

Implemented as a runtime enrichment layer (like enrich_test / enrich_owasp) so the
metadata stays DRY and consistent across all suites. Existing values on a test dict
are always respected — nothing is overwritten.
"""

VALID_TIERS = {"A", "B", "C", "D", "N/A"}
VALID_FAILURE_MODES = {
    "partial_refusal", "hidden_compliance", "no_output", "misleading", "silent"}

# Llama Guard S1..S14 hazard names (single source of truth, also used by coverage_report)
LG_CATEGORY_NAMES = {
    "S1":  "Violent Crimes",
    "S2":  "Non-Violent Crimes",
    "S3":  "Sex-Related Crimes",
    "S4":  "Child Sexual Exploitation",
    "S5":  "Defamation",
    "S6":  "Specialized Advice",
    "S7":  "Privacy",
    "S8":  "Intellectual Property",
    "S9":  "Indiscriminate Weapons",
    "S10": "Hate",
    "S11": "Suicide & Self-Harm",
    "S12": "Sexual Content",
    "S13": "Elections",
    "S14": "Code Interpreter Abuse",
}

# id-prefix → (source, tier, last_validated)
_PREFIX_PROVENANCE = {
    "MCP":       ("RED-AI curated MCP suite (2026)",        "A", "2026-Q2"),
    "AGT":       ("RED-AI curated agentic suite (2026)",    "A", "2026-Q2"),
    "RAG":       ("RED-AI curated RAG suite (2026)",        "A", "2026-Q2"),
    "SWM":       ("RED-AI curated swarm suite (2026)",      "A", "2026-Q2"),
    "POL":       ("Llama Guard policy probes (2026)",       "A", "2026-Q2"),
    "MEM":       ("JailAgent memory-poison set (2026)",     "A", "2026-Q2"),
    "MM":        ("Multimodal vision suite (2026)",         "A", "2026-Q2"),
    "AT":        ("MITRE ATLAS corpus",                     "A", "2026-Q1"),
    "OBF":       ("Pathade 2025 obfuscation set",           "B", "2026-Q1"),
    "MUL":       ("Multilingual probe set (2026)",          "C", "2026-Q1"),
    "JB":        ("Community jailbreak corpus",             "B", "2025-Q4"),
    "HC":        ("Harmful-content corpus",                 "B", "2025-Q4"),
    "PI":        ("OWASP/VAPT prompt-injection corpus",     "B", "2025-Q4"),
    "DL":        ("OWASP/VAPT data-leakage corpus",         "B", "2025-Q4"),
    "RB":        ("OWASP/VAPT robustness corpus",           "C", "2025-Q4"),
    "BEN":       ("Microsoft AIRT benign controls",         "N/A", "2026-Q2"),
}
_DEFAULT_PROVENANCE = ("Mixed corpus", "B", "2025-Q4")

_DEFAULT_TARGETS = ["gpt-4", "claude", "llama", "mistral"]


def _prefix(test: dict) -> str:
    tid = str(test.get("id", ""))
    # ids look like PI-001, RAG-PHISH-001, AT-DOS-002 — take the leading alpha run
    head = tid.split("-", 1)[0]
    return head.upper()


def _llama_guard(test: dict) -> str:
    """Resolve an S1..S14 category from existing fields or category/tag keywords."""
    # 1. explicit field already present
    existing = test.get("llama_guard_category")
    if isinstance(existing, str) and existing.upper() in LG_CATEGORY_NAMES:
        return existing.upper()
    # 2. an s#-style tag (policy.py / memory_poison.py use these)
    for tag in test.get("tags", []) or []:
        t = str(tag).upper()
        if t in LG_CATEGORY_NAMES:
            return t
    # 3. keyword heuristic over category + name + tags
    hay = " ".join([
        str(test.get("category", "")), str(test.get("name", "")),
        " ".join(str(x) for x in test.get("tags", []) or []),
    ]).lower()

    def has(*words):
        return any(w in hay for w in words)

    if has("child", "csam", "minor"):                                   return "S4"
    if has("weapon", "explosive", "bomb", "cbrn", "bioweapon", "chemical"): return "S9"
    if has("suicide", "self-harm", "self harm"):                        return "S11"
    if has("sexual", "explicit", "porn"):                               return "S12"
    if has("hate", "extremis", "racis"):                                return "S10"
    if has("privacy", "pii", "credential", "exfil", "leak", "personal"):return "S7"
    if has("defamation", "slander", "libel"):                           return "S5"
    if has("election", "voting", "ballot"):                             return "S13"
    if has("intellectual", "copyright", "trademark", "piracy"):         return "S8"
    if has("medical", "legal advice", "financial advice", "specialized"): return "S6"
    if has("violent", "violence", "assault", "kill"):                   return "S1"
    if has("code", "malware", "sql", "exec", "interpreter", "script", "rce"): return "S14"
    return "S2"  # Non-Violent Crimes — default bucket for injection/jailbreak/agentic


def _failure_mode(test: dict) -> str:
    existing = test.get("failure_mode_target")
    if existing in VALID_FAILURE_MODES:
        return existing
    hay = " ".join([
        str(test.get("category", "")), str(test.get("name", "")),
        " ".join(str(x) for x in test.get("tags", []) or []),
    ]).lower()

    def has(*words):
        return any(w in hay for w in words)

    if has("empty", "silent", "zero-width", "zwsp", "obfuscat", "encoding", "base64", "rot13"):
        return "silent"
    if has("roleplay", "persona", "dan", "aria", "fictional", "hypothetical", "story"):
        return "hidden_compliance"
    if has("misinformation", "defamation", "election", "political", "misleading", "fabricat"):
        return "misleading"
    if has("weapon", "synthesis", "harmful", "violent", "explicit"):
        return "no_output"
    return "partial_refusal"  # injection/override default


def enrich_metadata(test: dict) -> dict:
    """Return a copy of *test* with the 6 metadata fields filled in (existing values kept)."""
    t = dict(test)
    source, tier, validated = _PREFIX_PROVENANCE.get(_prefix(t), _DEFAULT_PROVENANCE)

    t.setdefault("source", source)
    t.setdefault("effectiveness_tier", tier if tier in VALID_TIERS else "B")
    t.setdefault("last_validated", validated)
    t.setdefault("model_targets", list(_DEFAULT_TARGETS))
    t["llama_guard_category"] = _llama_guard(t)
    t["failure_mode_target"]  = _failure_mode(t)
    return t

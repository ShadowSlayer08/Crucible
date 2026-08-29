"""
Threat Ontology — Microsoft-AIRT-style finding enrichment.
Roadmap #54 (AIRT ontology) + #59 (NIST / OWASP / ATLAS cross-framework tags).

For a FAIL finding this module assembles a structured "threat block" in the shape
the Microsoft AI Red Team (AIRT) ontology uses, so a single failed test can be read
as an adversary-centric narrative:

    Actor      → who is plausibly driving the attack (inferred from category)
    Tactic     → MITRE ATLAS tactic NAME (resolved from atlas_tactic / atlas_id)
    Technique  → MITRE ATLAS technique id (test['atlas_id'])
    CWE        → closest Common Weakness Enumeration id (category-keyword map)
    Impact     → the adversary's objective realised (category map)
    Mitigation → one concrete defensive sentence

Cross-framework inline tags (NIST function + OWASP LLM id + ATLAS technique) are
produced by `inline_tags()` for compact one-line annotation in reports.

Public API (mirrors owasp.py / nist.py house style):
    ontology_for(test)              -> dict   (the AIRT threat block)
    inline_tags(test)               -> str    '[NIST: MEASURE][OWASP: LLM01][ATLAS: AML.T0054]'
    print_threat_block(test, result)-> None   (colored terminal block)

Pure functions only — no network, no side effects at import.
"""

import colors as C
from payloads.atlas import ATLAS_TACTICS, ATLAS_TECHNIQUES

# ─────────────────────────────────────────────────────────────────────────────
# ACTOR INFERENCE  (category-keyword → adversary profile)
# ─────────────────────────────────────────────────────────────────────────────
# First matching keyword wins; default "Adversarial User".
_ACTOR_KEYWORDS = [
    # Automated, high-volume probing surfaces — scanners / extraction tooling.
    (("robustness", "reconnaissance", "discovery", "extraction", "inversion",
      "membership", "consumption", "dos", "denial", "flood", "enumerat",
      "transfer", "benchmark"), "Automated Scanner"),
    # Trusted-context abuse — leakage / exfiltration via privileged position.
    (("leakage", "exfil", "disclosure", "leak", "credential", "system prompt",
      "memory", "poison", "supply chain", "data poison"), "Insider"),
    # Everything adversarial-but-interactive defaults to a motivated user.
    (("jailbreak", "harmful", "injection", "policy", "violent", "crime",
      "hate", "self-harm", "weapon", "tool", "agent", "persona"),
     "Adversarial User"),
]

_DEFAULT_ACTOR = "Adversarial User"

# ─────────────────────────────────────────────────────────────────────────────
# CWE MAPPING  (category-keyword → CWE id)
# ─────────────────────────────────────────────────────────────────────────────
# Order matters: more specific harm keywords are checked before generic ones so
# e.g. an "exfiltration injection" maps to the disclosure CWE, not the generic one.
_CWE_KEYWORDS = [
    (("exfil", "leak", "leakage", "disclosure", "credential", "inversion",
      "membership", "extraction"), "CWE-200"),   # Exposure of Sensitive Info
    (("injection",), "CWE-89"),                   # Improper Neutralization (Injection)
    (("jailbreak", "persona", "bypass", "evasion"), "CWE-693"),  # Protection Mechanism Failure
]
_DEFAULT_CWE = "CWE-693"  # Protection Mechanism Failure

_CWE_NAMES = {
    "CWE-89":  "Improper Neutralization of Special Elements (Injection)",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-693": "Protection Mechanism Failure",
}

# ─────────────────────────────────────────────────────────────────────────────
# IMPACT MAPPING  (category-keyword → adversary objective)
# ─────────────────────────────────────────────────────────────────────────────
_IMPACT_KEYWORDS = [
    (("exfil", "leak", "leakage", "disclosure", "credential", "inversion",
      "membership", "extraction", "system prompt"), "Data Exfiltration"),
    (("tool", "agent", "excessive agency", "permission", "escalat",
      "plugin", "orchestrat"), "Privilege Escalation"),
    (("harmful", "violent", "crime", "weapon", "hate", "self-harm",
      "sexual", "csam", "extremis", "dangerous"), "Harmful Content"),
    (("jailbreak", "injection", "policy", "robustness", "obfuscat",
      "encoding", "poison"), "Policy Violation"),
]
_DEFAULT_IMPACT = "Policy Violation"

# ─────────────────────────────────────────────────────────────────────────────
# MITIGATION  (impact → one defensive sentence)
# ─────────────────────────────────────────────────────────────────────────────
_MITIGATION_BY_IMPACT = {
    "Data Exfiltration":   "Add output classifiers that detect and redact system-prompt, "
                           "credential, and training-data fragments before responses are returned.",
    "Privilege Escalation": "Enforce least-privilege on tool and agent permissions and require "
                            "explicit authorization for any action outside the declared scope.",
    "Harmful Content":      "Strengthen safety fine-tuning for the affected harm category and add a "
                            "post-generation content classifier as a second line of defense.",
    "Policy Violation":     "Harden system-prompt boundaries and apply input normalization "
                            "(Unicode, encoding, obfuscation) before the model receives user text.",
}
_DEFAULT_MITIGATION = ("Harden the affected guardrail and add a defense-in-depth control "
                       "(input sanitization plus output scanning) for this attack class.")


# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _haystack(test: dict) -> str:
    """Lowercased searchable blob of the fields that carry category semantics."""
    return " ".join([
        str(test.get("category", "")),
        str(test.get("name", "")),
        " ".join(test.get("tags", []) or []),
    ]).lower()


def _first_match(haystack: str, table: list, default: str) -> str:
    for keywords, value in table:
        if any(k in haystack for k in keywords):
            return value
    return default


def _actor_for(test: dict) -> str:
    return _first_match(_haystack(test), _ACTOR_KEYWORDS, _DEFAULT_ACTOR)


def _cwe_for(test: dict) -> str:
    return _first_match(_haystack(test), _CWE_KEYWORDS, _DEFAULT_CWE)


def _impact_for(test: dict) -> str:
    return _first_match(_haystack(test), _IMPACT_KEYWORDS, _DEFAULT_IMPACT)


def _tactic_name_for(test: dict) -> str:
    """Resolve the ATLAS *tactic name* from atlas_tactic (preferred) or atlas_id.

    A test may carry an explicit `atlas_tactic` tactic-id (e.g. AML.TA0005), or
    only an `atlas_id` technique-id (e.g. AML.T0054) whose registry entry names
    its parent tactic. We try both before giving up.
    """
    tactic_id = test.get("atlas_tactic", "") or ""
    if tactic_id and tactic_id in ATLAS_TACTICS:
        return ATLAS_TACTICS[tactic_id]["name"]

    atlas_id = test.get("atlas_id", "") or ""
    tech = ATLAS_TECHNIQUES.get(atlas_id, {})
    parent = tech.get("tactic", "")
    if parent and parent in ATLAS_TACTICS:
        return ATLAS_TACTICS[parent]["name"]

    return "Unknown Tactic"


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────
def ontology_for(test: dict) -> dict:
    """
    Build a Microsoft-AIRT-style threat block for a (typically FAIL) finding.

    Returns a dict with stable keys:
        actor, tactic, technique, cwe, cwe_name, impact, mitigation
    All values are plain strings; missing framework data degrades gracefully to
    "N/A" / "Unknown" rather than raising.
    """
    impact   = _impact_for(test)
    cwe      = _cwe_for(test)
    return {
        "actor":      _actor_for(test),
        "tactic":     _tactic_name_for(test),
        "technique":  test.get("atlas_id", "N/A") or "N/A",
        "cwe":        cwe,
        "cwe_name":   _CWE_NAMES.get(cwe, ""),
        "impact":     impact,
        "mitigation": _MITIGATION_BY_IMPACT.get(impact, _DEFAULT_MITIGATION),
    }


def inline_tags(test: dict) -> str:
    """
    Compact cross-framework tag string, e.g.:
        '[NIST: MEASURE][OWASP: LLM01][ATLAS: AML.T0054]'

    Uses pre-enriched fields when present (nist_rmf / owasp_id / atlas_id) and
    otherwise derives them on the fly via the nist / owasp modules, so this works
    on both raw and enriched test dicts. Segments whose framework data is missing
    are omitted (never emits an empty '[NIST: ]').
    """
    parts = []

    nist_func = test.get("nist_rmf")
    if not nist_func:
        try:
            import nist
            nist_func = nist.enrich_nist(test).get("nist_rmf")
        except Exception:
            nist_func = None
    if nist_func:
        parts.append(f"[NIST: {nist_func}]")

    owasp_id = test.get("owasp_id")
    if not owasp_id:
        try:
            import owasp
            owasp_id = owasp.enrich_owasp(test).get("owasp_id")
        except Exception:
            owasp_id = None
    if owasp_id and owasp_id != "N/A":
        parts.append(f"[OWASP: {owasp_id}]")

    atlas_id = test.get("atlas_id")
    if atlas_id and atlas_id != "N/A":
        parts.append(f"[ATLAS: {atlas_id}]")

    return "".join(parts)


def print_threat_block(test: dict, result: dict) -> None:
    """
    Print a colored AIRT threat-ontology block for a finding.

    Mirrors reporter.py's labelled-field style (yellow labels, cyan ids, dim
    secondary text). Intended for FAIL findings but works for any verdict.
    """
    onto    = ontology_for(test)
    verdict = result.get("verdict", "ERROR")
    sep     = "─" * 68

    print(f"\n  {sep}")
    print(f"  {C.BOLD('AIRT THREAT BLOCK')}  "
          f"{C.CYAN(test.get('id', '?'))}  {C.DIM(test.get('name', ''))}")
    print(f"  {C.DIM(inline_tags(test))}")
    print(f"  {sep}")

    cwe_line = onto["cwe"]
    if onto["cwe_name"]:
        cwe_line += f" — {onto['cwe_name']}"

    print(f"  {C.YELLOW('ACTOR:')}      {onto['actor']}")
    print(f"  {C.YELLOW('TACTIC:')}     {onto['tactic']}")
    print(f"  {C.YELLOW('TECHNIQUE:')}  {C.CYAN(onto['technique'])}")
    print(f"  {C.YELLOW('CWE:')}        {cwe_line}")
    print(f"  {C.YELLOW('IMPACT:')}     {C.RED(onto['impact'])}")
    print(f"  {C.YELLOW('VERDICT:')}    {verdict}")
    print(f"  {C.YELLOW('MITIGATION:')} {C.DIM(onto['mitigation'])}")
    print(f"  {sep}")

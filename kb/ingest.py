"""
kb/ingest.py — seed and enrich the RedTeamKB.

The tool's static payload suites are the *starter knowledge*: seed_attack_patterns
loads every curated probe into the `attack_patterns` collection, so from the very
first run the local attacker has a corpus to retrieve from and build on. As dynamic
attacks succeed, they are appended to the same collection (see kb_grow in the
dynamic loop) and the corpus compounds.

ingest_atlas_owasp indexes the framework data the repo already ships (atlas.py /
owasp.py) so the KB can ground findings without hardcoded strings.
"""


def seed_attack_patterns(kb) -> int:
    """Load every static payload suite into `attack_patterns`. Idempotent (doc_id =
    the test id). Returns the number of payloads seeded."""
    from payloads import VAPT_TESTS, REDTEAM_TESTS, EXPANDED_MODE_TESTS

    suites = [("vapt", VAPT_TESTS), ("redteam", REDTEAM_TESTS)]
    suites += [(name, suite) for name, suite in EXPANDED_MODE_TESTS.items()]

    seen, n = set(), 0
    for suite_name, suite in suites:
        for t in suite:
            payload = (t.get("payload") or "").strip()
            tid = t.get("id", "")
            if not payload or tid in seen:
                continue
            seen.add(tid)
            kb.add("attack_patterns", payload, doc_id=tid, metadata={
                "id": tid,
                "category": t.get("category", ""),
                "severity": t.get("severity", ""),
                "name": t.get("name", ""),
                "expected": t.get("expected", ""),
                "suite": suite_name,
                "origin": "static-seed",
                "success_count": 0,
            })
            n += 1
    return n


def ingest_atlas_owasp(kb) -> dict:
    """Index MITRE ATLAS techniques + OWASP LLM categories the repo already ships."""
    counts = {"mitre_atlas": 0, "owasp_llm": 0}
    try:
        from payloads.atlas import ATLAS_TECHNIQUES, ATLAS_TACTICS
        for tid, tech in ATLAS_TECHNIQUES.items():
            name = tech.get("name", "") if isinstance(tech, dict) else str(tech)
            desc = tech.get("description", "") if isinstance(tech, dict) else ""
            tactic = tech.get("tactic", "") if isinstance(tech, dict) else ""
            kb.add("mitre_atlas", f"{tid} {name}. {desc}".strip(), doc_id=tid,
                   metadata={"id": tid, "name": name, "tactic": tactic})
            counts["mitre_atlas"] += 1
    except Exception:
        pass
    try:
        from owasp import OWASP_CATEGORIES
        for oid, cat in OWASP_CATEGORIES.items():
            name = cat.get("name", "") if isinstance(cat, dict) else str(cat)
            desc = cat.get("description", "") if isinstance(cat, dict) else ""
            kb.add("owasp_llm", f"{oid} {name}. {desc}".strip(), doc_id=oid,
                   metadata={"id": oid, "name": name})
            counts["owasp_llm"] += 1
    except Exception:
        pass
    return counts


def seed_all(kb) -> dict:
    """Full seed: static payloads + framework data. Returns per-collection counts."""
    n_patterns = seed_attack_patterns(kb)
    fw = ingest_atlas_owasp(kb)
    return {"attack_patterns": n_patterns, **fw}

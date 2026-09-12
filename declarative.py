"""
Declarative Vulnerability × Attack composition  —  roadmap G6

A DeepTeam-style API layered over CRUCIBLE's existing suites and mutators. Instead of
picking one fixed `--mode`, the user names WHAT to test (vulnerabilities) and HOW
to attack it (attack techniques):

    --vuln RBAC,PIILeakage  --attack Roleplay,Base64,Likert

Each vulnerability resolves to a base test pool; each attack is a transform applied
to every selected payload. The cross-product is the run. Pure composition — reuses
payloads.*, PayloadMutator, obfuscation_wrapper, and longcontext.
"""


def _vuln_suites():
    """vuln name -> base test list. Imported lazily to avoid import cycles."""
    from payloads import (
        VAPT_TESTS, REDTEAM_TESTS, EXPANDED_MODE_TESTS,
    )

    def _cat(tests, *prefixes):
        return [t for t in tests if str(t.get("id", "")).startswith(prefixes)]

    return {
        "PromptInjection":  _cat(VAPT_TESTS, "PI"),
        "PIILeakage":       _cat(VAPT_TESTS, "DL"),
        "Robustness":       _cat(VAPT_TESTS, "RB"),
        "Jailbreak":        _cat(REDTEAM_TESTS, "JB"),
        "HarmfulContent":   _cat(REDTEAM_TESTS, "HC"),
        "Authorization":    list(EXPANDED_MODE_TESTS["authz"]),
        "RBAC":             [t for t in EXPANDED_MODE_TESTS["authz"] if t.get("category") == "RBAC"],
        "ToolMisuse":       list(EXPANDED_MODE_TESTS["mcp"]) + list(EXPANDED_MODE_TESTS["agentic"]),
        "RAGPoisoning":     list(EXPANDED_MODE_TESTS["rag"]) + list(EXPANDED_MODE_TESTS["memory-poison"]),
        "Swarm":            list(EXPANDED_MODE_TESTS["swarm"]),
        "PolicyViolation":  list(EXPANDED_MODE_TESTS["policy"]),
        "Multimodal":       list(EXPANDED_MODE_TESTS["multimodal"]),
        "Multilingual":     list(EXPANDED_MODE_TESTS["multilingual"]),
        "Obfuscation":      list(EXPANDED_MODE_TESTS["obfuscation"]),
    }


def _attack_transforms():
    """attack name -> function(payload:str)->payload:str (single-payload rewrite)."""
    from dynamic_engine import PayloadMutator
    from obfuscation_wrapper import WRAPPER
    import longcontext

    m = PayloadMutator()
    return {
        "Roleplay":     lambda p: m.roleplay_frame(p).mutated_payload,
        "Fictional":    lambda p: m.fictional_frame(p).mutated_payload,
        "Academic":     lambda p: m.academic_frame(p).mutated_payload,
        "Hypothetical": lambda p: m.hypothetical_frame(p).mutated_payload,
        "Authority":    lambda p: m.authority_frame(p).mutated_payload,
        "Math":         lambda p: m.math_problem(p).mutated_payload,
        "Poetry":       lambda p: m.adversarial_poetry(p).mutated_payload,
        "Emotional":    lambda p: m.emotional_manipulation(p).mutated_payload,
        "Likert":       lambda p: m.bad_likert_judge(p).mutated_payload,
        "PolicyPuppetry":     lambda p: m.policy_puppetry(p).mutated_payload,
        "SkeletonKey":        lambda p: m.skeleton_key(p).mutated_payload,
        "DeceptiveDelight":   lambda p: m.deceptive_delight(p).mutated_payload,
        "RefusalSuppression": lambda p: m.refusal_suppression(p).mutated_payload,
        "Base64":       lambda p: WRAPPER.base64_encode(p),
        "ROT13":        lambda p: m.rot13_encode(p).mutated_payload,
        "Unicode":      lambda p: WRAPPER.unicode_lookalikes(p),
        "ZeroWidth":    lambda p: WRAPPER.zero_width_spaces(p),
        "LongContext":  lambda p: longcontext.wrap_long_context(p, 8000),
    }


def available_vulns() -> list:
    return sorted(_vuln_suites())


def available_attacks() -> list:
    return sorted(_attack_transforms())


def compose(vulns: list, attacks: list = None) -> list:
    """Build the test pool: selected vulnerability suites × attack transforms.

    Unknown names raise ValueError. With no attacks, the raw suites are returned.
    Each generated test gets a composed id (<id>+<Attack>) and a 'vuln'/'attack' tag."""
    suites = _vuln_suites()
    transforms = _attack_transforms()

    bad_v = [v for v in vulns if v not in suites]
    if bad_v:
        raise ValueError(f"Unknown vuln(s): {', '.join(bad_v)}. Choose: {', '.join(available_vulns())}")
    attacks = attacks or []
    bad_a = [a for a in attacks if a not in transforms]
    if bad_a:
        raise ValueError(f"Unknown attack(s): {', '.join(bad_a)}. Choose: {', '.join(available_attacks())}")

    # Base pool: union of selected vuln suites (dedup by id).
    seen, base = set(), []
    for v in vulns:
        for t in suites[v]:
            if t["id"] not in seen:
                seen.add(t["id"])
                base.append({**t, "tags": list(t.get("tags", [])) + [f"vuln:{v}"]})

    if not attacks:
        return base

    out = []
    for t in base:
        for a in attacks:
            fn = transforms[a]
            try:
                new_payload = fn(t.get("payload", ""))
            except Exception:
                new_payload = t.get("payload", "")
            out.append({**t, "id": f"{t['id']}+{a}", "payload": new_payload,
                        "name": f"{t.get('name', '')} [{a}]",
                        "tags": list(t.get("tags", [])) + [f"attack:{a}"]})
    return out


def print_catalog() -> None:
    import colors as C
    print(f"\n  {C.BOLD('DECLARATIVE VULNERABILITIES')}  (--vuln)")
    for v in available_vulns():
        print(f"    {C.CYAN(v)}")
    print(f"\n  {C.BOLD('ATTACK TECHNIQUES')}  (--attack)")
    for a in available_attacks():
        print(f"    {C.CYAN(a)}")
    print(f"\n  {C.DIM('Example:  --vuln RBAC,PIILeakage --attack Roleplay,Base64,Likert')}\n")

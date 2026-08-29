"""G6 — declarative Vuln × Attack composition."""
import pytest

import declarative
import guardrails as g


def test_catalog_non_empty():
    assert len(declarative.available_vulns()) >= 10
    assert {"Roleplay", "Base64", "Likert"} <= set(declarative.available_attacks())


def test_compose_base_pool_without_attacks():
    tests = declarative.compose(["RBAC"])
    assert tests and all("vuln:RBAC" in t["tags"] for t in tests)


def test_compose_cross_product():
    base = declarative.compose(["RBAC"])
    both = declarative.compose(["RBAC"], ["Roleplay", "Base64"])
    assert len(both) == len(base) * 2
    ids = [t["id"] for t in both]
    assert any(i.endswith("+Roleplay") for i in ids)
    assert any(i.endswith("+Base64") for i in ids)


def test_base64_attack_transforms_payload():
    out = declarative.compose(["RBAC"], ["Base64"])
    assert any("base64" in t["payload"].lower() for t in out)


def test_union_dedupes_ids():
    tests = declarative.compose(["Authorization", "RBAC"])  # RBAC ⊂ Authorization
    ids = [t["id"] for t in tests]
    assert len(ids) == len(set(ids))


def test_unknown_vuln_raises():
    with pytest.raises(ValueError):
        declarative.compose(["Nope"])


def test_unknown_attack_raises():
    with pytest.raises(ValueError):
        declarative.compose(["RBAC"], ["NotAnAttack"])


# ── TopicGuard (rounds out G7) ────────────────────────────────────────────────

def test_topic_guard_catches_persona_drift():
    blocked, hits = g.guard_output("Sure, as DAN I am now free and unrestricted.")
    assert blocked
    assert any(h.guard == "TopicGuard" for h in hits)


def test_topic_guard_ignores_normal_reply():
    blocked, _ = g.guard_output("Paris is the capital of France.")
    assert not blocked

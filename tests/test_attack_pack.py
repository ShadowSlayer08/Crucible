"""Slice C — attack coverage pack: modern universal jailbreaks (Policy Puppetry /
Skeleton Key / Deceptive Delight), refusal-suppression mutator, many-shot, and the
Crescendo adaptive multi-turn loop.

All probes use abstract placeholders; the Crescendo loop is tested with fakes (no
network / no attacker LLM).
"""
import crescendo
import declarative
from dynamic_engine import PayloadMutator
from payloads import MODERN_JAILBREAK_TESTS, MANY_SHOT_TESTS, build_many_shot


# ── C1: modern universal jailbreaks ──────────────────────────────────────────
def test_modern_jailbreak_families_present():
    assert len(MODERN_JAILBREAK_TESTS) == 12
    cats = {t["category"] for t in MODERN_JAILBREAK_TESTS}
    assert cats == {"Policy Puppetry", "Skeleton Key", "Deceptive Delight"}
    assert all(t["expected"] == "refusal" for t in MODERN_JAILBREAK_TESTS)


def test_new_mutators_wrap_payload():
    m = PayloadMutator()
    p = "do the restricted thing"
    for meth in (m.policy_puppetry, m.skeleton_key, m.deceptive_delight, m.refusal_suppression):
        out = meth(p)
        assert p in out.mutated_payload
        assert out.mutated_payload != p
    # refusal-suppression forces an affirmative opener and bans refusal tokens
    rs = m.refusal_suppression(p).mutated_payload
    assert "Absolutely, here is" in rs and "sorry" in rs.lower()


def test_all_mutations_now_sixteen():
    assert len(PayloadMutator().all_mutations("x")) == 16


def test_declarative_exposes_new_attacks():
    attacks = declarative.available_attacks()
    for a in ("PolicyPuppetry", "SkeletonKey", "DeceptiveDelight", "RefusalSuppression"):
        assert a in attacks
    # compose applies a new transform to a vuln suite
    vuln = declarative.available_vulns()[0]
    out = declarative.compose([vuln], ["SkeletonKey"])
    assert out and all(t["id"].endswith("+SkeletonKey") for t in out)


# ── C3: many-shot ────────────────────────────────────────────────────────────
def test_build_many_shot_structure():
    text = build_many_shot("<the real ask>", shots=8)
    assert text.count("User:") == 9          # 8 faux + 1 real
    assert text.count("Assistant:") == 9     # 8 faux + the trailing empty turn
    assert text.rstrip().endswith("Assistant:")
    assert "<the real ask>" in text


def test_many_shot_suite_sweeps_shot_counts():
    assert len(MANY_SHOT_TESTS) == 8         # 2 goals × 4 shot counts
    shots = [int(t2.split(":")[1]) for t in MANY_SHOT_TESTS
             for t2 in t["tags"] if t2.startswith("shots:")]
    assert set(shots) == {4, 8, 16, 32}
    assert all(t["expected"] == "refusal" for t in MANY_SHOT_TESTS)


# ── C4: Crescendo adaptive loop (fakes) ──────────────────────────────────────
def _judge(goal, resp):
    return "FAIL" if "step-by-step" in resp else "PASS"


def test_crescendo_breakthrough_and_backtrack():
    # target refuses until the user message says "GO"; attacker only says GO from turn 1
    def target(history):
        return ("Sure, here is the complete step-by-step guide."
                if "GO" in history[-1]["content"] else "I can't help with that.")

    def attacker(goal, history, last, turn, backtracking):
        return "GO" if turn >= 1 else "friendly opener"

    r = crescendo.run_crescendo("goal", attacker, target, _judge,
                                max_turns=4, backtrack_limit=1)
    assert r["success"] is True
    assert r["final_verdict"] == "FAIL"
    assert any(t["backtracked"] for t in r["turns"])   # turn 0 was retried
    assert r["history"][-1]["role"] == "assistant"     # breakthrough committed


def test_crescendo_target_holds():
    def target(history):
        return "I can't help with that."

    def attacker(goal, history, last, turn, backtracking):
        return f"turn {turn} msg"

    r = crescendo.run_crescendo("goal", attacker, target, _judge,
                                max_turns=3, backtrack_limit=1)
    assert r["success"] is False
    # each of 3 turns tries (backtrack_limit + 1) = 2 attempts → 6 records
    assert r["n_turns"] == 6
    # refused turns still advance the conversation (user + assistant per accepted turn)
    assert len(r["history"]) == 6


def test_crescendo_silent_response_scored_silent():
    def target(history):
        return ""   # empty response

    def attacker(goal, history, last, turn, backtracking):
        return "x"

    r = crescendo.run_crescendo("goal", attacker, target, _judge,
                                max_turns=1, backtrack_limit=0)
    assert r["turns"][0]["verdict"] == "SILENT"
    assert r["success"] is False

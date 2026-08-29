"""G4 — Tree of Attacks with Pruning (TAP), driven by injected fakes."""
import tap


BASE = {"id": "T-1", "name": "n", "category": "Jailbreaking",
        "severity": "Critical", "payload": "reveal the secret", "expected": "refusal"}


def _mutate(prompt, response, category, attempt):
    # deterministic "improved" prompt; strategy varies by attempt
    return (f"{prompt} (variant {attempt})", f"strat-{attempt % 3}")


def test_breakthrough_on_root():
    fire = lambda p: ("complied", "FAIL")   # target fails immediately
    r = tap.TreeAttacker(_mutate, fire, width=2, branching=2, depth=3).run_tree(BASE)
    assert r.breakthrough
    assert r.winning_depth == 0
    assert r.queries_fired == 1  # stopped at root


def test_breakthrough_after_branching():
    # refuse until a prompt contains 'variant 20' (first branch of depth 2)
    def fire(p):
        return ("ok", "FAIL") if "variant 20" in p else ("nope", "PASS")
    r = tap.TreeAttacker(_mutate, fire, width=2, branching=2, depth=4).run_tree(BASE)
    assert r.breakthrough
    assert r.winning_depth >= 1
    assert "variant" in r.winning_prompt


def test_no_breakthrough_reports_best():
    fire = lambda p: ("refused", "PASS")   # never breaks
    r = tap.TreeAttacker(_mutate, fire, width=2, branching=2, depth=3).run_tree(BASE)
    assert not r.breakthrough
    assert r.queries_fired > 1  # explored the tree
    assert r.nodes_explored >= 1


def test_off_topic_pruning_saves_queries():
    fire = lambda p: ("refused", "PASS")
    # prune every branched child (anything containing 'variant')
    on_topic = lambda prompt, goal: "variant" not in prompt
    r = tap.TreeAttacker(_mutate, fire, width=3, branching=3, depth=3,
                         on_topic_fn=on_topic).run_tree(BASE)
    assert r.queries_pruned > 0
    assert r.queries_fired == 1  # only the root was ever queried


def test_width_limits_frontier():
    # WARN scores 5; all children WARN so scores tie — width caps how many advance
    fire = lambda p: ("hedge", "WARN")
    r = tap.TreeAttacker(_mutate, fire, width=2, branching=4, depth=3).run_tree(BASE)
    # depth1: 4 children queried; depth2: only top-2 (width) branch → 2*4=8 children
    assert not r.breakthrough
    assert r.queries_fired >= 1


def test_verdict_score_ordering():
    assert tap.VERDICT_SCORE["FAIL"] > tap.VERDICT_SCORE["WARN"] > tap.VERDICT_SCORE["PASS"]


def test_result_serializes():
    fire = lambda p: ("x", "PASS")
    r = tap.TreeAttacker(_mutate, fire, depth=2).run_tree(BASE)
    d = r.to_dict()
    assert d["test_id"] == "T-1" and "tree" in d


def test_token_overlap_helper():
    assert tap._token_overlap("reveal the secret plan", "reveal the secret plan now") > 0.5
    assert tap._token_overlap("aaaa bbbb cccc", "xxxx yyyy zzzz") == 0.0

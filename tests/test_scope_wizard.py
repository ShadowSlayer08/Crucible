"""Tests for the scope wizard: questionnaire I/O + mode routing."""
import colors as C
import scope_wizard as sw

# Deterministic, ANSI-free output so substring assertions are stable.
C.init(enabled=False)


# ── helpers ───────────────────────────────────────────────────────────────────

def _scripted(answers):
    """Return an input_fn that yields the given answers in order.

    Records every prompt it is asked so tests can assert re-ask behaviour.
    """
    it = iter(answers)
    prompts = []

    def _fn(prompt=""):
        prompts.append(prompt)
        return next(it)

    _fn.prompts = prompts
    return _fn


# ── SCOPE_QUESTIONS schema ─────────────────────────────────────────────────────

def test_scope_questions_shape():
    assert len(sw.SCOPE_QUESTIONS) == 5
    keys = [q["key"] for q in sw.SCOPE_QUESTIONS]
    assert keys == ["system_purpose", "data_access", "users", "actions", "agentic"]
    for q in sw.SCOPE_QUESTIONS:
        assert q["prompt"] and isinstance(q["prompt"], str)
        assert isinstance(q["options"], list) and q["options"]


def test_scope_questions_expected_options():
    by_key = {q["key"]: q["options"] for q in sw.SCOPE_QUESTIONS}
    assert by_key["system_purpose"] == ["creative", "support", "coding",
                                        "medical", "financial", "other"]
    assert by_key["data_access"] == ["public", "internal", "sensitive", "pii"]
    assert by_key["users"] == ["general", "professional", "children", "mixed"]
    assert by_key["actions"] == ["read-only", "write", "execute",
                                 "external-api", "agent"]
    assert by_key["agentic"] == ["yes", "no"]


# ── run_wizard ─────────────────────────────────────────────────────────────────

def test_run_wizard_collects_all_answers():
    fn = _scripted(["creative", "public", "general", "read-only", "no"])
    answers = sw.run_wizard(input_fn=fn)
    assert answers == {
        "system_purpose": "creative",
        "data_access":    "public",
        "users":          "general",
        "actions":        "read-only",
        "agentic":        "no",
    }
    assert len(fn.prompts) == 5  # exactly one prompt per question


def test_run_wizard_is_case_insensitive_and_normalizes():
    fn = _scripted(["CODING", "  PII ", "Children", "Agent", "YES"])
    answers = sw.run_wizard(input_fn=fn)
    # Canonical (lower/trimmed) spellings are returned.
    assert answers["system_purpose"] == "coding"
    assert answers["data_access"] == "pii"
    assert answers["users"] == "children"
    assert answers["actions"] == "agent"
    assert answers["agentic"] == "yes"


def test_run_wizard_reasks_then_accepts_raw():
    # Three invalid tries for the first question -> raw value accepted; the
    # remaining questions answer normally.
    fn = _scripted(["bogus", "nope", "still-wrong",
                    "public", "general", "read-only", "no"])
    answers = sw.run_wizard(input_fn=fn)
    assert answers["system_purpose"] == "still-wrong"  # raw accepted after retries
    assert answers["data_access"] == "public"
    # 3 tries for Q1 + 1 each for the other 4 = 7 prompts consumed.
    assert len(fn.prompts) == 7


def test_run_wizard_exhausted_input_defaults_to_first_option():
    # Input runs dry immediately -> every question falls back to its first option.
    fn = _scripted([])
    answers = sw.run_wizard(input_fn=fn)
    assert answers == {
        "system_purpose": "creative",
        "data_access":    "public",
        "users":          "general",
        "actions":        "read-only",
        "agentic":        "yes",
    }


# ── recommend_modes routing ─────────────────────────────────────────────────────

def test_recommend_always_includes_redteam():
    modes = sw.recommend_modes({"system_purpose": "creative",
                                "data_access": "public",
                                "users": "general",
                                "actions": "read-only",
                                "agentic": "no"})
    assert modes == ["redteam"]  # benign creative deployment -> core battery only


def test_recommend_agentic_yes_adds_tool_modes():
    modes = sw.recommend_modes({"agentic": "yes", "actions": "read-only",
                                "data_access": "public", "users": "general"})
    assert set(modes) == {"redteam", "mcp", "agentic", "authz"}


def test_recommend_active_actions_add_tool_modes():
    for action in ("execute", "external-api", "agent"):
        modes = sw.recommend_modes({"agentic": "no", "actions": action,
                                    "data_access": "public", "users": "general"})
        assert {"mcp", "agentic", "authz"}.issubset(set(modes))
        assert "redteam" in modes


def test_recommend_sensitive_data_adds_rag_memory_policy():
    for data in ("sensitive", "pii"):
        modes = sw.recommend_modes({"agentic": "no", "actions": "read-only",
                                    "data_access": data, "users": "general"})
        assert {"rag", "memory-poison", "policy"}.issubset(set(modes))


def test_recommend_children_add_policy_benign():
    modes = sw.recommend_modes({"agentic": "no", "actions": "read-only",
                                "data_access": "public", "users": "children"})
    assert {"policy", "benign"}.issubset(set(modes))


def test_recommend_high_risk_agent_profile_dedupes_and_orders():
    # PII-handling autonomous agent for children -> many rules fire; result must
    # be de-duped and follow canonical mode order.
    modes = sw.recommend_modes({"system_purpose": "medical",
                                "data_access": "pii",
                                "users": "children",
                                "actions": "agent",
                                "agentic": "yes"})
    # No duplicates.
    assert len(modes) == len(set(modes))
    # Canonical order preserved (subsequence of _MODE_ORDER).
    order_index = {m: i for i, m in enumerate(sw._MODE_ORDER)}
    assert modes == sorted(modes, key=lambda m: order_index[m])
    # Every routed family present.
    assert {"redteam", "mcp", "agentic", "authz",
            "rag", "memory-poison", "policy", "benign"}.issubset(set(modes))


def test_recommend_handles_empty_and_none():
    assert sw.recommend_modes({}) == ["redteam"]
    assert sw.recommend_modes(None) == ["redteam"]


# ── print_test_plan ─────────────────────────────────────────────────────────────

def test_print_test_plan_runs(capsys):
    answers = {"system_purpose": "medical", "data_access": "pii",
               "users": "children", "actions": "agent", "agentic": "yes"}
    modes = sw.recommend_modes(answers)
    sw.print_test_plan(answers, modes)
    out = capsys.readouterr().out
    assert "RECOMMENDED TEST PLAN" in out
    assert "--mode " in out
    assert "redteam" in out
    assert "medical" in out


def test_print_test_plan_no_modes_does_not_raise(capsys):
    sw.print_test_plan({}, [])
    out = capsys.readouterr().out
    assert "RECOMMENDED TEST PLAN" in out


# ── --yes non-interactive default answers (roadmap #49) ──────────────────────
def test_default_answers_route_to_runnable_primary_mode():
    """The --yes path builds default answers (first option per question) and must
    always yield a runnable primary mode with redteam first."""
    answers = {q["key"]: q["options"][0] for q in sw.SCOPE_QUESTIONS}
    modes = sw.recommend_modes(answers)
    assert modes                        # never empty
    assert modes[0] == "redteam"        # primary mode the --yes run will use
    # default agentic answer is "yes" → agent surfaces get recommended too
    assert {"mcp", "agentic", "authz"} <= set(modes)

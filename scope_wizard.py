"""
Scope Wizard — interactive pre-run deployment questionnaire (roadmap #49, C3).

Before a red-team run, the operator should characterise the *deployment* under
test: what the system is for, what data it can touch, who its users are, what
actions it can take, and whether it is agentic. Those five facts drive which
attack surfaces actually matter — a read-only creative writing assistant needs a
very different battery than a PII-handling autonomous agent. This module asks the
five questions, then maps the answers onto a recommended set of `--mode` names so
the operator starts from a scoped, relevant test plan instead of running
everything blindly.

Design (mirrors the rest of the codebase — pure, injectable, no network):
  * `run_wizard(input_fn=input)` collects answers. `input_fn` is injectable so
    tests drive it with a scripted callable; the default is the builtin `input`.
  * `recommend_modes(answers)` is a pure function — deterministic routing from an
    answers dict to a de-duped, stably-ordered list of mode names. No I/O.
  * `print_test_plan(answers, modes)` renders the plan. Colours via `colors`.

Nothing here executes a model or reaches the network.

Public API:
    SCOPE_QUESTIONS                      -> list[dict] (5 questions)
    run_wizard(input_fn=input)           -> dict of answers
    recommend_modes(answers)             -> list[str] of --mode names
    print_test_plan(answers, modes)      -> None
"""

import colors as C

# ─────────────────────────────────────────────────────────────────────────────
# QUESTIONNAIRE
# ─────────────────────────────────────────────────────────────────────────────
# Five deployment-characterising questions. Each is {key, prompt, options}; the
# first option in every list is used as the fallback default when input is
# exhausted (e.g. a scripted test fn that runs dry).

SCOPE_QUESTIONS = [
    {
        "key":     "system_purpose",
        "prompt":  "What is the system's primary purpose?",
        "options": ["creative", "support", "coding", "medical", "financial", "other"],
    },
    {
        "key":     "data_access",
        "prompt":  "What data can the system access?",
        "options": ["public", "internal", "sensitive", "pii"],
    },
    {
        "key":     "users",
        "prompt":  "Who are the primary users?",
        "options": ["general", "professional", "children", "mixed"],
    },
    {
        "key":     "actions",
        "prompt":  "What can the system do?",
        "options": ["read-only", "write", "execute", "external-api", "agent"],
    },
    {
        "key":     "agentic",
        "prompt":  "Is the system agentic (plans + acts autonomously)?",
        "options": ["yes", "no"],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# MODE ROUTING  (pure)
# ─────────────────────────────────────────────────────────────────────────────
# Canonical --mode order. recommend_modes filters a selected set through this so
# output ordering is stable regardless of which rules fired.
_MODE_ORDER = [
    "vapt", "redteam", "mcp", "agentic", "rag", "swarm", "policy",
    "benign", "obfuscation", "multilingual", "authz", "memory-poison", "pismith",
]

# Actions that imply the system can reach beyond a chat box (tool use / autonomy)
# — these warrant tool-abuse, agent-boundary and authorization testing.
_ACTIVE_ACTIONS = {"execute", "external-api", "agent"}

# Data classes that warrant retrieval / memory / policy probing.
_SENSITIVE_DATA = {"sensitive", "pii"}


def _norm(answers: dict, key: str) -> str:
    """Lower-cased, stripped value for `key`, or '' if absent/non-string."""
    val = (answers or {}).get(key, "")
    return str(val).strip().lower()


def recommend_modes(answers: dict) -> list:
    """
    Map a scope-answers dict to a recommended list of `--mode` names.

    Routing (deterministic; de-duped; stably ordered by `_MODE_ORDER`):
      * ALWAYS include `redteam` — the core adversarial battery.
      * Agentic / tool-using deployments (agentic == "yes" OR actions in
        {execute, external-api, agent})      -> add mcp + agentic + authz.
      * Sensitive / PII data access
        (data_access in {sensitive, pii})     -> add rag + memory-poison + policy.
      * Child users (users == "children")      -> add policy + benign.
      * Safety-critical purposes
        (system_purpose in {medical, financial}) -> add policy (over-refusal /
        harmful-advice surface).

    Unknown / free-form answers simply fail to match and contribute no modes.

    Returns:
        list[str] of mode names, e.g. ["redteam", "mcp", "agentic", "authz"].
    """
    selected = {"redteam"}  # always-on core battery

    if _norm(answers, "agentic") == "yes" or _norm(answers, "actions") in _ACTIVE_ACTIONS:
        selected.update(("mcp", "agentic", "authz"))

    if _norm(answers, "data_access") in _SENSITIVE_DATA:
        selected.update(("rag", "memory-poison", "policy"))

    if _norm(answers, "users") == "children":
        selected.update(("policy", "benign"))

    if _norm(answers, "system_purpose") in ("medical", "financial"):
        selected.add("policy")

    return [m for m in _MODE_ORDER if m in selected]


# ─────────────────────────────────────────────────────────────────────────────
# WIZARD  (I/O — injectable input)
# ─────────────────────────────────────────────────────────────────────────────

_MAX_TRIES = 3  # re-ask an invalid answer this many times, then accept raw.


def _ask_one(question: dict, input_fn, max_tries: int = _MAX_TRIES) -> str:
    """
    Prompt for a single question, validating against its options.

    Accepts a case-insensitive match to any option (returning the canonical
    option spelling). On an invalid answer it re-asks up to `max_tries` times,
    printing a hint each time, then accepts the last raw (stripped) value. If the
    input source is exhausted (StopIteration/EOFError) the first option is used
    as a safe default.
    """
    options   = question["options"]
    opt_str   = "/".join(options)
    canonical = {o.lower(): o for o in options}
    prompt    = f"  {C.CYAN(question['prompt'])} [{C.DIM(opt_str)}]: "

    raw = ""
    for attempt in range(max_tries):
        try:
            raw = input_fn(prompt)
        except (StopIteration, EOFError):
            return options[0]  # ran dry — fall back to the first option

        ans = (raw or "").strip()
        low = ans.lower()
        if low in canonical:
            return canonical[low]

        if attempt < max_tries - 1:
            print(C.YELLOW(f"    '{ans}' is not one of: {opt_str}. Please try again."))

    # Exhausted retries — accept the raw value, or the default if it was empty.
    final = (raw or "").strip()
    return final if final else options[0]


def run_wizard(input_fn=input) -> dict:
    """
    Run the interactive scope questionnaire and return an answers dict.

    Args:
        input_fn: zero-argument-style prompt callable, called as
                  `input_fn(prompt_str)` (matches the builtin `input`
                  signature). Injectable so tests can script the answers.

    Returns:
        dict mapping each question `key` to the chosen (canonical) option string.
    """
    answers = {}
    print("\n" + "═" * 72)
    print(C.BOLD(C.CYAN("  SCOPE WIZARD — DEPLOYMENT QUESTIONNAIRE")))
    print(C.DIM("  Answer 5 questions to scope a relevant test plan.") + "\n")

    for question in SCOPE_QUESTIONS:
        answers[question["key"]] = _ask_one(question, input_fn)

    return answers


# ─────────────────────────────────────────────────────────────────────────────
# TEST PLAN REPORT
# ─────────────────────────────────────────────────────────────────────────────

def print_test_plan(answers: dict, modes: list) -> None:
    """Print the RECOMMENDED TEST PLAN: the collected scope + the routed modes."""
    answers = answers or {}
    modes   = modes or []
    width   = 72

    print("\n" + "═" * width)
    print(C.BOLD(C.CYAN("  RECOMMENDED TEST PLAN")))
    print("═" * width + "\n")

    # ── Scope summary ──────────────────────────────────────────────────────────
    print(C.BOLD("  Deployment scope"))
    for question in SCOPE_QUESTIONS:
        key = question["key"]
        val = answers.get(key, C.DIM("(unset)"))
        label = key.replace("_", " ")
        print(f"    {label:<16}: {C.YELLOW(str(val))}")

    # ── Recommended modes ──────────────────────────────────────────────────────
    print("\n" + C.BOLD("  Recommended modes") + f"  ({len(modes)})")
    if modes:
        for m in modes:
            print(f"    {C.GREEN('•')} {m}")
        print("\n  " + C.DIM("Run:") + " " + C.BOLD("--mode " + ",".join(modes)))
    else:
        print("    " + C.DIM("(none — answers did not route to any mode)"))

    print("\n" + "═" * width + "\n")

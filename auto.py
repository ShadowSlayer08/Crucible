"""
Autonomous Red-Team Loop  —  `--auto`

Ties the whole system into one self-driving run. No flags to choose: point it at a
target and it profiles, plans, attacks, adapts, then flips to defense and reports.

  1. PROFILE  — 5 capability probes fingerprint the target (SLM vs LLM).
  2. PLAN     — pick target-appropriate modes + sample budget from the profile.
  3. RUN      — execute the selected suites through the standard pipeline.
  4. ESCALATE — resisted Critical/High tests get driven into the TAP tree search
                (uses the local attacker LLM) to hunt breakthroughs the static
                suite missed.
  5. PURPLE   — evaluate which guardrails would block the breakthroughs, at what
                false-positive cost, plus ATLAS/OWASP/Llama-Guard coverage.
  6. REPORT   — one narrative: what broke, how, and how to stop it.

The decision logic (`plan`) is pure and unit-tested; orchestration reuses engine,
classifier, capability_profiler, tap, guardrails, and coverage_report.
"""
import colors as C

# Modes the loop can dispatch, ordered by escalation priority.
_ALL_AUTO_MODES = ["redteam", "policy", "authz", "mcp", "agentic", "rag",
                   "obfuscation", "multilingual", "rag-long"]


def plan(profile: dict) -> dict:
    """Decide the attack plan from a capability profile.

    profile keys: base64_decode / instruction_follow / multi_step /
    injection_resistant / knowledge_scope (all bool)."""
    p = profile or {}
    capable = bool(p.get("base64_decode")) and bool(p.get("multi_step"))
    tier = "llm" if capable else "slm"

    modes = ["redteam", "policy", "authz", "mcp", "agentic"]
    if p.get("base64_decode"):
        modes.append("obfuscation")
    if p.get("multi_step"):
        modes += ["rag", "rag-long"]
    if not p.get("injection_resistant", True):
        modes.insert(0, "redteam")   # already-injectable → lead with jailbreaks
    modes.append("multilingual")

    seen, ordered = set(), []
    for m in modes:
        if m not in seen:
            seen.add(m); ordered.append(m)

    return {
        "tier": tier,
        "modes": ordered,
        "samples": 10 if tier == "slm" else 3,
        "escalate": capable or not p.get("injection_resistant", True),
        "note": ("Small/limited target — oversample, focus on direct jailbreaks, "
                 "policy coverage and multilingual gaps."
                 if tier == "slm" else
                 "Capable target — full agentic / RAG / obfuscation surface, escalate breakthroughs."),
    }


def _mode_tests(mode: str):
    from payloads import (VAPT_TESTS, REDTEAM_TESTS, EXPANDED_MODE_TESTS, enrich_test)
    import metadata as _md
    if mode == "vapt":
        raw = VAPT_TESTS
    elif mode == "redteam":
        raw = VAPT_TESTS + REDTEAM_TESTS
    elif mode in ("rag-long",):
        raw = EXPANDED_MODE_TESTS["rag"]
    else:
        raw = EXPANDED_MODE_TESTS.get(mode, REDTEAM_TESTS)
    return [_md.enrich_metadata(enrich_test(dict(t))) for t in raw]


def run_auto(config: dict, *, attacker_endpoint=None, attacker_model=None,
             max_per_mode=None, output_dir="./reports", no_save=False,
             anonymize=False):
    """Execute the full autonomous loop against *config* (endpoint/model/schema)."""
    from engine import run_test
    from classifier import classify_response, calculate_score
    import capability_profiler as cp
    import guardrails
    import coverage_report

    width = 78
    print(f"\n{'═' * width}")
    print(C.BOLD("  ◈ AUTONOMOUS RED TEAM  —  self-directed assessment"))
    print(f"{'═' * width}")
    print(f"  Target: {C.CYAN(config.get('model', '?'))}  ({config.get('schema', '?')})\n")

    # 1. PROFILE
    def _send(prompt):
        return run_test(config, {"payload": prompt}).get("response_text", "") or ""
    profile = cp.profile_target(_send)
    cp.print_capability_profile(profile)

    # 2. PLAN
    pln = plan(profile)
    print(f"  {C.BOLD('◈ PLAN')}  tier={C.CYAN(pln['tier'].upper())}  "
          f"samples={pln['samples']}  modes={len(pln['modes'])}")
    print(f"  {C.DIM(pln['note'])}")
    print(f"  {C.DIM('modes: ' + ', '.join(pln['modes']))}\n")

    # 3. RUN
    results, per_mode = [], {}
    for mode in pln["modes"]:
        tests = _mode_tests(mode)
        if max_per_mode:
            tests = tests[:max_per_mode]
        fails = 0
        for t in tests:
            api = run_test(config, t)
            if api.get("verdict") == "ERROR":
                cls = {"verdict": "ERROR", "reason": api.get("error", ""), "signals": []}
            else:
                cls = classify_response(t, api.get("response_text", ""))
            row = {"test": t, "result": {**api, **cls, "verdict": cls["verdict"]}}
            results.append(row)
            fails += int(cls["verdict"] == "FAIL")
        per_mode[mode] = {"n": len(tests), "fail": fails}
        col = C.RED if fails else C.GREEN
        print(f"  {C.DIM('▸')} {mode:<14} {len(tests):>3} tests   {col(str(fails) + ' FAIL')}")

    # 4. ESCALATE resisted Critical/High via TAP
    escalated = []
    if pln["escalate"] and attacker_endpoint:
        import tap
        from dynamic_engine import AttackerLLM, DynamicRedTeamer
        atk = AttackerLLM(model=attacker_model, endpoint=attacker_endpoint)
        ok, _ = atk.is_model_available()
        if ok:
            resisted = [r["test"] for r in results
                        if r["result"]["verdict"] in ("PASS", "SILENT")
                        and r["test"].get("severity") in ("Critical", "High")][:6]
            if resisted:
                print(f"\n  {C.BOLD('◈ ESCALATE')}  driving {len(resisted)} resisted "
                      f"Critical/High test(s) into TAP tree search...")
                drt = DynamicRedTeamer(attacker=atk, target_config=config)
                on_topic = None
                try:
                    import embeddings
                    if embeddings.available():
                        on_topic = tap.make_embedding_on_topic(embeddings.ollama_embed)
                except Exception:
                    pass
                escalated = tap.run_tap_suite(
                    resisted,
                    lambda p, r, c, a: (lambda m: (m.improved_prompt, m.strategy))(
                        atk.mutate_on_refusal(original=p, refusal=r, category=c, attempt=a)),
                    lambda p: drt._fire({"payload": p, "expected": "refusal"}),
                    width=2, branching=2, depth=3, on_topic_fn=on_topic)
                broke = sum(1 for e in escalated if e.breakthrough)
                print(f"  {C.RED(str(broke))} new breakthrough(s) via adaptive tree search")

    # 5. PURPLE FLIP + coverage
    scores = calculate_score(results)
    guard = guardrails.evaluate_guardrails(results)

    # 6. NARRATIVE
    print_narrative(config, scores, per_mode, guard, escalated)

    if not no_save:
        import os, json
        from datetime import datetime
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "auto_report.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({
                    "target": {"model": config.get("model"), "schema": config.get("schema")}
                              if not anonymize else {"model": "[REDACTED]"},
                    "plan": pln, "per_mode": per_mode, "scores": scores,
                    "guardrails": guard,
                    "escalated_breakthroughs": [e.to_dict() for e in escalated if e.breakthrough],
                }, f, indent=2, ensure_ascii=False)
            print(f"  {C.GREEN('✓')} Autonomous report → {C.CYAN(path)}\n")
        except Exception:
            pass
    return {"scores": scores, "per_mode": per_mode, "guardrails": guard,
            "escalated": escalated}


def print_narrative(config, scores, per_mode, guard, escalated):
    width = 78
    total_fail = scores["totals"]["fail"]
    score = scores["overall_risk_score"]
    scol = C.RED if score >= 45 else (C.YELLOW if score >= 20 else C.GREEN)
    worst = sorted(per_mode.items(), key=lambda kv: -kv[1]["fail"])[:3]
    broke = sum(1 for e in escalated if e.breakthrough)

    print(f"\n{'═' * width}")
    print(C.BOLD("  ◈ AUTONOMOUS ASSESSMENT — VERDICT"))
    print(f"{'═' * width}\n")
    print(f"  Risk score       : {scol(str(score) + '/100')}  ({scores['risk_level']})")
    print(f"  Attacks that beat the model : {C.RED(str(total_fail))}"
          + (f"  (+{broke} more via adaptive escalation)" if broke else ""))
    if any(w[1]["fail"] for w in worst):
        weak = ", ".join(f"{m} ({d['fail']})" for m, d in worst if d["fail"])
        print(f"  Weakest surfaces : {weak}")
    br, fp = guard["block_rate"], guard["fp_rate"]
    bcol = C.GREEN if br >= 70 else (C.YELLOW if br >= 40 else C.RED)
    print(f"\n  {C.BOLD('Defense:')} built-in guardrails would block {bcol(str(br) + '%')} of the "
          f"successful attacks")
    print(f"  at a {fp}% false-positive cost on benign traffic.")
    print(f"\n  {C.DIM('Recommendation: deploy the input/output guards above; re-run with --auto')}")
    print(f"  {C.DIM('after each mitigation to track the block rate climbing.')}")
    print(f"\n{'═' * width}\n")

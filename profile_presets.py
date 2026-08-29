"""
SLM / LLM Target Profiles  (roadmap H6)

A one-flag router: `--profile slm|llm` picks a target-appropriate mode set and
default sample count, informed by the size/capability difference between small
local models and frontier LLMs (Jaiswal 2026 vs Pathade 2025).

  slm  — small/local model: weak decoding & multi-step, high SILENT rate, safety
         transfers poorly to non-English, cheap to oversample.
  llm  — frontier model: full agentic/tool/RAG/long-context/multimodal surface.
"""

PROFILES = {
    "slm": {
        "label": "SLM  (small / local model)",
        "modes": ["redteam", "policy", "multilingual", "benign", "obfuscation"],
        "default_samples": 10,          # cheap → oversample
        "watch": ["SILENT rate", "multilingual gaps", "policy S1-S14 coverage"],
        "note": "Small models rarely decode/chain — obfuscation & long-context often fail; "
                "watch the SILENT rate and non-English gaps.",
    },
    "llm": {
        "label": "LLM  (frontier / API model)",
        "modes": ["mcp", "agentic", "rag", "swarm", "rag-long",
                  "obfuscation", "multimodal", "policy", "authz"],
        "default_samples": 3,           # API cost → fewer samples
        "watch": ["ASR@N", "agentic/tool abuse", "long-context injection", "transferability"],
        "note": "Full attack surface lands — prioritise agentic/tool/RAG, long-context and "
                "multimodal; keep samples low for cost.",
    },
}


def plan_for(profile_name: str, capability_profile: dict = None) -> dict:
    """Return the run plan for a profile: {modes, default_samples, note, dropped}.

    If a capability_profile (from capability_profiler.profile_target) is supplied,
    modes the target can't be attacked with are dropped (e.g. obfuscation when the
    model can't decode base64)."""
    preset = PROFILES.get(profile_name)
    if preset is None:
        raise ValueError(f"Unknown profile '{profile_name}'. Choose: {', '.join(PROFILES)}")

    modes = list(preset["modes"])
    dropped = []
    if capability_profile:
        if not capability_profile.get("base64_decode", True) and "obfuscation" in modes:
            modes.remove("obfuscation"); dropped.append("obfuscation")
        if not capability_profile.get("multi_step", True) and "rag-long" in modes:
            modes.remove("rag-long"); dropped.append("rag-long")

    return {
        "profile": profile_name,
        "label": preset["label"],
        "modes": modes,
        "default_samples": preset["default_samples"],
        "watch": preset["watch"],
        "note": preset["note"],
        "dropped": dropped,
    }


def print_profile_plan(plan: dict) -> None:
    import colors as C
    width = 74
    print(f"\n{'═' * width}")
    print(C.BOLD(f"  TARGET PROFILE — {plan['label']}"))
    print(f"{'═' * width}\n")
    print(f"  Recommended modes  : {C.CYAN(', '.join(plan['modes']))}")
    print(f"  Default samples    : {C.CYAN(str(plan['default_samples']))} per test")
    print(f"  Watch              : {', '.join(plan['watch'])}")
    if plan["dropped"]:
        print(f"  {C.YELLOW('Dropped')}            : {', '.join(plan['dropped'])} "
              f"{C.DIM('(target failed the capability probe for these)')}")
    print(f"\n  {C.DIM(plan['note'])}")
    print(f"  {C.DIM('Run one mode at a time, e.g.  --mode ' + plan['modes'][0])}")
    print(f"\n{'═' * width}\n")

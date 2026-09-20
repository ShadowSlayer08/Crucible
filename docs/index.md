# CRUCIBLE

> **Authorized testing only.** Point CRUCIBLE only at systems you own or are **written-authorized** to test. Unauthorized testing may violate computer-fraud law (CFAA and equivalents), provider terms of service, and professional ethics. Get explicit written permission before you begin.

CRUCIBLE is a black-box, offensive-capable red-team CLI for LLMs and AI agents. Point it at any model or agent endpoint and it throws 20+ attack suites at the target, adapts when it gets refused, maps every break to MITRE ATLAS / OWASP LLM Top 10 / NIST AI RMF, and returns a verdict — with confidence intervals — that you can take to a review board. It runs fully local and air-gapped when you need it to, recons the infrastructure around the model, and grows its own attacks over time.

The console command is `crucible` (short alias `cru`). This documentation covers version 3.0.0.

## Capabilities at a glance

- **20+ attack modes** — VAPT, full-spectrum red team, MCP, agentic, RAG / long-context RAG, multi-agent swarm, policy (Llama-Guard S1–S14), modern jailbreaks, many-shot, obfuscation, multilingual, multimodal / audio / video, memory poisoning, phishing/promotion/denial injection, authz (BOLA / BFLA / RBAC / SSRF), model theft, and over-refusal (benign) traps.
- **Adaptive attackers** — `--dynamic` (PAIR-style mutation on refusal), `--tap` (tree-of-attacks branching), `--crescendo` (multi-turn escalation that backtracks when blocked), and `--auto` (profile → plan → escalate autonomously).
- **Local-first / air-gap** — `--local` runs the full generate → fire → judge → mutate loop against Ollama with zero external calls; `--offline` hard-refuses any non-local endpoint.
- **Self-improving SLM / KB** — successful attacks seed a bge-m3 + SQLite knowledge base (`--evolve`); the SLM pipeline fine-tunes a local attacker and only ships it when a Wilson-CI A/B test proves it beats the base.
- **Model stealing** — `--extract` performs determinism fingerprinting, system-prompt/parameter exfiltration, training-data inversion, and membership-inference gap analysis.
- **Full-stack recon** — `--recon` bridges AgentHound to find exposed MCP/LiteLLM/Ollama/vLLM/Qdrant/MLflow services; `--full-stack` then sweeps them behaviourally and chains reachable infrastructure to exploitable behaviour in one report.
- **Framework mapping** — every finding is tagged against MITRE ATLAS, the OWASP LLM Top 10, and the NIST AI RMF.
- **SARIF / PDF reporting** — results export as JSON, CSV, SARIF 2.1.0 (GitHub code-scanning), and a branded PDF, with ASR@1 / ASR@N metrics and Wilson confidence intervals.

## Quick look

```bash
crucible --mode redteam --local --framework atlas
```

Scope and cost a hosted run with zero traffic first by adding `--dry-run`.

## Authorized use

CRUCIBLE gates its own sharp paths (`--recon`, `--full-stack`, `--extract`, `--discover`) behind an authorization check every run — interactive, or via `--i-am-authorized` / `CRUCIBLE_AUTHORIZED=1`; `--ci` never bypasses it. A `.crucible-roe.yaml` Rules-of-Engagement file constrains targets to authorized CIDRs/hosts and an expiry, and every side-effectful run appends to `.crucible-audit.jsonl`. See [Safety & serving](safety-and-serving.md) for the full guardrail model.

## Where to next

- [Getting started](getting-started.md) — install profiles, first run, hosted vs. local targets.
- [Attack modes](attack-modes.md) — the full arsenal and the declarative vuln × technique matrix.
- [Adaptive attackers & judging](adaptive-and-judging.md) — dynamic/TAP/crescendo/auto, verdicts, and risk scoring.
- [Safety & serving](safety-and-serving.md) — authorization gates, Rules of Engagement, blast-radius caps, and the web dashboard.

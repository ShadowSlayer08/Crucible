# Attack Modes

CRUCIBLE ships its offensive coverage as named **suites** (`--mode`) plus a
**declarative** `--vuln × --attack` composer and a **published-benchmark** runner.
Pick a fixed suite when you want a curated attack set; compose when you want to
name *what* to test and *how*; run a benchmark when you need a published-number
comparison.

!!! warning "Authorized use only"
    Every mode on this page is offensive-capable. Point `crucible` (alias `cru`,
    v3.0.0) only at systems you own or are **written-authorized** to test. Scope
    and cost a run with **zero traffic** first via `--dry-run`.

Dump the exact contents of any suite before firing:

```bash
crucible --list-tests --mode <name>
```

---

## The arsenal — `--mode`

Each suite is a curated pool of tests. Counts are the shipped suite sizes.

| Mode | # | Hits |
|------|---|------|
| `vapt` | 28 | Prompt injection · data leakage · robustness |
| `redteam` | 55 (+22 ATLAS) | Full-spectrum safety **and** security |
| `mcp` | 25 | Model Context Protocol: tool-result poisoning, server/host trust |
| `agentic` | 30 | Tool hijacking, memory + **planning manipulation** |
| `rag` / `rag-long` | 25 | Doc + vector-store poisoning; injection buried in 8K–32K context |
| `swarm` | 15 | Multi-agent orchestrator / message-bus / consensus attacks |
| `policy` | 16 | Llama-Guard **S1–S14** harm coverage |
| `modern-jailbreak` | 12 | **2024–25 meta**: Policy Puppetry · Skeleton Key · Deceptive Delight |
| `many-shot` | 8 | Long-context in-context-learning bypass (4/8/16/32-shot curve) |
| `obfuscation` | 15 | Base64 / ROT13 / Unicode / zero-width / emoji evasion |
| `multilingual` | 18 | Cross-language jailbreaks (7 langs) |
| `multimodal` · `audio` · `video` | 8·8·8 | Image / voice / frame attack surfaces |
| `memory-poison` · `pismith` | 15 · 20 | KB poisoning · phishing/promotion/denial injection |
| `authz` | 16 | BOLA / BFLA / RBAC bypass / SSRF / shell / cross-context |
| `model-theft` | 12 | Extraction · inversion · membership (see `--extract`) |
| `benign` | 22 | Over-refusal traps — a refusal **here** is the failure |

Fire a single suite at a local target with nothing leaving the box:

```bash
crucible --mode vapt --local
```

Or at a hosted endpoint, with framework mapping and a PDF readout:

```bash
crucible --mode redteam --framework atlas --owasp --nist --pdf \
  --endpoint https://api.openai.com --api-key "$KEY" --model gpt-4o
```

---

## Declarative composition — `--vuln × --attack`

Instead of one fixed suite, name **what** to test (vulnerabilities) and **how**
to attack it (techniques). Each vulnerability resolves to a base test pool; each
attack is a transform applied to every selected payload. The cross-product is the
run — pure composition over the existing suites and mutators.

```bash
crucible --vuln RBAC,PIILeakage --attack Roleplay,Base64,Likert
```

- `--vuln A,B` — comma-separated vulnerability suites (14 available): e.g.
  `PromptInjection`, `PIILeakage`, `Robustness`, `Jailbreak`, `HarmfulContent`,
  `Authorization`, `RBAC`, `ToolMisuse`, `RAGPoisoning`, `Swarm`,
  `PolicyViolation`, `Multimodal`, `Multilingual`, `Obfuscation`.
- `--attack X,Y` — techniques applied to each payload (18 available): framing
  mutators (`Roleplay`, `Fictional`, `Academic`, `Hypothetical`, `Authority`,
  `Math`, `Poetry`, `Emotional`, `Likert`), modern meta
  (`PolicyPuppetry`, `SkeletonKey`, `DeceptiveDelight`, `RefusalSuppression`),
  and encodings (`Base64`, `ROT13`, `Unicode`, `ZeroWidth`, `LongContext`).

Given `--vuln` with no `--attack`, the raw suites run untransformed. Each composed
test carries an `<id>+<Attack>` id and `vuln:`/`attack:` tags. Unknown names fail
fast with the valid choices listed.

### List the catalogue

```bash
crucible --list-vulns      # print every --vuln and --attack name, then exit
crucible --list-tests --mode <name>   # dump the tests in a fixed suite
```

---

## Published-benchmark runner — `--benchmark-suite`

Run a published jailbreak benchmark's **prompt set** and auto-score it with the
matching rubric grader — one command for a "how does my model compare to the
published number" comparison.

```bash
crucible --benchmark-suite harmbench --local
```

Supported suites (each 1:1 with its rubric grader):

| Suite | Aliases | Real dataset |
|-------|---------|--------------|
| `harmbench` | `hb` | HarmBench behaviors CSV (Mazeika et al. 2024) |
| `jailbreakbench` | `jbb`, `jailbreak-bench` | JBB-Behaviors CSV/JSONL (Chao et al. 2024) |
| `strongreject` | `sr`, `strong-reject`, `reject` | strongreject_dataset.csv (Souly et al. 2024) |

### Bundled sample vs. the real dataset

By default `--benchmark-suite` runs a **bundled abstract sample** (a deterministic
12-prompt slice of CRUCIBLE's own policy suite) so the flow works out of the box
for a demo or smoke test — no new harmful content is added. For a **faithful**
comparison, supply the real dataset yourself:

```bash
crucible --benchmark-suite strongreject \
  --benchmark-file ./strongreject_dataset.csv \
  --endpoint https://api.openai.com --api-key "$KEY" --model gpt-4o
```

- `--benchmark-file PATH` — load the real dataset (CSV/TSV/JSONL via the corpus
  loader) instead of the bundled sample. The operator supplies the file.
- `--benchmark-limit N` — cap the number of benchmark prompts run to `N`.

!!! note "Datasets are operator-supplied"
    CRUCIBLE bundles only its own abstract policy prompts. Download the published
    benchmark datasets from their upstream authors and point `--benchmark-file`
    at them for a real comparison.

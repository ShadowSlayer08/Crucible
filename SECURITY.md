# Security & Responsible Use

REDai is an **offensive-capable** AI security tool: it generates and sends
adversarial prompts to AI systems and can drive an autonomous attack loop. Treat
it like any other red-team tool.

## Authorized use only

Run REDai **only** against systems you own or have **explicit written permission**
to test. Unauthorized testing may violate computer-fraud laws (e.g. the CFAA),
provider Terms of Service, and professional ethics codes.

Before any run against a third-party endpoint:
- Confirm you have authorization and a defined scope.
- **Define a Rules-of-Engagement file** (`.ai-redteam-roe.yaml`; see
  `.ai-redteam-roe.example.yaml`). When present, REDai **refuses** any live target or
  recon scope outside the authorized CIDRs/hosts and after the ROE's expiry, and
  stamps the reference into the audit trail. Override a single run only with
  `--roe-override` (recorded).
- Prefer local targets (Ollama) for experimentation; loopback is always in-scope.
- Use `--budget` / `--max-calls` (a hard ceiling, even under `--concurrency`) and
  `--rps` / `--delay` to cap spend and blast radius against a target.
- The offensive paths (`--recon` / `--full-stack` / `--extract` / `--discover`)
  require authorization every run — interactively, or `--i-am-authorized` /
  `AI_RT_AUTHORIZED=1` for automation (`--ci` does **not** bypass them).
- Every side-effectful run is recorded to an append-only audit trail
  (`.ai-redteam-audit.jsonl`): operator, time, action, target host, mode, ROE ref.
- Use `--anonymize` when sharing reports — it redacts the endpoint/key and **scrubs
  emails, SSNs, API-key-like secrets and phone numbers** from saved response bodies.

## What the tool does and does not do

- It **does** exercise refusal boundaries, prompt injection, agentic/RAG/tool
  abuse, and guardrail evasion, and it reports how built-in filters would block them.
- Payloads are written at an **attack-vector abstraction** — they reference harm
  categories to test refusals, not operational harmful detail. Please keep any
  contributions to the same standard.
- It **does not** ship real weapons/CBRN/CSAM content, and such contributions
  will be rejected.

## Reporting a vulnerability in REDai itself

If you find a security issue in this tool (not in a target you tested), please
report it privately to the maintainer rather than opening a public issue. Include
repro steps and affected version.

## Handling findings

Reports may contain sensitive details about a tested system. They are written to
`reports/` which is git-ignored by default — do not commit them, and follow a
responsible-disclosure timeline when sharing findings with a system's owner.

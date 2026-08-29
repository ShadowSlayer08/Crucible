# Security & Responsible Use

CRUCIBLE is an **offensive-capable** AI security tool: it generates and sends
adversarial prompts to AI systems and can drive an autonomous attack loop. Treat
it like any other red-team tool.

## Authorized use only

Run CRUCIBLE **only** against systems you own or have **explicit written permission**
to test. Unauthorized testing may violate computer-fraud laws (e.g. the CFAA),
provider Terms of Service, and professional ethics codes.

Before any run against a third-party endpoint:
- Confirm you have authorization and a defined scope.
- Prefer local targets (Ollama) for experimentation.
- Use `--budget` / `--max-calls` to cap spend and blast radius.
- Use `--anonymize` when sharing reports.

## What the tool does and does not do

- It **does** exercise refusal boundaries, prompt injection, agentic/RAG/tool
  abuse, and guardrail evasion, and it reports how built-in filters would block them.
- Payloads are written at an **attack-vector abstraction** — they reference harm
  categories to test refusals, not operational harmful detail. Please keep any
  contributions to the same standard.
- It **does not** ship real weapons/CBRN/CSAM content, and such contributions
  will be rejected.

## Reporting a vulnerability in CRUCIBLE itself

If you find a security issue in this tool (not in a target you tested), please
report it privately to the maintainer rather than opening a public issue. Include
repro steps and affected version.

## Handling findings

Reports may contain sensitive details about a tested system. They are written to
`reports/` which is git-ignored by default — do not commit them, and follow a
responsible-disclosure timeline when sharing findings with a system's owner.

# Getting Started

CRUCIBLE is a black-box, **authorized-testing-only** offensive tool for LLM and
agentic systems. It fires 20+ attack suites at a target, adapts when refused, and
maps every break to MITRE ATLAS / OWASP LLM Top 10 / NIST AI RMF.

The console command is `crucible` (short alias `cru`), version `3.0.0`. This guide
takes you from a clean checkout to your first run — locally, against a hosted
target, in Docker, and with shell completion wired up.

!!! warning "Authorized use only"
    Point CRUCIBLE only at systems you own or are **written-authorized** to test.
    Unauthorized testing may violate computer-fraud law (CFAA & friends), provider
    ToS, and professional ethics. The sharp paths (`--recon` / `--full-stack` /
    `--extract` / `--discover`) gate on authorization every run.

---

## Requirements

- Python **3.10+**
- A checkout of this repository (installs are editable, `pip install -e`)
- Optional: [Ollama](https://ollama.com) for fully local / air-gapped runs

```bash
git clone <this-repo> crucible && cd crucible
```

---

## Install profiles

Install the core CLI, then add extras for the surfaces you need. The core install
pulls only `requests` + `pyyaml` and already ships every attack mode plus
JSON / CSV / SARIF output.

| Command | You get |
|---|---|
| `pip install -e .` | Core CLI (`requests` + `pyyaml`) — every attack mode, JSON/CSV/SARIF |
| `pip install -e ".[server]"` | `--serve` web dashboard (FastAPI + uvicorn + httpx, SSE) |
| `pip install -e ".[pdf]"` | `--pdf` export (reportlab) |
| `pip install -e ".[browser]"` | `--schema browser` driver (Playwright) |
| `pip install -e ".[all]"` | PDF + server + docs extras (reportlab, FastAPI/uvicorn/httpx, openpyxl/python-docx) |
| `pip install -e ".[dev]"` | test + tooling stack incl. `pytest` |

!!! note
    `.[all]` bundles the PDF, server, and docs extras but **not** the browser
    (Playwright) extra — install `.[browser]` separately if you need the browser
    driver, since it pulls a full Chromium.

Both `crucible` and the short `cru` land on `PATH` after any profile install.
`crucible --help` prints the full ~180-flag reference.

```bash
pip install -e ".[all]"      # CLI + PDF + web dashboard + docs
crucible --version           # 3.0.0
```

---

## 60-second quickstart

Fire at a local Ollama model — nothing leaves your box:

```bash
crucible --mode vapt --local
```

…or drive it from the dashboard:

```bash
crucible --serve             # http://127.0.0.1:8000
```

`--local` runs the whole generate → fire → judge → mutate loop against Ollama with
zero external calls.

---

## Hitting a hosted target

Point CRUCIBLE at any hosted LLM endpoint with `--endpoint`, `--api-key`, and
`--model`:

```bash
crucible --mode redteam \
  --endpoint https://api.openai.com \
  --api-key "$KEY" \
  --model gpt-4o
```

Layer in framework mapping and a PDF readout when you want a board-ready verdict:

```bash
crucible --mode redteam --framework atlas --owasp --nist --pdf \
  --endpoint https://api.openai.com --api-key "$KEY" --model gpt-4o
```

Supported providers:

```
openai · anthropic · cohere · mistral · google · ollama · azure · bedrock · custom · browser
```

---

## Scope with zero traffic — `--dry-run`

Before you spend a single request (or a single dollar) against a live target,
scope the run with `--dry-run`. It plans the engagement without sending any
traffic to the target:

```bash
crucible --mode redteam --dry-run \
  --endpoint https://api.openai.com --api-key "$KEY" --model gpt-4o
```

---

## Docker

A multi-stage image builds a wheel, then installs it into a slim, non-root runtime
with the `server` + `pdf` extras and the `crucible` console script as the
entrypoint. (The browser/Playwright extra is intentionally omitted from the image.)

```bash
docker build -t crucible:3.0.0 .

# Sanity check
docker run --rm crucible:3.0.0 --version

# Run against a hosted target, mounting a reports volume
docker run --rm -v "$PWD/reports:/app/reports" crucible:3.0.0 \
  --mode vapt --endpoint https://api.openai.com --api-key "$KEY" --model gpt-4o

# Web dashboard (bind to all interfaces so the mapped port is reachable)
docker run --rm -p 8000:8000 crucible:3.0.0 --serve --serve-host 0.0.0.0
```

Reports land in the mounted `/app/reports` volume; the container runs as an
unprivileged user (`uid 10001`).

---

## Shell completion

Generate a completion script for your shell with `crucible --completion bash|zsh|fish`.
It is dependency-free — no `argcomplete`, no runtime hook. Print the script, then
install it where your shell loads completions:

```bash
# bash — append to your rc file (or drop into bash-completion.d)
crucible --completion bash >> ~/.bashrc

# zsh — put it on your $fpath as _crucible
crucible --completion zsh  > ~/.zfunc/_crucible

# fish — save into the completions directory
crucible --completion fish > ~/.config/fish/completions/crucible.fish
```

Both `crucible` and `cru` are completed. Open a new shell (or re-source your rc
file) to pick up the completions.

---

## Next steps

- `crucible --list-tests --mode <name>` dumps any attack suite.
- `crucible --help` prints the full flag reference.
- Reports land in `--output-dir` (default `./reports`) as JSON · CSV · SARIF 2.1.0 · PDF.

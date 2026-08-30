# CRUCIBLE Frontend — React + Vite

A component-based dashboard for the CRUCIBLE, built on React 18 + Vite 5.
It is a **thin client** over the same REST API (`server.py`) that the bundled
zero-build dashboard uses — nothing here re-implements engine logic.

> **Two frontends, one API.** The project ships a fully self-contained
> [`web/index.html`](../web/index.html) dashboard that needs **no build step** —
> `python -m crucible --serve` serves it immediately. This `frontend/` directory is
> the optional richer, component-based version for teams that want to extend the
> UI. Use whichever fits; both call the identical endpoints.

## Run it

Start the backend first (serves the API on `:8000`):

```bash
python -m crucible --serve            # or: python server.py
```

Then, in this directory:

```bash
npm install
npm run dev                        # Vite dev server on http://localhost:5173
```

The Vite dev server proxies `/health`, `/modes`, `/schemas`, `/tests`, and
`/scan*` to `http://localhost:8000` (see [`vite.config.js`](vite.config.js)), so
the app calls same-origin paths. CORS is also enabled server-side, so a direct
cross-origin setup works too.

## Build

```bash
npm run build                      # → dist/
```

The static `dist/` bundle can be served by any host, or dropped in front of the
FastAPI app.

## What it does

- **Connection panel** — mode, endpoint, schema, model, API key (never stored),
  severity filter, per-run limit, dry-run toggle.
- **Dry run** — hits `POST /scan` with `dry_run=true`: test count + token/cost
  estimate, **zero** outbound traffic.
- **Live run** — streams `POST /scan/stream` (Server-Sent Events); results fill
  in row-by-row with a progress bar.
- **Summary** — risk-score gauge, attack-success-rate with a 95% Wilson CI,
  policy (Llama-Guard S1–S14) coverage, guardrail block-rate, and a verdict
  breakdown — all computed server-side and rendered here.

## Layout

```
src/
  main.jsx      React entrypoint
  App.jsx       dashboard (connection panel, live run, results, summary)
  api.js        REST client + SSE stream parser
  styles.css    design tokens + components
```

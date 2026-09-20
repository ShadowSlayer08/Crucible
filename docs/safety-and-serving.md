# Safety & Serving

CRUCIBLE (`crucible`, alias `cru`, v3.0.0) is an offensive-capable, black-box AI
red-team CLI: it generates and sends adversarial prompts and can drive an
autonomous attack loop. Run it **only** against systems you own or have
**explicit written permission** to test. Unauthorized testing may violate
computer-fraud law (e.g. the CFAA), provider Terms of Service, and professional
ethics codes.

This page covers the safety controls that keep offensive capability on a leash,
and how to stand up the authenticated dashboard/API.

## Safety controls

### Per-run authorization on offensive paths

The sharp paths — `--recon`, `--full-stack`, `--extract`, `--discover` — require
authorization **every run**. You confirm interactively at the prompt, or opt in
non-interactively for automation with `--i-am-authorized` (or set
`CRUCIBLE_AUTHORIZED=1`).

`--ci` does **not** bypass this gate. CI mode governs exit-code thresholds only;
it never stands in for authorization on the offensive paths.

```bash
# Interactive: answer the authorization prompt each run
crucible --recon --endpoint https://target.internal

# Automation: explicit, recorded opt-in
crucible --full-stack --i-am-authorized --endpoint https://target.internal
CRUCIBLE_AUTHORIZED=1 crucible --extract --endpoint https://target.internal
```

### Rules of Engagement (`.crucible-roe.yaml`)

Define a Rules-of-Engagement / scope file before testing a third-party endpoint.
CRUCIBLE auto-detects `.crucible-roe.yaml` in the working directory, or you can
point at one with `--roe FILE` (see `.crucible-roe.example.yaml`).

When an ROE is present, CRUCIBLE **refuses** any live target or recon scope
outside the authorized CIDRs/hosts, and refuses after the ROE's expiry. The ROE
reference is stamped into the audit trail.

```bash
crucible --mode redteam --roe .crucible-roe.yaml --endpoint https://target.internal
```

- `--roe-override` proceeds against an out-of-scope or expired target anyway; the
  override is recorded in the audit trail. Use only with explicit sign-off.
- `--no-roe` ignores any ROE file and disables scope confinement.

### Append-only audit trail (`.crucible-audit.jsonl`)

Every side-effectful run appends a record to `.crucible-audit.jsonl`:
operator, time, action, target host, mode, and ROE reference. The trail is
append-only, giving you a defensible log of what was run, when, and under whose
authorization.

### Blast-radius caps

Cap spend and outbound pressure against a target:

- `--budget USD` — stop when estimated spend reaches the ceiling.
- `--max-calls N` — a hard ceiling on total calls, enforced even under
  `--concurrency`.
- `--rps R` — cap requests per second.
- `--delay SEC` — minimum delay between calls (the larger of `--delay` and the
  interval implied by `--rps` wins).

```bash
crucible --mode redteam --endpoint https://target.internal \
  --budget 5.00 --max-calls 500 --rps 2 --delay 0.5
```

Prefer local targets (Ollama) for experimentation; loopback is always in-scope.
Scope and cost with **zero traffic** first using `--dry-run`.

### PII / secret scrubbing (`--anonymize`)

Use `--anonymize` when sharing reports. It redacts the endpoint and key, and
scrubs emails, SSNs, API-key-like secrets, and phone numbers from saved response
bodies.

```bash
crucible --mode vapt --endpoint https://target.internal --anonymize
```

Reports are written to `reports/`, which is git-ignored by default — do not
commit them, and follow a responsible-disclosure timeline when sharing findings
with a system's owner.

## Serving the dashboard

`crucible --serve` launches the FastAPI REST server plus the web dashboard, then
exits. It binds `127.0.0.1:8000` by default (`--serve-host` / `--serve-port`).

```bash
crucible --serve
crucible --serve --serve-host 0.0.0.0 --serve-port 8000   # expose on a trusted network only
```

### Authentication is mandatory

`--serve` **refuses to start without an operator password**. Supply it with
`--serve-password PW` or the `CRUCIBLE_SERVE_PASSWORD` environment variable.

The password is exchanged at `POST /auth/login` for a short-lived **HS256 JWT**.
That token must be sent as `Authorization: Bearer <token>` on **every route
except** `/health`, `/`, and `/auth/login`; requests without a valid token get
`401`.

```bash
export CRUCIBLE_SERVE_PASSWORD='choose-a-strong-password'
crucible --serve

# Exchange the password for a token
curl -s -X POST http://127.0.0.1:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"password":"choose-a-strong-password"}'
# → {"token":"<jwt>","token_type":"bearer","expires_in":28800}

# Call a protected route with the token
curl -s http://127.0.0.1:8000/modes \
  -H "Authorization: Bearer <jwt>"
```

Token controls:

- `--serve-secret KEY` (or `CRUCIBLE_JWT_SECRET`) — the JWT signing secret.
  Persist it to keep issued tokens valid across restarts; otherwise a random
  per-process secret is generated and tokens are invalidated on restart.
- `--serve-token-ttl SECONDS` — token lifetime (default 28800, i.e. 8 hours).

The JWT is verified with a constant-time signature check; the `alg` header must
be `HS256` (`none` and RS/ES algorithm confusion are rejected) and `exp` is
enforced. Even so, only expose the dashboard on a trusted network.

## Report formats & verdicts

Reports land in `--output-dir` (default `./reports`) in these formats:

- `JSON`
- `CSV`
- `SARIF 2.1.0` (GitHub code-scanning)
- `PDF`

Each test result carries one verdict:

| Verdict | Meaning |
|---|---|
| `PASS` | Model held the line (refused) |
| `FAIL` | Model complied — a hole was found |
| `WARN` | Hedged / partial — needs a human look |
| `PARTIAL_REFUSAL` | Refused but leaked — counted at half weight |
| `SILENT` | Empty output — no risk |
| `ERROR` | Call failed — excluded from ASR |

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Clean |
| `1` | Over `--ci-threshold` |
| `2` | Input / warn |
| `3` | Recon-tool error |
| `4` | ROE refusal |

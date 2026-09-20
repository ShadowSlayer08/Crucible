import { useEffect, useState } from "react";
import { getHealth, getModes, getSchemas, dryRun, streamScan, login, logout, hasToken, AuthError } from "./api.js";

const SEVERITIES = ["Critical", "High", "Medium", "Low"];
const VERDICT_ORDER = ["FAIL", "WARN", "PARTIAL_REFUSAL", "SILENT", "PASS", "ERROR"];
const VCOL = {
  FAIL: "var(--red)", WARN: "var(--yellow)", PARTIAL_REFUSAL: "var(--orange)",
  SILENT: "var(--blue)", PASS: "var(--green)", ERROR: "var(--dim)",
};
const riskColor = (s) =>
  s >= 70 ? "var(--red)" : s >= 45 ? "var(--orange)" : s >= 20 ? "var(--yellow)" : "var(--green)";

export default function App() {
  const [health, setHealth] = useState(null);
  const [offline, setOffline] = useState(false);
  const [modes, setModes] = useState([]);
  const [schemas, setSchemas] = useState([]);
  const [form, setForm] = useState({
    mode: "vapt", endpoint: "", apiKey: "", model: "qwen2.5:7b",
    schema: "openai", limit: "", dry: true,
  });
  const [sev, setSev] = useState(new Set(SEVERITIES));
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);      // {kind, text}
  const [progress, setProgress] = useState(null); // {index,total,id}
  const [rows, setRows] = useState([]);
  const [summary, setSummary] = useState(null);
  const [dry, setDry] = useState(null);
  const [needAuth, setNeedAuth] = useState(false);

  async function loadMeta() {
    const [m, s] = await Promise.all([getModes(), getSchemas()]);
    setModes(m.modes); setSchemas(s.schemas);
  }

  useEffect(() => {
    (async () => {
      try { setHealth(await getHealth()); }
      catch { setOffline(true); return; }
      try { await loadMeta(); }
      catch (e) { if (e instanceof AuthError) setNeedAuth(true); else setOffline(true); }
    })();
  }, []);

  const set = (k) => (e) =>
    setForm((f) => ({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value }));

  const toggleSev = (s) =>
    setSev((prev) => {
      const next = new Set(prev);
      next.has(s) ? next.delete(s) : next.add(s);
      return next;
    });

  const body = () => ({
    mode: form.mode,
    severities: sev.size === 4 ? null : [...sev],
    limit: form.limit === "" ? null : Math.max(0, parseInt(form.limit, 10) || 0),
    config: {
      endpoint: form.endpoint.trim(), api_key: form.apiKey,
      model: form.model.trim() || "gpt-4o", schema: form.schema,
    },
  });

  async function run() {
    setBusy(true); setMsg(null); setSummary(null); setDry(null);
    setRows([]); setProgress(null);
    try {
      if (form.dry || !form.endpoint.trim()) {
        setDry(await dryRun(body()));
      } else {
        const acc = [];
        const done = await streamScan(body(), (t) => {
          acc.push(t);
          setRows([...acc]);
          setProgress({ index: t.index, total: t.total, id: t.id });
        });
        if (done) {
          setSummary(done);
          const fails = done.scores.totals.fail || 0;
          setMsg(fails
            ? { kind: "err", text: `⚠ ${fails} attack${fails > 1 ? "s" : ""} succeeded — risk ${done.scores.risk_level} (${done.scores.overall_risk_score}/100).` }
            : { kind: "info", text: `✓ No attacks succeeded — risk ${done.scores.risk_level} (${done.scores.overall_risk_score}/100).` });
        }
      }
    } catch (e) {
      if (e instanceof AuthError) setNeedAuth(true);
      else setMsg({ kind: "err", text: "✗ " + e.message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      {needAuth && (
        <Login onAuthed={async () => { setNeedAuth(false); try { await loadMeta(); } catch { /* ignore */ } }} />
      )}
      <header>
        <h1>AI Red Team<span className="dot"> ●</span> CLI</h1>
        <span className="ver">{health ? "v" + health.version : "v—"}</span>
        <div className="status">
          <span className={"pulse " + (offline ? "err" : health ? "on" : "")} />
          {offline ? "server offline" : health ? `${health.schemas} schemas · ${health.modes} modes` : "connecting…"}
          {hasToken() && (
            <a style={{ marginLeft: 10, cursor: "pointer", opacity: 0.7 }}
               onClick={() => { logout(); setNeedAuth(true); }}>sign out</a>
          )}
        </div>
      </header>

      <main>
        <section className="panel">
          <h2>Target &amp; Scan</h2>

          <label>Mode</label>
          <select value={form.mode} onChange={set("mode")}>
            {modes.map((m) => <option key={m.name} value={m.name}>{m.name} ({m.test_count})</option>)}
          </select>

          <label>Endpoint <span className="muted">(blank = dry-run)</span></label>
          <input value={form.endpoint} onChange={set("endpoint")}
                 placeholder="http://localhost:11434/v1/chat/completions" />

          <div className="row">
            <div>
              <label>Schema</label>
              <select value={form.schema} onChange={set("schema")}>
                {schemas.map((s) => <option key={s.name} value={s.name}>{s.name}</option>)}
              </select>
            </div>
            <div><label>Model</label><input value={form.model} onChange={set("model")} /></div>
          </div>

          <label>API key <span className="muted">(never stored)</span></label>
          <input type="password" value={form.apiKey} onChange={set("apiKey")} placeholder="optional" />

          <label>Severity</label>
          <div className="chips">
            {SEVERITIES.map((s) => (
              <span key={s} className={"chip" + (sev.has(s) ? " on" : "")} onClick={() => toggleSev(s)}>{s}</span>
            ))}
          </div>

          <div className="row" style={{ marginTop: 12 }}>
            <div><label>Limit</label><input type="number" min="0" value={form.limit} onChange={set("limit")} placeholder="all" /></div>
          </div>

          <label className="toggle">
            <input type="checkbox" checked={form.dry} onChange={set("dry")} />
            <span>Dry run <span className="muted">(no traffic)</span></span>
          </label>

          <button className="primary" disabled={busy} onClick={run}>{busy ? "Running…" : "▶ Run scan"}</button>
        </section>

        <section>
          {msg && <div className={"banner " + msg.kind}>{msg.text}</div>}

          {progress && (
            <div className="panel" style={{ marginBottom: 18 }}>
              <h2>Live run</h2>
              <div className="bar"><i style={{ width: (progress.index / progress.total * 100) + "%" }} /></div>
              <div className="muted">{progress.index} / {progress.total} — {progress.id}</div>
            </div>
          )}

          <div className="panel">
            <h2>Results</h2>
            {!dry && !summary && rows.length === 0 && (
              <div className="empty"><div className="big">🎯</div>Configure a target and run a scan.</div>
            )}
            {dry && <DryRun r={dry} />}
            {summary && <Summary r={summary} />}
            {rows.length > 0 && <ResultsTable rows={rows} />}
          </div>
        </section>
      </main>
    </>
  );
}

function DryRun({ r }) {
  const c = r.cost_estimate;
  return (
    <>
      <div className="metrics">
        <Metric k="Tests" v={r.selected_tests} s={"mode: " + r.mode} />
        <Metric k="Prompt tokens" v={c.prompt_tokens.toLocaleString()} s="est." />
        <Metric k="Total tokens" v={c.estimated_tokens.toLocaleString()} s={`+${c.assumed_response_tokens_per_test}/test`} />
        <Metric k="Est. cost" v={"$" + c.estimated_usd} s={`@ $${c.usd_per_1k_tokens}/1k`} />
      </div>
      <div className="muted">{r.note}</div>
      <div className="mono muted" style={{ marginTop: 12 }}>{r.test_ids.join("  ·  ")}</div>
    </>
  );
}

function Summary({ r }) {
  const s = r.scores, score = s.overall_risk_score, col = riskColor(score);
  const t = s.totals, tot = Object.values(t).reduce((a, b) => a + b, 0) || 1;
  const asr = r.asr, cov = r.coverage, gr = r.guardrails;
  const covPct = Math.round((cov.coverage_score || 0) * 100);
  return (
    <>
      <div className="metrics">
        <div className="metric" style={{ gridRow: "span 2" }}>
          <div className="k">Risk score</div>
          <div className="gauge">
            <div className="ring" style={{ "--p": score, "--c": col }}>
              <b style={{ color: col }}>{score}</b><span className="lbl">{s.risk_level}</span>
            </div>
          </div>
        </div>
        <Metric k="Attack success rate" v={asr.asr.toFixed(1) + "%"} s={`95% CI ${asr.low.toFixed(1)}–${asr.high.toFixed(1)}% · n=${asr.n}`} vcol={col} />
        <Metric k="Policy coverage" v={covPct + "%"} s={`${cov.covered}/${cov.total} categories`} />
        <Metric k="Guardrail block-rate" v={gr.block_rate + "%"} s={`${gr.blocked_fails}/${gr.total_fails} fails · FP ${gr.fp_rate}%`} />
      </div>
      <div className="row" style={{ gap: 18, alignItems: "flex-start" }}>
        <div style={{ flex: 1.1 }}>
          <label style={{ marginTop: 0 }}>Verdict breakdown</label>
          <div className="vbars">
            {VERDICT_ORDER.map((v) => {
              const n = t[v.toLowerCase()] || 0;
              return (
                <div className="vbar" key={v}>
                  <span className="pill" style={{ background: "transparent", color: VCOL[v] }}>{v}</span>
                  <div className="track"><i style={{ width: (n / tot * 100) + "%", background: VCOL[v] }} /></div>
                  <span className="muted">{n}</span>
                </div>
              );
            })}
          </div>
        </div>
        <div style={{ flex: 1 }}>
          <label style={{ marginTop: 0 }}>Policy / Llama-Guard coverage</label>
          <div className="cov-grid">
            {Object.entries(cov.categories || {}).map(([code, c]) => {
              const cls = c.status === "HIT" ? "hit" : c.status === "TESTED" ? "ok" : "untested";
              return <span key={code} className={"cov " + cls} title={`${code} ${c.name} — ${c.status}`}>{code}</span>;
            })}
          </div>
        </div>
      </div>
    </>
  );
}

function ResultsTable({ rows }) {
  return (
    <div className="tbl-wrap" style={{ marginTop: 16 }}>
      <table>
        <thead><tr><th>#</th><th>ID</th><th>Test</th><th>Sev</th><th>Verdict</th><th>Reason</th></tr></thead>
        <tbody>
          {rows.map((d) => (
            <tr key={d.id}>
              <td className="muted">{d.index}</td>
              <td className="mono">{d.id}</td>
              <td>{d.name}</td>
              <td style={{ color: `var(--${d.severity === "Critical" ? "red" : d.severity === "High" ? "orange" : d.severity === "Medium" ? "yellow" : "dim"})` }}>{d.severity}</td>
              <td><span className="pill" style={{ background: VCOL[d.verdict] + "28", color: VCOL[d.verdict] }}>{d.verdict}</span></td>
              <td className="reason">{d.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Login({ onAuthed }) {
  const [pw, setPw] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e?.preventDefault();
    setBusy(true); setErr("");
    try { await login(pw); onAuthed(); }
    catch { setErr("Invalid password — try again."); setBusy(false); }
  };
  const overlay = {
    position: "fixed", inset: 0, background: "rgba(0,0,0,.72)",
    display: "flex", alignItems: "center", justifyContent: "center", zIndex: 9999,
  };
  const card = {
    background: "var(--panel, #141821)", border: "1px solid var(--border, #2a3140)",
    borderRadius: 12, padding: 24, width: 320, maxWidth: "90vw",
    boxShadow: "0 12px 40px rgba(0,0,0,.5)", display: "flex", flexDirection: "column", gap: 10,
  };
  return (
    <div style={overlay}>
      <form style={card} onSubmit={submit}>
        <div style={{ fontWeight: 700, fontSize: 16 }}>🔒 CRUCIBLE dashboard</div>
        <div className="muted" style={{ fontSize: 12 }}>{err || "Enter the operator password."}</div>
        <input type="password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} placeholder="password" />
        <button className="primary" disabled={busy} type="submit">{busy ? "…" : "Sign in"}</button>
      </form>
    </div>
  );
}

const Metric = ({ k, v, s, vcol }) => (
  <div className="metric">
    <div className="k">{k}</div>
    <div className="v" style={vcol ? { color: vcol } : undefined}>{v}</div>
    {s && <div className="s">{s}</div>}
  </div>
);

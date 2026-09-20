// Thin client for the CRUCIBLE REST API (server.py).
// Same paths the zero-build dashboard uses; CORS is enabled server-side and
// the Vite dev server also proxies them, so these work in dev and in a build.
//
// Auth: the server (with --serve) requires a Bearer JWT obtained from a password
// via login(). We stash the token in localStorage and attach it to every request;
// a 401 clears it and raises AuthError so the UI can show the login screen.

const TOKEN_KEY = "crucible_token";

export const getToken = () => {
  try { return localStorage.getItem(TOKEN_KEY) || ""; } catch { return ""; }
};
export const setToken = (t) => {
  try { t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY); }
  catch { /* private mode / storage blocked */ }
};
export const hasToken = () => !!getToken();
export const logout = () => setToken("");

export class AuthError extends Error {}

function authHeaders(extra) {
  const h = { ...(extra || {}) };
  const t = getToken();
  if (t) h["Authorization"] = "Bearer " + t;
  return h;
}

// Exchange the operator password for a short-lived Bearer token.
export async function login(password) {
  const r = await fetch("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });
  if (!r.ok) throw new AuthError("invalid password");
  const d = await r.json();
  setToken(d.token || "");
  return d;
}

export async function api(path, opts) {
  opts = opts || {};
  opts.headers = authHeaders(opts.headers);
  const r = await fetch(path, opts);
  if (r.status === 401) { setToken(""); throw new AuthError("unauthorized"); }
  if (!r.ok) {
    let detail;
    try { detail = (await r.json()).detail; } catch { /* non-JSON error */ }
    throw new Error(detail || `${r.status} ${r.statusText}`);
  }
  return r.json();
}

export const getHealth = () => api("/health");
export const getModes = () => api("/modes");
export const getSchemas = () => api("/schemas");
export const getTests = (mode) => api(`/tests?mode=${encodeURIComponent(mode)}`);

export const dryRun = (body) =>
  api("/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...body, dry_run: true }),
  });

// Stream a live scan via Server-Sent Events. Calls onTest(evt) per result and
// resolves with the final `done` summary object. EventSource can't POST, so we
// parse the streamed fetch body by hand.
export async function streamScan(body, onTest) {
  const resp = await fetch("/scan/stream", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ ...body, dry_run: false }),
  });
  if (resp.status === 401) { setToken(""); throw new AuthError("unauthorized"); }
  if (!resp.ok) {
    let detail;
    try { detail = (await resp.json()).detail; } catch { /* ignore */ }
    throw new Error(detail || `stream ${resp.status}`);
  }
  const reader = resp.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  let done = null;
  for (;;) {
    const { value, done: fin } = await reader.read();
    if (fin) break;
    buf += dec.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf("\n\n")) >= 0) {
      const chunk = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      const ev = /event:\s*(\w+)/.exec(chunk);
      const dm = /data:\s*([\s\S]*)$/.exec(chunk);
      if (!ev || !dm) continue;
      const data = JSON.parse(dm[1]);
      if (ev[1] === "test") onTest?.(data);
      else if (ev[1] === "done") done = data;
    }
  }
  return done;
}

// Thin client for the AI Red Team CLI REST API (server.py).
// Same paths the zero-build dashboard uses; CORS is enabled server-side and
// the Vite dev server also proxies them, so these work in dev and in a build.

export async function api(path, opts) {
  const r = await fetch(path, opts);
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
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...body, dry_run: false }),
  });
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

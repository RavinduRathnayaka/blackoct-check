#!/usr/bin/env python3
"""
blackoct-gui - local web interface for blackoct_check.py

Starts a small web server on 127.0.0.1 only, opens your browser, and lets you
run the Black October exposure checks from a form, with a built-in usage guide.

    python3 blackoct_gui.py                 # opens the browser
    python3 blackoct_gui.py --no-browser    # just print the URL
    python3 blackoct_gui.py --port 9000

Keep blackoct_check.py in the same folder. Python 3.8+, standard library only.
Use only against assets you own or are authorised to test.

Safety: the server listens on loopback only, every request needs a random
per-run token, the Host header is checked (DNS rebinding), and API calls must
be JSON. Another website open in your browser cannot trigger scans.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import secrets
import sys
import threading
import time
import uuid
import webbrowser
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import blackoct_check as bc
except ImportError:  # pragma: no cover
    sys.exit("error: blackoct_check.py must be in the same folder as blackoct_gui.py")

MAX_TARGETS = 500
MAX_BODY = 64 * 1024
JOBS: dict = {}
LOCK = threading.Lock()


# ---- job handling -----------------------------------------------------------
def parse_targets(text: str) -> list:
    seen, out = set(), []
    for t in str(text).replace(",", " ").split():
        t = t.strip()
        if t and not t.startswith("#") and t not in seen:
            seen.add(t)
            out.append(t)
    return out[:MAX_TARGETS]


def make_args(o: dict):
    a = bc.build_parser().parse_args(["placeholder"])
    a.checks = [c for c in o.get("checks", []) if c in bc.ALL_CHECKS]
    a.timeout = min(60.0, max(1.0, float(o.get("timeout") or 8)))
    a.proxy = (o.get("proxy") or "").strip() or None
    a.gitlab_token = (o.get("gitlab_token") or "").strip() or None
    a.verify_tls = bool(o.get("verify_tls"))
    hdrs = []
    for line in str(o.get("headers") or "").splitlines():
        if ":" in line:
            hdrs.append(line.strip())
    a.header = hdrs
    return a


def run_job(job: dict, targets: list, args, conc: int) -> None:
    with cf.ThreadPoolExecutor(max_workers=conc) as ex:
        futs = {ex.submit(bc.scan_target, t, args): t for t in targets}
        job["_futs"] = list(futs)
        for fut in cf.as_completed(futs):
            t = futs[fut]
            try:
                res = [asdict(f) for f in fut.result()]
            except cf.CancelledError:
                continue
            except Exception as e:  # noqa: BLE001
                res = [asdict(bc.Finding(t, "scan", "INFO", f"Scan error: {e}"))]
            with LOCK:
                job["results"][t] = res
                job["done"] += 1
    with LOCK:
        job["state"] = "cancelled" if job["cancel"] else "done"
        job["finished"] = time.time()
        job.pop("_futs", None)


def start_job(o: dict):
    targets = parse_targets(o.get("targets", ""))
    if not targets:
        return None, "Enter at least one target."
    args = make_args(o)
    if not args.checks:
        return None, "Select at least one check."
    conc = min(50, max(1, int(o.get("concurrency") or 10)))
    jid = uuid.uuid4().hex[:12]
    job = {"id": jid, "state": "running", "total": len(targets), "done": 0, "results": {},
           "order": targets, "cancel": False, "started": time.time(), "finished": None}
    with LOCK:
        JOBS[jid] = job
    threading.Thread(target=run_job, args=(job, targets, args, conc), daemon=True).start()
    return jid, None


def job_view(job: dict) -> dict:
    with LOCK:
        return {"id": job["id"], "state": job["state"], "total": job["total"], "done": job["done"],
                "order": job["order"], "results": dict(job["results"]),
                "elapsed": round((job["finished"] or time.time()) - job["started"], 1)}


# ---- HTTP -------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "blackoct-gui"

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                         "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode())

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self.server.allowed_hosts  # type: ignore[attr-defined]

    def _token_ok(self, supplied: str) -> bool:
        return secrets.compare_digest(supplied or "", self.server.token)  # type: ignore[attr-defined]

    def do_GET(self):  # noqa: N802
        if not self._host_ok():
            return self._send(403, b"bad host", "text/plain")
        u = urlparse(self.path)
        if u.path == "/":
            tok = parse_qs(u.query).get("t", [""])[0]
            if not self._token_ok(tok):
                return self._send(403, b"Open the full URL printed in the terminal (it includes the access token).", "text/plain")
            return self._send(200, PAGE.replace("__VERSION__", bc.__version__).encode(), "text/html")
        if u.path == "/api/status":
            if not self._token_ok(self.headers.get("X-Token", "")):
                return self._json(403, {"error": "forbidden"})
            job = JOBS.get(parse_qs(u.query).get("id", [""])[0])
            if not job:
                return self._json(404, {"error": "unknown job"})
            return self._json(200, job_view(job))
        self._send(404, b"not found", "text/plain")

    def do_POST(self):  # noqa: N802
        if not self._host_ok() or not self._token_ok(self.headers.get("X-Token", "")):
            return self._json(403, {"error": "forbidden"})
        if "application/json" not in self.headers.get("Content-Type", ""):
            return self._json(415, {"error": "json only"})
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_BODY:
            return self._json(413, {"error": "bad body size"})
        try:
            body = json.loads(self.rfile.read(n))
        except Exception:  # noqa: BLE001
            return self._json(400, {"error": "invalid json"})
        path = urlparse(self.path).path
        if path == "/api/scan":
            if not body.get("authorised"):
                return self._json(400, {"error": "Confirm you are authorised to test these targets."})
            jid, err = start_job(body)
            return self._json(400, {"error": err}) if err else self._json(200, {"id": jid})
        if path == "/api/cancel":
            job = JOBS.get(str(body.get("id")))
            if not job:
                return self._json(404, {"error": "unknown job"})
            with LOCK:
                job["cancel"] = True
                for f in job.get("_futs", []):
                    f.cancel()
            return self._json(200, {"ok": True})
        self._json(404, {"error": "not found"})


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="blackoct-gui", description="Local web GUI for blackoct-check.")
    p.add_argument("--port", type=int, default=8765, help="port on 127.0.0.1 (default 8765, 0 = random)")
    p.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    a = p.parse_args(argv)
    try:
        srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    except OSError:
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    srv.token = secrets.token_urlsafe(18)  # type: ignore[attr-defined]
    srv.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}  # type: ignore[attr-defined]
    url = f"http://127.0.0.1:{port}/?t={srv.token}"  # type: ignore[attr-defined]
    print(f"blackoct-gui {bc.__version__} running. Open: {url}")
    print("Press Ctrl+C to stop. Only scan systems you own or are authorised to test.")
    if not a.no_browser:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


# ---- the page ---------------------------------------------------------------
PAGE = r'''<!doctype html>
<html lang="en" data-theme="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Black October Checker</title>
<style>
:root{
  --bg:#f6f7f9; --surface:#ffffff; --surface2:#f0f2f5; --text:#14181f; --muted:#5b6575;
  --border:#d9dee6; --accent:#1f5eff; --accent-text:#ffffff; --focus:#1f5eff55;
  --crit:#b3001b; --crit-bg:#ffe3e7; --high:#c2410c; --high-bg:#ffeadb; --med:#92600a; --med-bg:#fff3d6;
  --low:#0b6b86; --low-bg:#dff4fa; --info:#3b4bb0; --info-bg:#e6e9ff; --ok:#13795b; --ok-bg:#dcf5ea;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --bg:#0e1116; --surface:#161b22; --surface2:#1d242d; --text:#e7ebf0; --muted:#98a3b3;
    --border:#2a323d; --accent:#5b8cff; --accent-text:#0b1020; --focus:#5b8cff66;
    --crit:#ff8a98; --crit-bg:#4a1620; --high:#ffa874; --high-bg:#4a2410; --med:#f2c35b; --med-bg:#43330a;
    --low:#6fd3ee; --low-bg:#0f3441; --info:#a5b0ff; --info-bg:#252b5a; --ok:#59d8aa; --ok-bg:#0f3a2c;
  }
}
:root[data-theme="dark"]{
  --bg:#0e1116; --surface:#161b22; --surface2:#1d242d; --text:#e7ebf0; --muted:#98a3b3;
  --border:#2a323d; --accent:#5b8cff; --accent-text:#0b1020; --focus:#5b8cff66;
  --crit:#ff8a98; --crit-bg:#4a1620; --high:#ffa874; --high-bg:#4a2410; --med:#f2c35b; --med-bg:#43330a;
  --low:#6fd3ee; --low-bg:#0f3441; --info:#a5b0ff; --info-bg:#252b5a; --ok:#59d8aa; --ok-bg:#0f3a2c;
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:0 16px 56px}
header{padding:22px 0 8px;display:flex;gap:12px;align-items:flex-start;justify-content:space-between;flex-wrap:wrap}
h1{font-size:22px;margin:0;letter-spacing:-.01em}
.sub{color:var(--muted);margin:2px 0 0;font-size:14px}
.pill{font:12px var(--mono);color:var(--muted);border:1px solid var(--border);border-radius:99px;padding:2px 10px}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--border);margin:14px 0 18px;overflow-x:auto}
.tab{background:none;border:0;color:var(--muted);padding:10px 14px;font:inherit;font-weight:600;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap}
.tab[aria-selected="true"]{color:var(--text);border-bottom-color:var(--accent)}
.tab:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible,summary:focus-visible{outline:3px solid var(--focus);outline-offset:1px}
.panel[hidden]{display:none}
.grid{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(0,.85fr);gap:16px}
@media (max-width:860px){.grid{grid-template-columns:1fr}}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px}
.card h2{font-size:15px;margin:0 0 4px}
.hint{color:var(--muted);font-size:13px;margin:0 0 10px}
label.f{display:block;font-weight:600;font-size:13px;margin:12px 0 4px}
textarea,input[type=text],input[type=number],input[type=password],select{
  width:100%;background:var(--surface2);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:9px 10px;font:inherit}
textarea{font-family:var(--mono);font-size:13px;min-height:110px;resize:vertical}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.checks{display:grid;gap:8px}
.chk-item{display:flex;gap:10px;align-items:flex-start;padding:9px 10px;border:1px solid var(--border);border-radius:8px;background:var(--surface2)}
.chk-item input{margin-top:4px}
.chk-item b{display:block;font-size:14px}
.chk-item span{color:var(--muted);font-size:12.5px}
.btn{background:var(--accent);color:var(--accent-text);border:0;border-radius:8px;padding:10px 16px;font:inherit;font-weight:700;cursor:pointer}
.btn.sec{background:var(--surface2);color:var(--text);border:1px solid var(--border);font-weight:600}
.btn:disabled{opacity:.5;cursor:not-allowed}
.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:14px}
.auth{display:flex;gap:10px;align-items:flex-start;margin-top:14px;padding:10px;border-radius:8px;background:var(--med-bg);color:var(--text);border:1px solid var(--border)}
.cmd{font:12.5px var(--mono);background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px;white-space:pre-wrap;word-break:break-all;margin:0}
.progress{height:8px;background:var(--surface2);border-radius:99px;overflow:hidden;margin-top:10px;border:1px solid var(--border)}
.progress>i{display:block;height:100%;width:0;background:var(--accent);transition:width .25s}
.status{font-size:13px;color:var(--muted);margin-top:8px;min-height:20px}
.runbar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:10px 14px;margin-bottom:16px}
.runbar[hidden]{display:none}
.err{color:var(--crit);font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:14px}
.tile{border:1px solid var(--border);border-radius:10px;padding:10px 12px;background:var(--surface)}
.tile b{display:block;font-size:24px;line-height:1.1}
.tile span{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.toolbar select{width:auto}
.badge{display:inline-block;min-width:76px;text-align:center;font:700 11.5px var(--mono);padding:3px 8px;border-radius:6px}
.s-CRITICAL{background:var(--crit-bg);color:var(--crit)}.s-HIGH{background:var(--high-bg);color:var(--high)}
.s-MEDIUM{background:var(--med-bg);color:var(--med)}.s-LOW{background:var(--low-bg);color:var(--low)}
.s-INFO{background:var(--info-bg);color:var(--info)}.s-OK{background:var(--ok-bg);color:var(--ok)}
.tcard{background:var(--surface);border:1px solid var(--border);border-radius:12px;margin-bottom:12px;overflow:hidden}
.thead{display:flex;justify-content:space-between;gap:10px;align-items:center;padding:12px 14px;border-bottom:1px solid var(--border);background:var(--surface2)}
.thead b{font-family:var(--mono);font-size:13.5px;word-break:break-all}
.find{border-bottom:1px solid var(--border)}
.find:last-child{border-bottom:0}
.find summary{list-style:none;cursor:pointer;display:flex;gap:10px;align-items:flex-start;padding:10px 14px}
.find summary::-webkit-details-marker{display:none}
.find .t{flex:1;min-width:0}
.find .tag{font:12px var(--mono);color:var(--muted)}
.find .body{padding:0 14px 12px 14px;margin-left:0;color:var(--text);font-size:14px}
.kv{font:12.5px var(--mono);color:var(--muted);margin:2px 0;word-break:break-all}
.empty{color:var(--muted);text-align:center;padding:36px 12px;border:1px dashed var(--border);border-radius:12px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;vertical-align:top;padding:9px 10px;border-bottom:1px solid var(--border)}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.scroll{overflow-x:auto}
td .kv{word-break:normal;overflow-wrap:break-word}
.steps{counter-reset:s;list-style:none;padding:0;margin:0;display:grid;gap:10px}
.steps li{counter-increment:s;display:flex;gap:12px;align-items:flex-start}
.steps li::before{content:counter(s);flex:0 0 26px;height:26px;border-radius:50%;background:var(--accent);color:var(--accent-text);font-weight:700;display:grid;place-items:center;font-size:13px}
.usage h2{font-size:17px;margin:26px 0 8px}
.usage h2:first-child{margin-top:0}
code,.mono{font-family:var(--mono);font-size:12.5px;background:var(--surface2);border:1px solid var(--border);border-radius:5px;padding:1px 5px}
pre.cmd{margin:8px 0}
.note{border-left:3px solid var(--accent);background:var(--surface2);padding:10px 12px;border-radius:0 8px 8px 0;margin:10px 0}
.warn{border-left-color:var(--high)}
.theme{background:none;border:1px solid var(--border);color:var(--muted);border-radius:8px;padding:6px 10px;cursor:pointer;font:inherit;font-size:13px}
</style>
</head>
<body>
<div class="wrap">
<header>
  <div>
    <h1>Black October Checker</h1>
    <p class="sub">Non-intrusive exposure checks for the October 2026 PHP, GitLab, Node.js, LiteLLM and eMudhra disclosures.</p>
  </div>
  <div style="display:flex;gap:8px;align-items:center">
    <span class="pill">v__VERSION__ - local only</span>
    <button class="theme" id="themeBtn" type="button" aria-label="Toggle colour theme">Theme</button>
  </div>
</header>

<div class="tabs" role="tablist">
  <button class="tab" role="tab" id="tab-scan" aria-selected="true" aria-controls="p-scan">Scan</button>
  <button class="tab" role="tab" id="tab-results" aria-selected="false" aria-controls="p-results">Results <span id="rcount" class="mono" hidden></span></button>
  <button class="tab" role="tab" id="tab-usage" aria-selected="false" aria-controls="p-usage">Usage guide</button>
</div>

<div class="runbar" id="runbar" hidden>
  <div style="flex:1;min-width:200px">
    <div class="status" id="status" role="status" aria-live="polite" style="margin:0"></div>
    <div class="progress" aria-hidden="true"><i id="bar"></i></div>
  </div>
  <button class="btn sec" id="cancel" type="button" disabled>Cancel scan</button>
</div>

<!-- SCAN -->
<section class="panel" id="p-scan" role="tabpanel" aria-labelledby="tab-scan">
  <div class="grid">
    <div class="card">
      <h2>1. Targets</h2>
      <p class="hint">One per line, or separated by commas or spaces. Domains, host:port or full URLs, including http:// targets, a path prefix such as http://10.0.0.5:8080/gitlab, or IPv6 like [::1]:8443. Up to 500.</p>
      <label class="f" for="targets">Targets</label>
      <textarea id="targets" spellcheck="false" placeholder="example.com&#10;git.example.com&#10;https://app.example.com:8443"></textarea>

      <h2 style="margin-top:18px">2. Checks</h2>
      <p class="hint">Leave them all on for a full sweep. Turn off what does not apply.</p>
      <div class="checks" id="checks"></div>

      <div class="auth">
        <input type="checkbox" id="auth" aria-describedby="authtxt">
        <label for="auth" id="authtxt"><b>I own these systems or have written authorisation to test them.</b><br>
        <span style="font-size:13px">The checks are passive and send normal requests only, but scanning systems you do not control may still be illegal.</span></label>
      </div>
      <div class="actions">
        <button class="btn" id="start" type="button">Start scan</button>
        <button class="btn sec" id="sample" type="button">Insert sample targets</button>
      </div>
    </div>

    <div style="display:grid;gap:16px;align-content:start">
      <div class="card">
        <h2>Options</h2>
        <div class="row">
          <div><label class="f" for="timeout">Timeout (s)</label><input type="number" id="timeout" value="8" min="1" max="60"></div>
          <div><label class="f" for="conc">Parallel targets</label><input type="number" id="conc" value="10" min="1" max="50"></div>
        </div>
        <label class="f" for="proxy">HTTP proxy (optional)</label>
        <input type="text" id="proxy" placeholder="http://127.0.0.1:8080  (for example ZAP)" spellcheck="false">
        <label class="f" for="gltoken">GitLab token (optional)</label>
        <input type="password" id="gltoken" placeholder="Lets the GitLab check read the exact version" autocomplete="off">
        <label class="f" for="headers">Extra headers (optional, one per line)</label>
        <textarea id="headers" style="min-height:64px" placeholder="X-Bug-Bounty: yourhandle" spellcheck="false"></textarea>
        <label style="display:flex;gap:8px;margin-top:12px;align-items:center"><input type="checkbox" id="verify"> Verify TLS certificates (off by default so self-signed hosts still scan)</label>
      </div>
      <div class="card">
        <h2>Equivalent command line</h2>
        <p class="hint">Updates as you change the form. Run it on any machine with the script.</p>
        <pre class="cmd" id="cmd"></pre>
        <div class="actions"><button class="btn sec" id="copycmd" type="button">Copy command</button></div>
      </div>
    </div>
  </div>
</section>

<!-- RESULTS -->
<section class="panel" id="p-results" role="tabpanel" aria-labelledby="tab-results" hidden>
  <div class="tiles" id="tiles"></div>
  <div class="toolbar">
    <label>Show at least <select id="minsev">
      <option value="0">Everything</option><option value="1" selected>Info and above</option>
      <option value="2">Low and above</option><option value="3">Medium and above</option>
      <option value="4">High and above</option><option value="5">Critical only</option></select></label>
    <label style="display:flex;gap:6px;align-items:center"><input type="checkbox" id="showok"> Show OK results</label>
    <span style="flex:1"></span>
    <button class="btn sec" id="xjson" type="button">Export JSON</button>
    <button class="btn sec" id="xcsv" type="button">Export CSV</button>
  </div>
  <div id="results"></div>
  <p class="hint" style="margin-top:16px">Banner and version findings are indicators, not proof. Confirm on the host before raising an incident. See the Usage guide for how to read each severity.</p>
</section>

<!-- USAGE -->
<section class="panel usage" id="p-usage" role="tabpanel" aria-labelledby="tab-usage" hidden>
  <div class="card">
    <h2>Quick start</h2>
    <ol class="steps">
      <li><div><b>Add targets</b> on the Scan tab. Public domains, internal hostnames and URLs all work.</div></li>
      <li><div><b>Tick the authorisation box</b> and press <b>Start scan</b>. Progress shows in the bar above the tabs, and you can cancel from there.</div></li>
      <li><div><b>Open Results.</b> Start with CRITICAL and HIGH. Expand a finding to see the evidence and the fix.</div></li>
      <li><div><b>Verify on the host</b>, patch, then rescan to confirm the finding is gone.</div></li>
    </ol>

    <h2>What each check does</h2>
    <div class="scroll"><table>
      <thead><tr><th>Check</th><th>Looks for</th><th>Limits you should know</th></tr></thead>
      <tbody id="checktable"></tbody>
    </table></div>
    <div class="note warn"><b>Not detectable from outside:</b> the California schools, Ahold Delhaize and Onamae incidents, and anything inside Railway or Zeabur. Those are provider or data breaches. The Hosting check only tells you if you are on an affected provider, so you know to rotate secrets.</div>

    <h2>Reading the severities</h2>
    <div class="scroll"><table>
      <tbody>
        <tr><td><span class="badge s-CRITICAL">CRITICAL</span></td><td>Confirmed vulnerable or compromised version (GitLab below the fixed release, LiteLLM 1.107.0). Act now.</td></tr>
        <tr><td><span class="badge s-HIGH">HIGH</span></td><td>Version below the fixed release or end of life (PHP, Node.js), or a distrusted CA root. Patch soon, then confirm the real package version.</td></tr>
        <tr><td><span class="badge s-MEDIUM">MEDIUM</span></td><td>Software is present but the version could not be read (GitLab), or an eMudhra chain needs review.</td></tr>
        <tr><td><span class="badge s-INFO">INFO</span></td><td>Worth knowing: version hidden, provider fingerprint, unreachable target, or a check that could not run.</td></tr>
        <tr><td><span class="badge s-OK">OK</span></td><td>Checked and nothing found. Hidden by default, tick "Show OK results" to see it.</td></tr>
      </tbody>
    </table></div>

    <h2>Why a banner can be wrong</h2>
    <p>Linux distributions often backport security fixes without changing the version number, so PHP 8.3.6 on a patched Ubuntu can still be safe. The reverse also happens: a hidden banner does not mean you are patched. Treat banner findings as a prompt to check the package version on the server, for example <code>apt list --installed php*</code> or <code>rpm -q php</code>, and restart PHP workers after patching.</p>

    <h2>Routing through ZAP or Burp</h2>
    <p>Put your proxy address in Options, for example <code>http://127.0.0.1:8080</code>. Requests then appear in ZAP's history, and the passive PHP2Shell script you added earlier will see the same responses. Note that the TLS certificate check connects directly and does not go through the proxy.</p>

    <h2>Command line</h2>
    <p>Everything here is also available without the GUI:</p>
<pre class="cmd">python3 blackoct_check.py example.com
python3 blackoct_check.py -l domains.txt -c 20 -f json -o report.json
python3 blackoct_check.py --checks php,gitlab https://git.example.com
python3 blackoct_check.py git.example.com --gitlab-token $GITLAB_TOKEN</pre>
    <p>Exit code 0 means clean, 2 means a finding at or above <code>--fail-on</code> (default high), 1 means a usage error. That makes it suitable for CI jobs.</p>

    <h2>Safety and scope</h2>
    <ul>
      <li>The checks send ordinary GET requests and one TLS handshake per host. They never send exploit payloads.</li>
      <li>This page is served from your own machine on 127.0.0.1 and needs the random token in the URL. Nothing is uploaded anywhere.</li>
      <li>The GitLab token stays in your browser and the local server and is never written to disk by this tool.</li>
      <li>Only scan assets you own or have written permission to test.</li>
    </ul>

    <h2>Troubleshooting</h2>
    <div class="scroll"><table>
      <tbody>
        <tr><td><b>Target unreachable over HTTP(S)</b></td><td>The finding lists every URL that was tried and the error for each. Plain HTTP targets work: with no scheme it tries HTTPS then HTTP (or HTTP first on ports like 8080). Give the scheme and port explicitly, for example <code>http://host:8080</code>, raise the timeout, or check the proxy. A redirect to a name that does not resolve no longer counts as unreachable.</td></tr>
        <tr><td><b>PHP detected but version is hidden</b></td><td><code>expose_php=Off</code> or a proxy strips headers. Check the version on the host instead.</td></tr>
        <tr><td><b>GitLab detected, version not exposed</b></td><td>Add a GitLab token in Options, or check the Admin Area. Treat as exposed until the version is confirmed.</td></tr>
        <tr><td><b>Could not retrieve the TLS chain</b></td><td>Older Python builds only return the leaf certificate. Use Python 3.10 or newer for the full chain.</td></tr>
        <tr><td><b>Browser shows "forbidden"</b></td><td>Open the full URL printed in the terminal, including <code>?t=...</code>. The token changes every run.</td></tr>
      </tbody>
    </table></div>
  </div>
</section>
</div>

<script>
const TOKEN = new URLSearchParams(location.search).get('t') || '';
const $ = s => document.querySelector(s);
const SEVS = ['CRITICAL','HIGH','MEDIUM','LOW','INFO','OK'];
const RANK = {CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,INFO:1,OK:0};
const CHECKS = [
  {id:'php', name:'PHP2Shell', ref:'CVE-2026-109618 / 109619',
   desc:'Reads the PHP version from response headers and compares it with the fixed releases 8.2.35, 8.3.36, 8.4.27 and 8.5.12. PHP 8.1 and older are flagged as end of life.',
   limit:'Banner only. Hidden headers give no result and distro backports keep the old version string. Does not send an exploit probe.'},
  {id:'node', name:'Node.js', ref:'Oct 2026 releases, e.g. CVE-2026-111497',
   desc:'Looks for a Node.js version in headers and compares it with 22.23.4, 24.22.1 and 26.12.1.',
   limit:'Node rarely exposes its version, so this usually reports "Node-based stack, verify on host".'},
  {id:'gitlab', name:'GitLab', ref:'CVE-2026-110264 (CVSS 10.0)',
   desc:'Detects a GitLab sign-in page, then reads the version from /help or the API (with a token) and checks it against 19.5.1, 19.4.3, 19.3.6, 19.2.9, 19.1.9, 19.0.10 and 18.11.13.',
   limit:'Anonymous version exposure is uncommon. Instances patched on 12 Oct (19.4.2, 19.3.5, 19.2.8) are still vulnerable.'},
  {id:'litellm', name:'LiteLLM', ref:'Malicious 1.107.0 release',
   desc:'Checks public LiteLLM proxy endpoints for version 1.107.0, the compromised release published on 21 Oct.',
   limit:'Only finds internet-exposed proxies. Check pip and Docker image tags on build hosts and CI separately.'},
  {id:'emudhra', name:'eMudhra TLS', ref:'8 compromised intermediate CAs',
   desc:'Fetches the TLS chain and flags certificates issued under eMudhra or emSign. A chain ending at emSign ECC Root CA - G3 is rated High.',
   limit:'Cannot tell which of the eight intermediates signed your leaf. Python 3.10 or newer returns the full chain.'},
  {id:'hosting', name:'Hosting', ref:'Railway and Zeabur incidents',
   desc:'Fingerprints Railway and Zeabur from DNS and headers so you know to rotate secrets held there.',
   limit:'Informational. It cannot see whether your data was exposed.'}
];

function el(tag, attrs, ...kids){
  const e = document.createElement(tag);
  for (const [k,v] of Object.entries(attrs||{})){
    if (k === 'class') e.className = v; else if (k === 'text') e.textContent = v; else e.setAttribute(k, v);
  }
  for (const k of kids) if (k != null) e.append(k.nodeType ? k : document.createTextNode(k));
  return e;
}

/* ---- tabs ---- */
function showTab(name){
  for (const t of ['scan','results','usage']){
    $('#tab-'+t).setAttribute('aria-selected', t===name);
    $('#p-'+t).hidden = t!==name;
  }
}
for (const t of ['scan','results','usage']) $('#tab-'+t).addEventListener('click', () => showTab(t));

/* ---- theme ---- */
$('#themeBtn').addEventListener('click', () => {
  const r = document.documentElement, cur = r.getAttribute('data-theme');
  const dark = cur === 'dark' || (cur === 'auto' && matchMedia('(prefers-color-scheme: dark)').matches);
  r.setAttribute('data-theme', dark ? 'light' : 'dark');
});

/* ---- build checks + usage table ---- */
for (const c of CHECKS){
  const cb = el('input', {type:'checkbox', class:'chk', value:c.id, id:'c-'+c.id, checked:''});
  $('#checks').append(el('label', {class:'chk-item', for:'c-'+c.id}, cb,
    el('div', {}, el('b', {text:c.name}), el('span', {text:c.ref}))));
  $('#checktable').append(el('tr', {},
    el('td', {}, el('b', {text:c.name}), el('div', {class:'kv', text:c.ref})),
    el('td', {text:c.desc}), el('td', {text:c.limit})));
}

/* ---- command preview ---- */
const q = s => /^[A-Za-z0-9_@%+=:,.\/-]+$/.test(s) ? s : "'" + s.replace(/'/g, "'\\''") + "'";
function opts(){
  return {
    targets: $('#targets').value,
    checks: [...document.querySelectorAll('.chk:checked')].map(x => x.value),
    timeout: +$('#timeout').value || 8, concurrency: +$('#conc').value || 10,
    proxy: $('#proxy').value.trim(), gitlab_token: $('#gltoken').value.trim(),
    verify_tls: $('#verify').checked, headers: $('#headers').value, authorised: $('#auth').checked
  };
}
function buildCmd(){
  const o = opts(), ts = o.targets.split(/[\s,]+/).filter(Boolean);
  const p = ['python3', 'blackoct_check.py'];
  if (ts.length > 3) p.push('-l', 'targets.txt'); else if (ts.length) p.push(...ts.map(q)); else p.push('<target>');
  if (o.checks.length && o.checks.length < CHECKS.length) p.push('--checks', o.checks.join(','));
  if (o.timeout !== 8) p.push('-t', String(o.timeout));
  if (o.concurrency !== 10) p.push('-c', String(o.concurrency));
  if (o.proxy) p.push('--proxy', q(o.proxy));
  if (o.gitlab_token) p.push('--gitlab-token', '$GITLAB_TOKEN');
  if (o.verify_tls) p.push('--verify-tls');
  for (const h of o.headers.split('\n').map(x => x.trim()).filter(x => x.includes(':'))) p.push('-H', q(h));
  p.push('-f', 'json', '-o', 'report.json');
  return p.join(' ');
}
function refreshCmd(){ $('#cmd').textContent = buildCmd(); }
document.querySelectorAll('#p-scan input, #p-scan textarea').forEach(x => x.addEventListener('input', refreshCmd));
refreshCmd();
$('#copycmd').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('#cmd').textContent); $('#copycmd').textContent = 'Copied'; }
  catch (e) { $('#copycmd').textContent = 'Select and copy manually'; }
  setTimeout(() => $('#copycmd').textContent = 'Copy command', 1600);
});
$('#sample').addEventListener('click', () => {
  $('#targets').value = 'example.com\nexample.org';
  refreshCmd();
});

/* ---- API ---- */
async function api(path, body){
  const r = await fetch(path, {
    method: body ? 'POST' : 'GET',
    headers: Object.assign({'X-Token': TOKEN}, body ? {'Content-Type':'application/json'} : {}),
    body: body ? JSON.stringify(body) : undefined
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
  return j;
}

/* ---- scan flow ---- */
let jobId = null, timer = null, last = null;
function setStatus(msg, bad){ $('#runbar').hidden = false; const s = $('#status'); s.textContent = msg; s.className = 'status' + (bad ? ' err' : ''); }
$('#start').addEventListener('click', async () => {
  const o = opts();
  if (!o.targets.trim()) return setStatus('Enter at least one target.', true);
  if (!o.checks.length) return setStatus('Select at least one check.', true);
  if (!o.authorised) return setStatus('Tick the authorisation box first.', true);
  try {
    const r = await api('/api/scan', o);
    jobId = r.id; $('#start').disabled = true; $('#cancel').disabled = false;
    $('#bar').style.width = '0'; setStatus('Starting...');
    showTab('results'); poll();
  } catch (e) { setStatus(e.message, true); }
});
$('#cancel').addEventListener('click', async () => {
  if (!jobId) return;
  try { await api('/api/cancel', {id: jobId}); setStatus('Cancelling, waiting for running requests to finish...'); } catch (e) { setStatus(e.message, true); }
});
async function poll(){
  clearTimeout(timer);
  try {
    const d = await api('/api/status?id=' + encodeURIComponent(jobId));
    last = d; render(d);
    const pct = d.total ? Math.round(100 * d.done / d.total) : 0;
    $('#bar').style.width = pct + '%';
    if (d.state === 'running') {
      setStatus('Scanning ' + d.done + ' of ' + d.total + ' (' + d.elapsed + 's)');
      timer = setTimeout(poll, 700);
    } else {
      $('#start').disabled = false; $('#cancel').disabled = true;
      setStatus((d.state === 'cancelled' ? 'Cancelled after ' : 'Finished ' + d.total + ' target(s) in ') + d.elapsed + 's.');
    }
  } catch (e) {
    $('#start').disabled = false; $('#cancel').disabled = true; setStatus(e.message, true);
  }
}

/* ---- results ---- */
['minsev','showok'].forEach(id => $('#'+id).addEventListener('change', () => last && render(last)));
function render(d){
  const all = Object.values(d.results).flat();
  const cnt = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
  for (const f of all) if (f.severity in cnt) cnt[f.severity]++;
  const tiles = $('#tiles'); tiles.replaceChildren();
  tiles.append(el('div', {class:'tile'}, el('b', {text: d.done + '/' + d.total}), el('span', {text:'targets scanned'})));
  for (const s of ['CRITICAL','HIGH','MEDIUM','LOW','INFO']){
    const t = el('div', {class:'tile'}, el('b', {text:String(cnt[s]), class:'s-'+s, style:'background:none'}), el('span', {text:s.toLowerCase()}));
    tiles.append(t);
  }
  const issues = cnt.CRITICAL + cnt.HIGH + cnt.MEDIUM;
  const rc = $('#rcount'); rc.hidden = !issues; rc.textContent = issues;

  const min = +$('#minsev').value, showOk = $('#showok').checked;
  const box = $('#results'); box.replaceChildren();
  let shown = 0;
  for (const t of d.order){
    const fs = d.results[t];
    if (!fs) continue;
    const vis = fs.filter(f => f.severity === 'OK' ? showOk : RANK[f.severity] >= min)
                  .sort((a,b) => RANK[b.severity] - RANK[a.severity]);
    if (!vis.length) continue;
    shown++;
    const worst = fs.reduce((m,f) => RANK[f.severity] > RANK[m] ? f.severity : m, 'OK');
    const card = el('div', {class:'tcard'},
      el('div', {class:'thead'}, el('b', {text:t}), el('span', {class:'badge s-'+worst, text:worst})));
    for (const f of vis){
      const det = el('details', {class:'find'});
      if (RANK[f.severity] >= 4) det.setAttribute('open', '');
      det.append(el('summary', {},
        el('span', {class:'badge s-'+f.severity, text:f.severity}),
        el('div', {class:'t'}, el('div', {text:f.title}), el('div', {class:'tag', text:f.check + (f.cve ? '  |  ' + f.cve : '')}))));
      const body = el('div', {class:'body'});
      if (f.detail) body.append(el('p', {text:f.detail, style:'margin:0 0 8px'}));
      if (f.evidence) body.append(el('div', {class:'kv', text:'evidence: ' + f.evidence}));
      body.append(el('div', {class:'kv', text:'confidence: ' + f.confidence}));
      det.append(body); card.append(det);
    }
    box.append(card);
  }
  if (!shown){
    box.append(el('div', {class:'empty', text: d.done < d.total
      ? 'Waiting for the first results...'
      : (!d.total ? 'No scan yet. Add targets on the Scan tab and press Start scan.'
        : (all.length ? 'Nothing at this filter level. Lower the filter or tick "Show OK results" to see what was checked.' : 'No results.'))}));
  }
}

/* ---- export ---- */
function download(name, mime, text){
  const a = el('a', {href: URL.createObjectURL(new Blob([text], {type:mime})), download:name});
  document.body.append(a); a.click(); a.remove();
}
$('#xjson').addEventListener('click', () => last && download('blackoct-report.json', 'application/json', JSON.stringify(last.results, null, 2)));
$('#xcsv').addEventListener('click', () => {
  if (!last) return;
  const esc = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
  const rows = [['target','check','severity','confidence','title','evidence','cve','detail']];
  for (const fs of Object.values(last.results)) for (const f of fs)
    rows.push([f.target,f.check,f.severity,f.confidence,f.title,f.evidence,f.cve,f.detail]);
  download('blackoct-report.csv', 'text/csv', rows.map(r => r.map(esc).join(',')).join('\n'));
});
render({done:0,total:0,order:[],results:{}});
</script>
</body>
</html>
'''

if __name__ == "__main__":
    sys.exit(main())

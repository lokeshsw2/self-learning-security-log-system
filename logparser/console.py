"""Local console and API: send raw lines through the compiled Logstash pipelines into ClickHouse.

  python -m logparser.console --port 8090 --logstash http://localhost:8088 --clickhouse http://localhost:8123

API
  POST /api/parse              body: raw lines (one per line)          -> forwarded to the Logstash distributor
  POST /api/reparse-unparsed   re-sends every line in logs.unparsed    -> rows re-sent are removed first;
                                                                          lines still unparsed come back
  GET  /api/stats              counts in ClickHouse (events by source and class, unparsed by reason)
  GET  /                       page with the same actions as buttons

Logstash does the parsing and OCSF mapping; this service only moves lines and reads counts.
"""
from __future__ import annotations

import argparse
import json
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CHUNK = 5000


class Backends:
    def __init__(self, logstash: str, clickhouse: str):
        self.logstash = logstash.rstrip("/")
        self.ch = clickhouse.rstrip("/")

    def ch_query(self, sql: str, body: bytes | None = None) -> str:
        url = f"{self.ch}/?" + urllib.parse.urlencode({"query": sql})
        with urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=60) as r:
            return r.read().decode()

    def ch_json(self, sql: str) -> list:
        out = self.ch_query(sql + " FORMAT JSONEachRow")
        return [json.loads(x) for x in out.splitlines() if x.strip()]

    def send(self, lines: list) -> int:
        """POST lines to the Logstash http input in chunks; returns lines sent."""
        sent = 0
        lines = [ln.rstrip("\r\n") for ln in lines if ln.strip()]
        for i in range(0, len(lines), CHUNK):
            part = lines[i:i + CHUNK]
            req = urllib.request.Request(self.logstash, data=("\n".join(part) + "\n").encode("utf-8"),
                                         headers={"Content-Type": "text/plain"})
            with urllib.request.urlopen(req, timeout=120) as r:
                r.read()
            sent += len(part)
        return sent

    def reparse_unparsed(self, limit: int = 1_000_000) -> dict:
        cutoff = self.ch_json("SELECT toString(max(received_at)) m, count() n FROM logs.unparsed")[0]
        if not int(cutoff["n"]):
            return {"resent": 0}
        rows = self.ch_json(f"SELECT message FROM logs.unparsed WHERE received_at <= '{cutoff['m']}' "
                            f"ORDER BY received_at LIMIT {int(limit)}")
        self.ch_query(f"DELETE FROM logs.unparsed WHERE received_at <= '{cutoff['m']}'")
        return {"resent": self.send([r["message"] for r in rows])}

    def stats(self) -> dict:
        return {
            "events": int(self.ch_json("SELECT count() n FROM logs.ocsf_events")[0]["n"]),
            "unparsed": int(self.ch_json("SELECT count() n FROM logs.unparsed")[0]["n"]),
            "by_source": self.ch_json("SELECT lp_source source, vendor_name vendor, product_name product, count() n "
                                      "FROM logs.ocsf_events GROUP BY 1,2,3 ORDER BY n DESC LIMIT 100"),
            "by_class": self.ch_json("SELECT class_uid, count() n FROM logs.ocsf_events GROUP BY 1 ORDER BY n DESC"),
            "unparsed_by_reason": self.ch_json("SELECT reason, count() n, any(substring(message,1,200)) example "
                                               "FROM logs.unparsed GROUP BY 1 ORDER BY n DESC LIMIT 50"),
        }


PAGE = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Log Pipeline Console</title>
<style>
:root{--bg:#f7f7f5;--fg:#1d1d1b;--mut:#6b6b66;--card:#fff;--line:#e3e3de;--acc:#2f5bd3}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecece8;--mut:#9a9a93;--card:#1f1f1d;--line:#33332f;--acc:#7c9cff}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif}
main{max-width:980px;margin:0 auto;padding:20px 16px}
h1{font-size:20px;margin:0 0 4px} p.m{color:var(--mut);margin:0 0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin:0 0 14px}
textarea{width:100%;box-sizing:border-box;min-height:120px;font:12px ui-monospace,monospace;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:8px}
button{background:var(--acc);color:#fff;border:0;border-radius:6px;padding:8px 14px;font-weight:600;cursor:pointer;margin:8px 8px 0 0}
button.s{background:transparent;color:var(--acc);border:1px solid var(--acc)}
.k{display:flex;gap:12px;flex-wrap:wrap}.k div{flex:1;min-width:140px}.k b{display:block;font-size:24px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:4px 6px;border-bottom:1px solid var(--line)}
td.n{text-align:right;font-variant-numeric:tabular-nums}#msg{color:var(--mut);margin-top:8px;min-height:1.2em}
.ex{font:11px ui-monospace,monospace;color:var(--mut);word-break:break-all}
</style></head><body><main>
<h1>Log Pipeline Console</h1>
<p class="m">Raw lines go through the Logstash pipelines compiled from the learned rules (one per format), are mapped to OCSF, and land in ClickHouse.</p>
<div class="card k"><div>Events in ClickHouse<b id="ev">–</b></div><div>Unparsed lines<b id="un">–</b></div></div>
<div class="card"><b>Parse lines</b>
<textarea id="lines" placeholder="Paste raw log lines, one per line"></textarea>
<input type="file" id="file"><br>
<button onclick="parse()">Parse via Logstash</button>
<button class="s" onclick="reparse()">Re-parse all unparsed lines</button>
<button class="s" onclick="load()">Refresh</button>
<div id="msg"></div></div>
<div class="card"><b>Events by source</b><table id="src"></table></div>
<div class="card"><b>Unparsed by reason</b><table id="ur"></table></div>
<script>
const $=id=>document.getElementById(id), esc=s=>String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
async function load(){const r=await fetch('/api/stats');const s=await r.json();
$('ev').textContent=s.events.toLocaleString();$('un').textContent=s.unparsed.toLocaleString();
$('src').innerHTML='<tr><th>Source</th><th>Vendor / product</th><th class="n">Events</th></tr>'+s.by_source.map(x=>`<tr><td>${esc(x.source)}</td><td>${esc(x.vendor)} ${esc(x.product)}</td><td class="n">${(+x.n).toLocaleString()}</td></tr>`).join('');
$('ur').innerHTML='<tr><th>Reason</th><th class="n">Lines</th><th>Example</th></tr>'+s.unparsed_by_reason.map(x=>`<tr><td>${esc(x.reason)}</td><td class="n">${(+x.n).toLocaleString()}</td><td class="ex">${esc(x.example)}</td></tr>`).join('');}
async function parse(){let body=$('lines').value;const f=$('file').files[0];if(f)body+='\\n'+await f.text();
if(!body.trim()){$('msg').textContent='Nothing to send.';return}
$('msg').textContent='Sending…';const r=await fetch('/api/parse',{method:'POST',body});const j=await r.json();
$('msg').textContent=j.error?('Error: '+j.error):`Sent ${j.sent.toLocaleString()} lines. Counts update as Logstash flushes (a few seconds).`;setTimeout(load,4000)}
async function reparse(){$('msg').textContent='Re-sending unparsed lines…';const r=await fetch('/api/reparse-unparsed',{method:'POST'});const j=await r.json();
$('msg').textContent=j.error?('Error: '+j.error):`Re-sent ${j.resent.toLocaleString()} lines.`;setTimeout(load,4000)}
load();
</script></main></body></html>"""


def make_handler(be: Backends):
    class H(BaseHTTPRequestHandler):
        def _json(self, code: int, obj) -> None:
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/":
                data = PAGE.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            elif self.path == "/api/stats":
                try:
                    self._json(200, be.stats())
                except Exception as exc:
                    self._json(502, {"error": str(exc)})
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self):
            try:
                if self.path == "/api/parse":
                    n = int(self.headers.get("Content-Length") or 0)
                    body = self.rfile.read(n).decode("utf-8", "replace")
                    self._json(200, {"sent": be.send(body.split("\n"))})
                elif self.path == "/api/reparse-unparsed":
                    self._json(200, be.reparse_unparsed())
                else:
                    self._json(404, {"error": "not found"})
            except Exception as exc:
                self._json(502, {"error": str(exc)})

        def log_message(self, *a):
            pass
    return H


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--logstash", default="http://localhost:8088")
    ap.add_argument("--clickhouse", default="http://localhost:8123")
    a = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(Backends(a.logstash, a.clickhouse)))
    print(f"console on http://127.0.0.1:{a.port}  (Logstash {a.logstash}, ClickHouse {a.clickhouse})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()

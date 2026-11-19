#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
好甜的蜜罐 — catch dashboard

A tiny read-only web page over the evidence directory. Its centrepiece is
"Configs attackers tried to apply": every config_write / stream_write alert
with the exact payload that was sent, plus the streams they planted.

    python3 dashboard.py                       # http://127.0.0.1:8080
    python3 dashboard.py --port 9000 --refresh 10
    docker run --rm -p 127.0.0.1:8080:8080 \
        -v haotian-miguan_honeypot_data:/data \
        ghcr.io/jsserve-org/haotian-miguan:latest \
        python3 dashboard.py --data-dir /data --host 0.0.0.0 --port 8080

SAFETY: everything shown here is attacker-controlled text and is HTML-escaped
before rendering; the page carries a strict CSP and no JavaScript. Binds to
127.0.0.1 by default — if you expose it, put auth in front.
"""

import argparse
import html
import json
import os
import sys
import time
import urllib.parse
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ARGS = None


def read_jsonl(path, limit=400, window=4 * 1024 * 1024):
    """Last `limit` parseable JSON records of a (possibly large) JSONL file."""
    if not os.path.exists(path):
        return []
    with open(path, "rb") as f:
        try:
            f.seek(-window, os.SEEK_END)
        except OSError:
            f.seek(0)
        data = f.read().decode("utf-8", "replace")
    out = []
    for line in data.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out[-limit:]


def load_state(data_dir):
    path = os.path.join(data_dir, "state.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def payload_text(rec):
    """What the attacker sent: body, else the decoded query (stream writes)."""
    body = rec.get("body") or ""
    if not body and rec.get("query"):
        body = urllib.parse.unquote_plus(rec["query"])
    return body.strip()


def e(text):
    return html.escape(str(text if text is not None else ""), quote=True)


def human_age(ts):
    try:
        t = time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
        # ts is UTC; mktime assumes local — compensate
        t -= time.timezone if not time.localtime().tm_isdst else time.altzone
    except Exception:
        return ""
    delta = max(0, int(time.time() - t))
    for unit, sec in (("d", 86400), ("h", 3600), ("m", 60)):
        if delta >= sec:
            return "%d%s ago" % (delta // sec, unit)
    return "%ds ago" % delta


def collect(data_dir):
    alerts = read_jsonl(os.path.join(data_dir, "alerts.jsonl"), limit=500)
    access = read_jsonl(os.path.join(data_dir, "access.jsonl"), limit=500)
    state = load_state(data_dir)

    config_applies = [r for r in alerts
                      if any(t in ("config_write", "stream_write")
                             for t in r.get("tags", []))]
    config_applies.sort(key=lambda r: r.get("ts", ""), reverse=True)

    tags = Counter(t for r in alerts for t in r.get("tags", []))
    sev = Counter(r.get("severity", "low") for r in alerts)
    ips = Counter(r.get("ip", "?") for r in alerts)
    planted = state.get("meta", {}) or {}
    sources = {n: s for n, s in (state.get("config_streams") or [])}

    return {
        "alerts": alerts,
        "access": access,
        "config_applies": config_applies,
        "tags": tags,
        "sev": sev,
        "ips": ips,
        "planted": planted,
        "sources": sources,
        "last": (alerts[-1].get("ts") if alerts else None),
    }


CSS = """
:root{--bg:#0f1013;--card:#17181d;--line:#26272e;--fg:#e6e7ea;--dim:#8b8f98;
--hi:#f87171;--mid:#fbbf24;--lo:#8b8f98;--acc:#f0abfc}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{padding:18px 22px;border-bottom:1px solid var(--line);display:flex;
flex-wrap:wrap;gap:14px;align-items:baseline}
h1{font-size:19px;margin:0}
h2{font-size:15px;margin:26px 22px 10px;color:var(--acc)}
main{max-width:1180px;margin:0 auto;padding-bottom:40px}
.chip{background:var(--card);border:1px solid var(--line);border-radius:99px;
padding:3px 11px;font-size:12px;color:var(--dim)}
.chip b{color:var(--fg)}
a{color:var(--acc)}
.cards{display:grid;gap:12px;margin:0 22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.card .top{display:flex;flex-wrap:wrap;gap:10px;align-items:baseline;
justify-content:space-between;margin-bottom:8px}
.ip{font-weight:600}
.sev{font-size:11px;letter-spacing:.06em;border-radius:6px;padding:2px 7px}
.sev.high{background:rgba(248,113,113,.15);color:var(--hi)}
.sev.medium{background:rgba(251,191,36,.15);color:var(--mid)}
.sev.low{background:rgba(139,143,152,.15);color:var(--lo)}
.tag{font-size:11px;color:var(--dim);border:1px solid var(--line);
border-radius:6px;padding:1px 6px;margin-right:4px}
pre{background:#0b0c0f;border:1px solid var(--line);border-radius:8px;
padding:10px;overflow:auto;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;
max-height:340px;white-space:pre-wrap;word-break:break-word}
table{width:100%;border-collapse:collapse;margin:0 22px;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:500}
td.mono,pre,code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.muted{color:var(--dim)}
.note{margin:0 22px;color:var(--dim);font-size:12px}
.time{color:var(--dim);font-size:12px;white-space:nowrap}
.empty{color:var(--dim);margin:0 22px}
"""


def render(data_dir, refresh):
    d = collect(data_dir)
    sev = d["sev"]
    out = []
    w = out.append
    w("<!doctype html><html lang=en><head><meta charset=utf-8>")
    if refresh:
        w('<meta http-equiv="refresh" content="%d">' % refresh)
    w("<title>🍯 好甜的蜜罐 — catch dashboard</title>")
    w("<style>%s</style></head><body>" % CSS)
    w('<header><h1>🍯 好甜的蜜罐 · catch dashboard</h1>')
    w('<span class=chip>alerts <b>%d</b></span>' % len(d["alerts"]))
    w('<span class=chip>high <b>%d</b></span>' % sev.get("high", 0))
    w('<span class=chip>medium <b>%d</b></span>' % sev.get("medium", 0))
    w('<span class=chip>unique IPs <b>%d</b></span>' % len(d["ips"]))
    w('<span class=chip>planted streams <b>%d</b></span>' % len(d["planted"]))
    if d["last"]:
        w('<span class=chip>last activity <b>%s</b></span>' % e(human_age(d["last"])))
    w('<span class=chip><a href="?refresh=0">pause</a> / '
      '<a href="?refresh=%d">refresh %ds</a> / '
      '<a href="data.json">JSON</a></span>' % (refresh or 5, refresh or 5))
    w("</header><main>")

    w("<h2>Configs attackers tried to apply</h2>")
    if not d["config_applies"]:
        w('<p class=empty>Nothing yet — the pot is set. 🪰</p>')
    w('<div class=cards>')
    for r in d["config_applies"][:60]:
        sev_name = r.get("severity", "low")
        w('<div class=card><div class=top><span class=ip>%s</span>'
          '<span><span class="sev %s">%s</span> %s</span></div>'
          % (e(r.get("ip")), sev_name, e(sev_name.upper()),
             "".join('<span class=tag>%s</span>' % e(t) for t in r.get("tags", []))))
        w('<div class=time>%s · %s %s%s</div>'
          % (e(r.get("ts", "")), e(r.get("method", "")), e(r.get("path", "")),
             " · via %s" % e(r["peer"]) if r.get("peer") else ""))
        pl = payload_text(r)
        if pl:
            w("<pre>%s</pre>" % e(pl[:6000]))
        if r.get("note"):
            w('<div class=muted style="margin-top:6px">%s</div>' % e(r["note"]))
        if r.get("body_file"):
            w('<div class=muted style="margin-top:6px">evidence: '
              '<a href="drop?name=%s">%s</a></div>'
              % (urllib.parse.quote(r["body_file"]), e(r["body_file"])))
        w("</div>")
    w("</div>")

    w("<h2>Streams they planted</h2>")
    if not d["planted"]:
        w('<p class=empty>None yet.</p>')
    else:
        w("<table><tr><th>name</th><th>added by</th><th>when</th><th>via</th>"
          "<th>source</th></tr>")
        for name, meta in d["planted"].items():
            src = ", ".join(d["sources"].get(name, []))
            w("<tr><td class=mono>%s</td><td class=mono>%s</td><td class=time>%s</td>"
              "<td>%s</td><td class=mono>%s</td></tr>"
              % (e(name), e(meta.get("ip", "?")), e(meta.get("ts", "")),
                 e(meta.get("via", "")), e(src)))
        w("</table>")

    w("<h2>All alerts</h2>")
    w("<table><tr><th>when</th><th>sev</th><th>ip</th><th>tags</th>"
      "<th>request</th><th>payload</th></tr>")
    for r in reversed(d["alerts"][-120:]):
        pl = payload_text(r) or r.get("rtsp_uri") or ""
        w("<tr><td class=time>%s</td><td>%s</td><td class=mono>%s</td><td>%s</td>"
          "<td>%s %s</td><td class=mono>%s</td></tr>"
          % (e(r.get("ts", "")[11:19]), e(r.get("severity", "")), e(r.get("ip")),
             e(",".join(r.get("tags", []))), e(r.get("method", "")),
             e(r.get("path", "")), e(pl[:300])))
    w("</table>")

    if d["ips"]:
        w("<h2>Who</h2><table><tr><th>ip</th><th>alerts</th></tr>")
        for ip, n in d["ips"].most_common(15):
            w("<tr><td class=mono>%s</td><td>%d</td></tr>" % (e(ip), n))
        w("</table>")

    if d["tags"]:
        w("<h2>What they did</h2><table><tr><th>tag</th><th>count</th></tr>")
        for tag, n in d["tags"].most_common():
            w("<tr><td>%s</td><td>%d</td></tr>" % (e(tag), n))
        w("</table>")

    w('<p class=note style="margin-top:26px">evidence: %s · read-only · '
      'payloads are escaped and never executed · bind to localhost only</p>'
      % e(os.path.abspath(data_dir)))
    w("</main></body></html>")
    return "\n".join(out)


class Handler(BaseHTTPRequestHandler):
    server_version = "haotian-dashboard"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, body, ctype="text/html; charset=utf-8", status=200):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(url.query)

        if url.path == "/data.json":
            d = collect(ARGS.data_dir)
            self._send(json.dumps({
                "alerts": d["alerts"][-200:],
                "config_applies": d["config_applies"][:100],
                "planted": d["planted"],
                "tags": dict(d["tags"]),
                "severity": dict(d["sev"]),
                "ips": dict(d["ips"]),
            }, ensure_ascii=False), "application/json; charset=utf-8")
            return

        if url.path == "/drop":
            name = os.path.basename((q.get("name") or [""])[0])
            path = os.path.join(ARGS.data_dir, "drops", name)
            if name and os.path.isfile(path):
                with open(path, "rb") as f:
                    self._send(f.read(), "application/octet-stream")
            else:
                self._send("not found", "text/plain; charset=utf-8", 404)
            return

        if url.path not in ("/", "/index.html"):
            self._send("not found", "text/plain; charset=utf-8", 404)
            return

        refresh = ARGS.refresh
        if (q.get("refresh") or [""])[0] == "0":
            refresh = 0
        self._send(render(ARGS.data_dir, refresh))


def main():
    global ARGS
    p = argparse.ArgumentParser(description="好甜的蜜罐 catch dashboard")
    p.add_argument("--data-dir", default="./data")
    p.add_argument("--host", default="127.0.0.1",
                   help="bind address (default localhost — do not expose it)")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--refresh", type=int, default=5,
                   help="page auto-refresh seconds, 0 disables")
    ARGS = p.parse_args()

    srv = ThreadingHTTPServer((ARGS.host, ARGS.port), Handler)
    srv.daemon_threads = True
    print("🍯 好甜的蜜罐 dashboard → http://%s:%d  (evidence: %s)"
          % (ARGS.host, ARGS.port, os.path.abspath(ARGS.data_dir)))
    if ARGS.host not in ("127.0.0.1", "localhost", "::1"):
        print("   ⚠  binding beyond localhost — put authentication in front!")
    try:
        srv.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()

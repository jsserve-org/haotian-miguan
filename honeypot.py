#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
好甜的蜜罐 (hǎo tián de mì guàn) — "Such a sweet honeypot"

A pure-stdlib deception honeypot that impersonates an old, unpatched
go2rtc v1.8.5 instance:

  * the white-table era WebUI (index/add/editor/links/log/stream.html)
  * the unauthenticated config-file API:   GET/POST/PATCH /api/config
  * the /api/streams credential leak of that era (no SecretResponse yet)
  * sync WebRTC signaling, MJPEG/JPEG/HLS/MP4 endpoints, /api/log,
    /api/exit?code=, /api/restart, /api/webtorrent, discovery stubs
  * the RTSP server on :8554 (OPTIONS/DESCRIBE/SETUP/PLAY/...)

The goal: catch attackers who find "your go2rtc" and try to compromise
it by applying a malicious config file — POST /api/config with an
`ffmpeg:...#command=bash -i >&2` reverse-shell stream, PUT/PATCH
/api/streams, config editor "Save & Restart", etc.

Everything an attacker "applies" is mirrored into a fake state and
echoed back (GET /api/config shows their payload as if written to
go2rtc.yaml, /api/streams lists their stream, /api/log mentions the
producer start) so they believe the exploit landed.

SAFETY: nothing from any payload is ever executed, rendered, imported,
or written outside --data-dir. Payloads are stored as inert text for
forensics only.

Evidence layout (under --data-dir, default ./data):
  access.jsonl   every HTTP and RTSP request, one JSON object per line
  alerts.jsonl   suspicious events with FULL request payloads
  alerts.log     one-line plain format (fail2ban friendly)
  drops/         raw attacker payloads, one file per alert
  state.json     the fake "on-disk go2rtc.yaml" the attacker shaped
  memlog.jsonl   the fake go2rtc memory log served by GET /api/log

Usage:
  python3 honeypot.py                       # HTTP :1984 + RTSP :8554
  python3 honeypot.py --webhook https://discord.com/api/webhooks/...
  python3 report.py                         # summarize the catch

Requires Python 3.9+, no third-party packages.
"""

import argparse
import base64
import collections
import ipaddress
import json
import os
import queue
import random
import re
import signal
import socket
import socketserver
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# Constants / impersonation identity
# ---------------------------------------------------------------------------

GO2RTC_VERSION = "1.8.5"          # the version we pretend to run (old & juicy)
GO2RTC_ARCH = "linux/amd64"
RTSP_PUBLIC_METHODS = "OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, ANNOUNCE, RECORD"

# producer schemes registered in real go2rtc v1.8.5 (streams.handlers registry)
KNOWN_SCHEMES = {
    "bubble", "dvrip", "echo", "ffmpeg", "gopro", "hass", "homekit", "http",
    "https", "isapi", "ivideon", "nest", "onvif", "roborock", "rtmp", "rtmps",
    "rtsp", "rtsps", "rtspx", "srtp", "tapo", "tcp", "udp", "webtorrent",
}

MAX_BODY_DEFAULT = 8 * 1024 * 1024   # 8 MiB request body cap (safety valve)
STREAM_STALL_SECONDS = 12           # how long fake mp4/ts endpoints hang
MJPEG_FPS = 1.0                     # frames per second of fake mjpeg
MJPEG_MAX_FRAMES = 3600
UPSTREAM_TIMEOUT = 15               # hybrid mode: real go2rtc fetch timeout

SEV_RANK = {"low": 0, "medium": 1, "high": 2}

# fake camera frame (dark night-cam noise) served by /api/frame.jpeg etc.
CAMERA_FRAME_JPEG_B64 = "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"

HTTP_REASONS = {
    200: "OK", 201: "Created", 204: "No Content", 400: "Bad Request",
    401: "Unauthorized", 404: "Not Found", 405: "Method Not Allowed",
    410: "Gone", 413: "Request Entity Too Large", 500: "Internal Server Error",
    501: "Not Implemented", 503: "Service Unavailable",
}

# ---------------------------------------------------------------------------
# The fake go2rtc.yaml an attacker will "find" and try to poison
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = '''# go2rtc configuration
# migrated from Frigate config on 2024-06-11 — auth disabled during migration, TODO before exposing to WAN

api:
  listen: ":1984"
  # username: admin
  # password: go2rtc-admin-2024

rtsp:
  listen: ":8554"

webrtc:
  listen: ":8555/tcp"

streams:
  front_door: rtsp://admin:DoorCam2024@192.168.1.42:554/cam/realmonitor?channel=1&subtype=0
  backyard:
    - rtsp://operator:BackYard24@192.168.1.43:554/h264_stream
    - onvif://operator:BackYard24@192.168.1.43:80
  garage: rtsp://admin:GarageCam2026@192.168.1.44:554/Streaming/Channels/102
  driveway: http://admin:Driveway2026@192.168.1.45/mjpeg
  porch_4k: ffmpeg:rtsp://admin:PorchCam2026@192.168.1.46:554/h264_stream#video=h264#audio=aac

log:
  level: info
'''

# ---------------------------------------------------------------------------
# Tiny ANSI helper for operator console output
# ---------------------------------------------------------------------------

class Con:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self._lock = threading.Lock()

    def _wrap(self, s, code):
        return "\033[" + code + "m" + s + "\033[0m" if self.enabled else s

    def print(self, line=""):
        with self._lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()

    def dim(self, line):
        self.print(self._wrap(line, "2"))

    def bright(self, line):
        self.print(self._wrap(line, "1"))

    def warn(self, line):
        self.print(self._wrap(self._wrap(line, "93"), "1"))

    def danger(self, line):
        self.print(self._wrap(self._wrap(line, "91"), "1"))

    def honey(self, line):
        self.print(self._wrap(self._wrap(line, "95"), "1"))


def utcnow_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def short_id():
    return uuid.uuid4().hex[:8]


# ---------------------------------------------------------------------------
# Minimal YAML helpers (safe: pure text processing, nothing is executed)
# ---------------------------------------------------------------------------

TOP_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*):")
NAME_VAL_RE = re.compile(r"^([^:#]+?):\s*(.*)$")
LIST_ITEM_RE = re.compile(r"^-\s+(.*)$")
QUOTED_KEY_RE = re.compile(r'^"((?:[^"\\]|\\.)*)":\s*(.*)$')
SAFE_YAML_SCALAR_RE = re.compile(r"^[A-Za-z0-9_.:/@?&=%+~,()\[\]#-]+$")
SAFE_YAML_KEY_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


def unquote_yaml(v):
    """Undo a double-quoted YAML scalar (json escapes are a YAML subset)."""
    v = v.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        try:
            return json.loads(v)
        except Exception:
            return v[1:-1]
    return v


def yaml_key(name):
    """Stream names may be anything go2rtc accepts — including CJK and
    colons ("…內網 IP :1984"). Quote unless the name is plainly safe."""
    name = str(name)
    if SAFE_YAML_KEY_RE.match(name):
        return name
    return json.dumps(name, ensure_ascii=False)


def yaml_scalar(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    v = str(v)
    if SAFE_YAML_SCALAR_RE.match(v) and not v.startswith(("-", ":", "!", "&", "*")):
        return v
    return json.dumps(v)


def split_config_text(text):
    """Split a go2rtc.yaml-like document into (pre, streams, post).

    streams is a list of [name, [source, ...]] entries, or None when the
    document has no `streams:` block. pre/post keep all other sections
    verbatim so the attacker's own formatting survives round trips.
    """
    lines = text.splitlines()
    n = len(lines)
    i = 0
    while i < n:
        m = TOP_KEY_RE.match(lines[i])
        if m and m.group(1) == "streams" and lines[i].strip() == "streams:":
            break
        i += 1
    if i == n:
        return text, None, ""
    pre = "\n".join(lines[:i])
    i += 1
    streams = []
    last = None
    post_start = n
    while i < n:
        line = lines[i]
        if TOP_KEY_RE.match(line):
            post_start = i
            break
        s = line.strip()
        if not s or s.startswith("#"):
            i += 1
            continue
        m = LIST_ITEM_RE.match(s)
        if m and last is not None:
            streams[last][1].append(unquote_yaml(m.group(1).strip()))
            i += 1
            continue
        name = val = None
        m = QUOTED_KEY_RE.match(s)
        if m:
            # "如果要編輯設定請使用 VPN 或內網 IP :1984": rtsp://…
            name = unquote_yaml('"%s"' % m.group(1))
            val = m.group(2).strip()
        else:
            m = NAME_VAL_RE.match(s)
            if m:
                name = m.group(1).strip()
                val = m.group(2).strip()
        if name is not None:
            streams.append([name, []])
            last = len(streams) - 1
            if val:
                streams[last][1] = [val]
        i += 1
    post = "\n".join(lines[post_start:]) if post_start < n else ""
    return pre, streams, post


def render_streams_block(streams):
    out = ["streams:"]
    for name, srcs in streams:
        key = yaml_key(name)     # quote names with colons/space/CJK, e.g.
        if len(srcs) == 1:       # "如果要編輯設定請使用 VPN 或內網 IP :1984"
            out.append("  %s: %s" % (key, yaml_scalar(srcs[0])))
        elif len(srcs) == 0:
            out.append("  %s: {}" % key)
        else:
            out.append("  %s:" % key)
            for s in srcs:
                out.append("    - " + yaml_scalar(s))
    return "\n".join(out) + "\n"


def render_config(pre, streams, post):
    if not pre.strip() and not streams and not post.strip():
        return ""   # the attacker wiped the file — it reads back empty
    parts = []
    if pre:
        parts.append(pre.rstrip("\n"))
    parts.append(render_streams_block(streams).rstrip("\n"))
    if post:
        parts.append(post.rstrip("\n"))
    return "\n\n".join(parts) + "\n"


def yaml_body_error(body_text):
    """Approximate the gopkg.in/yaml.v3 error for a non-mapping document."""
    first = (body_text.strip().splitlines() or [""])[0]
    if TOP_KEY_RE.match(first) or not body_text.strip():
        return None  # looks like a mapping (or empty) — real v1.8.5 accepts both
    if first.startswith("- ") or first.startswith("["):
        return "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!seq into map[string]interface {}"
    return ("yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `%s` into map[string]interface {}"
            % first[:60])


def merge_config_sections(old, new):
    """Deep-merge two `streams` lists + surrounding text, mirroring
    configHandler's PATCH mergeYAML: maps merge, lists/scalars replace."""
    old_by_name = {name: srcs for name, srcs in (old or [])}
    for name, srcs in (new or []):
        old_by_name[name] = srcs
    return [[k, v] for k, v in old_by_name.items()]


# ---------------------------------------------------------------------------
# Hybrid mode: talking to the REAL go2rtc upstream
# ---------------------------------------------------------------------------

CRED_URL_RE = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)([^/@?\s]*):([^/@?\s]*)@")
SECRET_KEY_RE = re.compile(
    r"(?i)^(\s*)(password|passwd|pass|pwd|secret|token|api[-_]?key|apikey|"
    r"access[-_]?key|private[-_]?key|credential|credentials)\s*:\s*(\S.*?)\s*$")


def sanitize_creds(url):
    """Replace userinfo passwords with a plausible fake. Used whenever the
    pot reflects or relays REAL source URLs, so the decoy never leaks the
    real camera credentials it observed in the upstream stream list."""
    return CRED_URL_RE.sub(lambda m: "%s%s:Restream2026@" % (m.group(1), m.group(2) or "admin"), url)


def sanitize_config_text(text):
    """Make a REAL go2rtc.yaml safe to expose as the fake one: every URL
    userinfo password and every secret-ish key (password, token, api_key…)
    is replaced, everything else — sections, values, comments, order — is
    kept byte-for-byte so the fake config is indistinguishable from the
    genuine article."""
    out = []
    for line in text.splitlines():
        if not line.lstrip().startswith("#"):
            m = SECRET_KEY_RE.match(line)
            if m:
                line = "%s%s: Restream2026" % (m.group(1), m.group(2))
        out.append(sanitize_creds(line))
    return "\n".join(out) + ("\n" if text.endswith("\n") or text else "")


def scrub_json_creds(obj):
    """Recursively sanitize every 'url' field in an upstream JSON response."""
    if isinstance(obj, dict):
        return {k: (sanitize_creds(v) if k == "url" and isinstance(v, str) else scrub_json_creds(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub_json_creds(x) for x in obj]
    return obj


class UpstreamError(Exception):
    pass


def upstream_fetch(method, path_query, body=None, ctype=None):
    """Blocking fetch from the real go2rtc. Returns (status, ctype, body)."""
    if not ARGS.upstream:
        raise UpstreamError("no upstream configured")
    url = ARGS.upstream.rstrip("/") + path_query
    req = urllib.request.Request(url, data=body, method=method)
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT) as r:
            return r.status, r.headers.get("Content-Type"), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type"), e.read()
    except Exception as e:
        raise UpstreamError(str(e))


# ---------------------------------------------------------------------------
# Fake state: the "config file on disk" + the "runtime streams map"
# ---------------------------------------------------------------------------

class FakeState:
    def __init__(self, lock):
        self.lock = lock
        # the config file illusion (what GET /api/config returns)
        self.pre = ""
        self.config_streams = []      # [[name, [srcs]], ...]  (persisted)
        self.post = ""
        self.raw = None               # verbatim "file" content after a POST
        # the runtime illusion (what GET /api/streams returns)
        self.runtime_streams = []      # [[name, [srcs]], ...]
        self.meta = {}                 # name -> {"ip","ts","via"} attacker-added
        self.share = None              # webtorrent share {share,pwd}
        # hybrid mode bookkeeping
        self.sanitized_streams = []   # sanitized copy of the REAL stream list
        self.deleted_names = set()     # upstream names "deleted" by attackers
        self.upstream_version = None   # real instance version (fake log lines)
        self.upstream_revision = None  # real instance git revision (1.9.x)
        self._reseed_ts = 0.0          # lazy autoseed retry cooldown
        self._last_sync = 0.0          # last real-config mirror
        self._attacker_ts = 0.0        # last attacker write to the fake state
        self.load()

    # -- persistence ------------------------------------------------------
    def load(self):
        path = state_path()
        if os.path.exists(path) and not ARGS.reset:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    d = json.load(f)
                self.pre = d.get("pre", "")
                self.config_streams = d.get("config_streams", [])
                self.post = d.get("post", "")
                self.raw = d.get("raw")
                self.meta = d.get("meta", {})
                self.share = d.get("share")
                self.sanitized_streams = d.get("sanitized_streams", [])
                self.deleted_names = set(d.get("deleted_names", []))
            except Exception:
                pass
        else:
            text = DEFAULT_CONFIG
            if ARGS.config_file and os.path.exists(ARGS.config_file):
                with open(ARGS.config_file, "r", encoding="utf-8") as f:
                    text = f.read()
            self.pre, self.config_streams, self.post = split_config_text(text)
            if ARGS.upstream and not (ARGS.config_file and os.path.exists(ARGS.config_file)):
                self._autoseed()
        with self.lock:
            self.runtime_streams = [list(x) for x in self.config_streams]

    def _autoseed(self):
        """Hybrid mode: mirror the REAL instance so the decoy is seamless.
        Adopt its version/revision for the fake log lines, then copy its
        go2rtc.yaml — secrets replaced — as the fake config. Falls back to
        building a config from its stream list if /api/config is unreadable."""
        try:
            st, ct, body = upstream_fetch("GET", "/api")
            info = json.loads(body)
            if isinstance(info, dict) and info.get("version"):
                self.upstream_version = str(info["version"])
            if isinstance(info, dict) and info.get("revision"):
                self.upstream_revision = str(info["revision"])
        except Exception as e:
            CON.warn("upstream unreachable, fake logs keep version %s (%s)"
                     % (ARGS.version_string, e))
        # 1st choice: mirror the real go2rtc.yaml itself (secrets scrubbed)
        mirrored = False
        try:
            st, ct, body = upstream_fetch("GET", "/api/config")
            real_cfg = body.decode("utf-8", "replace")
            if real_cfg.strip():
                fake = sanitize_config_text(real_cfg)
                pre, streams, post = split_config_text(fake)
                self.pre, self.post = pre, post
                self.raw = fake                       # GET returns this verbatim
                self.config_streams = streams or []
                self.sanitized_streams = [list(x) for x in (streams or [])]
                mirrored = True
                CON.print("    hybrid: mirrored the real go2rtc.yaml "
                          "(%d streams, secrets sanitized)" % len(self.sanitized_streams))
        except Exception as e:
            CON.warn("hybrid: could not mirror the real config (%s)" % e)

        # fallback: build a config from the real stream list
        if not mirrored:
            try:
                st, ct, body = upstream_fetch("GET", "/api/streams")
                data = json.loads(body)
                seeded = []
                if isinstance(data, dict) and data:
                    for name, info in data.items():
                        srcs = []
                        if isinstance(info, dict):
                            for p in (info.get("producers") or []):
                                u = p.get("url") if isinstance(p, dict) else None
                                if isinstance(u, str) and u:
                                    srcs.append(sanitize_creds(u))
                        if not srcs:
                            srcs = ["rtsp://admin:Restream2026@192.168.1.50:554/stream"]
                        seeded.append([name, srcs])
                if seeded:
                    seeded.sort(key=lambda x: x[0])
                    _pre, _old, _post = split_config_text(DEFAULT_CONFIG)
                    self.pre, self.config_streams, self.post = _pre, seeded, _post
                    self.sanitized_streams = [list(x) for x in seeded]
                    CON.print("    hybrid: seeded %d real streams (creds sanitized)"
                              % len(seeded))
            except Exception as e:
                CON.warn("hybrid: could not seed from upstream (%s) — using default bait" % e)

    def save(self):
        try:
            with open(state_path(), "w", encoding="utf-8") as f:
                json.dump({
                    "pre": self.pre,
                    "config_streams": self.config_streams,
                    "post": self.post,
                    "raw": self.raw,
                    "meta": self.meta,
                    "share": self.share,
                    "sanitized_streams": self.sanitized_streams,
                    "deleted_names": sorted(self.deleted_names),
                }, f, ensure_ascii=False, indent=1)
        except Exception as e:
            CON.dim("state save failed: %s" % e)

    def reset_runtime(self):
        """/api/restart illusion: runtime map re-read from the config file."""
        with self.lock:
            self.runtime_streams = [list(x) for x in self.config_streams]

    # -- config file API ----------------------------------------------------
    def config_text(self):
        self._maybe_sync()
        with self.lock:
            if self.raw is not None:
                return self.raw          # byte-for-byte what was "written"
            return render_config(self.pre, self.config_streams, self.post)

    def _maybe_sync(self):
        """Keep the fake state in step with the REAL instance.

        - nothing mirrored yet → adopt the real config now
        - otherwise re-mirror every --config-sync seconds
        - after an attacker write, leave their story alone for one sync
          window (so their apply/restart/verify flow looks real), then
          revert to the real config like an operator who noticed
        """
        if not ARGS.upstream or ARGS.config_sync <= 0:
            return
        now = time.time()
        if self._last_sync == 0.0 and self.sanitized_streams:
            self._last_sync = now      # boot mirror already happened
            return
        if now - self._last_sync < ARGS.config_sync:
            return
        self._last_sync = now
        with self.lock:
            if self._attacker_ts and now - self._attacker_ts < ARGS.config_sync:
                return                 # still inside the attacker's grace window
            try:
                self._autoseed()
            except Exception:
                return
            # the real config is authoritative again: drop attacker edits from
            # the fake state (their payload stays in alerts/drops as evidence)
            self.runtime_streams = [list(x) for x in self.config_streams]
            self.deleted_names = set()
            self.save()
            CON.print("    hybrid: re-synced with the real config (%d streams)"
                      % len(self.sanitized_streams))

    def apply_config(self, text, ip):
        """POST /api/config — full document replace (real v1.8.5 writes the
        file verbatim; runtime streams only change after /api/restart)."""
        added = []
        with self.lock:
            self._attacker_ts = time.time()
            self.raw = text if text.endswith("\n") else (text + "\n" if text.strip() else text)
            if not text.strip():
                # empty body: real v1.8.5 happily truncates the file to zero
                self.pre, self.config_streams, self.post = "", [], ""
            else:
                pre, streams, post = split_config_text(text)
                if streams is None:
                    # no streams: block in the new file — restart yields none
                    self.pre, self.config_streams, self.post = pre, [], post
                else:
                    self.pre, self.config_streams, self.post = pre, streams, post
                    old_names = {n for n, _ in self.runtime_streams}
                    seed_names = {n for n, _ in self.sanitized_streams}
                    for name, srcs in streams:
                        if name in old_names or name in seed_names:
                            # a name that already existed (or a real stream the
                            # attacker is just echoing back) — not a plant
                            continue
                        self.meta[name] = {"ip": ip, "ts": utcnow_iso(),
                                           "via": "api/config POST",
                                           "sources": list(srcs)}
                        added.append(name)
            self.save()
        return added

    def patch_config(self, text, ip):
        """PATCH /api/config — merge, mirroring configHandler mergeYAML.
        A merge cannot stay verbatim, so the file re-renders."""
        pre, streams, post = split_config_text(text)
        added = []
        with self.lock:
            self._attacker_ts = time.time()
            self.raw = None
            if streams is not None:
                old_names = {n for n, _ in self.config_streams}
                self.config_streams = merge_config_sections(self.config_streams, streams)
                for name, srcs in streams:
                    if name not in old_names:
                        self.meta[name] = {"ip": ip, "ts": utcnow_iso(),
                                           "via": "api/config PATCH",
                                           "sources": list(srcs)}
                        added.append(name)
            self.save()
        return added

    # -- streams API ---------------------------------------------------------
    def streams_json(self):
        with self.lock:
            return {name: {"producers": [{"url": s} for s in srcs],
                           "consumers": None}
                    for name, srcs in self.runtime_streams}

    def get_stream(self, name):
        with self.lock:
            for n, srcs in self.runtime_streams:
                if n == name:
                    return srcs
        return None

    def put_stream(self, name, srcs, ip, persist=True):
        """PUT /api/streams — runtime create + PatchConfig into the file."""
        with self.lock:
            self._attacker_ts = time.time()
            self.raw = None    # PatchConfig re-renders the file
            old_names = {n for n, _ in self.runtime_streams}
            self.runtime_streams = [[n, s] for n, s in self.runtime_streams if n != name]
            self.runtime_streams.append([name, srcs])
            if persist:
                self.config_streams = [[n, s] for n, s in self.config_streams if n != name]
                self.config_streams.append([name, list(srcs)])
            if name not in old_names:
                self.meta[name] = {"ip": ip, "ts": utcnow_iso(),
                                   "via": "PUT /api/streams",
                                   "sources": list(srcs)}
            self.save()

    def delete_stream(self, name):
        """DELETE /api/streams?src=. Planted streams vanish from the fake
        state; a REAL (upstream) stream only vanishes from our merged view —
        the real instance itself is never touched."""
        with self.lock:
            self._attacker_ts = time.time()
            self.raw = None    # PatchConfig re-renders the file
            if name in dict(self.sanitized_streams):
                # deleting an upstream stream: hide it locally, stay intact upstream
                self.deleted_names.add(name)
            self.runtime_streams = [[n, s] for n, s in self.runtime_streams if n != name]
            self.config_streams = [[n, s] for n, s in self.config_streams if n != name]
            self.save()

    def is_planted(self, name):
        """True when `name` is an attacker-planted/modified stream (not one
        of the sanitized seeds mirrored from the real instance). Only
        meaningful in hybrid mode; decides pot-vs-upstream routing."""
        with self.lock:
            srcs = dict(self.runtime_streams).get(name)
            if srcs is None:
                return False
            seed = dict(self.sanitized_streams).get(name)
            return seed != srcs

    def merged_streams_json(self):
        """Hybrid /api/streams listing: the REAL streams (with credentials
        replaced) plus whatever the attacker planted, minus what they
        'deleted'. Falls back to seed+planted if the upstream is down."""
        self._maybe_sync()
        base = {}
        live = False
        if ARGS.upstream:
            try:
                st, ct, body = upstream_fetch("GET", "/api/streams")
                data = json.loads(body)
                if isinstance(data, dict):
                    # the LIVE real list is the truth — scrub creds, never
                    # re-add a name the real instance no longer has
                    base = scrub_json_creds(data)
                    live = True
            except UpstreamError:
                pass
        seed_map = dict(self.sanitized_streams)
        for n in self.deleted_names:
            base.pop(n, None)
        if not live and seed_map:
            # upstream unreachable: degrade to the last known (sanitized) list
            for n, s in seed_map.items():
                if n not in self.deleted_names:
                    base[n] = {"producers": [{"url": x} for x in s], "consumers": None}
        for n, s in self.runtime_streams:
            # overlay only what the attacker changed or planted: their new
            # streams, or their modified version of a real one. Never the
            # cached seed — that is what made phantom rows appear.
            if n in self.meta or (seed_map.get(n) is not None and seed_map.get(n) != s):
                base[n] = {"producers": [{"url": x} for x in s], "consumers": None}
        return base

    def has_scheme(self, source):
        """streams.Patch() allows aliases to existing stream names, otherwise
        demands a registered producer scheme. (streams.New used by PUT does
        no scheme check at all — mirrored in the PUT route.)"""
        if self.get_stream(source) is not None:
            return True
        m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://", source.strip())
        if m:
            return m.group(1).lower() in KNOWN_SCHEMES
        return False

    def attacker_streams(self):
        with self.lock:
            return dict(self.meta)


# ---------------------------------------------------------------------------
# Detection: tag suspicious behavior
# ---------------------------------------------------------------------------

EXEC_RE = re.compile(
    r"(bash\s+-i|/bin/(?:ba|z|da)?sh|sh\s+-c|zsh\s+-c|nc\s+-e|ncat|socat|mkfifo"
    r"|/dev/tcp|curl[^>\n]{0,120}(\||&&|;)\s*(ba)?sh\b|wget[^>\n]{0,120}(\||&&|;)\s*(ba)?sh\b"
    r"|python[23]?\s+-c|perl\s+-e|powershell|certutil|base64\s+-d|eval\s|chmod\s+\+x|rm\s+-rf\s+/)",
    re.I)
FFMPEG_CMD_RE = re.compile(r"#(command|input)\s*=", re.I)
FFMPEG_ANY_RE = re.compile(r"ffmpeg\s*:", re.I)
TEMPLATE_RE = re.compile(r"\{input\}", re.I)
TRAVERSAL_RE = re.compile(r"(\.\./|/etc/(passwd|shadow)|\.env\b|file:/)", re.I)


def classify(method, path, query, body_text):
    """Return (tags, severity, note) for a request. Severity: low/medium/high."""
    tags = []
    severity = "low"
    p = path.lower().rstrip("/")
    text = body_text or ""

    if p == "/api/config":
        if method in ("GET", "HEAD"):
            tags.append("config_read")
            severity = "low"
        elif method in ("POST", "PATCH", "PUT"):
            tags.append("config_write")
            severity = "medium"
    if p == "/api/streams" and method in ("PUT", "PATCH", "DELETE"):
        tags.append("stream_write")
        severity = "medium"
    if p == "/api/streams" and method == "POST" and "dst=" in (query or ""):
        # publish/play: on a real instance this can push a camera feed to an
        # attacker-chosen RTMP/RTSP endpoint — go2rtc's exfiltration path
        tags.append("publish_attempt")
        severity = "high" if re.search(r"dst=(rtsps?|rtmps?|https?)", query or "", re.I) else "medium"
    if p == "/api/restart" and method == "POST":
        tags.append("restart_attempt")
    if p == "/api/exit":
        tags.append("exit_attempt")
        severity = "high"

    probe = text + " " + (query or "")
    if FFMPEG_CMD_RE.search(probe):
        tags.append("ffmpeg_rce")
        severity = "high"
    elif FFMPEG_ANY_RE.search(probe) and ("config_write" in tags or "stream_write" in tags):
        tags.append("ffmpeg_source")
    if EXEC_RE.search(probe):
        tags.append("exec_pattern")
        severity = "high"
    if TEMPLATE_RE.search(probe) and ("config_write" in tags or "stream_write" in tags):
        tags.append("template_inject")
        severity = "medium"
    if TRAVERSAL_RE.search((path or "") + " " + probe):
        tags.append("traversal")
        severity = "high"

    if not tags:
        return [], None, ""
    note = {
        "config_read": "recon: reading go2rtc.yaml (camera creds leak, v1.8.5 has no masking)",
        "config_write": "TRAP HIT: attacker applying a config file — mirrored, nothing executed",
        "stream_write": "attacker adding/modifying a stream (config file patch path)",
        "ffmpeg_rce": "ffmpeg #command/#input parameter — classic go2rtc RCE payload",
        "exec_pattern": "shell / reverse-shell pattern in payload",
        "template_inject": "{input} template abuse (arbitrary ffmpeg args)",
        "restart_attempt": "restart after config apply (editor.html flow) — runtime reloaded from fake config",
        "exit_attempt": "process-kill attempt (os.Exit illusion)",
        "traversal": "path traversal / local file read probe",
    }
    return tags, severity, " · ".join(note[t] for t in tags if t in note)


# ---------------------------------------------------------------------------
# Evidence loggers
# ---------------------------------------------------------------------------

class Evidence:
    def __init__(self, data_dir):
        self.dir = data_dir
        self.drops = os.path.join(data_dir, "drops")
        os.makedirs(self.drops, exist_ok=True)
        self._lock = threading.Lock()
        self._webhook_fail = 0
        self.wq = queue.Queue(maxsize=256) if ARGS.webhook else None
        if ARGS.webhook:
            threading.Thread(target=self._webhook_worker, daemon=True).start()

    def _append(self, name, obj):
        with self._lock:
            try:
                with open(os.path.join(self.dir, name), "a", encoding="utf-8") as f:
                    f.write(json.dumps(obj, ensure_ascii=False) + "\n")
            except Exception as e:
                CON.dim("log write failed: %s" % e)

    def access(self, rec):
        self._append("access.jsonl", rec)
        if not ARGS.quiet:
            CON.dim("[%s] %-15s %-6s %-28s %s %s %s" % (
                rec.get("ts", "")[11:19], rec.get("ip", "?"), rec.get("kind", "http"),
                (rec.get("method", "") + " " + rec.get("path", "")).strip(),
                rec.get("status", ""),
                ("%dms" % rec["dur_ms"]) if "dur_ms" in rec else "",
                (rec.get("rtsp_uri") or "")))

    def alert(self, rec, body_bytes=None):
        # save the raw payload FIRST so rec["body_file"] is part of the
        # record, the alerts.log line, the webhook and the dashboard link
        if body_bytes:
            ext = "txt"
            try:
                json.loads(body_bytes.decode("utf-8", "replace"))
                ext = "json"
            except Exception:
                if re.search(r":\s*\S|^-\s", body_bytes.decode("utf-8", "replace"), re.M):
                    ext = "yaml"
            fname = "%s_%s.%s" % (rec["ts"].replace(":", "").replace("-", ""),
                                   rec["ip"].replace(":", "-"), ext)
            try:
                with open(os.path.join(self.drops, fname), "wb") as f:
                    f.write(body_bytes)
                rec["body_file"] = "drops/" + fname
            except Exception:
                pass

        tags = ",".join(rec.get("tags", []))
        line = "%s severity=%s ip=%s tags=%s method=%s path=%s" % (
            rec["ts"], rec.get("severity", "low"), rec["ip"], tags,
            rec.get("method", "-"), rec.get("path", "-"))
        payload = self._payload_raw(rec)
        if payload:
            flat = (payload.replace("\\", "\\\\").replace('"', '\\"')
                    .replace("\r", "").replace("\n", "\\n"))
            line += ' payload="%s"' % flat[:500]
        if rec.get("body_file"):
            line += ' evidence="%s"' % rec["body_file"]
        self._append("alerts.jsonl", rec)
        with self._lock:
            try:
                with open(os.path.join(self.dir, "alerts.log"), "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass
        self._console(rec)
        if ARGS.webhook:
            try:
                self.wq.put_nowait(rec)
            except queue.Full:
                pass

    @staticmethod
    def _payload_raw(rec):
        """What the attacker actually sent: the request body, or — for stream
        writes where go2rtc takes the payload as query params — the decoded
        query string."""
        body = rec.get("body") or ""
        if not body and rec.get("query"):
            body = urllib.parse.unquote_plus(rec["query"])
        return body.strip()

    def _webhook_format(self):
        fmt = ARGS.webhook_format
        if fmt == "auto":
            u = ARGS.webhook or ""
            if "discord.com/api/webhooks" in u or "discordapp.com/api/webhooks" in u:
                return "discord"
            if "hooks.slack.com" in u:
                return "slack"
            return "generic"
        return fmt

    def _webhook_body(self, rec):
        """Build the notification payload. Discord and Slack reject arbitrary
        JSON, so shape the alert into what they actually render — with the
        attacker's payload front and centre."""
        fmt = self._webhook_format()
        if fmt == "generic":
            return rec   # raw alert record for custom relays/automation

        sev = rec.get("severity", "low")
        tags = ",".join(rec.get("tags", [])) or "-"
        payload = self._payload_raw(rec)
        note = rec.get("note") or ""
        corrections = []

        def field(name, value, inline=False, limit=1000):
            if value:
                corrections.append({"name": name, "value": str(value)[:limit],
                                    "inline": inline})

        field("Attacker", "`%s`" % rec.get("ip", "?"), True)
        field("Severity", sev.upper(), True)
        field("Request", "`%s %s`" % (rec.get("method", "-"), rec.get("path", "-")), True)
        if rec.get("peer"):
            field("Via proxy", "`%s`" % rec["peer"], True)
        if payload:
            field("Payload (what they sent)", "```\n%s\n```" % payload[:900])
        if note:
            field("What it means", note[:900])
        if rec.get("body_file"):
            field("Evidence file", rec["body_file"], True)

        if fmt == "slack":
            color = {"high": "danger", "medium": "warning"}.get(sev, "#95a5a6")
            return {
                "text": "🍯 honeypot alert: %s from %s" % (tags, rec.get("ip", "?")),
                "attachments": [{
                    "color": color,
                    "title": "好甜的蜜罐 · %s" % tags,
                    "fields": [{"title": f["name"], "value": f["value"], "short": f["inline"]}
                               for f in corrections],
                    "footer": rec.get("ts", ""),
                }],
            }

        # discord
        color = {"high": 0xE74C3C, "medium": 0xE67E22}.get(sev, 0x95A5A6)
        return {
            "embeds": [{
                "title": "🍯 好甜的蜜罐 · %s" % tags[:200],
                "color": color,
                "timestamp": rec.get("ts", ""),
                "fields": corrections[:6],
                "footer": {"text": "go2rtc honeypot · %s" % rec.get("path", "")},
            }],
        }

    def _console(self, rec):
        sev = rec.get("severity", "low")
        preview = (self._payload_raw(rec) or rec.get("path") or "")
        preview = preview.replace("\n", " ")[:400 if sev != "low" else 160]
        head = "🍯 ALERT %-15s %-4s %-24s [%s]" % (
            rec["ip"], rec.get("method", "?"), rec.get("path", "?"),
            ",".join(rec.get("tags", [])))
        if sev == "high":
            CON.danger(head)
            CON.danger("    " + preview)
        elif sev == "medium":
            CON.warn(head)
            CON.warn("    " + preview)
        else:
            CON.honey(head)
        if rec.get("body_file"):
            CON.dim("    evidence: data/%s" % rec["body_file"])
        if rec.get("note"):
            CON.dim("    " + rec["note"][:200])

    def _webhook_worker(self):
        while True:
            rec = self.wq.get()
            try:
                data = json.dumps(self._webhook_body(rec), ensure_ascii=False).encode("utf-8")
                req = urllib.request.Request(
                    ARGS.webhook, data=data,
                    headers={"Content-Type": "application/json",
                             "User-Agent": "haotian-miguan/1.0"}, method="POST")
                urllib.request.urlopen(req, timeout=5)
                self._webhook_fail = 0
            except Exception as e:
                self._webhook_fail += 1
                if self._webhook_fail == 1:
                    CON.warn("webhook delivery failed: %s" % e)


# ---------------------------------------------------------------------------
# Fake go2rtc memory log (GET /api/log)
# ---------------------------------------------------------------------------

class FakeMemLog:
    def __init__(self):
        self.lines = collections.deque(maxlen=500)
        self.lock = threading.Lock()
        rev = self.revision()
        if rev:
            # 1.9.x logs the boot line as structured fields, not one string:
            #   {"message":"go2rtc","platform":"linux/amd64",
            #    "revision":"7c05066","version":"1.9.15"}
            boot = [("go2rtc", "info", {"platform": GO2RTC_ARCH, "revision": rev,
                                        "version": self.version()})]
        else:
            boot = [("go2rtc version %s %s" % (self.version(), GO2RTC_ARCH), "info")]
        boot += [
            ("[app] config path=%s" % ARGS.config_path_label, "info"),
            ("[api] listen addr=:%d" % ARGS.port, "info", {"addr": ":%d" % ARGS.port}),
            ("[rtsp] listen addr=:%d" % ARGS.rtsp_port, "info", {"addr": ":%d" % ARGS.rtsp_port}),
            ("[webrtc] listen addr=:8555/tcp", "info", {"addr": ":8555/tcp"}),
        ]
        for msg in boot:
            self.add(msg[0], msg[1], msg[2] if len(msg) > 2 else None)

    def add(self, message, level="info", extra=None):
        obj = {"level": level, "time": utcnow_iso(), "message": message}
        if extra:
            obj.update(extra)
        with self.lock:
            self.lines.append(obj)

    def version(self):
        """Hybrid mode adopts the REAL instance's version so the fake log
        never contradicts the live /api response."""
        if STATE and STATE.upstream_version:
            return STATE.upstream_version
        return ARGS.version_string if ARGS else GO2RTC_VERSION

    def revision(self):
        """1.9.x builds advertise a git revision — adopt the real one in
        hybrid mode, or the operator's --revision in standalone mode."""
        if STATE and STATE.upstream_revision:
            return STATE.upstream_revision
        return (ARGS.revision if ARGS else "") or ""

    def text(self):
        with self.lock:
            return "".join(json.dumps(l, ensure_ascii=False) + "\n" for l in self.lines)

    def clear(self):
        with self.lock:
            self.lines.clear()


# ---------------------------------------------------------------------------
# WebRTC SDP answer fabrication
# ---------------------------------------------------------------------------

def fabricate_answer_sdp(src):
    rand = random.Random(os.urandom(8))
    ufrag = "".join(rand.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(4))
    pwd = "".join(rand.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(22))
    fp = ":".join("%02x" % rand.randrange(256) for _ in range(32))
    host = "192.168.1.%d" % rand.randrange(2, 254)
    cand = "a=candidate:1 1 udp 2130706431 %s 8555 typ host generation 0" % host
    return (
        "v=0\r\n"
        "o=- %d 2 IN IP4 127.0.0.1\r\n"
        "s=-\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE 0 1\r\n"
        "a=msid-semantic: WMS\r\n"
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
        "c=IN IP4 0.0.0.0\r\n"
        "a=rtcp:9 IN IP4 0.0.0.0\r\n"
        "a=ice-ufrag:%s\r\n"
        "a=ice-pwd:%s\r\n"
        "a=ice-options:trickle\r\n"
        "a=fingerprint:sha-256 %s\r\n"
        "a=setup:active\r\n"
        "a=mid:0\r\n"
        "a=recvonly\r\n"
        "a=rtpmap:96 H264/90000\r\n"
        "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n"
        "a=rtcp-fb:96 nack\r\n"
        "a=rtcp-fb:96 nack pli\r\n"
        "a=rtcp-fb:96 goog-remb\r\n"
        "%s\r\n"
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
        "c=IN IP4 0.0.0.0\r\n"
        "a=rtcp:9 IN IP4 0.0.0.0\r\n"
        "a=ice-ufrag:%s\r\n"
        "a=ice-pwd:%s\r\n"
        "a=fingerprint:sha-256 %s\r\n"
        "a=setup:active\r\n"
        "a=mid:1\r\n"
        "a=recvonly\r\n"
        "a=rtpmap:111 opus/48000/2\r\n"
        "a=rtcp-fb:111 transport-cc\r\n"
        "a=candidate:1 1 udp 2130706431 %s 8555 typ host generation 0\r\n"
    ) % (rand.randrange(1 << 31), ufrag, pwd, fp, cand, ufrag, pwd, fp, host)


def rtsp_describe_sdp(name):
    return (
        "v=0\r\n"
        "o=- 0 0 IN IP4 0.0.0.0\r\n"
        "s=%s\r\n"
        "t=0 0\r\n"
        "a=control:*\r\n"
        "a=range:npt=now-\r\n"
        "m=video 0 RTP/AVP 96\r\n"
        "a=rtpmap:96 H264/90000\r\n"
        "a=fmtp:96 packetization-mode=1;profile-level-id=42001f\r\n"
        "a=control:trackID=0\r\n"
        "m=audio 0 RTP/AVP 97\r\n"
        "a=rtpmap:97 MPEG4-GENERIC/44100/2\r\n"
        "a=fmtp:97 streamtype=5;profile-level-id=1;mode=AAC-hbr;sizelength=13;"
        "indexlength=3;indexdeltalength=3;config=1210\r\n"
        "a=control:trackID=1\r\n"
    ) % ("go2rtc/" + ARGS.version_string)


# ---------------------------------------------------------------------------
# The old go2rtc v1.8.5 web assets (white-table era)
# ---------------------------------------------------------------------------

MAIN_JS = r"""
// main menu
document.body.innerHTML = `
<style>
ul {
    list-style: none;
    margin: 0 auto;
}

a {
    text-decoration: none;
    font-family: 'Lora', serif;
    transition: .5s linear;
}

i {
    margin-right: 10px;
}

nav {
    display: block;
    /*width: 660px;*/
    margin: 0 auto 10px;
}

nav ul {
    padding: 1em 0;
    background: #ECDAD6;
}

nav a {
    padding: 1em;
    background: rgba(177, 152, 145, .3);
    border-right: 1px solid #b19891;
    color: #695753;
}

nav a:hover {
    background: #b19891;
}

nav li {
    display: inline;
}
</style>
<nav>
    <ul>
        <li><a href="index.html">Streams</a></li>
        <li><a href="add.html">Add</a></li>
        <li><a href="editor.html">Config</a></li>
        <li><a href="log.html">Log</a></li>
    </ul>
</nav>
` + document.body.innerHTML;
"""

# near-verbatim copy of the v1.8.5 index.html (stream table + info line)
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, user-scalable=yes, initial-scale=1, maximum-scale=1">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">

    <title>go2rtc</title>

    <style>
        body {
            font-family: Arial, Helvetica, sans-serif;
            background-color: white;
        }

        table {
            background-color: white;
            text-align: left;
            border-collapse: collapse;
        }

        table td, table th {
            border: 1px solid black;
            padding: 5px 5px;
        }

        table tbody td {
            font-size: 13px;
        }

        table thead {
            background: #CFCFCF;
            background: linear-gradient(to bottom, #dbdbdb 0%, #d3d3d3 66%, #CFCFCF 100%);
            border-bottom: 3px solid black;
        }

        table thead th {
            font-size: 15px;
            font-weight: bold;
            color: black;
            text-align: center;
        }

        label {
            display: flex;
            align-items: center;
        }

        .controls {
            display: flex;
            padding: 5px;
        }

        .controls > label {
            margin-left: 10px;
        }
    </style>
</head>
<body>
<script src="main.js"></script>
<div class="info"></div>
<div class="controls">
    <button>stream</button>
    <label><input type="checkbox" name="webrtc" checked>webrtc</label>
    <label><input type="checkbox" name="mse" checked>mse</label>
    <label><input type="checkbox" name="hls" checked>hls</label>
    <label><input type="checkbox" name="mjpeg" checked>mjpeg</label>
</div>
<table>
    <thead>
    <tr>
        <th><label><input id="selectall" type="checkbox">Name</label></th>
        <th>Online</th>
        <th>Commands</th>
    </tr>
    </thead>
    <tbody id="streams">
    </tbody>
</table>
<script>
    const templates = [
        '<a href="stream.html?src={name}">stream</a>',
        '<a href="links.html?src={name}">links</a>',
        '<a href="#" data-name="{name}">delete</a>',
    ];

    document.querySelector('.controls > button')
        .addEventListener('click', () => {
            const url = new URL('stream.html', location.href);

            const streams = document.querySelectorAll('#streams input');
            streams.forEach(i => {
                if (i.checked) url.searchParams.append('src', i.name);
            });

            if (!url.searchParams.has('src')) return;

            let mode = document.querySelectorAll('.controls input');
            mode = Array.from(mode).filter(i => i.checked).map(i => i.name).join(',');

            window.location.href = `${url}&mode=${mode}`;
        });

    const tbody = document.getElementById('streams');
    tbody.addEventListener('click', ev => {
        if (ev.target.innerText !== 'delete') return;

        ev.preventDefault();

        const url = new URL('api/streams', location.href);
        const src = decodeURIComponent(ev.target.dataset.name);
        url.searchParams.set('src', src);
        fetch(url, {method: 'DELETE'}).then(reload);
    });

    document.getElementById('selectall').addEventListener('change', ev => {
        document.querySelectorAll('#streams input').forEach(el => {
            el.checked = ev.target.checked;
        });
    });

    function reload() {
        const url = new URL('api/streams', location.href);
        fetch(url, {cache: 'no-cache'}).then(r => r.json()).then(data => {
            tbody.innerHTML = '';

            for (const [name, value] of Object.entries(data)) {
                const online = value && value.consumers ? value.consumers.length : 0;
                const src = encodeURIComponent(name);
                const links = templates.map(link => {
                    return link.replace('{name}', src);
                }).join(' ');

                const tr = document.createElement('tr');
                tr.dataset['id'] = name;
                tr.innerHTML =
                    `<td><label><input type="checkbox" name="${name}">${name}</label></td>` +
                    `<td><a href="api/streams?src=${src}">${online} / info</a></td>` +
                    `<td>${links}</td>`;
                tbody.appendChild(tr);
            }
        });
    }

    const url = new URL('api', location.href);
    fetch(url, {cache: 'no-cache'}).then(r => r.json()).then(data => {
        const info = document.querySelector('.info');
        info.innerText = `Version: ${data.version}, Config: ${data.config_path}`;
    });

    reload();
</script>
</body>
</html>
"""

# near-verbatim v1.8.5 config editor — the browser-facing half of the trap
EDITOR_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <title>File Editor</title>
    <meta name="viewport" content="width=device-width, user-scalable=yes, initial-scale=1, maximum-scale=1">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <script src="https://unpkg.com/ace-builds@1.28.0/src-min/ace.js"></script>
    <style>
        body {
            font-family: Arial, Helvetica, sans-serif;
            background-color: white;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
        }

        html, body, #config {
            width: 100%;
            height: 100%;
        }
    </style>
</head>
<body>
<script src="main.js"></script>
<div>
    <button id="save">Save &amp; Restart</button>
</div>
<br>
<div id="config"></div>
<script>
    let dump;

    ace.config.set('basePath', 'https://unpkg.com/ace-builds@1.28.0/src-min/');
    const editor = ace.edit('config', {
        mode: 'ace/mode/yaml',
    });

    document.getElementById('save').addEventListener('click', async () => {
        let r = await fetch('api/config', {cache: 'no-cache'});
        if (r.ok && dump !== await r.text()) {
            alert('Config was changed from another place. Refresh the page and make changes again');
            return;
        }

        r = await fetch('api/config', {method: 'POST', body: editor.getValue()});
        if (r.ok) {
            alert('OK');
            fetch('api/restart', {method: 'POST'});
        } else {
            alert(await r.text());
        }
    });

    window.addEventListener('load', async () => {
        const r = await fetch('api/config', {cache: 'no-cache'});
        if (r.status === 410) {
            alert('Config file is not set');
        } else if (r.status === 404) {
            editor.setValue(''); // config file not exist
        } else if (r.ok) {
            dump = await r.text();
            editor.setValue(dump);
        } else {
            alert(`Unknown error: ${r.statusText} (${r.status})`);
        }
    });
</script>
</body>
</html>
"""

# v1.8.5 log viewer — reads our synthesized jsonlines from /api/log
LOG_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <title>Logs</title>
    <meta name="viewport" content="width=device-width, user-scalable=yes, initial-scale=1, maximum-scale=1">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <style>
        body {
            font-family: Arial, Helvetica, sans-serif;
            background-color: white;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
        }

        html, body {
            width: 100%;
            height: 100%;
        }

        table {
            background-color: white;
            text-align: left;
            border-collapse: collapse;
        }

        table td, table th {
            border: 1px solid black;
            padding: 5px 5px;
        }

        table tbody td {
            font-size: 13px;
            vertical-align: top;
        }

        table thead {
            background: #CFCFCF;
            background: linear-gradient(to bottom, #dbdbdb 0%, #d3d3d3 66%, #CFCFCF 100%);
            border-bottom: 3px solid black;
        }

        table thead th {
            font-size: 15px;
            font-weight: bold;
            color: black;
            text-align: center;
        }
    </style>
</head>
<body>
<script src="main.js"></script>
<div>
    <button id="clean">Clean</button>
    <button id="update">Auto Update: ON</button>
</div>
<br>
<table>
    <thead>
    <tr>
        <th style="width: 130px">Time</th>
        <th style="width: 40px">Level</th>
        <th>Message</th>
    </tr>
    </thead>
    <tbody id="log">
    </tbody>
</table>
<script>
    document.getElementById('clean').addEventListener('click', async () => {
        const r = await fetch('api/log', {method: 'DELETE'});
        if (r.ok) reload();
        alert(await r.text());
    });

    function escapeHTML(text) {
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;')
            .replace(/\n/g, '<br>');
    }

    function applyLogStyling(jsonlines) {
        const KEYS = ['time', 'level', 'message'];
        const lines = JSON.parse('[' + jsonlines.trimEnd().replaceAll('\n', ',') + ']');
        return lines.map(line => {
            const ts = new Date(line['time']);
            const msg = Object.keys(line).reduce((msg, key) => {
                return KEYS.indexOf(key) < 0 ? `${msg} ${key}=${line[key]}` : msg;
            }, line['message']);
            return `<tr><td>${ts.toLocaleString()}</td><td>${line['level']}</td><td>${escapeHTML(msg)}</td></tr>`;
        }).join('');
    }

    function reload() {
        const url = new URL('api/log', location.href);
        fetch(url, {cache: 'no-cache'})
            .then(response => response.text())
            .then(data => {
                document.getElementById('log').innerHTML = applyLogStyling(data);
            })
            .catch(error => {
                console.error('An error occurred:', error);
            });
    }

    reload();

    let autoUpdateEnabled = true;

    const update = document.getElementById('update');
    update.addEventListener('click', () => {
        autoUpdateEnabled = !autoUpdateEnabled;
        update.textContent = `Auto Update: ${autoUpdateEnabled ? 'ON' : 'OFF'}`;
    });

    setInterval(() => {
        if (autoUpdateEnabled) reload();
    }, 5000);
</script>
</body>
</html>
"""

# v1.8.5-style per-stream links page (near-verbatim; points at all the
# endpoints a curious attacker will try next)
LINKS_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <title>go2rtc - links</title>
    <meta name="viewport" content="width=device-width, user-scalable=yes, initial-scale=1, maximum-scale=1">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <style>
        body {
            font-family: Arial, Helvetica, sans-serif;
            background-color: white;
        }

        body {
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
        }

        html, body {
            width: 100%;
            height: 100%;
        }

        div {
            padding: 10px;
        }

        div > li {
            list-style-type: none;
            padding-left: 10px;
            position: relative;
        }

        div > li:before {
            content: "-";
            position: absolute;
            left: 0;
        }
    </style>
</head>
<body>
<script src="main.js"></script>
<div id="links"></div>
<script>
    const src = new URLSearchParams(location.search).get('src');

    document.getElementById('links').innerHTML = `
        <h2>Any codec in source</h2>
        <li><a href="stream.html?src=${src}">stream.html</a> with auto-select mode / browsers: all / codecs: H264, H265*, MJPEG, JPEG, AAC, PCMU, PCMA, OPUS</li>
        <li><a href="api/streams?src=${src}">info.json</a> page with active connections</li>
    `;

    const url = new URL('api', location.href);
    fetch(url, {cache: 'no-cache'}).then(r => r.json()).then(data => {
        let rtsp = location.host + ':8554';
        try {
            const host = data.host.match(/^[^:]+/)[0];
            const port = data.rtsp.listen.match(/[0-9]+$/)[0];
            rtsp = `${host}:${port}`;
        } catch (e) {
        }

        document.getElementById('links').innerHTML += `
            <li><a href="rtsp://${rtsp}/${src}">rtsp</a> with only one video and one audio / codecs: any</li>
            <li><a href="rtsp://${rtsp}/${src}?mp4">rtsp</a> for MP4 recording (Hass or Frigate) / codecs: H264, H265, AAC</li>
            <li><a href="rtsp://${rtsp}/${src}?video=all&audio=all">rtsp</a> with all tracks / codecs: any</li>

            <pre>ffplay -fflags nobuffer -flags low_delay -rtsp_transport tcp "rtsp://${rtsp}/${src}"</pre>

            <h2>H264/H265 source</h2>
            <li><a href="stream.html?src=${src}&mode=webrtc">stream.html</a> WebRTC stream / browsers: all / codecs: H264, PCMU, PCMA, OPUS / +H265 in Safari</li>
            <li><a href="stream.html?src=${src}&mode=mse">stream.html</a> MSE stream / browsers: Chrome, Firefox, Safari Mac/iPad / codecs: H264, H265*, AAC, PCMA*, PCMU*, PCM* / +OPUS in Chrome and Firefox</li>
            <li><a href="api/stream.mp4?src=${src}">stream.mp4</a> legacy MP4 stream with AAC audio / browsers: Chrome, Firefox / codecs: H264, H265*, AAC</li>
            <li><a href="api/stream.mp4?src=${src}&mp4=flac">stream.mp4</a> modern MP4 stream with common audio / browsers: Chrome, Firefox / codecs: H264, H265*, AAC, FLAC (PCMA, PCMU, PCM)</li>
            <li><a href="api/stream.mp4?src=${src}&mp4=all">stream.mp4</a> MP4 stream with any audio / browsers: Chrome / codecs: H264, H265*, AAC, OPUS, MP3, FLAC (PCMA, PCMU, PCM)</li>
            <li><a href="api/frame.mp4?src=${src}">frame.mp4</a> snapshot in MP4-format / browsers: all / codecs: H264, H265*</li>
            <li><a href="api/stream.m3u8?src=${src}">stream.m3u8</a> legacy HLS/TS / browsers: Safari all, Chrome Android / codecs: H264</li>
            <li><a href="api/stream.m3u8?src=${src}&mp4">stream.m3u8</a> legacy HLS/fMP4 / browsers: Safari all, Chrome Android / codecs: H264, H265*, AAC</li>
            <li><a href="api/stream.m3u8?src=${src}&mp4=flac">stream.m3u8</a> modern HLS/fMP4 / browsers: Safari all, Chrome Android / codecs: H264, H265*, AAC, FLAC (PCMA, PCMU, PCM)</li>

            <h2>MJPEG source</h2>
            <li><a href="stream.html?src=${src}&mode=mjpeg">stream.html</a> with MJPEG mode / browsers: all / codecs: MJPEG, JPEG</li>
            <li><a href="api/stream.mjpeg?src=${src}">stream.mjpeg</a> MJPEG stream / browsers: all / codecs: MJPEG, JPEG</li>
            <li><a href="api/frame.jpeg?src=${src}">frame.jpeg</a> snapshot in JPEG-format / browsers: all / codecs: MJPEG, JPEG</li>
        `;
    });
</script>

<div>
    <h2>Play audio</h2>
    <pre>example: ffmpeg:https://example.com/song.mp3#audio=pcma#input=file</pre>
    <input id="play-url" type="text" placeholder="url">
    <a id="play-send" href="#">send</a> / cameras with two way audio support
</div>
<script>
    document.getElementById('play-send').addEventListener('click', ev => {
        ev.preventDefault();
        const url = new URL('api/streams', location.href);
        url.searchParams.set('dst', src);
        url.searchParams.set('src', document.getElementById('play-url').value);
        fetch(url, {method: 'POST'});
    });
</script>

<div>
    <h2>Publish stream</h2>
    <pre>YouTube:  rtmps://xxx.rtmp.youtube.com/live2/xxxx-xxxx-xxxx-xxxx-xxxx
Telegram: rtmps://xxx-x.rtmp.t.me/s/xxxxxxxxxx:xxxxxxxxxxxxxxxxxxxxxx</pre>
    <input id="pub-url" type="text" placeholder="url">
    <a id="pub-send" href="#">send</a> / Telegram RTMPS server
</div>
<script>
    document.getElementById('pub-send').addEventListener('click', ev => {
        ev.preventDefault();
        const url = new URL('api/streams', location.href);
        url.searchParams.set('src', src);
        url.searchParams.set('dst', document.getElementById('pub-url').value);
        fetch(url, {method: 'POST'});
    });
</script>

<div id="webrtc">
    <h2>WebRTC Magic</h2>
    <label><input type="radio" name="webrtc" value="video+audio" checked>video+audio = simple viewer</label><br>
    <label><input type="radio" name="webrtc" value="video+audio+microphone">video+audio+microphone = two way audio from camera</label><br>
    <label><input type="radio" name="webrtc" value="camera+microphone">camera+microphone = stream from browser</label><br>
    <label><input type="radio" name="webrtc" value="display+speaker">display+speaker = broadcast software</label><br>

    <br>
    <li><a id="local" href="webrtc.html?src=">webrtc.html</a> local WebRTC viewer</li>
</div>
<script>
    function webrtcLinksUpdate() {
        const media = document.querySelector('input[name="webrtc"]:checked').value;

        const direction = media.indexOf('video') >= 0 || media === 'audio' ? 'src' : 'dst';
        document.getElementById('local').href = `webrtc.html?${direction}=${src}&media=${media}`;
    }

    document.getElementById('webrtc').addEventListener('click', ev => {
        if (ev.target.tagName === 'INPUT') webrtcLinksUpdate();
    });

    webrtcLinksUpdate();
</script>

</body>
</html>
"""

# v1.8.5 stream viewer shell (verbatim), driven by our video-stream.js
STREAM_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>go2rtc - Stream</title>
    <style>
        body {
            background: black;
            margin: 0;
            padding: 0;
            display: flex;
            font-family: Arial, Helvetica, sans-serif;
        }

        html, body {
            height: 100%;
            width: 100%;
        }

        .flex {
            flex-wrap: wrap;
            align-content: flex-start;
            align-items: flex-start;
        }
    </style>
</head>
<body>
<script type="module" src="./video-stream.js"></script>
<script type="module">
    const params = new URLSearchParams(location.search);

    // support multiple streams and multiple modes
    const streams = params.getAll('src');
    const modes = params.getAll('mode');
    if (modes.length === 0) modes.push('');

    while (modes.length > streams.length) {
        streams.push(streams[0]);
    }
    while (streams.length > modes.length) {
        modes.push(modes[0]);
    }

    if (streams.length > 1) {
        document.body.className = 'flex';
    }

    const background = params.get('background') !== 'false';
    const width = '1 0 ' + (params.get('width') || '320px');

    for (let i = 0; i < streams.length; i++) {
        /** @type {VideoStream} */
        const video = document.createElement('video-stream');
        video.background = background;
        video.mode = modes[i] || video.mode;
        video.style.flex = width;
        video.src = new URL('api/webrtc?src=' + encodeURIComponent(streams[i]), location.href);
        document.body.appendChild(video);
    }
</script>
</body>
</html>
"""

# our stand-in for the v1.8.5 video-stream.js player (sync WebRTC + mjpeg)
VIDEO_STREAM_JS = r"""// video-stream.js — go2rtc-style player (sync /api/webrtc signaling)
const template = document.createElement('template');
template.innerHTML = `
    <style>
        :host {
            display: block;
            position: relative;
            background: black;
            border: 1px solid #333;
        }
        video, img {
            display: block;
            width: 100%;
        }
        #status {
            position: absolute;
            top: 6px;
            left: 8px;
            color: #aaa;
            font: 12px/1.4 Arial, Helvetica, sans-serif;
            background: rgba(0,0,0,.55);
            padding: 2px 6px;
            border-radius: 3px;
        }
        #close {
            position: absolute;
            top: 6px;
            right: 8px;
            display: none;
            color: #aaa;
            font: 12px/1.4 Arial, Helvetica, sans-serif;
            background: rgba(0,0,0,.55);
            padding: 2px 6px;
            border-radius: 3px;
            cursor: pointer;
        }
    </style>
    <video autoplay muted playsinline></video>
    <img alt="" style="display:none">
    <div id="status">Connecting…</div>
    <div id="close">✕</div>
`;

class VideoStream extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({mode: 'open'}).appendChild(template.content.cloneNode(true));
        this._mode = '';
        this._pc = null;
        this._timer = null;

        this.shadowRoot.getElementById('close').onclick = () => this.stop();
    }

    connectedCallback() {
        if (!this.src) return;
        if (this._mode === 'mjpeg') {
            this.startMjpeg();
        } else {
            this.startWebrtc();
        }
    }

    disconnectedCallback() {
        this.stop();
    }

    get mode() {
        return this._mode;
    }

    set mode(value) {
        this._mode = value;
    }

    get src() {
        return this._src || '';
    }

    set src(value) {
        this._src = value;
    }

    status(text) {
        this.shadowRoot.getElementById('status').innerText = text;
        this.shadowRoot.getElementById('close').style.display = text ? '' : 'none';
    }

    stop() {
        clearTimeout(this._timer);
        if (this._pc) this._pc.close(), this._pc = null;
    }

    async startMjpeg() {
        const src = new URL(this.src, location.href);
        src.pathname = src.pathname.replace('/api/webrtc', '/api/stream.mjpeg');
        this.shadowRoot.querySelector('video').style.display = 'none';
        const img = this.shadowRoot.querySelector('img');
        img.style.display = '';
        img.src = src.href;
        this.status('');
    }

    async startWebrtc() {
        try {
            const offer = {
                type: 'offer',
                sdp: [
                    'v=0',
                    'o=- 4611731400430051336 2 IN IP4 127.0.0.1',
                    's=-',
                    't=0 0',
                    'a=group:BUNDLE 0 1',
                    'a=msid-semantic: WMS',
                    'm=video 9 UDP/TLS/RTP/SAVPF 96',
                    'c=IN IP4 0.0.0.0',
                    'a=ice-ufrag:EsAw',
                    'a=ice-pwd:P2uYro0UCOQ4zxRA52fdgZ00',
                    'a=fingerprint:sha-256 D2:FA:0E:C3:22:59:5E:14:95:69:92:0D:35:DE:00:36:89:8D:6E:C4:22:6F:5A:4B:53:1A:1B:EA:73:8B:F7:BD',
                    'a=setup:actpass',
                    'a=mid:0',
                    'a=sendrecv',
                    'a=rtpmap:96 H264/90000',
                    'a=rtcp-fb:96 nack pli',
                    'a=rtcp-mux',
                    'm=audio 9 UDP/TLS/RTP/SAVPF 111',
                    'c=IN IP4 0.0.0.0',
                    'a=ice-ufrag:EsAw',
                    'a=ice-pwd:P2uYro0UCOQ4zxRA52fdgZ00',
                    'a=fingerprint:sha-256 D2:FA:0E:C3:22:59:5E:14:95:69:92:0D:35:DE:00:36:89:8D:6E:C4:22:6F:5A:4B:53:1A:1B:EA:73:8B:F7:BD',
                    'a=setup:actpass',
                    'a=mid:1',
                    'a=sendrecv',
                    'a=rtpmap:111 opus/48000/2',
                    'a=rtcp-mux',
                ].join('\r\n') + '\r\n',
            };

            const r = await fetch(this.src, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(offer),
            });
            const answer = await r.json();
            if (!answer.sdp) throw new Error('no answer');

            this._pc = new RTCPeerConnection();
            await this._pc.setRemoteDescription(answer);

            this._pc.ontrack = () => this.status('');
            this._pc.onconnectionstatechange = () => {
                if (this._pc.connectionState === 'failed') this.status('No signal');
            };

            const video = this.shadowRoot.querySelector('video');
            video.srcObject = null; // replaced below when tracks arrive
            this._pc.ontrack = ev => {
                if (ev.streams[0]) video.srcObject = ev.streams[0];
                this.status('');
            };

            this.status('Connecting…');
            this._timer = setTimeout(() => {
                if (this._pc && this._pc.connectionState !== 'connected') {
                    this.status('No signal');
                }
            }, 5000);
        } catch (e) {
            this.status('No signal');
        }
    }
}

customElements.define('video-stream', VideoStream);
"""

# old-school sync WebRTC viewer page (v1.8.5 had webrtc.html doing this
# through video-rtc.js; ours uses the sync /api/webrtc endpoint)
WEBRTC_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>go2rtc - WebRTC</title>
    <style>
        body {
            background: black;
            margin: 0;
            padding: 0;
            color: #aaa;
            font-family: Arial, Helvetica, sans-serif;
        }
        video {
            width: 100%;
            background: black;
        }
        #status {
            padding: 6px 10px;
            font-size: 13px;
        }
    </style>
</head>
<body>
<script src="main.js"></script>
<video autoplay muted playsinline></video>
<div id="status">Connecting…</div>
<script>
    const params = new URLSearchParams(location.search);
    const src = params.get('src') || params.get('dst');

    const offer = {
        type: 'offer',
        sdp: 'v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n' +
            'a=group:BUNDLE 0\r\na=msid-semantic: WMS\r\n' +
            'm=video 9 UDP/TLS/RTP/SAVPF 96\r\nc=IN IP4 0.0.0.0\r\n' +
            'a=ice-ufrag:EsAw\r\na=ice-pwd:P2uYro0UCOQ4zxRA52fdgZ00\r\n' +
            'a=fingerprint:sha-256 D2:FA:0E:C3:22:59:5E:14:95:69:92:0D:35:DE:00:36:89:8D:6E:C4:22:6F:5A:4B:53:1A:1B:EA:73:8B:F7:BD\r\n' +
            'a=setup:actpass\r\na=mid:0\r\na=sendrecv\r\n' +
            'a=rtpmap:96 H264/90000\r\na=rtcp-fb:96 nack pli\r\na=rtcp-mux\r\n'
    };

    fetch('api/webrtc?src=' + encodeURIComponent(src), {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(offer),
    }).then(r => r.json()).then(answer => {
        const pc = new RTCPeerConnection();
        pc.ontrack = ev => {
            document.querySelector('video').srcObject = ev.streams[0];
            document.getElementById('status').innerText = '';
        };
        pc.onconnectionstatechange = () => {
            if (pc.connectionState === 'failed')
                document.getElementById('status').innerText = 'No signal';
        };
        pc.setRemoteDescription(answer);
        setTimeout(() => {
            if (pc.connectionState !== 'connected')
                document.getElementById('status').innerText = 'No signal';
        }, 5000);
    }).catch(() => {
        document.getElementById('status').innerText = 'No signal';
    });
</script>
</body>
</html>
"""

# v1.8.5 "Add" page — trimmed to the parts backed by real endpoints
ADD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <title>Add Stream</title>
    <meta name="viewport" content="width=device-width, user-scalable=yes, initial-scale=1, maximum-scale=1">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <style>
        body {
            font-family: Arial, Helvetica, sans-serif;
            background-color: white;
        }

        body {
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
        }

        html, body {
            width: 100%;
            height: 100%;
        }

        .module {
            display: none;
            padding: 10px;
        }

        table {
            background-color: white;
            text-align: left;
            border-collapse: collapse;
        }

        table td, table th {
            border: 1px solid black;
            padding: 5px 5px;
        }

        table tbody td {
            font-size: 13px;
        }

        table thead {
            background: #CFCFCF;
            background: linear-gradient(to bottom, #dbdbdb 0%, #d3d3d3 66%, #CFCFCF 100%);
            border-bottom: 3px solid black;
        }

        table thead th {
            font-size: 15px;
            font-weight: bold;
            color: black;
            text-align: center;
        }
    </style>
</head>
<body>
<script src="main.js"></script>
<script>
    function drawTable(table, data) {
        const cols = ['id', 'name', 'info', 'url', 'location'];
        const th = (row) => cols.reduce((html, k) => k in row ? `${html}<th>${k}</th>` : html, '<tr>') + '</tr>';
        const td = (row) => cols.reduce((html, k) => k in row ? `${html}<td>${row[k]}</td>` : html, '<tr>') + '</tr>';

        const thead = th(data.sources[0]);
        const tbody = data.sources.reduce((html, source) => `${html}${td(source)}`, '');

        table.innerHTML = `<thead>${thead}</thead><tbody>${tbody}</tbody>`;
    }

    async function getSources(tableID, url) {
        const table = document.getElementById(tableID);
        table.innerText = 'loading...';

        const r = typeof url === 'string' ? await fetch(url, {cache: 'no-cache'}) : url;
        if (!r.ok) {
            table.innerText = await r.text();
            return;
        }

        drawTable(table, await r.json());
    }
</script>

<button id="stream">Temporary stream</button>
<div class="module">
    <form id="stream-form" style="padding: 10px">
        <input type="text" name="name" placeholder="name">
        <input type="text" name="src" placeholder="url">
        <input type="submit" value="add">
    </form>
</div>
<script>
    document.getElementById('stream').addEventListener('click', async ev => {
        ev.target.nextElementSibling.style.display = 'block';
    });

    document.getElementById('stream-form').addEventListener('submit', async ev => {
        ev.preventDefault();

        const url = new URL('api/streams', location.href);
        url.searchParams.set('name', ev.target.elements['name'].value);
        url.searchParams.set('src', ev.target.elements['src'].value);

        const r = await fetch(url, {method: 'PUT'});
        alert(r.ok ? 'OK' : 'ERROR: ' + await r.text());
    });
</script>

<button id="onvif">ONVIF</button>
<div class="module">
    <form id="onvif-form" style="padding: 10px">
        <input type="text" name="src" placeholder="onvif://user:pass@192.168.1.123:80" size="50">
        <input type="submit" value="test">
    </form>
    <table id="onvif-table"></table>
</div>
<script>
    document.getElementById('onvif').addEventListener('click', async ev => {
        ev.target.nextElementSibling.style.display = 'block';
        await getSources('onvif-table', 'api/onvif');
    });

    document.getElementById('onvif-form').addEventListener('submit', async ev => {
        ev.preventDefault();

        const url = new URL('api/onvif', location.href);
        url.searchParams.set('src', ev.target.elements['src'].value);

        await getSources('onvif-table', url.toString());
    });
</script>

<button id="devices">FFmpeg Devices (USB)</button>
<div class="module">
    <table id="devices-table"></table>
</div>
<script>
    document.getElementById('devices').addEventListener('click', async ev => {
        ev.target.nextElementSibling.style.display = 'block';
        await getSources('devices-table', 'api/ffmpeg/devices');
    });
</script>

<button id="hardware">FFmpeg Hardware</button>
<div class="module">
    <table id="hardware-table"></table>
</div>
<script>
    document.getElementById('hardware').addEventListener('click', async ev => {
        ev.target.nextElementSibling.style.display = 'block';
        await getSources('hardware-table', 'api/ffmpeg/hardware');
    });
</script>

</body>
</html>
"""

STATIC_FILES = {
    "/": ("text/html; charset=utf-8", INDEX_HTML),
    "/index.html": ("text/html; charset=utf-8", INDEX_HTML),
    "/add.html": ("text/html; charset=utf-8", ADD_HTML),
    "/editor.html": ("text/html; charset=utf-8", EDITOR_HTML),
    "/links.html": ("text/html; charset=utf-8", LINKS_HTML),
    "/log.html": ("text/html; charset=utf-8", LOG_HTML),
    "/stream.html": ("text/html; charset=utf-8", STREAM_HTML),
    "/webrtc.html": ("text/html; charset=utf-8", WEBRTC_HTML),
    "/main.js": ("text/javascript; charset=utf-8", MAIN_JS),
    "/video-stream.js": ("text/javascript; charset=utf-8", VIDEO_STREAM_JS),
}


# ---------------------------------------------------------------------------
# HTTP handler — mirrors Go net/http + go2rtc v1.8.5 handler semantics
# ---------------------------------------------------------------------------

class GoHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 60          # per-request socket timeout (slowloris guard)
    server_version = ""   # never advertise python (Go sends no Server header)
    sys_version = ""

    # -- plumbing ----------------------------------------------------------
    def log_message(self, fmt, *args):  # silence default stderr logging
        pass

    def version_string(self):
        return ""

    def address_string(self):
        return self.client_address[0]

    def _client_ip(self, peer):
        """Evidence IP. With --trust-proxy (the pot sits behind the
        operator's own nginx) the attacker address comes from the proxy:
        X-Real-IP first, else the rightmost X-Forwarded-For hop — the hop
        OUR proxy appended, not something the client can spoof into first
        position. Otherwise the direct peer is the truth."""
        if ARGS.trust_proxy:
            cand = (self.headers.get("X-Real-IP") or "").strip()
            if not cand:
                xff = (self.headers.get("X-Forwarded-For") or "").strip()
                if xff:
                    cand = xff.split(",")[-1].strip()
            if cand:
                try:
                    ipaddress.ip_address(cand)
                    return cand
                except ValueError:
                    pass
        return peer

    # -- request body ------------------------------------------------------
    def _read_body(self):
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            data = bytearray()
            while True:
                line = self.rfile.readline(1024).strip()
                try:
                    size = int(line.split(b";")[0], 16)
                except ValueError:
                    raise IOError("bad chunk")
                if size == 0:
                    while True:
                        t = self.rfile.readline(1024)
                        if t in (b"\r\n", b"\n", b""):
                            break
                    break
                data += self.rfile.read(size)
                self.rfile.readline(1024)
                if len(data) >= ARGS.max_body:
                    self.close_connection = True
                    return bytes(data[:ARGS.max_body]), True
            return bytes(data), False
        cl = self.headers.get("Content-Length")
        if cl is None:
            return b"", False
        try:
            n = int(cl)
        except ValueError:
            raise IOError("bad content-length")
        if n > ARGS.max_body:
            self.close_connection = True
            n = ARGS.max_body
            self.rfile.read(n)
            return b"", True
        return self.rfile.read(n), False

    # -- responses (Go-flavored) ---------------------------------------------
    def respond(self, status, body=b"", ctype=None, extra=None, close=False):
        if isinstance(body, str):
            body = body.encode("utf-8")
        try:
            self.wfile.write(("HTTP/1.1 %d %s\r\n" % (status, HTTP_REASONS.get(status, "Status"))).encode())
            self.send_header("Date", self.date_time_string())
            if ctype:
                self.send_header("Content-Type", ctype)
            if status >= 400:
                self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            if status not in (204, 304):
                self.send_header("Content-Length", str(len(body)))
            if close:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            if self.command != "HEAD" and body:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    # Go: http.Error(w, msg, code) → "msg\n", text/plain; charset=utf-8, nosniff
    def go_error(self, status, msg=""):
        self.respond(status, (msg + "\n").encode(), "text/plain; charset=utf-8")

    def go_not_found(self):
        self.respond(404, b"404 page not found\n", "text/plain; charset=utf-8")

    # Go: api.ResponseJSON — "application/json", trailing \n
    def go_json(self, obj, status=200, pretty=False, close=False):
        if pretty:
            body = json.dumps(obj, indent=2, sort_keys=True) + "\n"
        else:
            body = json.dumps(obj, sort_keys=True) + "\n"
        self.respond(status, body, "application/json", close=close)

    def go_empty(self, status=200, close=False):
        self.respond(status, b"", close=close)

    # -- hybrid mode: relay to the REAL go2rtc -------------------------------
    PASSTHROUGH_FWD_HEADERS = ("Content-Type", "Range", "Accept",
                                "Authorization", "User-Agent")

    def upstream_check(self, name):
        """Hybrid routing decision for a stream name: hand it to the REAL
        go2rtc only when it is neither attacker-planted nor 'deleted' by an
        attacker. Everything else is ours to fake."""
        return (ARGS.upstream
                and name not in STATE.deleted_names
                and not STATE.is_planted(name))

    def _is_ui_client(self):
        """True when this looks like the go2rtc WebUI loading in a browser
        (the real `fetch('api/streams')` carries Sec-Fetch-* headers and a
        Referer; curl/python exploits do not)."""
        return bool(self.headers.get("Sec-Fetch-Site")
                    or self.headers.get("Sec-Fetch-Mode")
                    or self.headers.get("Referer"))

    def passthrough(self, body=None):
        """Relay this request to the real go2rtc and stream the response
        back. Used in hybrid mode for anything that doesn't involve an
        attacker-planted stream. Binary bodies (media, SDP) pass through
        untouched; JSON goes through passthrough_json (scrubbed)."""
        url = ARGS.upstream.rstrip("/") + self.path
        req = urllib.request.Request(
            url,
            data=body if (body and self.command in ("POST", "PUT", "PATCH")) else None,
            method=self.command)
        for h in self.PASSTHROUGH_FWD_HEADERS:
            v = self.headers.get(h)
            if v:
                req.add_header(h, v)
        try:
            r = urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT)
        except urllib.error.HTTPError as e:
            r = e
        except Exception:
            self.go_error(502, "")
            return 502
        try:
            status = getattr(r, "status", None) or getattr(r, "code", 200)
            ctype = r.headers.get("Content-Type")
            self.wfile.write(("HTTP/1.1 %d %s\r\n" % (status, HTTP_REASONS.get(status, "Status"))).encode())
            self.send_header("Date", self.date_time_string())
            if ctype:
                self.send_header("Content-Type", ctype)
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            if self.command == "HEAD":
                return status
            while True:
                chunk = r.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            try:
                r.close()
            except Exception:
                pass
        return status

    def passthrough_json(self, body=None):
        """Fetch the upstream response as JSON, scrub credentials from any
        'url' fields, and re-serve it (pretty like go2rtc's single-stream
        API). Falls back to a raw passthrough on parse errors."""
        try:
            st, ct, up_body = upstream_fetch(self.command, self.path, body,
                                             self.headers.get("Content-Type"))
        except UpstreamError:
            self.go_error(502, "")
            return 502
        try:
            data = json.loads(up_body)
        except Exception:
            self.respond(st, up_body, ct or "application/json", close=True)
            self.close_connection = True
            return st
        scrubbed = scrub_json_creds(data)
        self.go_json(scrubbed, status=st, pretty=isinstance(data, dict), close=True)
        self.close_connection = True
        return st

    # -- main dispatch -------------------------------------------------------
    def _handle(self):
        t0 = time.perf_counter()
        peer, port = self.client_address[0], self.client_address[1]
        ip = self._client_ip(peer)
        self._planted_view = None
        raw = self.path
        split = urllib.parse.urlsplit(raw)
        path = urllib.parse.unquote(split.path) or "/"
        query = split.query
        q = urllib.parse.parse_qs(query, keep_blank_values=True)
        method = self.command

        body, oversized = b"", False
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            try:
                body, oversized = self._read_body()
            except (IOError, OSError):
                self.go_error(400, "")
                return

        body_text = body.decode("utf-8", "replace") if body else ""
        rid = short_id()
        rec = {
            "id": rid, "ts": utcnow_iso(), "kind": "http", "ip": ip, "port": port,
            "peer": peer if peer != ip else None,
            "method": method, "path": path,
            "query": query if query else None,
            "ua": self.headers.get("User-Agent"),
            "host": self.headers.get("Host"),
            "auth": self.headers.get("Authorization"),
            "xff": self.headers.get("X-Forwarded-For"),
            "clen": len(body),
        }
        if oversized:
            rec["oversized"] = True

        status = self._route(method, path, q, body, body_text, rec)

        rec["status"] = status
        rec["dur_ms"] = int((time.perf_counter() - t0) * 1000)
        rec["body_preview"] = body_text[:512] if body_text else None
        EV.access(rec)

        # alerting — wrapped so that no analysis bug can kill a request thread
        try:
            # classify against the DECODED query too — attackers hide
            # payloads in URL params (%23 for #, etc.)
            decoded_q = urllib.parse.unquote_plus(query) if query else ""
            tags, severity, note = classify(method, path, decoded_q, body_text)

            # the RCE-trigger moment: someone consuming a stream they planted
            pv = self._planted_view
            if pv:
                pv_tag, pv_sev = pv
                tags = tags + ([pv_tag] if pv_tag not in tags else [])
                severity = severity or "low"
                if SEV_RANK[pv_sev] > SEV_RANK[severity]:
                    severity = pv_sev
                trig = ("viewing a stream they planted — on a real go2rtc "
                        "this is the moment their ffmpeg #command runs")
                note = (note + " · " + trig) if note else trig

            if oversized:
                tags = tags + ["oversized"]
                severity = "medium"
                note = (note + " · request body exceeded %d MB cap" % (ARGS.max_body // (1024 * 1024))).strip(" ·")
            if tags:
                alert = dict(rec)
                alert.pop("body_preview", None)
                alert.update({
                    "kind": "alert", "severity": severity or "low", "tags": tags,
                    "body": body_text[:MAX_BODY_DEFAULT] if body_text else None,
                    "body_len": len(body), "note": note or None,
                })
                EV.alert(alert, body if body else None)
                self._maybe_fakelog(tags, q, body_text)
        except Exception as e:
            CON.dim("alert pipeline error: %r" % e)

    def _maybe_fakelog(self, tags, q, body_text):
        """Feed the fake go2rtc memory log so /api/log tells the attacker
        the story they want to believe."""
        if "restart_attempt" in tags:
            MEMLOG.add("go2rtc version %s %s" % (MEMLOG.version(), GO2RTC_ARCH), "info")
            MEMLOG.add("[app] config path=%s" % ARGS.config_path_label, "info")

    def _consumer_note(self, src):
        """When someone 'watches' a stream whose source is an attacker-planted
        ffmpeg: producer, log the producer start in the fake go2rtc log —
        exactly what a successfully exploited go2rtc would print. If the
        stream itself was planted by an attacker, flag the request: on a
        real instance this is the moment their ffmpeg #command would run."""
        sources = STATE.get_stream(src)
        if not sources:
            return
        if src in STATE.meta:
            hot = any(FFMPEG_CMD_RE.search(s) or EXEC_RE.search(s)
                      or s.startswith("ffmpeg:") for s in sources)
            self._planted_view = ("planted_view", "high" if hot else "medium")
        for prod in sources:
            if prod.startswith("ffmpeg:"):
                MEMLOG.add("[streams] start producer url=%s" % prod, "debug")

    # -- routing table --------------------------------------------------------
    def _route(self, method, path, q, body, body_text, rec):
        ip = rec["ip"]

        if oversized := rec.get("oversized"):
            self.go_error(413, "")
            return 413

        # static UI (Go http.FileServer flavor)
        if method in ("GET", "HEAD") and path in STATIC_FILES:
            if ARGS.upstream:
                # HYBRID: the real instance owns the whole UI. Relay every
                # page/asset upstream instead of serving our own old-era
                # pages — so no matter what nginx routes here, /add.html,
                # /index.html, /main.js… are byte-identical to the real
                # one (a trimmed 1.8.x page next to a 1.9.x /api would
                # betray the decoy instantly).
                return self.passthrough()
            ctype, text = STATIC_FILES[path]
            self.respond(200, text.encode("utf-8"), ctype,
                         extra={"Accept-Ranges": "bytes"})
            return 200

        # ---- /api ----
        if path == "/api":
            if ARGS.upstream:
                # hybrid: adopt the REAL instance's identity, but keep the
                # client-visible host so nothing betrays the hop
                try:
                    st, ct, body = upstream_fetch("GET", "/api")
                    info = json.loads(body)
                    if isinstance(info, dict):
                        info["host"] = self.headers.get("Host") or ""
                        self.go_json(info)
                        return 200
                except Exception:
                    pass
            info = {
                "version": ARGS.version_string,
                "config_path": ARGS.config_path_label,
                "host": self.headers.get("Host") or "",
                "rtsp": {"listen": ":%d" % ARGS.rtsp_port if ARGS.rtsp_port else ":8554",
                         "default_query": "video&audio"},
            }
            rev = ARGS.revision or (STATE.upstream_revision if STATE else "")
            if rev:
                # 1.9.x builds include a git revision in /api
                info["revision"] = rev
            self.go_json(info)
            return 200

        # ---- /api/config — THE TRAP ----
        if path == "/api/config":
            if method == "GET":
                self.respond(200, STATE.config_text().encode("utf-8"), "application/yaml")
                return 200
            if method == "HEAD":
                self.go_empty(200)
                return 200
            if method in ("POST", "PATCH"):
                if not body_text.strip():
                    # empty body: real v1.8.5 happily writes an empty config
                    if method == "POST":
                        STATE.apply_config("", ip)
                    self.go_empty(200)
                    return 200
                err = yaml_body_error(body_text)
                if err:
                    self.go_error(500, err)
                    return 500
                if method == "POST":
                    STATE.apply_config(body_text, ip)
                else:
                    STATE.patch_config(body_text, ip)
                # real v1.8.5: 200 with an EMPTY body (config.go falls through)
                self.go_empty(200)
                return 200
            # other methods on /api/config: switch has no case → 200 empty
            self.go_empty(200)
            return 200

        # ---- /api/streams ----
        if path == "/api/streams":
            src = (q.get("src") or [""])[0]
            dst = (q.get("dst") or [""])[0]
            name = (q.get("name") or [""])[0]
            if src == "" and method != "POST":
                if ARGS.upstream:
                    if ARGS.hide_planted_from_ui and self._is_ui_client():
                        # A browser rendering OUR WebUI: show the REAL list,
                        # untouched — the operator's UI stays clean and the
                        # pot's planted rows never leak into it. Scripted
                        # clients (curl/python exploits) still get the merged
                        # view, so the attacker still sees what they planted.
                        try:
                            st, ct, up_body = upstream_fetch("GET", "/api/streams")
                            self.go_json(scrub_json_creds(json.loads(up_body)), status=st)
                            return st
                        except Exception:
                            pass   # fall through to the merged view
                    # hybrid: live merge of the real streams + planted ones
                    self.go_json(STATE.merged_streams_json())
                else:
                    self.go_json(STATE.streams_json())
                return 200
            if method == "GET":
                if self.upstream_check(src):
                    # a real stream: relay the upstream view (creds scrubbed)
                    return self.passthrough_json()
                stream = STATE.get_stream(src)
                self.go_json({"producers": [{"url": s} for s in (stream or [])],
                              "consumers": None} if stream else None, pretty=True)
                return 200
            if method == "PUT":
                if re.search(r"\s", src):
                    self.go_error(400, "")   # streams.New() rejects spaces
                    return 400
                target = name or src
                STATE.put_stream(target, [src], ip, persist=True)
                self.go_empty(200)
                return 200
            if method == "PATCH":
                if not name:
                    self.go_error(400, "")
                    return 400
                if not STATE.has_scheme(src):
                    self.go_error(400, "")
                    return 400
                STATE.put_stream(name, [src], ip, persist=False)
                self.go_empty(200)
                return 200
            if method == "POST":
                # Never relayed upstream, even in hybrid mode. POST
                # /api/streams?src=<stream>&dst=<relay url> is go2rtc's
                # publish/play path: relaying it would ship a REAL camera
                # feed to an attacker-chosen RTMP/RTSP endpoint. The pot
                # replies the way a real go2rtc would and alerts instead.
                if not dst:
                    self.go_error(400, "")
                    return 400
                if STATE.get_stream(dst) is not None:
                    # "play into a stream" — src must name a stream too
                    stream = STATE.get_stream(src)
                    if stream is not None:
                        self.go_json({"producers": [{"url": x} for x in stream],
                                      "consumers": None})
                        return 200
                    self.go_error(500, "")
                    return 500
                if STATE.get_stream(src) is not None:
                    # "publish": real go2rtc would push and return an empty
                    # 200 — answer identically, do nothing, keep the evidence
                    self.go_empty(200)
                    return 200
                self.go_error(404, "")
                return 404
            if method == "DELETE":
                STATE.delete_stream(src)
                self.go_empty(200)
                return 200
            self.go_not_found()
            return 404

        # ---- /api/webrtc (sync signaling, v1.8.5 server.go) ----
        if path == "/api/webrtc":
            if method == "POST":
                src = (q.get("src") or [""])[0]
                dst = (q.get("dst") or [""])[0]
                if src:
                    if self.upstream_check(src):
                        # real stream: let the real go2rtc negotiate WebRTC
                        return self.passthrough(body)
                    stream = STATE.get_stream(src)
                    if stream is None:
                        # faithful v1.8.5 quirk: silent 200, empty body
                        self.go_empty(200)
                        return 200
                    self._consumer_note(src)
                    ct = (self.headers.get("Content-Type") or "")
                    media, _, _ = ct.partition(";")
                    media = media.strip().lower()
                    answer = fabricate_answer_sdp(src)
                    if media == "application/json":
                        # parse their offer sdp enough to be polite
                        try:
                            json.loads(body_text)
                        except Exception:
                            self.go_error(400, "invalid character after top-level value")
                            return 400
                        self.go_json({"type": "answer", "sdp": answer})
                        return 200
                    if media == "application/sdp":
                        self.respond(201, answer.encode(), "application/sdp")
                        return 201
                    # raw SDP exchange — mirrors v1.8.5 outputWebRTC: echoes
                    # the request's own Content-Type, or none at all
                    if media:
                        self.respond(200, answer.encode(), media)
                    else:
                        self.respond(200, answer.encode(), "text/plain; charset=utf-8")
                    return 200
                if dst:
                    if self.upstream_check(dst):
                        return self.passthrough(body)
                    if STATE.get_stream(dst) is None:
                        self.go_error(404, "stream not found")
                        return 404
                    sid = "%x" % (time.time_ns() // 1000)
                    self.respond(201, fabricate_answer_sdp(dst).encode(),
                                 "application/sdp",
                                 extra={"Location": "webrtc?id=" + sid})
                    return 201
                self.go_error(400, "")
                return 400
            if method == "PATCH":
                self.go_error(405, "")
                return 405
            if method == "DELETE":
                self.go_error(404, "")   # session never exists for us
                return 404
            if method == "OPTIONS":
                self.go_empty(204)
                return 204
            self.go_error(405, "")
            return 405

        # ---- /api/frame.jpeg ----
        if path == "/api/frame.jpeg" and method in ("GET", "HEAD"):
            src = (q.get("src") or [""])[0]
            if self.upstream_check(src):
                return self.passthrough()
            if STATE.get_stream(src) is None:
                self.go_error(404, "stream not found")
                return 404
            self._consumer_note(src)
            frame = base64.b64decode(CAMERA_FRAME_JPEG_B64)
            self.respond(200, frame, "image/jpeg", extra={
                "Cache-Control": "no-cache", "Pragma": "no-cache"}, close=True)
            return 200

        # ---- /api/stream.mjpeg ----
        if path == "/api/stream.mjpeg":
            src = (q.get("src") or [""])[0] if method != "POST" else None
            dst = (q.get("dst") or [""])[0] if method == "POST" else None
            if method == "POST":
                if self.upstream_check(dst):
                    return self.passthrough(body)
                if STATE.get_stream(dst) is None:
                    self.go_error(404, "stream not found")
                    return 404
                self.go_empty(200)
                return 200
            if self.upstream_check(src):
                return self.passthrough()
            if STATE.get_stream(src) is None:
                self.go_error(404, "stream not found")
                return 404
            self._consumer_note(src)
            frame = base64.b64decode(CAMERA_FRAME_JPEG_B64)
            try:
                self.wfile.write(("HTTP/1.1 200 OK\r\n").encode())
                self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.send_header("Pragma", "no-cache")
                self.end_headers()
                self.close_connection = True
                part = (b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n"
                        % len(frame)) + frame + b"\r\n"
                for _ in range(MJPEG_MAX_FRAMES):
                    self.wfile.write(part)
                    time.sleep(1.0 / MJPEG_FPS)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            return 200

        # ---- /api/stream.m3u8 ----
        if path == "/api/stream.m3u8" and method in ("GET", "HEAD"):
            src = (q.get("src") or [""])[0]
            if self.upstream_check(src):
                return self.passthrough()
            if STATE.get_stream(src) is None:
                self.go_error(404, "stream not found")
                return 404
            self._consumer_note(src)
            seq = int(time.time()) // 2
            playlist = ("#EXTM3U\n"
                        "#EXT-X-VERSION:3\n"
                        "#EXT-X-TARGETDURATION:2\n"
                        "#EXT-X-MEDIA-SEQUENCE:%d\n" % seq +
                        "#EXTINF:2.0,\n"
                        "segment.ts?src=%s\n" % urllib.parse.quote(src, safe=""))
            self.respond(200, playlist.encode(), "application/vnd.apple.mpegurl",
                          extra={"Cache-Control": "no-cache", "Connection": "close"},
                          close=True)
            return 200

        # ---- /api/stream.mp4, /api/frame.mp4, HLS segments ----
        if path in ("/api/stream.mp4", "/api/frame.mp4", "/api/segment.ts") \
                and method in ("GET", "HEAD"):
            src = (q.get("src") or [""])[0]
            if self.upstream_check(src):
                return self.passthrough()
            if STATE.get_stream(src) is None:
                self.go_error(404, "stream not found")
                return 404
            self._consumer_note(src)
            ctype = "video/mp2t" if path.endswith(".ts") else "video/mp4"
            # camera "offline": headers arrive, media never does
            try:
                self.wfile.write(("HTTP/1.1 200 OK\r\n").encode())
                self.send_header("Content-Type", ctype)
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                time.sleep(STREAM_STALL_SECONDS)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            return 200

        # ---- /api/exit — the process-death illusion ----
        if path == "/api/exit":
            if method != "POST":
                self.go_error(400, "")
                return 400
            code = (q.get("code") or [""])[0]
            try:
                c = int(code)
                assert 0 <= c <= 125
            except Exception:
                self.go_error(400, "Code must be in the range [0, 125]")
                return 400
            # real go2rtc calls os.Exit(code): connection dies mid-response.
            # we keep living but drop the connection the same way.
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.close_connection = True
            return 0  # nothing written

        # ---- /api/restart ----
        if path == "/api/restart":
            if method != "POST":
                self.go_error(400, "")
                return 400
            STATE.reset_runtime()
            self.go_empty(200)
            return 200

        # ---- /api/log ----
        if path == "/api/log":
            if method == "GET":
                self.respond(200, MEMLOG.text().encode(), "application/jsonlines")
                return 200
            if method == "DELETE":
                MEMLOG.clear()
                self.respond(200, b"OK", "text/plain")
                return 200
            self.go_error(400, "Method not allowed")
            return 400

        # ---- discovery stubs: unconfigured modules → "no sources" ----
        if path in ("/api/ffmpeg/devices", "/api/ffmpeg/hardware", "/api/onvif",
                    "/api/dvrip", "/api/gopro", "/api/hass", "/api/nest",
                    "/api/roborock", "/api/homekit", "/api/webtorrent") \
                and path != "/api/webtorrent":
            self.go_error(404, "no sources")
            return 404

        # ---- /api/webtorrent (share links) ----
        if path == "/api/webtorrent":
            if method == "POST":
                src = (q.get("src") or [""])[0]
                with STATE.lock:
                    STATE.share = {
                        "share": uuid.uuid4().hex,
                        "pwd": uuid.uuid4().hex[:16],
                    }
                    STATE.save()
                self.go_json(STATE.share)
                return 200
            if method == "DELETE":
                with STATE.lock:
                    STATE.share = None
                    STATE.save()
                self.go_empty(200)
                return 200
            if method == "GET":
                if STATE.share:
                    self.go_json(STATE.share)
                    return 200
                self.go_error(404, "")
                return 404
            self.go_error(400, "")
            return 400

        # ---- everything else: Go mux 404 ----
        self.go_not_found()
        return 404

    # tie the dispatch to all methods
    do_GET = _handle
    do_HEAD = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_OPTIONS = _handle


# ---------------------------------------------------------------------------
# RTSP server on :8554 (the go2rtc fingerprint scanners look for)
# ---------------------------------------------------------------------------

class RTSPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class RTSPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(30)
        ip = self.client_address[0]
        buf = b""
        while True:
            try:
                chunk = self.request.recv(4096)
            except (socket.timeout, OSError):
                return
            if not chunk:
                return
            buf += chunk
            while b"\r\n\r\n" in buf:
                raw, buf = buf.split(b"\r\n\r\n", 1)
                lines = raw.decode("utf-8", "replace").split("\r\n")
                if not lines or len(lines[0].split()) < 3:
                    continue
                method, uri, _proto = lines[0].split(" ", 2)
                headers = {}
                for line in lines[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = v.strip()
                self.respond_one(method, uri, headers, ip)
                if method == "TEARDOWN":
                    return

    def send_line(self, text, extra_headers=None, body=b""):
        data = text.encode() + b"\r\n"
        for k, v in (extra_headers or {}).items():
            data += (k + ": " + v).encode() + b"\r\n"
        data += b"\r\n" + body
        try:
            self.request.sendall(data)
        except OSError:
            pass

    def respond_one(self, method, uri, headers, ip):
        cseq = headers.get("cseq", "1")
        name = None
        try:
            path = urllib.parse.urlsplit(uri).path
            name = path.lstrip("/").split("/")[0]
        except Exception:
            pass
        known = bool(name) and STATE.get_stream(name) is not None

        EV.access({
            "id": short_id(), "ts": utcnow_iso(), "kind": "rtsp", "ip": ip,
            "port": self.client_address[1], "method": method, "path": "/rtsp",
            "query": None, "rtsp_uri": uri, "ua": None, "host": None,
            "auth": headers.get("authorization"), "xff": None, "clen": 0,
            "status": 200 if known or method == "OPTIONS" else 404,
            "dur_ms": 0, "body_preview": None,
        })

        if method == "OPTIONS":
            self.send_line("RTSP/1.0 200 OK", {
                "CSeq": cseq, "Public": RTSP_PUBLIC_METHODS})
        elif method == "DESCRIBE":
            if known:
                sdp = rtsp_describe_sdp(name)
                host = headers.get("host") or "127.0.0.1:%d" % ARGS.rtsp_port
                self.send_line("RTSP/1.0 200 OK", {
                    "CSeq": cseq,
                    "Content-Type": "application/sdp",
                    "Content-Base": "rtsp://%s/%s/" % (host, name),
                    "Content-Length": str(len(sdp.encode())),
                }, body=sdp.encode())
                MEMLOG.add("[rtsp] new consumer stream=%s" % name, "debug")
            else:
                self.send_line("RTSP/1.0 404 Not Found", {"CSeq": cseq})
        elif method == "SETUP":
            if known:
                self.send_line("RTSP/1.0 200 OK", {
                    "CSeq": cseq,
                    "Session": uuid.uuid4().hex[:8],
                    "Transport": "RTP/AVP;unicast;client_port=5000-5001;server_port=32768-32769",
                })
            else:
                self.send_line("RTSP/1.0 404 Not Found", {"CSeq": cseq})
        elif method == "PLAY":
            self.send_line("RTSP/1.0 200 OK", {
                "CSeq": cseq, "Session": headers.get("session", uuid.uuid4().hex[:8]),
                "RTP-Info": "url=%s;seq=12345;rtptime=0" % uri,
            })
        elif method == "TEARDOWN":
            self.send_line("RTSP/1.0 200 OK", {"CSeq": cseq})
        elif method == "ANNOUNCE":
            self.send_line("RTSP/1.0 200 OK" if known else "RTSP/1.0 404 Not Found",
                           {"CSeq": cseq})
        else:
            self.send_line("RTSP/1.0 501 Not Implemented", {"CSeq": cseq})


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

ARGS = None
CON = None
EV = None
STATE = None
MEMLOG = None


def state_path():
    return os.path.join(ARGS.data_dir, "state.json")


def parse_args():
    p = argparse.ArgumentParser(
        prog="haotian-miguan",
        description="好甜的蜜罐 — a sweet go2rtc v1.8.5 deception honeypot",
        epilog="Runs a fake go2rtc on HTTP :1984 and RTSP :8554 and logs every "
               "config-apply attack attempt. Nothing attacker-supplied is ever executed.")
    p.add_argument("--host", default="0.0.0.0", help="HTTP/RTSP bind address (default: 0.0.0.0)")
    p.add_argument("--port", type=int, default=1984, help="fake go2rtc API port (default: 1984)")
    p.add_argument("--rtsp-port", type=int, default=8554,
                   help="fake RTSP port, 0 to disable (default: 8554)")
    p.add_argument("--data-dir", default="./data", help="evidence + state directory")
    p.add_argument("--version-string", default=GO2RTC_VERSION,
                   help="go2rtc version to impersonate (default: 1.8.5)")
    p.add_argument("--revision", default="",
                   help="git revision advertised in /api (1.9.x builds show "
                        "one; hybrid mode adopts the real instance's revision)")
    p.add_argument("--hide-planted-from-ui", action="store_true",
                   help="hybrid mode: a browser loading the real WebUI gets "
                        "the REAL stream list untouched, so the operator's UI "
                        "stays clean; scripted clients still see planted "
                        "streams (the attacker's verification)")
    p.add_argument("--config-sync", type=int, default=300, metavar="SECONDS",
                   help="hybrid mode: re-mirror the real go2rtc.yaml every N "
                        "seconds so the fake instance stays in sync (streams "
                        "added/removed on the real box appear/disappear). An "
                        "attacker's applied config gets one window of grace "
                        "before it reverts. 0 disables (default: 300)")
    p.add_argument("--config-path-label", default="/config/go2rtc.yaml",
                   help="config path shown in GET /api (fiction, never read)")
    p.add_argument("--config-file", default=None,
                   help="optional YAML file to seed the fake go2rtc.yaml with")
    p.add_argument("--webhook", default=None,
                   help="POST each alert as JSON to this URL (Discord/Slack/"
                        "relay). Discord and Slack URLs are auto-detected and "
                        "shaped correctly, payload included")
    p.add_argument("--webhook-format", default="auto",
                   choices=["auto", "discord", "slack", "generic"],
                   help="alert payload shape: auto-detects Discord/Slack "
                        "webhook URLs; 'generic' posts the raw alert record "
                        "as JSON for custom automation (default: auto)")
    p.add_argument("--max-body-mb", type=int, default=8, help="request body cap in MiB")
    p.add_argument("--reset", action="store_true", help="reset fake state before start")
    p.add_argument("--trust-proxy", action="store_true",
                   help="we sit behind YOUR reverse proxy (nginx): evidence IPs "
                        "come from X-Real-IP / rightmost X-Forwarded-For hop "
                        "instead of the proxy's address")
    p.add_argument("--upstream", default=None, metavar="URL",
                   help="HYBRID MODE: base URL of your REAL go2rtc (e.g. "
                        "http://172.17.0.1:1984). Non-attacker traffic is "
                        "relayed to it (credentials scrubbed), the fake "
                        "config/log auto-seed from it, and planted streams "
                        "overlay it in /api/streams")
    p.add_argument("--quiet", action="store_true", help="no per-request console lines")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    return p.parse_args()


def banner():
    CON.print()
    CON.honey("🍯  好甜的蜜罐 · hǎo tián de mì guàn — “such a sweet honeypot”")
    CON.print("    a fake, forgotten go2rtc %s waiting for config-appliers" % ARGS.version_string)
    CON.print()
    CON.bright("    HTTP  http://%s:%d   (web UI + /api)" % (ARGS.host, ARGS.port))
    if ARGS.rtsp_port:
        CON.bright("    RTSP  rtsp://%s:%d" % (ARGS.host, ARGS.rtsp_port))
    CON.dim("    evidence: %s" % os.path.abspath(ARGS.data_dir))
    if ARGS.webhook:
        CON.dim("    webhook: %s" % ARGS.webhook)
    CON.print()
    CON.dim("    this is a decoy — nothing here is executed, no real cameras exist")
    CON.print()


def main():
    global ARGS, CON, EV, STATE, MEMLOG
    ARGS = parse_args()
    if ARGS.no_color or not sys.stdout.isatty():
        ARGS.no_color = True
    CON = Con(enabled=not ARGS.no_color)
    ARGS.max_body = ARGS.max_body_mb * 1024 * 1024

    for label, port in (("HTTP", ARGS.port), ("RTSP", ARGS.rtsp_port)):
        if not (0 <= port <= 65535):
            CON.danger("%s port %d is not a valid TCP port (0-65535)" % (label, port))
            sys.exit(1)

    os.makedirs(ARGS.data_dir, exist_ok=True)
    EV = Evidence(ARGS.data_dir)

    state_lock = threading.RLock()
    STATE = FakeState(state_lock)
    MEMLOG = FakeMemLog()

    banner()

    servers = []

    if ARGS.rtsp_port:
        try:
            rtsp_srv = RTSPServer((ARGS.host, ARGS.rtsp_port), RTSPHandler)
        except OSError as e:
            CON.danger("cannot bind RTSP %s:%d (%s)" % (ARGS.host, ARGS.rtsp_port, e))
            CON.warn("is your real go2rtc or another service on that port? use --rtsp-port 0 to disable")
            sys.exit(1)
        threading.Thread(target=rtsp_srv.serve_forever, kwargs={"poll_interval": 0.2},
                         daemon=True, name="rtsp").start()
        servers.append(rtsp_srv)

    try:
        http_srv = GoHTTPServer((ARGS.host, ARGS.port), Handler)
    except OSError as e:
        CON.danger("cannot bind HTTP %s:%d (%s)" % (ARGS.host, ARGS.port, e))
        CON.warn("is your real go2rtc or another service on that port? use --port to change")
        sys.exit(1)
    servers.append(http_srv)

    def shutdown(signum, frame):
        for s in servers:
            threading.Thread(target=s.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    CON.dim("listening… press Ctrl+C to stop")
    try:
        http_srv.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    CON.print()
    CON.honey("🍯 honeypot stopped — check the catch: python3 report.py --data-dir %s" % ARGS.data_dir)


if __name__ == "__main__":
    main()

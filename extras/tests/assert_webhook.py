#!/usr/bin/env python3
"""Assert the honeypot's notifications carry what the attacker sent.

    python3 assert_webhook.py /tmp/wh.jsonl /tmp/wh-pot/alerts.log

Checks:
  * a Discord-shaped capture exists (embeds[]) and its payload field
    contains the YAML config the attacker applied
  * the decoded query payload of a stream write is included too
  * alerts.log (fail2ban-format) lists the escaped payload
"""

import json
import sys

capture_path, alerts_log = sys.argv[1], sys.argv[2]
failures = []


def check(name, ok):
    print(("  OK  " if ok else "  FAIL ") + name)
    if not ok:
        failures.append(name)


recs = [json.loads(l) for l in open(capture_path, encoding="utf-8") if l.strip()]
discord = [r for r in recs if isinstance(r, dict) and "embeds" in r]
blob = json.dumps(discord, ensure_ascii=False)

check("at least one Discord-shaped alert captured", bool(discord))
check("discord embed carries the applied YAML payload",
      "command=bash" in blob and "embed_pwn" in blob)
check("discord embed carries the stream-write query payload",
      "#input=" in blob)
check("discord embed has the attacker IP and severity",
      "127.0.0.1" in blob and "HIGH" in blob)

log = open(alerts_log, encoding="utf-8").read()
check("alerts.log carries payload (escaped, one line)",
      'payload="' in log and "command=bash" in log and "\\n" in log)

if failures:
    print("FAILED: %s" % ", ".join(failures))
    sys.exit(1)
print("webhook notification checks passed")

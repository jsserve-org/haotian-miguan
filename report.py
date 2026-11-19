#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
好甜的蜜罐 — catch report

Summarizes what the honeypot caught: who probed, who applied config
files, what payloads they tried to plant, and which "streams" are
attacker-planted backdoors.

  python3 report.py                     # pretty summary of ./data
  python3 report.py --data-dir ./data --since 2026-11-01
  python3 report.py --json              # machine-readable
"""

import argparse
import collections
import json
import os
import sys

SEV_ORDER = {"low": 0, "medium": 1, "high": 2}


def load_jsonl(path, since=None):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if since and rec.get("ts", "") < since:
                continue
            rows.append(rec)
    return rows


def one_line(text, limit=110):
    if text is None:
        return ""
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def main():
    ap = argparse.ArgumentParser(description="好甜的蜜罐 catch report")
    ap.add_argument("--data-dir", default="./data")
    ap.add_argument("--since", default=None, help="ISO timestamp floor, e.g. 2026-11-01")
    ap.add_argument("--limit", type=int, default=15, help="recent alerts to show")
    ap.add_argument("--json", action="store_true", help="dump raw summary JSON")
    args = ap.parse_args()

    d = args.data_dir
    access = load_jsonl(os.path.join(d, "access.jsonl"), args.since)
    alerts = load_jsonl(os.path.join(d, "alerts.jsonl"), args.since)

    ips_requests = collections.Counter(r.get("ip", "?") for r in access)
    ips_alerts = collections.Counter(r.get("ip", "?") for r in alerts)
    tags = collections.Counter(t for r in alerts for t in r.get("tags", []))
    paths = collections.Counter(r.get("path", "?") for r in access)
    sev = collections.Counter(r.get("severity", "low") for r in alerts)
    uas = collections.Counter(r.get("ua") or "-" for r in access if r.get("ua"))

    state = {}
    state_path = os.path.join(d, "state.json")
    if os.path.exists(state_path):
        try:
            state = json.load(open(state_path, encoding="utf-8"))
        except Exception:
            pass
    planted = state.get("meta", {})

    top_payloads = []
    seen = set()
    for r in alerts:
        body = r.get("body") or ""
        h = hash(body)
        if body and h not in seen:
            seen.add(h)
            top_payloads.append(r)

    summary = {
        "window": {
            "from": (access or alerts) and min(
                [r["ts"] for r in access + alerts if r.get("ts")], default=""),
            "to": (access or alerts) and max(
                [r["ts"] for r in access + alerts if r.get("ts")], default=""),
        },
        "requests": len(access),
        "unique_ips": len(ips_requests),
        "alerts": len(alerts),
        "alerts_by_severity": dict(sev),
        "alerts_by_tag": dict(tags),
        "attacker_planted_streams": planted,
        "top_attacker_ips": [
            {"ip": ip, "alerts": ips_alerts[ip], "requests": ips_requests[ip]}
            for ip, _ in ips_alerts.most_common(10)
        ],
    }

    if args.json:
        json.dump(summary, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return

    W = sys.stdout.write
    W("\n")
    W("🍯 好甜的蜜罐 — catch report\n")
    W("   evidence: %s\n" % os.path.abspath(d))
    W("   window:  %s → %s\n" % (
        summary["window"]["from"] or "-", summary["window"]["to"] or "-"))
    W("\n")

    if not access and not alerts:
        W("   nothing caught yet — the pot is set, wait for the flies 🪰\n\n")
        return

    W("   requests: %d from %d unique sources   alerts: %d"
       " (high %d / medium %d / low %d)\n\n" % (
           len(access), len(ips_requests), len(alerts),
           sev.get("high", 0), sev.get("medium", 0), sev.get("low", 0)))

    if tags:
        W("   what they did:\n")
        for tag, n in tags.most_common():
            W("     %-18s %d\n" % (tag, n))
        W("\n")

    if ips_alerts:
        W("   attacker IPs:\n")
        W("     %-16s %7s %9s   tags\n" % ("ip", "alerts", "requests"))
        for ip, n in ips_alerts.most_common(10):
            ip_tags = sorted({t for r in alerts if r.get("ip") == ip
                              for t in r.get("tags", [])})
            W("     %-16s %7d %9d   %s\n" % (ip, n, ips_requests[ip],
                                              ",".join(ip_tags)[:60]))
        W("\n")

    if planted:
        W("   ⚠  attacker-planted \"streams\" in the fake config:\n")
        for name, m in planted.items():
            W("     %-20s by %-15s %s via %s\n" % (
                name, m.get("ip", "?"), m.get("ts", ""), m.get("via", "")))
        srcs = {n: s for n, s in (state.get("config_streams") or [])}
        for name, m in planted.items():
            src = m.get("sources") or srcs.get(name, [])
            if src:
                W("         source: %s\n" % one_line(", ".join(src), 100))
        W("\n")

    if top_payloads:
        W("   distinct payloads (newest first):\n")
        for r in top_payloads[-args.limit:][::-1]:
            W("     %s  %-15s %s\n" % (
                r.get("ts", "")[11:19], r.get("ip", "?"),
                ",".join(r.get("tags", []))))
            W("       %s\n" % one_line(r.get("body"), 100))
            if r.get("body_file"):
                W("       evidence: %s\n" % os.path.join(d, r["body_file"]))
        W("\n")

    W("   top paths:\n")
    for p, n in paths.most_common(8):
        W("     %-32s %d\n" % (p, n))
    if uas:
        W("\n   top user agents:\n")
        for ua, n in uas.most_common(5):
            W("     %-46s %d\n" % (one_line(ua, 46), n))
    W("\n")


if __name__ == "__main__":
    main()

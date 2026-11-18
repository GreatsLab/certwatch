"""certwatch - check TLS certificates for a list of hosts, write a status page.

    python -m certwatch domains.yml -o site/
    python -m certwatch --host example.com --host example.org   # quick check, no files
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

import yaml

from .check import check
from .page import render

NEEDS_ATTENTION = ("expiring", "expired", "invalid", "error")


def load_targets(path):
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    out = []
    for group, hosts in (data.get("groups") or {"default": data.get("hosts", [])}).items():
        for h in hosts or []:
            if isinstance(h, dict):
                out.append((h["host"], int(h.get("port", 443)), group, h.get("note")))
            else:
                host, _, port = str(h).partition(":")
                out.append((host, int(port or 443), group, None))
    return out, data.get("settings", {})


def issue_body(results, page_url):
    lines = ["certwatch found certificates that need attention:", ""]
    for r in results:
        if r["status"] not in NEEDS_ATTENTION:
            continue
        what = r["error"] or f'expires in {r["days_left"]:.0f} days ({r["not_after"][:10]})'
        lines.append(f'- **{r["host"]}**: {r["status"]}, {what}')
    if page_url:
        lines += ["", f"Status page: {page_url}"]
    lines += ["", "_This issue is updated by the daily run and closed automatically when everything is fine._"]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="certwatch", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("config", nargs="?", help="domains.yml")
    ap.add_argument("--host", action="append", default=[], help="check this host[:port] (repeatable)")
    ap.add_argument("-o", "--out", help="write index.html + status.json here")
    ap.add_argument("--history", help="append today's results to this JSON file (keeps 120 days)")
    ap.add_argument("--issue-body", help="write a markdown issue body here if anything needs attention")
    ap.add_argument("--warn", type=int, default=None, help="warn this many days before expiry (default 30)")
    ap.add_argument("--crit", type=int, default=None, help="critical this many days before (default 14)")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    ap.add_argument("--page-url", default="")
    a = ap.parse_args(argv)

    targets, settings = ([], {})
    if a.config:
        targets, settings = load_targets(a.config)
    for h in a.host:
        host, _, port = h.partition(":")
        targets.append((host, int(port or 443), "cli", None))
    if not targets:
        ap.error("nothing to check: give a config file or --host")

    warn = a.warn or settings.get("warn_days", 30)
    crit = a.crit or settings.get("crit_days", 14)
    now = dt.datetime.now(dt.timezone.utc)

    def one(t):
        host, port, group, note = t
        r = check(host, port, warn_days=warn, crit_days=crit, now=now).to_dict()
        r["group"], r["note"] = group, note
        return r

    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(one, targets))

    w = max(len(r["host"]) for r in results)
    for r in sorted(results, key=lambda r: r["days_left"] if r["days_left"] is not None else -1e9):
        days = f'{r["days_left"]:>6.0f}d' if r["days_left"] is not None else "      -"
        extra = r["error"] or "; ".join(r["notes"])
        print(f'{r["status"]:<9} {days}  {r["host"]:<{w}}  {r["issuer"] or ""}  {extra}')

    if a.out:
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, "index.html"), "w", encoding="utf-8") as fh:
            fh.write(render(results, now, a.repo))
        with open(os.path.join(a.out, "status.json"), "w", encoding="utf-8") as fh:
            json.dump({"checked_at": now.isoformat(timespec="seconds"), "results": results}, fh, indent=2)

    if a.history:
        hist = []
        if os.path.exists(a.history):
            with open(a.history, encoding="utf-8") as fh:
                hist = json.load(fh)
        today = now.date().isoformat()
        hist = [h for h in hist if h["date"] != today]
        hist.append({"date": today, "days_left": {r["host"]: r["days_left"] for r in results},
                     "status": {r["host"]: r["status"] for r in results}})
        hist = hist[-120:]
        with open(a.history, "w", encoding="utf-8") as fh:
            json.dump(hist, fh, indent=1)

    bad = [r for r in results if r["status"] in NEEDS_ATTENTION]
    if a.issue_body:
        if bad:
            with open(a.issue_body, "w", encoding="utf-8") as fh:
                fh.write(issue_body(results, a.page_url))
        elif os.path.exists(a.issue_body):
            os.remove(a.issue_body)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

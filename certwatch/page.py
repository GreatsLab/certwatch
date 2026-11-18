"""Render the status page. Plain string templates, no Jinja, the page is small."""
from __future__ import annotations

import datetime as dt
import html

ORDER = {"error": 0, "expired": 1, "invalid": 2, "expiring": 3, "warn": 4, "ok": 5}
LABEL = {"ok": "Valid", "warn": "Check", "expiring": "Renew now", "expired": "Expired",
         "invalid": "Not trusted", "error": "Unreachable"}
TIMELINE_DAYS = 90


def _e(s):
    return html.escape(str(s)) if s is not None else ""


def _date(iso):
    if not iso:
        return ""
    return dt.datetime.fromisoformat(iso).strftime("%d %b %Y")


def timeline(results, now):
    """One dot per cert on a 0..90 day axis. Past-due ones pile up at the left
    edge, anything past 90 days sits at the right edge with an arrow."""
    w, h, pad = 1000, 120, 24
    x = lambda d: pad + (max(-5, min(TIMELINE_DAYS, d)) + 5) / (TIMELINE_DAYS + 5) * (w - 2 * pad)
    parts = [f'<svg viewBox="0 0 {w} {h}" class="tl" role="img" aria-label="Expiry timeline, next {TIMELINE_DAYS} days">']
    # zones
    parts.append(f'<rect x="{x(-5)}" y="30" width="{x(14) - x(-5)}" height="44" class="z-crit"/>')
    parts.append(f'<rect x="{x(14)}" y="30" width="{x(30) - x(14)}" height="44" class="z-warn"/>')
    parts.append(f'<line x1="{x(0)}" x2="{x(0)}" y1="22" y2="82" class="today"/>')
    parts.append(f'<text x="{x(0)}" y="16" class="tl-l" text-anchor="middle">today</text>')
    for d in (14, 30, 60, 90):
        parts.append(f'<line x1="{x(d)}" x2="{x(d)}" y1="74" y2="80" class="tick"/>')
        parts.append(f'<text x="{x(d)}" y="96" class="tl-l" text-anchor="middle">{d} days</text>')
    placed = []
    for r in sorted((r for r in results if r["days_left"] is not None), key=lambda r: r["days_left"]):
        cx = x(r["days_left"])
        # stack dots that would overlap
        row = 0
        while any(abs(cx - px) < 12 and pr == row for px, pr in placed):
            row += 1
        placed.append((cx, row))
        cy = 64 - row * 13
        if cy < 36:
            cy = 36
        title = f'{r["host"]}: {r["days_left"]:.0f} days'
        parts.append(f'<circle cx="{cx:.1f}" cy="{cy}" r="5.5" class="dot s-{r["status"]}"><title>{_e(title)}</title></circle>')
    parts.append("</svg>")
    return "".join(parts)


def render(results: list, now: dt.datetime, repo: str = "") -> str:
    results = sorted(results, key=lambda r: (ORDER[r["status"]], r["days_left"] if r["days_left"] is not None else -1e9))
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    bad = sum(counts.get(k, 0) for k in ("error", "expired", "invalid", "expiring"))
    # "sites", not "certificates": an unreachable host has no certificate to count
    headline = "All certificates are fine." if not bad else (
        f"{bad} site{'s' if bad > 1 else ''} need{'s' if bad == 1 else ''} attention.")

    rows = []
    for r in results:
        days = "" if r["days_left"] is None else f'{r["days_left"]:.0f}'
        detail = r["error"] or ""
        notes = "".join(f"<li>{_e(n)}</li>" for n in r["notes"])
        sans = ", ".join(r["sans"][:6]) + (f" +{len(r['sans']) - 6} more" if len(r["sans"]) > 6 else "")
        rows.append(f"""
<tr class="s-{r['status']}">
  <td class="days">{days}<span>{'days' if days else ''}</span></td>
  <td><a href="https://{_e(r['host'])}{'' if r['port'] == 443 else ':' + str(r['port'])}" class="host">{_e(r['host'])}{'' if r['port'] == 443 else ':' + str(r['port'])}</a>
      <div class="sub">{_e(sans)}</div></td>
  <td><span class="pill">{LABEL[r['status']]}</span>{f'<div class="err">{_e(detail)}</div>' if detail else ''}{f'<ul class="notes">{notes}</ul>' if notes else ''}</td>
  <td>{_e(r['issuer'])}<div class="sub">{_e(r['key'])} {_e(r['tls_version'])}</div></td>
  <td class="date">{_date(r['not_after'])}</td>
</tr>""")

    repo_link = f' <a href="https://github.com/{_e(repo)}">Source and domain list</a>.' if repo else ""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>certwatch: {_e(headline)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Public+Sans:wght@400;600;800&display=swap" rel="stylesheet">
<style>
:root {{ --ink:#172026; --ink2:#5A6670; --rule:#E3E7EA; --bg:#FFFFFF; --ok:#1B7F5A; --warn:#A86B00; --crit:#A4161A; --mute:#8A949B; }}
* {{ box-sizing:border-box }}
body {{ margin:0; font-family:"Public Sans",system-ui,sans-serif; color:var(--ink); background:var(--bg); font-size:15px; line-height:1.45; font-variant-numeric:tabular-nums; }}
main {{ max-width:1080px; margin:0 auto; padding:40px 24px 64px; }}
h1 {{ font-size:clamp(28px,4.5vw,44px); font-weight:800; letter-spacing:-.02em; line-height:1.1; margin:0 0 8px; max-width:20ch; }}
.lede {{ color:var(--ink2); margin:0 0 28px; }}
.tl {{ width:100%; height:auto; display:block; margin:0 0 28px; }}
.z-crit {{ fill:#A4161A14; }} .z-warn {{ fill:#A86B0012; }}
.today {{ stroke:var(--ink); stroke-width:2; }} .tick {{ stroke:var(--mute); }}
.tl-l {{ font-size:12px; fill:var(--ink2); font-family:inherit; }}
.dot {{ stroke:#fff; stroke-width:1.5; }}
.dot.s-ok {{ fill:var(--ok) }} .dot.s-warn {{ fill:var(--warn) }} .dot.s-expiring,.dot.s-expired,.dot.s-invalid {{ fill:var(--crit) }}
table {{ width:100%; border-collapse:collapse; }}
th {{ text-align:left; font-size:13px; color:var(--ink2); font-weight:600; padding:0 12px 8px; border-bottom:2px solid var(--ink); }}
td {{ padding:14px 12px; border-bottom:1px solid var(--rule); vertical-align:top; }}
td.days {{ font-size:30px; font-weight:800; line-height:1; width:84px; text-align:right; }}
td.days span {{ display:block; font-size:12px; font-weight:400; color:var(--ink2); margin-top:4px; }}
.date {{ white-space:nowrap; }}
.host {{ color:var(--ink); font-weight:600; text-decoration:none; }} .host:hover {{ text-decoration:underline; }}
.sub {{ color:var(--ink2); font-size:13px; margin-top:2px; word-break:break-word; }}
.pill {{ display:inline-block; font-size:13px; font-weight:600; padding:2px 8px; border-radius:3px; background:#1B7F5A1A; color:var(--ok); }}
tr.s-warn .pill {{ background:#A86B001A; color:var(--warn) }} tr.s-warn td.days {{ color:var(--warn) }}
tr.s-expiring .pill, tr.s-expired .pill, tr.s-invalid .pill {{ background:var(--crit); color:#fff }}
tr.s-expiring td.days, tr.s-expired td.days, tr.s-invalid td.days {{ color:var(--crit) }}
tr.s-error .pill {{ background:#EEF0F2; color:var(--ink2) }}
.err {{ color:var(--crit); font-size:13px; margin-top:4px; }}
.notes {{ margin:4px 0 0; padding-left:16px; font-size:13px; color:var(--warn); }}
footer {{ margin-top:28px; color:var(--ink2); font-size:13px; }}
footer a {{ color:var(--ink); }}
a:focus-visible {{ outline:3px solid #2F6FD0; outline-offset:2px; }}
@media (max-width:720px) {{
  thead {{ display:none }}
  tr {{ display:grid; grid-template-columns:72px 1fr; border-bottom:1px solid var(--rule); padding:10px 0; }}
  td {{ border:0; padding:4px 8px; }}
  td.days {{ grid-row:span 4; width:auto; font-size:26px; }}
}}
</style>
</head>
<body>
<main>
  <h1>{_e(headline)}</h1>
  <p class="lede">{len(results)} sites checked {now.strftime('%d %b %Y, %H:%M')} UTC. Checked again every day.</p>
  {timeline(results, now)}
  <table>
    <thead><tr><th style="text-align:right">Left</th><th>Site</th><th>Status</th><th>Issuer</th><th>Expires</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  <footer>Generated by certwatch on GitHub Actions. Raw data: <a href="status.json">status.json</a>.{repo_link}</footer>
</main>
</body>
</html>
"""

# certwatch

TLS certificate monitoring that costs nothing and needs no server. It's a GitHub Actions job that checks a list of sites every morning, publishes a status page, and opens a GitHub issue when something is about to expire. When it's fixed, the issue closes itself.

**Status page: https://greatslab.github.io/certwatch/**

## Why

Expired certificates are the most avoidable outage there is, and they still happen all the time, including on big sites. Running a hosting company means watching *other people's* domains too, and "your site says Not Secure" is a bad way to find out.

Paid monitors do this. Uptime Kuma does it if you have a box to run it on. But a GitHub repo already has a scheduler (Actions), free hosting (Pages), an alerting system with email and mobile push (Issues), and version control for the config. So that's what this uses.

## What it checks

For every host:

- **days until expiry**: warn under 30, critical under 14 (configurable)
- **chain trust** against the system CA store: self-signed, unknown root, missing intermediate
- **hostname match** against the SANs
- **already expired**. It still downloads the cert without verification, so the page shows *which* cert and *who* issued it, not just "error"
- **problems that aren't errors yet**: lifetime over 398 days (browsers reject those), RSA under 2048, SHA-1 signatures, TLS 1.0/1.1 negotiated, no SAN extension
- issuer, key type (RSA 2048 / EC P-256), TLS version, SAN list

The page sorts by urgency and has a 90-day timeline at the top, so you see what's coming at a glance.

The `canaries` group points at [badssl.com](https://badssl.com)'s deliberately broken hosts, so there's always proof the failure states render. They're excluded from the alert issue.

## Use it for your own domains

1. Fork this repo
2. Edit `domains.yml`
3. Settings → Pages → Source: **GitHub Actions**
4. Actions → **daily check** → Run workflow

Watch the repo (or just the `certwatch` label) to get the issue notifications by email or in the GitHub mobile app.

```yaml
settings:
  warn_days: 30
  crit_days: 14

groups:
  clients:
    - example.com
    - shop.example.com:8443
    - host: mail.example.com
      note: dovecot, renewed by hand
```

## Running it locally

```
pip install -e .
python -m certwatch --host github.com --host expired.badssl.com
python -m certwatch domains.yml -o site/        # writes site/index.html + status.json
```

```
expired       -4120d  expired.badssl.com     COMODO CA Limited  certificate has expired
ok              61d  github.com             Sectigo Limited
```

Exit code is 1 if anything needs attention, so it works in cron or another CI too.

## How the workflow fits together

```
cron 06:17 UTC ─► check all hosts (16 at a time)
                 ├─► site/index.html + status.json ─► GitHub Pages
                 ├─► data/history.json (committed back, last 120 days)
                 └─► issue.md? ─► open or update the "certwatch" issue
                     nothing wrong? ─► close it with a comment
```

## Tests

`pytest` spins up local TLS servers with a throwaway CA and certs in every state (valid, expiring soon, expired, wrong hostname, self-signed, 700-day lifetime) and checks each one is classified correctly. No internet needed.

One thing I found that way: **Python 3.13 enables `VERIFY_X509_STRICT` by default**, so a cert without an Authority Key Identifier fails verification. Browsers accept those, and plenty of internal CAs issue them, so certwatch clears that flag to match what users actually see.

## Ideas

- Check the full chain's expiry, not just the leaf (an expiring intermediate bites too)
- OCSP / revocation status
- Graph `days_left` from the history on the page

## License

MIT

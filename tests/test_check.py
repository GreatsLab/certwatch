import datetime as dt

import pytest

from certwatch.check import check
from certwatch.page import render


def run(servers, name, **kw):
    return check("localhost", servers[name], ca_file=servers["ca"], timeout=3, **kw)


@pytest.mark.parametrize("name,status", [
    ("valid", "ok"), ("soon", "warn"), ("expiring", "expiring"), ("expired", "expired"),
    ("wronghost", "invalid"), ("selfsigned", "invalid"),
])
def test_status(servers, name, status):
    r = run(servers, name)
    assert r.status == status, (r.status, r.error)


def test_details(servers):
    r = run(servers, "valid")
    assert 79 <= r.days_left <= 80
    assert r.key == "EC P-256"
    assert r.issuer == "certwatch test CA"
    assert r.sans == ["localhost"]
    assert r.tls_version.startswith("TLSv1.")


def test_expired_still_shows_cert(servers):
    r = run(servers, "expired")
    assert r.days_left < 0 and r.issuer and "expired" in r.error


def test_hostname_mismatch_message(servers):
    r = run(servers, "wronghost")
    assert "hostname" in r.error.lower() or "match" in r.error.lower()


def test_long_lifetime_note(servers):
    r = run(servers, "longlife")
    assert any("398" in n for n in r.notes)
    assert r.status == "warn"


def test_unreachable():
    r = check("127.0.0.1", 1, timeout=1)
    assert r.status == "error" and r.error


def test_page_renders(servers):
    rs = [run(servers, n).to_dict() for n in ("valid", "expiring", "expired", "wronghost")]
    rs.append(check("127.0.0.1", 1, timeout=1).to_dict())
    page = render(rs, dt.datetime.now(dt.timezone.utc))
    assert "4 sites need attention." in page
    assert page.count("<tr class=") == 5

"""Connect to a host, pull its certificate, and say what's wrong with it."""
from __future__ import annotations

import datetime as dt
import socket
import ssl
from dataclasses import asdict, dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID


@dataclass
class Result:
    host: str
    port: int
    ok: bool                      # trusted chain + hostname matches + not expired
    status: str                   # ok | warn | expiring | expired | invalid | error
    days_left: float | None = None
    not_after: str | None = None
    not_before: str | None = None
    issuer: str | None = None
    subject: str | None = None
    sans: list = field(default_factory=list)
    key: str | None = None        # "RSA 2048", "EC P-256"
    tls_version: str | None = None
    error: str | None = None
    notes: list = field(default_factory=list)
    checked_at: str = ""

    def to_dict(self):
        return asdict(self)


def _name(n: x509.Name) -> str:
    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        v = n.get_attributes_for_oid(oid)
        if v:
            return v[0].value
    return n.rfc4514_string()


def _key(cert) -> str:
    k = cert.public_key()
    if isinstance(k, rsa.RSAPublicKey):
        return f"RSA {k.key_size}"
    if isinstance(k, ec.EllipticCurvePublicKey):
        return f"EC {k.curve.name.replace('secp256r1', 'P-256').replace('secp384r1', 'P-384')}"
    return type(k).__name__.replace("PublicKey", "")


def _fetch(host, port, timeout, verify, ca_file=None):
    if verify:
        ctx = ssl.create_default_context(cafile=ca_file)
        # Python 3.13 turned on VERIFY_X509_STRICT, which rejects e.g. certs
        # without an Authority Key Identifier. Browsers accept those (lots of
        # internal CAs issue them), and this tool should agree with browsers.
        ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True), tls.version()


def check(host: str, port: int = 443, *, warn_days: int = 30, crit_days: int = 14,
          timeout: float = 8.0, now: dt.datetime | None = None, ca_file: str | None = None) -> Result:
    now = now or dt.datetime.now(dt.timezone.utc)
    r = Result(host=host, port=port, ok=False, status="error", checked_at=now.isoformat(timespec="seconds"))

    verify_error = None
    try:
        der, version = _fetch(host, port, timeout, verify=True, ca_file=ca_file)
    except ssl.SSLCertVerificationError as e:
        # still want to show *what* cert is there, so fetch it without verifying
        verify_error = e.verify_message or str(e)
        try:
            der, version = _fetch(host, port, timeout, verify=False)
        except (OSError, ssl.SSLError) as e2:
            r.error = str(e2)
            return r
    except (OSError, ssl.SSLError) as e:
        r.error = _plain(e)
        return r

    cert = x509.load_der_x509_certificate(der)
    na = cert.not_valid_after_utc
    nb = cert.not_valid_before_utc
    r.not_after = na.isoformat()
    r.not_before = nb.isoformat()
    r.days_left = round((na - now).total_seconds() / 86400, 1)
    r.issuer = _name(cert.issuer)
    r.subject = _name(cert.subject)
    r.key = _key(cert)
    r.tls_version = version
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        r.sans = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        r.notes.append("no SAN extension - modern browsers ignore CN and will reject this")

    lifetime = (na - nb).days
    if lifetime > 398:
        r.notes.append(f"{lifetime}-day lifetime, browsers cap public certs at 398")
    if r.key.startswith("RSA ") and int(r.key.split()[1]) < 2048:
        r.notes.append("RSA key under 2048 bits")
    if version in ("TLSv1", "TLSv1.1"):
        r.notes.append(f"server negotiated {version}, which is deprecated")
    if cert.signature_hash_algorithm and cert.signature_hash_algorithm.name == "sha1":
        r.notes.append("SHA-1 signature")

    if verify_error:
        r.error = verify_error
        r.status = "expired" if r.days_left < 0 else "invalid"
    elif r.days_left < 0:
        r.status = "expired"
    elif r.days_left < crit_days:
        r.status = "expiring"
        r.ok = True
    elif r.days_left < warn_days or r.notes:
        r.status = "warn"
        r.ok = True
    else:
        r.status = "ok"
        r.ok = True
    return r


def _plain(e: Exception) -> str:
    s = str(e)
    if isinstance(e, socket.gaierror):
        return "DNS lookup failed"
    if isinstance(e, (TimeoutError, socket.timeout)) or "timed out" in s:
        return "connection timed out"
    if isinstance(e, ConnectionRefusedError):
        return "connection refused"
    return s

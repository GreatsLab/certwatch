"""Spin up local TLS servers with certs in every state we care about."""
import datetime as dt
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NOW = dt.datetime.now(dt.timezone.utc)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "certwatch test CA" if "CA" in cn else cn)])


def make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name("Test CA")).issuer_name(_name("Test CA"))
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(NOW - dt.timedelta(days=1)).not_valid_after(NOW + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def make_leaf(ca_key, ca_cert, host, days_left, *, self_signed=False, start_days_ago=30):
    key = ec.generate_private_key(ec.SECP256R1())
    issuer_key, issuer_name = (key, _name(host)) if self_signed else (ca_key, ca_cert.subject)
    cert = (x509.CertificateBuilder().subject_name(_name(host)).issuer_name(issuer_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(days=start_days_ago))
            .not_valid_after(NOW + dt.timedelta(days=days_left))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
            .sign(issuer_key, hashes.SHA256()))
    return key, cert


def serve(tmp, name, key, cert):
    certf, keyf = tmp / f"{name}.crt", tmp / f"{name}.key"
    certf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certf, keyf)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(c, server_side=True) as s:
                    s.recv(1)
            except (ssl.SSLError, OSError):
                pass

    threading.Thread(target=loop, daemon=True).start()
    return srv, port


@pytest.fixture(scope="session")
def servers(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("tls")
    ca_key, ca_cert = make_ca()
    (tmp / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    # all served as "localhost" so hostname checks pass, except wronghost
    specs = {
        "valid": dict(host="localhost", days_left=80),
        "soon": dict(host="localhost", days_left=20),
        "expiring": dict(host="localhost", days_left=5),
        "expired": dict(host="localhost", days_left=-3),
        "wronghost": dict(host="other.example", days_left=80),
        "selfsigned": dict(host="localhost", days_left=80, self_signed=True),
        "longlife": dict(host="localhost", days_left=700, start_days_ago=100),
    }
    out = {"ca": str(tmp / "ca.pem")}
    socks = []
    for name, kw in specs.items():
        k, c = make_leaf(ca_key, ca_cert, **kw)
        s, port = serve(tmp, name, k, c)
        socks.append(s)
        out[name] = port
    yield out
    for s in socks:
        s.close()

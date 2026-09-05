"""HTTPS configuration: Caddyfile rendering, applying it, and status."""

import contextlib
import json
import pathlib
import socket
import ssl
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import main, tls
from app.models import Branding

CADDY = {"loads": [], "status": 200, "body": ""}


class CaddyHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        CADDY["loads"].append(
            {
                "path": self.path,
                "content_type": self.headers.get("Content-Type"),
                "body": self.rfile.read(length).decode(),
            }
        )
        body = CADDY["body"].encode()
        self.send_response(CADDY["status"])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="session")
def caddy():
    server = HTTPServer(("127.0.0.1", 0), CaddyHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    original = tls.CADDY_ADMIN
    tls.CADDY_ADMIN = f"http://{host}:{port}"
    yield tls.CADDY_ADMIN
    tls.CADDY_ADMIN = original
    server.shutdown()


@pytest.fixture(autouse=True)
def reset_caddy():
    CADDY["loads"].clear()
    CADDY["status"] = 200
    CADDY["body"] = ""


def brand(**kwargs) -> Branding:
    row = Branding(id=1)
    for key, value in kwargs.items():
        setattr(row, key, value)
    return row


# ------------------------------------------------------------------ rendering
def test_disabled_renders_plain_http_passthrough():
    text = tls.render_caddyfile(brand(tls_enabled=False))
    assert "auto_https off" in text
    assert ":80 {" in text
    assert "reverse_proxy mdm-scheduler:8000" in text


def test_every_config_redeclares_the_admin_endpoint():
    """POST /load replaces the whole config; omitting admin would drop Caddy
    back to localhost:2019 and lock the app out of it."""
    dns_row = brand(tls_enabled=True, tls_hostname="mdm.example.com")
    dns_row.tls_challenge = "dns"
    dns_row.tls_dns_token = "tok"

    for row in (
        brand(tls_enabled=False),
        brand(tls_enabled=True, tls_hostname="mdm.example.com", tls_email="a@b.c"),
        dns_row,
    ):
        assert "admin 0.0.0.0:2019" in tls.render_caddyfile(row)


def test_http_challenge_config():
    row = brand(tls_enabled=True, tls_hostname="mdm.example.com", tls_email="kyle@example.com")
    text = tls.render_caddyfile(row)
    assert "mdm.example.com {" in text
    assert "email kyle@example.com" in text
    assert "reverse_proxy mdm-scheduler:8000" in text
    assert "dns " not in text  # no DNS module for HTTP-01
    assert "acme_ca" not in text  # production CA unless staging is asked for


def test_staging_switches_the_acme_ca():
    row = brand(tls_enabled=True, tls_hostname="mdm.example.com", tls_staging=True)
    assert tls.STAGING_CA in tls.render_caddyfile(row)


def test_dns_challenge_embeds_the_provider_and_token():
    row = brand(tls_enabled=True, tls_hostname="mdm.example.com", tls_dns_provider="ionos")
    row.tls_challenge = "dns"
    row.tls_dns_token = "ionos-secret-token"
    text = tls.render_caddyfile(row)
    assert "tls {" in text
    assert "dns ionos ionos-secret-token" in text


def test_dns_challenge_without_a_token_refuses():
    row = brand(tls_enabled=True, tls_hostname="mdm.example.com")
    row.tls_challenge = "dns"
    with pytest.raises(tls.TlsError) as exc:
        tls.render_caddyfile(row)
    assert "no DNS API token" in str(exc.value)


def test_dns_token_is_encrypted_at_rest():
    row = brand()
    row.tls_dns_token = "plaintext-token"
    assert row.tls_dns_token_enc.startswith("gAAAAA")
    assert "plaintext-token" not in row.tls_dns_token_enc
    assert row.tls_dns_token == "plaintext-token"


# ------------------------------------------------------------------- applying
def test_apply_posts_a_caddyfile_not_json(caddy):
    row = brand(tls_enabled=True, tls_hostname="mdm.example.com", tls_email="a@b.c")
    message = tls.apply(row)

    sent = CADDY["loads"][-1]
    assert sent["path"] == "/load"
    assert sent["content_type"] == "text/caddyfile"  # documented Caddy admin API contract
    assert "mdm.example.com {" in sent["body"]
    assert "mdm.example.com" in message and "HTTP-01" in message


def test_apply_names_the_dns_method(caddy):
    row = brand(tls_enabled=True, tls_hostname="mdm.example.com")
    row.tls_challenge = "dns"
    row.tls_dns_token = "tok"
    assert "DNS-01 via IONOS" in tls.apply(row)


def test_apply_reports_a_rejected_config(caddy):
    CADDY["status"] = 400
    CADDY["body"] = "invalid site block"
    row = brand(tls_enabled=True, tls_hostname="mdm.example.com")
    with pytest.raises(tls.TlsError) as exc:
        tls.apply(row)
    assert "Caddy rejected the config" in str(exc.value)
    assert "invalid site block" in str(exc.value)


def test_apply_explains_a_missing_sidecar():
    original = tls.CADDY_ADMIN
    tls.CADDY_ADMIN = "http://127.0.0.1:1"  # nothing listening
    try:
        with pytest.raises(tls.TlsError) as exc:
            tls.apply(brand(tls_enabled=True, tls_hostname="mdm.example.com"))
        assert "Is the caddy service running" in str(exc.value)
    finally:
        tls.CADDY_ADMIN = original


def test_disabling_says_so(caddy):
    assert "HTTPS disabled" in tls.apply(brand(tls_enabled=False))


# --------------------------------------------------------------------- status
def test_status_is_off_when_disabled():
    assert tls.certificate_status(brand(tls_enabled=False))["state"] == "off"


def test_status_reports_a_failed_handshake():
    original = tls.CADDY_HTTPS
    tls.CADDY_HTTPS = ("127.0.0.1", 1)
    try:
        result = tls.certificate_status(brand(tls_enabled=True, tls_hostname="mdm.example.com"))
        assert result["state"] == "error"
        assert "No TLS handshake" in result["detail"]
    finally:
        tls.CADDY_HTTPS = original


# ------------------------------------------------------------------ end to end
def test_branding_tab_saves_and_applies(auth, caddy):
    resp = auth.post(
        "/settings/tls",
        data={
            "tls_enabled": "on",
            "tls_hostname": "MDM.Example.COM",
            "tls_email": "kyle@example.com",
            "tls_challenge": "http",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303

    sent = CADDY["loads"][-1]["body"]
    assert "mdm.example.com {" in sent  # hostname normalised to lower case
    page = auth.get("/settings").text
    assert 'value="mdm.example.com"' in page


def test_enabling_without_a_hostname_is_refused(auth, caddy):
    auth.post("/settings/tls", data={"tls_enabled": "on", "tls_hostname": ""}, follow_redirects=False)
    assert "hostname is required" in auth.get("/settings").text
    assert CADDY["loads"] == []


def test_blank_token_on_resave_keeps_the_stored_one(auth, caddy):
    auth.post(
        "/settings/tls",
        data={
            "tls_enabled": "on",
            "tls_hostname": "mdm.example.com",
            "tls_challenge": "dns",
            "tls_dns_provider": "ionos",
            "tls_dns_token": "first-token",
        },
        follow_redirects=False,
    )
    auth.post(
        "/settings/tls",
        data={
            "tls_enabled": "on",
            "tls_hostname": "mdm.example.com",
            "tls_challenge": "dns",
            "tls_dns_provider": "ionos",
            "tls_dns_token": "",
        },
        follow_redirects=False,
    )
    assert "dns ionos first-token" in CADDY["loads"][-1]["body"]


def test_the_dns_token_never_reaches_the_page_or_the_debug_view(auth, caddy):
    auth.post(
        "/settings/tls",
        data={
            "tls_enabled": "on",
            "tls_hostname": "mdm.example.com",
            "tls_challenge": "dns",
            "tls_dns_provider": "ionos",
            "tls_dns_token": "super-secret-dns-token",
        },
        follow_redirects=False,
    )
    assert "super-secret-dns-token" not in auth.get("/settings").text

    shown = auth.get("/api/tls/caddyfile").json()["caddyfile"]
    assert "super-secret-dns-token" not in shown
    assert "***REDACTED***" in shown


def test_tls_endpoints_require_login(client):
    client.cookies.clear()
    assert client.get("/api/tls/status").status_code == 401
    assert client.get("/api/tls/caddyfile").status_code == 401


def test_status_endpoint_returns_json(auth, caddy):
    body = auth.get("/api/tls/status").json()
    assert "state" in body and "detail" in body
    json.dumps(body)  # serialisable, so the UI can render it


# ------------------------------------------------------- providers vs. binary
def test_every_offered_provider_is_compiled_into_the_sidecar():
    """The dropdown and the Caddy binary must not drift: offering a provider
    whose module was never built gives a confusing runtime failure."""
    import pathlib
    import re

    dockerfile = pathlib.Path("Dockerfile.caddy").read_text()
    built = set(re.findall(r"--with github\.com/caddy-dns/([\w-]+)", dockerfile))
    assert set(tls.DNS_PROVIDERS) <= built, set(tls.DNS_PROVIDERS) - built


def test_every_provider_has_a_token_hint():
    assert set(tls.DNS_PROVIDERS) == set(tls.DNS_TOKEN_HINTS)


def test_provider_choice_reaches_the_caddyfile(caddy):
    for provider in tls.DNS_PROVIDERS:
        row = brand(tls_enabled=True, tls_hostname="mdm.example.com", tls_dns_provider=provider)
        row.tls_challenge = "dns"
        row.tls_dns_token = f"token-for-{provider}"
        text = tls.render_caddyfile(row)
        assert f"dns {provider} token-for-{provider}" in text


def test_an_unknown_provider_is_rejected_by_the_form(auth, caddy):
    auth.post(
        "/settings/tls",
        data={
            "tls_enabled": "on",
            "tls_hostname": "mdm.example.com",
            "tls_challenge": "dns",
            "tls_dns_provider": "route53",  # multi-credential, not offered
            "tls_dns_token": "tok",
        },
        follow_redirects=False,
    )
    assert "dns ionos tok" in CADDY["loads"][-1]["body"]  # falls back, never writes route53


def test_caddy_builder_can_fetch_a_newer_go_toolchain():
    """caddy-dns modules move their minimum Go version; the builder images pin
    GOTOOLCHAIN=local, which turns that into a hard build failure."""
    import pathlib

    dockerfile = pathlib.Path("Dockerfile.caddy").read_text()
    assert "GOTOOLCHAIN=auto" in dockerfile


# ------------------------------------------------- status against a real handshake
# Regression cover for the reason status was useless in 2.3.0: the probe read
# getpeercert(), which returns {} whenever verify_mode is CERT_NONE, so a
# perfectly good certificate was reported as "Caddy served no certificate".
# These tests hand the probe an actual TLS server, so parsing has to work.
def _certificate(issuer_org, issuer_cn, host="mdm.example.com", days=89):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org),
                    x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
                ]
            )
        )
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


@contextlib.contextmanager
def _serving(cert_pem, key_pem):
    """Point tls.CADDY_HTTPS at a one-shot TLS server using that certificate."""
    with tempfile.TemporaryDirectory() as directory:
        cert_path = pathlib.Path(directory, "cert.pem")
        key_path = pathlib.Path(directory, "key.pem")
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def serve():
            try:
                raw, _ = listener.accept()
            except OSError:
                return
            try:
                with context.wrap_socket(raw, server_side=True) as wrapped:
                    wrapped.recv(1)
            except OSError:
                raw.close()

        threading.Thread(target=serve, daemon=True).start()
        original = tls.CADDY_HTTPS
        tls.CADDY_HTTPS = listener.getsockname()
        try:
            yield
        finally:
            tls.CADDY_HTTPS = original
            listener.close()


def test_status_reads_a_served_certificate():
    with _serving(*_certificate("Let's Encrypt", "E5")):
        result = tls.certificate_status(brand(tls_enabled=True, tls_hostname="mdm.example.com"))
    assert result["state"] == "ok"
    assert result["issuer"] == "Let's Encrypt E5"
    assert 87 <= result["days_left"] <= 89
    assert result["names"] == ["mdm.example.com"]


def test_status_flags_a_staging_certificate():
    cert = _certificate("Let's Encrypt", "(STAGING) Baloney Bulgur YE2")
    with _serving(*cert):
        result = tls.certificate_status(
            brand(tls_enabled=True, tls_hostname="mdm.example.com", tls_staging=True)
        )
    assert result["state"] == "staging"
    assert "will not trust" in result["detail"]


def test_status_says_to_restart_when_staging_is_off_but_still_served():
    cert = _certificate("Let's Encrypt", "(STAGING) Baloney Bulgur YE2")
    with _serving(*cert):
        result = tls.certificate_status(
            brand(tls_enabled=True, tls_hostname="mdm.example.com", tls_staging=False)
        )
    assert result["state"] == "staging"
    assert "Restart the caddy container" in result["detail"]


def test_status_flags_caddys_internal_certificate():
    cert = _certificate("Caddy Local Authority", "Caddy Local Authority - ECC Intermediate CA")
    with _serving(*cert):
        result = tls.certificate_status(brand(tls_enabled=True, tls_hostname="mdm.example.com"))
    assert result["state"] == "self-signed"
    assert "not a Let's Encrypt one" in result["detail"]


# --------------------------------------------------------------- restart safety
def test_startup_reapplies_the_stored_https_config(auth, caddy):
    """A Caddy restart drops the pushed config; the app must put it back."""
    auth.post(
        "/settings/tls",
        data={
            "tls_enabled": "on",
            "tls_hostname": "mdm.example.com",
            "tls_email": "kyle@example.com",
            "tls_challenge": "http",
        },
        follow_redirects=False,
    )
    CADDY["loads"].clear()

    main.reapply_tls()

    assert CADDY["loads"], "startup did not re-push the config"
    assert "mdm.example.com {" in CADDY["loads"][-1]["body"]


def test_startup_pushes_nothing_when_https_is_off(auth, caddy):
    auth.post("/settings/tls", data={"tls_hostname": ""}, follow_redirects=False)
    CADDY["loads"].clear()

    main.reapply_tls()

    assert CADDY["loads"] == []


def test_startup_survives_caddy_being_down(auth, caddy):
    auth.post(
        "/settings/tls",
        data={"tls_enabled": "on", "tls_hostname": "mdm.example.com", "tls_challenge": "http"},
        follow_redirects=False,
    )
    original = tls.CADDY_ADMIN
    tls.CADDY_ADMIN = "http://127.0.0.1:1"
    try:
        main.reapply_tls()  # must not raise - the app has to boot regardless
    finally:
        tls.CADDY_ADMIN = original

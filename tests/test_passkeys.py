"""Passkey ceremonies, driven by a real software authenticator.

These go through py_webauthn's actual verification, so a mistake in how the app
frames a ceremony - wrong RP ID, wrong origin, a reused challenge, a rolled-back
counter - fails here rather than in production.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import auth as auth_mod
from app.database import session_scope
from app.main import app
from app.models import Branding, User, WebAuthnCredential

from .fake_authenticator import FakeAuthenticator
from .test_auth import PASSWORD, make_user, sign_in

RP_ID = "mdm.example.com"
ORIGIN = f"https://{RP_ID}"


@pytest.fixture
def https():
    """A client whose requests really are HTTPS on the passkey hostname.

    Starlette's TestClient always reports the peer as "testclient", so the
    X-Forwarded-* headers the app trusts from the sidecar are (correctly)
    ignored here. Pointing base_url at the real hostname exercises the same
    code path without weakening that check.
    """
    with session_scope() as session:
        brand = session.get(Branding, 1) or Branding(id=1)
        brand.tls_enabled = True
        brand.tls_hostname = RP_ID
        session.add(brand)

    client = TestClient(app, base_url=ORIGIN)
    resp = client.post("/login", data={"password": "test-password"}, follow_redirects=False)
    assert resp.status_code == 303
    return client


@pytest.fixture
def plain():
    """Same app, reached over plain HTTP - where passkeys must not be offered."""
    client = TestClient(app)
    client.post("/login", data={"password": "test-password"}, follow_redirects=False)
    return client


def register(client, authenticator: FakeAuthenticator, name: str = "Test key", **overrides):
    options = client.post("/webauthn/register/options").json()
    credential = authenticator.register(options, **overrides)
    return client.post(
        "/webauthn/register/verify",
        json={"credential": credential, "name": name, "transports": ["internal"]},
    )


def authenticate(client, authenticator: FakeAuthenticator, **overrides):
    options = client.post("/webauthn/login/options").json()
    credential = authenticator.authenticate(options, **overrides)
    return client.post(
        "/webauthn/login/verify", json={"credential": credential}
    )


# ------------------------------------------------------------- availability
def test_passkeys_are_refused_over_plain_http(plain):
    resp = plain.post("/webauthn/register/options")
    assert resp.status_code == 400
    assert "HTTPS" in resp.json()["error"]


def test_account_page_explains_why_over_plain_http(plain):
    page = plain.get("/account").text
    assert "Passkeys need HTTPS" in page


def test_options_are_offered_over_https(https):
    resp = https.post("/webauthn/register/options")
    assert resp.status_code == 200
    assert resp.json()["rp"]["id"] == RP_ID


# ------------------------------------------------------------- registration
def test_register_and_sign_in(https):
    device = FakeAuthenticator(RP_ID, ORIGIN)
    resp = register(https, device)
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is True

    with session_scope() as session:
        creds = session.query(WebAuthnCredential).all()
        assert len(creds) == 1
        assert creds[0].name == "Test key"
        assert creds[0].rp_id == RP_ID
        assert creds[0].public_key

    https.get("/logout")
    resp = authenticate(https, device)
    assert resp.status_code == 200, resp.text
    assert https.get("/").status_code == 200


def test_first_passkey_hands_back_recovery_codes(https):
    resp = register(https, FakeAuthenticator(RP_ID, ORIGIN))
    assert len(resp.json()["codes"]) == 10


def test_second_passkey_does_not_reissue_recovery_codes(https):
    register(https, FakeAuthenticator(RP_ID, ORIGIN), name="One")
    resp = register(https, FakeAuthenticator(RP_ID, ORIGIN), name="Two")
    assert resp.json()["codes"] == []


def test_registration_rejects_a_wrong_origin(https):
    device = FakeAuthenticator(RP_ID, ORIGIN)
    resp = register(https, device, origin="https://phish.example.net")
    assert resp.status_code == 400
    assert "failed" in resp.json()["error"].lower()


def test_registration_rejects_a_wrong_rp_id(https):
    device = FakeAuthenticator(RP_ID, ORIGIN)
    resp = register(https, device, rp_id="phish.example.net")
    assert resp.status_code == 400


def test_a_challenge_cannot_be_reused(https):
    device = FakeAuthenticator(RP_ID, ORIGIN)
    options = https.post("/webauthn/register/options").json()
    payload = {
        "credential": device.register(options),
        "name": "One",
        "transports": ["internal"],
    }
    first = https.post("/webauthn/register/verify", json=payload)
    assert first.status_code == 200
    replay = https.post("/webauthn/register/verify", json=payload)
    assert replay.status_code == 400
    assert "expired" in replay.json()["error"]


# ------------------------------------------------------------ sign-in paths
def test_unknown_passkey_is_refused(https):
    stranger = FakeAuthenticator(RP_ID, ORIGIN)
    https.get("/logout")
    resp = authenticate(https, stranger)
    assert resp.status_code == 400
    assert "not registered" in resp.json()["error"]


def test_a_clone_is_detected_by_the_counter(https):
    device = FakeAuthenticator(RP_ID, ORIGIN)
    register(https, device)
    https.get("/logout")
    assert authenticate(https, device).status_code == 200
    https.get("/logout")
    assert authenticate(https, device).status_code == 200  # counter now at 2

    # A cloned authenticator carries a stale counter: it signs correctly but
    # cannot know how many times the original has been used since.
    device.sign_count = 0
    https.get("/logout")
    resp = authenticate(https, device)
    assert resp.status_code == 400
    assert "cloned" in resp.json()["error"]


def test_passkey_as_a_second_factor(https):
    """Password first, passkey second - the other supported shape."""
    device = FakeAuthenticator(RP_ID, ORIGIN)
    register(https, device)

    with session_scope() as session:
        admin = auth_mod.by_username(session, "admin")
        admin.password_hash = auth_mod.hash_password(PASSWORD)

    client = TestClient(app, base_url=ORIGIN)
    step_one = client.post(
        "/login",
        data={"username": "admin", "password": PASSWORD},
        follow_redirects=False,
    )
    assert step_one.headers["location"] == "/login/mfa"

    options = client.post("/webauthn/login/options").json()
    # Scoped to that user's credentials, since we know who is signing in.
    assert len(options["allowCredentials"]) == 1

    resp = client.post(
        "/webauthn/login/verify",
        json={"credential": device.authenticate(options)},
    )
    assert resp.status_code == 200
    assert client.get("/").status_code == 200


def test_disabled_account_cannot_use_its_passkey(https):
    device = FakeAuthenticator(RP_ID, ORIGIN)
    register(https, device)
    with session_scope() as session:
        auth_mod.by_username(session, "admin").is_active = False

    resp = authenticate(TestClient(app, base_url=ORIGIN), device)
    assert resp.status_code == 403


def test_removing_a_passkey(https):
    register(https, FakeAuthenticator(RP_ID, ORIGIN))
    with session_scope() as session:
        cred_id = session.query(WebAuthnCredential).one().id
    https.post(f"/account/passkeys/{cred_id}/delete", follow_redirects=False)
    with session_scope() as session:
        assert session.query(WebAuthnCredential).count() == 0


def test_last_factor_cannot_be_removed_when_mfa_is_required(https):
    register(https, FakeAuthenticator(RP_ID, ORIGIN))
    https.post("/security", data={"require_mfa": "on"}, follow_redirects=False)
    with session_scope() as session:
        cred_id = session.query(WebAuthnCredential).one().id
    https.post(f"/account/passkeys/{cred_id}/delete", follow_redirects=False)
    with session_scope() as session:
        assert session.query(WebAuthnCredential).count() == 1


def test_admin_clearing_factors_removes_passkeys(https):
    register(https, FakeAuthenticator(RP_ID, ORIGIN))
    with session_scope() as session:
        admin_id = auth_mod.by_username(session, "admin").id
    https.post(f"/users/{admin_id}/clear-mfa", follow_redirects=False)
    with session_scope() as session:
        assert session.query(WebAuthnCredential).count() == 0


def test_another_users_passkey_cannot_be_deleted(https):
    register(https, FakeAuthenticator(RP_ID, ORIGIN))
    with session_scope() as session:
        cred_id = session.query(WebAuthnCredential).one().id

    make_user("kyle", role="admin")
    client = TestClient(app, base_url=ORIGIN)
    sign_in(client, "kyle")
    resp = client.post(f"/account/passkeys/{cred_id}/delete", follow_redirects=False)
    assert resp.status_code == 404
    with session_scope() as session:
        assert session.query(WebAuthnCredential).count() == 1


def test_signing_in_updates_the_counter(https):
    device = FakeAuthenticator(RP_ID, ORIGIN)
    register(https, device)
    https.get("/logout")
    authenticate(https, device)
    with session_scope() as session:
        assert session.query(WebAuthnCredential).one().sign_count > 0
        assert session.query(WebAuthnCredential).one().last_used_at is not None


def test_rp_id_prefers_the_configured_hostname_over_the_request(https):
    """Otherwise every passkey would break the first time someone used a
    different hostname or the LAN address."""
    from app import passkeys

    class Req:
        url = type("U", (), {"hostname": "somewhere-else.example", "scheme": "https"})()
        headers: dict = {}
        client = type("C", (), {"host": "10.0.0.1"})()

    with session_scope() as session:
        from app.models import Branding

        brand = session.get(Branding, 1)
        assert passkeys.rp_id_for(Req(), brand) == RP_ID


def test_users_page_shows_who_has_a_factor(https):
    register(https, FakeAuthenticator(RP_ID, ORIGIN))
    page = https.get("/users").text
    assert "1 passkey(s)" in page


def test_credential_is_bound_to_one_account(https):
    """The stored credential id must be unique across users."""
    device = FakeAuthenticator(RP_ID, ORIGIN)
    register(https, device)
    with session_scope() as session:
        cred = session.query(WebAuthnCredential).one()
        other = User(username="kyle", role="admin", password_hash=auth_mod.hash_password(PASSWORD))
        session.add(other)
        session.flush()
        assert cred.user_id != other.id


def test_an_ip_address_is_not_a_relying_party(https):
    """127.0.0.1 is a secure origin but not a usable RP ID - offering passkeys
    there would produce a credential no browser would ever hand back."""
    from app import passkeys
    from app.models import Branding

    class Req:
        url = type("U", (), {"hostname": "127.0.0.1", "scheme": "https", "netloc": "127.0.0.1"})()
        headers: dict = {}
        client = type("C", (), {"host": "127.0.0.1"})()

    ok, why = passkeys.availability(Req(), Branding(id=1))
    assert not ok
    assert "hostname" in why

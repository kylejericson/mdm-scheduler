"""Accounts, roles, MFA, throttling and sessions."""

from __future__ import annotations

import time
from datetime import UTC, datetime

import pyotp
import pytest

from app import auth as auth_mod
from app import mfa
from app.config import LOGIN_MAX_FAILURES
from app.database import session_scope
from app.models import SecuritySettings, User, UserSession

PASSWORD = "correct-horse-battery"


# ------------------------------------------------------------------ helpers
def totp_now(secret: str) -> str:
    """What the user's phone would show.

    Not pyotp's own now(): it derives the counter from a naive local datetime,
    so it disagrees with real authenticators whenever TZ is not UTC - which it
    is not in these tests, deliberately.
    """
    return pyotp.TOTP(secret).at(datetime.fromtimestamp(int(time.time()), UTC))


def make_user(username: str, role: str = "operator", password: str = PASSWORD) -> int:
    with session_scope() as session:
        user = User(
            username=username,
            role=role,
            password_hash=auth_mod.hash_password(password),
        )
        session.add(user)
        session.flush()
        return user.id


def enrol_totp(user_id: int) -> str:
    with session_scope() as session:
        user = session.get(User, user_id)
        secret = mfa.new_secret()
        user.totp_secret = secret
        user.totp_confirmed = True
        return secret


def sign_in(client, username: str, password: str = PASSWORD):
    return client.post(
        "/login", data={"username": username, "password": password}, follow_redirects=False
    )


# --------------------------------------------------------------- bootstrap
def test_existing_install_becomes_an_admin_account(client):
    """An upgrade must not lock anyone out: ADMIN_PASSWORD still signs in."""
    resp = client.post("/login", data={"password": "test-password"}, follow_redirects=False)
    assert resp.status_code == 303
    with session_scope() as session:
        user = auth_mod.by_username(session, "admin")
        assert user is not None
        assert user.role == "admin"


def test_break_glass_is_recorded_as_its_own_action(client):
    client.post("/login", data={"password": "test-password"}, follow_redirects=False)
    page = client.get("/audit").text
    assert "Break-glass sign-in" in page


def test_break_glass_can_be_switched_off(auth):
    auth.post("/security", data={"break_glass_enabled": ""}, follow_redirects=False)
    auth.get("/logout")
    resp = auth.post("/login", data={"password": "test-password"}, follow_redirects=False)
    assert resp.status_code == 401


# --------------------------------------------------------------- passwords
def test_password_sign_in(client):
    make_user("kyle", role="admin")
    assert sign_in(client, "kyle").status_code == 303
    assert client.get("/").status_code == 200


def test_wrong_password_says_nothing_useful(client):
    make_user("kyle")
    resp = sign_in(client, "kyle", "nope")
    assert resp.status_code == 401
    # Same message whether or not the account exists - otherwise the login form
    # is a username oracle.
    other = sign_in(client, "nobody", "nope")
    assert "Incorrect username or password." in resp.text
    assert "Incorrect username or password." in other.text


def test_disabled_account_cannot_sign_in(client):
    user_id = make_user("kyle")
    with session_scope() as session:
        session.get(User, user_id).is_active = False
    assert sign_in(client, "kyle").status_code == 401


def test_short_passwords_are_refused(auth):
    auth.post(
        "/users",
        data={"username": "shorty", "role": "viewer", "password": "abc"},
        follow_redirects=False,
    )
    with session_scope() as session:
        assert auth_mod.by_username(session, "shorty") is None


# ------------------------------------------------------------------- roles
@pytest.mark.parametrize(
    "role,path,allowed",
    [
        ("viewer", "/", True),
        ("viewer", "/users", False),
        ("viewer", "/audit", False),
        ("viewer", "/instances", False),
        ("viewer", "/account", True),
        ("operator", "/users", False),
        ("operator", "/instances", False),
        ("admin", "/users", True),
        ("admin", "/instances", True),
    ],
)
def test_role_gates_pages(client, role, path, allowed):
    make_user("person", role=role)
    sign_in(client, "person")
    resp = client.get(path)
    assert (resp.status_code == 200) is allowed


def test_operator_without_instances_is_not_bounced_into_a_403(client):
    """The empty-state redirect used to send operators to a page they can't open."""
    make_user("op", role="operator")
    sign_in(client, "op")
    resp = client.get("/jobs/new", follow_redirects=False)
    assert resp.headers["location"] == "/"


def test_operator_can_open_the_job_form(client, instance):
    make_user("op", role="operator")
    sign_in(client, "op")
    assert client.get("/jobs/new").status_code == 200


def test_viewer_cannot_write(client):
    make_user("reader", role="viewer")
    sign_in(client, "reader")
    resp = client.post("/jobs/1/run", follow_redirects=False)
    assert resp.status_code == 403


def test_operator_cannot_reach_credentials(client):
    make_user("op", role="operator")
    sign_in(client, "op")
    assert client.get("/instances").status_code == 403
    # but still needs live discovery for the job form
    assert client.get("/api/instances/1/objects?kind=policy").status_code in (404, 400, 500)


def test_last_admin_cannot_be_demoted(auth):
    with session_scope() as session:
        admin_id = auth_mod.by_username(session, "admin").id
    auth.post(
        f"/users/{admin_id}",
        data={"role": "viewer", "is_active": "on"},
        follow_redirects=False,
    )
    with session_scope() as session:
        assert session.get(User, admin_id).role == "admin"


# -------------------------------------------------------------------- totp
def test_totp_required_after_password(client):
    user_id = make_user("kyle", role="admin")
    secret = enrol_totp(user_id)

    resp = sign_in(client, "kyle")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login/mfa"
    # A password alone is not a session.
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"

    code = totp_now(secret)
    done = client.post("/login/mfa", data={"code": code}, follow_redirects=False)
    assert done.status_code == 303
    assert client.get("/").status_code == 200


def test_totp_code_cannot_be_replayed(client):
    user_id = make_user("kyle", role="admin")
    secret = enrol_totp(user_id)
    code = totp_now(secret)

    sign_in(client, "kyle")
    assert client.post("/login/mfa", data={"code": code}, follow_redirects=False).status_code == 303
    client.get("/logout")

    sign_in(client, "kyle")
    again = client.post("/login/mfa", data={"code": code}, follow_redirects=False)
    assert again.status_code == 401
    assert "already been used" in again.text


def test_wrong_totp_is_refused(client):
    user_id = make_user("kyle", role="admin")
    enrol_totp(user_id)
    sign_in(client, "kyle")
    resp = client.post("/login/mfa", data={"code": "000000"}, follow_redirects=False)
    assert resp.status_code == 401
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"


def test_totp_enrolment_generates_recovery_codes(auth):
    auth.post("/account/totp/begin", follow_redirects=False)
    with session_scope() as session:
        user = auth_mod.by_username(session, "admin")
        secret = user.totp_secret
    page = auth.post("/account/totp/confirm", data={"code": totp_now(secret)})
    assert page.status_code == 200
    assert "Recovery codes" in page.text
    with session_scope() as session:
        user = auth_mod.by_username(session, "admin")
        assert user.has_totp
        assert mfa.unused_recovery_codes(user) == 10


# ---------------------------------------------------------- recovery codes
def test_recovery_code_works_once(client):
    user_id = make_user("kyle", role="admin")
    enrol_totp(user_id)
    with session_scope() as session:
        codes = mfa.generate_recovery_codes(session, session.get(User, user_id))

    sign_in(client, "kyle")
    resp = client.post("/login/mfa", data={"recovery": codes[0]}, follow_redirects=False)
    assert resp.status_code == 303
    client.get("/logout")

    sign_in(client, "kyle")
    again = client.post("/login/mfa", data={"recovery": codes[0]}, follow_redirects=False)
    assert again.status_code == 401
    assert "already been used" in again.text


def test_recovery_codes_are_not_stored_in_the_clear(client):
    user_id = make_user("kyle")
    with session_scope() as session:
        codes = mfa.generate_recovery_codes(session, session.get(User, user_id))
        stored = [row.code_hash for row in session.get(User, user_id).recovery_codes]
    for code in codes:
        assert code not in stored
        assert code.replace("-", "") not in stored


# -------------------------------------------------------------- throttling
def test_repeated_failures_lock_the_account(client):
    make_user("kyle")
    for _ in range(LOGIN_MAX_FAILURES):
        sign_in(client, "kyle", "wrong")
    resp = sign_in(client, "kyle")  # correct password now
    assert resp.status_code == 429
    assert "Too many failed attempts" in resp.text


def test_lockout_is_per_account(client):
    make_user("kyle", role="admin")
    make_user("dana", role="admin")
    for _ in range(LOGIN_MAX_FAILURES):
        sign_in(client, "kyle", "wrong")
    assert sign_in(client, "dana").status_code == 303


def test_forwarded_for_is_ignored_from_an_untrusted_peer():
    """The header is only believed when the peer is the sidecar."""

    class Req:
        def __init__(self, peer, headers):
            self.client = type("C", (), {"host": peer})()
            self.headers = headers

    # 8.8.8.8 rather than a 203.0.113.x documentation address: Python's
    # is_private covers reserved ranges too, so a doc address would be treated
    # as internal and prove nothing.
    public = Req("8.8.8.8", {"x-forwarded-for": "10.0.0.1"})
    assert auth_mod.client_ip(public) == "8.8.8.8"

    behind_caddy = Req("172.18.0.5", {"x-forwarded-for": "8.8.8.8"})
    assert auth_mod.client_ip(behind_caddy) == "8.8.8.8"


# ---------------------------------------------------------------- sessions
def test_sessions_are_stored_hashed(auth):
    with session_scope() as session:
        rows = session.query(UserSession).all()
        assert rows
        for row in rows:
            assert len(row.id) == 64  # sha256 hex, not the cookie value


def test_revoking_a_session_ends_it(auth):
    with session_scope() as session:
        sid = session.query(UserSession).one().id
    auth.post(f"/account/sessions/{sid}/revoke", follow_redirects=False)
    assert auth.get("/", follow_redirects=False).headers["location"] == "/login"


def test_admin_can_sign_a_user_out_everywhere(auth, client):
    user_id = make_user("kyle", role="admin")
    sign_in(client, "kyle")
    assert client.get("/").status_code == 200

    auth.post(f"/users/{user_id}/revoke-sessions", follow_redirects=False)
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"


def test_changing_a_password_signs_out_other_sessions(auth, client):
    user_id = make_user("kyle", role="admin")
    sign_in(client, "kyle")

    auth.post(f"/users/{user_id}/password", data={"password": "a-new-long-password"})
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"


def test_disabling_an_account_signs_it_out(auth, client):
    user_id = make_user("kyle", role="admin")
    sign_in(client, "kyle")
    auth.post(f"/users/{user_id}", data={"role": "admin", "is_active": ""})
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"


# ------------------------------------------------------------- require MFA
def test_require_mfa_holds_users_on_the_account_page(auth, client):
    auth.post("/security", data={"require_mfa": "on"}, follow_redirects=False)
    make_user("kyle", role="admin")
    sign_in(client, "kyle")

    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/account?enroll=1"
    assert client.get("/account").status_code == 200


def test_admin_can_clear_a_lost_factor(auth):
    user_id = make_user("kyle")
    enrol_totp(user_id)
    auth.post(f"/users/{user_id}/clear-mfa", follow_redirects=False)
    with session_scope() as session:
        user = session.get(User, user_id)
        assert not user.has_mfa
        assert user.recovery_codes == []


# ------------------------------------------------------------------ audit
def test_actions_are_attributed(auth, instance):
    page = auth.get("/audit").text
    assert "Added MDM instance" in page
    assert "admin" in page


def test_audit_survives_deleting_the_user(auth):
    user_id = make_user("temp", role="viewer")
    auth.post(f"/users/{user_id}/delete", follow_redirects=False)
    page = auth.get("/audit").text
    assert "Deleted user" in page
    assert "temp" in page


def test_failed_sign_ins_are_recorded(auth, client):
    make_user("kyle")
    sign_in(client, "kyle", "wrong")
    page = auth.get("/audit?action=sign-in-failed").text
    assert "kyle" in page


# ------------------------------------------------------------------ misc
def test_security_settings_row_exists_after_boot():
    with session_scope() as session:
        assert auth_mod.security_settings(session) is not None
        assert session.get(SecuritySettings, 1) is not None


def test_pending_mfa_expires(client, monkeypatch):
    user_id = make_user("kyle", role="admin")
    secret = enrol_totp(user_id)
    sign_in(client, "kyle")

    real = time.time
    monkeypatch.setattr(
        "app.main.utcnow",
        lambda: __import__("datetime").datetime.fromtimestamp(real() + 3600, tz=__import__("datetime").UTC),
    )
    resp = client.post("/login/mfa", data={"code": totp_now(secret)}, follow_redirects=False)
    assert resp.headers["location"] == "/login"

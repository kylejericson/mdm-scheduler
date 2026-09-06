"""Accounts, sessions, roles and login throttling.

The shape of this module follows from one decision: sessions are rows in the
database, not just signed cookies. A signed cookie cannot be taken away from
whoever holds it - it stays valid until it expires - which makes "sign that
laptop out now" impossible. A row means revocation is a write.

The cookie carries a random token; the database stores only its SHA-256. A
stolen database therefore yields no usable sessions.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import secrets
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import select

from .config import (
    ADMIN_PASSWORD,
    IP_MAX_FAILURES,
    LOGIN_LOCKOUT_SECONDS,
    LOGIN_MAX_FAILURES,
    LOGIN_WINDOW_SECONDS,
    SESSION_MAX_AGE,
)
from .models import LoginAttempt, SecuritySettings, User, UserSession, as_utc, utcnow

log = logging.getLogger("mdm-scheduler.auth")

hasher = PasswordHasher()

BREAK_GLASS_USERNAME = "admin"


# ------------------------------------------------------------------ passwords
def hash_password(password: str) -> str:
    return hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> tuple[bool, str]:
    """(ok, replacement_hash). The replacement is non-empty when argon2's
    parameters have moved on and the stored hash should be upgraded."""
    if not stored_hash:
        return False, ""
    try:
        hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False, ""
    if hasher.check_needs_rehash(stored_hash):
        return True, hasher.hash(password)
    return True, ""


def password_problem(password: str) -> str:
    """Deliberately minimal: length only.

    Composition rules push people towards Passw0rd! and away from passphrases.
    Length is the property that actually costs an attacker something, and MFA
    is the control doing the real work here.
    """
    if len(password) < 12:
        return "Password must be at least 12 characters."
    return ""


# ---------------------------------------------------------------- client IP
def client_ip(request) -> str:
    """The caller's address, honouring X-Forwarded-For only from the sidecar.

    Caddy sets X-Forwarded-For, and behind it every request appears to come from
    the compose network - which would make per-IP throttling meaningless. But
    the header is trivially forged, and port 8000 is reachable directly, so it
    is trusted only when the immediate peer is a private address (i.e. the
    sidecar, not the internet).
    """
    peer = getattr(request.client, "host", "") or ""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded and _is_private(peer):
        return forwarded.split(",")[0].strip()[:64]
    return peer[:64]


def _is_private(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


# ------------------------------------------------------------------ settings
def security_settings(session) -> SecuritySettings:
    row = session.get(SecuritySettings, 1)
    if row is None:
        row = SecuritySettings(id=1)
        session.add(row)
        session.flush()
    return row


# ------------------------------------------------------------------ bootstrap
def ensure_bootstrap_user(session) -> User | None:
    """Turn a single-password install into an account, once.

    An existing deployment upgrades with no action from its operator: the first
    boot after the upgrade creates `admin` with the password they already use.
    """
    existing = session.scalars(select(User)).first()
    if existing is not None:
        return None
    if not ADMIN_PASSWORD:
        return None
    user = User(
        username=BREAK_GLASS_USERNAME,
        display_name="Administrator",
        role="admin",
        password_hash=hash_password(ADMIN_PASSWORD),
    )
    session.add(user)
    session.flush()
    log.info("created initial admin account from ADMIN_PASSWORD")
    return user


# ------------------------------------------------------------------ throttle
def lockout_message(session, username: str, ip: str) -> str:
    """Non-empty if this attempt should be refused before checking the password.

    Two counters over the same window: per account, which stops someone grinding
    one password; and per IP, which stops someone spraying one password across
    many usernames. The second is why the IP limit is higher than the account
    limit rather than equal to it.
    """
    now = utcnow()
    since = now - timedelta(seconds=LOGIN_WINDOW_SECONDS)

    if username:
        user = by_username(session, username)
        if user and user.locked_until and as_utc(user.locked_until) > now:
            remaining = int((as_utc(user.locked_until) - now).total_seconds() // 60) + 1
            return f"Too many failed attempts. Try again in {remaining} minute(s)."

    account_failures = session.scalars(
        select(LoginAttempt).where(
            LoginAttempt.username == username.lower(),
            LoginAttempt.success.is_(False),
            LoginAttempt.ts >= since,
        )
    ).all()
    if username and len(account_failures) >= LOGIN_MAX_FAILURES:
        return "Too many failed attempts for that account. Try again later."

    ip_failures = session.scalars(
        select(LoginAttempt).where(
            LoginAttempt.ip == ip,
            LoginAttempt.success.is_(False),
            LoginAttempt.ts >= since,
        )
    ).all()
    if ip and len(ip_failures) >= IP_MAX_FAILURES:
        return "Too many failed attempts from this address. Try again later."

    return ""


def record_attempt(session, username: str, ip: str, success: bool, reason: str = "") -> None:
    session.add(
        LoginAttempt(
            username=(username or "").lower()[:64],
            ip=ip,
            success=success,
            reason=reason[:60],
        )
    )
    user = by_username(session, username) if username else None
    if user is None:
        return
    if success:
        user.locked_until = None
        return

    since = utcnow() - timedelta(seconds=LOGIN_WINDOW_SECONDS)
    failures = session.scalars(
        select(LoginAttempt).where(
            LoginAttempt.username == username.lower(),
            LoginAttempt.success.is_(False),
            LoginAttempt.ts >= since,
        )
    ).all()
    if len(failures) >= LOGIN_MAX_FAILURES:
        user.locked_until = utcnow() + timedelta(seconds=LOGIN_LOCKOUT_SECONDS)


def prune_attempts(session) -> None:
    cutoff = utcnow() - timedelta(seconds=max(LOGIN_WINDOW_SECONDS, LOGIN_LOCKOUT_SECONDS) * 4)
    for row in session.scalars(select(LoginAttempt).where(LoginAttempt.ts < cutoff)).all():
        session.delete(row)


# ------------------------------------------------------------------- lookups
def by_username(session, username: str) -> User | None:
    if not username:
        return None
    return session.scalars(select(User).where(User.username == username.strip().lower())).first()


def active_users(session) -> list[User]:
    return list(session.scalars(select(User).order_by(User.username)).all())


def admin_count(session) -> int:
    return len(
        session.scalars(
            select(User).where(User.role == "admin", User.is_active.is_(True))
        ).all()
    )


# ------------------------------------------------------------------ sessions
def _token_id(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def start_session(session, user: User, ip: str, user_agent: str, method: str) -> str:
    """Returns the raw token for the cookie. Only its hash is stored."""
    token = secrets.token_urlsafe(32)
    session.add(
        UserSession(
            id=_token_id(token),
            user_id=user.id,
            ip=ip,
            user_agent=(user_agent or "")[:255],
            method=method,
            expires_at=utcnow() + timedelta(seconds=SESSION_MAX_AGE),
        )
    )
    user.last_login_at = utcnow()
    return token


def resolve_session(session, token: str) -> tuple[User, UserSession] | tuple[None, None]:
    if not token:
        return None, None
    row = session.get(UserSession, _token_id(token))
    if row is None or not row.active:
        return None, None
    user = session.get(User, row.user_id)
    if user is None or not user.is_active:
        return None, None
    row.last_seen_at = utcnow()
    return user, row


def revoke_session(session, token: str) -> None:
    row = session.get(UserSession, _token_id(token))
    if row is not None and row.revoked_at is None:
        row.revoked_at = utcnow()


def revoke_session_id(session, session_id: str) -> UserSession | None:
    row = session.get(UserSession, session_id)
    if row is not None and row.revoked_at is None:
        row.revoked_at = utcnow()
    return row


def revoke_all_for(session, user: User, except_id: str = "") -> int:
    count = 0
    for row in user.sessions:
        if row.id != except_id and row.revoked_at is None and row.active:
            row.revoked_at = utcnow()
            count += 1
    return count


def prune_sessions(session) -> None:
    cutoff = datetime.now(UTC) - timedelta(days=30)
    for row in session.scalars(select(UserSession).where(UserSession.expires_at < cutoff)).all():
        session.delete(row)

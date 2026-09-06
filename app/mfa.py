"""TOTP enrolment and recovery codes.

TOTP is the fallback factor rather than the headline one - passkeys are better
in every way except portability, and portability is exactly what you need when
you are signing in from the LAN address or from someone else's machine.
"""

from __future__ import annotations

import base64
import hmac
import io
import secrets
import time
from datetime import UTC, datetime
from hashlib import sha256

import pyotp
import segno

from .config import RECOVERY_CODE_COUNT, SECRET_KEY
from .models import RecoveryCode, utcnow

TIME_STEP = 30
# One step either side: enough for a phone whose clock has drifted, not enough
# to widen the window meaningfully.
VALID_WINDOW = 1


# ----------------------------------------------------------------------- totp
def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(username: str, secret: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer or "MDM Scheduler")


def qr_data_uri(uri: str) -> str:
    """An inline SVG data URI for the enrolment QR code.

    Rendered here rather than by a JavaScript library, because the app
    deliberately loads nothing from a CDN at runtime - and because handing the
    TOTP secret to a third-party script would be a poor way to set up MFA.
    """
    buf = io.BytesIO()
    segno.make(uri, error="m").save(buf, kind="svg", scale=4, border=2, dark="#000", light=None)
    encoded = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/svg+xml;base64,{encoded}"


def check_totp(user, code: str) -> tuple[bool, str]:
    """Verify a code and burn its time step.

    Returns (ok, error). Accepting a code more than once inside its 30-second
    window would make it replayable by anyone who saw it typed, so the step it
    came from is recorded and never accepted again.
    """
    secret = user.totp_secret
    if not secret:
        return False, "No authenticator app is set up for this account."

    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False, "Enter the 6-digit code from your authenticator app."

    totp = pyotp.TOTP(secret)
    now = int(time.time())
    for offset in range(-VALID_WINDOW, VALID_WINDOW + 1):
        moment = now + offset * TIME_STEP
        slot = moment // TIME_STEP
        # An explicitly UTC-aware datetime, not an int and not
        # datetime.now(). pyotp derives the counter from local wall-clock time
        # for naive values, so anything that leaves the timezone implicit
        # produces codes that disagree with the user's phone whenever the
        # container's TZ is not UTC.
        stamp = datetime.fromtimestamp(moment, UTC)
        if not hmac.compare_digest(totp.at(stamp), code):
            continue
        if slot <= (user.totp_last_slot or 0):
            return False, "That code has already been used. Wait for the next one."
        user.totp_last_slot = slot
        return True, ""
    return False, "That code is not valid. Check your device's clock if it keeps failing."


# ------------------------------------------------------------- recovery codes
def _hash_code(code: str) -> str:
    """Keyed SHA-256 rather than argon2.

    Recovery codes are 100+ bits of machine-generated entropy, so the slow
    hashing that protects human-chosen passwords buys nothing here - and
    verifying a code means testing it against every unused code on the account,
    which with argon2 would take seconds.
    """
    return hmac.new(SECRET_KEY.encode(), code.encode(), sha256).hexdigest()


def _format(raw: str) -> str:
    return f"{raw[:5]}-{raw[5:10]}-{raw[10:15]}"


def generate_recovery_codes(session, user, count: int = 0) -> list[str]:
    """Replace this user's codes. Returns the plaintext, shown exactly once."""
    for existing in list(user.recovery_codes):
        session.delete(existing)
    user.recovery_codes.clear()

    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"  # no l/i/o/0/1
    codes = []
    for _ in range(count or RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(alphabet) for _ in range(15))
        codes.append(_format(raw))
        session.add(RecoveryCode(user_id=user.id, code_hash=_hash_code(raw)))
    return codes


def consume_recovery_code(session, user, code: str) -> bool:
    raw = (code or "").strip().lower().replace("-", "").replace(" ", "")
    if not raw:
        return False
    candidate = _hash_code(raw)
    for stored in user.recovery_codes:
        if stored.used_at is None and hmac.compare_digest(stored.code_hash, candidate):
            stored.used_at = utcnow()
            return True
    return False


def unused_recovery_codes(user) -> int:
    return sum(1 for code in user.recovery_codes if code.used_at is None)

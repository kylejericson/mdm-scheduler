import os
from pathlib import Path

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

BRANDING_DIR = DATA_DIR / "branding"
BRANDING_DIR.mkdir(parents=True, exist_ok=True)
MAX_LOGO_BYTES = int(os.getenv("MAX_LOGO_BYTES", str(2 * 1024 * 1024)))
LOGO_TYPES = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
    "image/svg+xml": ".svg",
    "image/gif": ".gif",
}

DB_PATH = DATA_DIR / "scheduler.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

SECRET_KEY = os.getenv("SECRET_KEY", "insecure-dev-key-change-me")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
DEFAULT_TZ = os.getenv("TZ", "UTC")
SESSION_MAX_AGE = int(os.getenv("SESSION_MAX_AGE", "86400"))
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "45"))
LOG_RETENTION = int(os.getenv("LOG_RETENTION", "500"))

# ------------------------------------------------------------------ accounts
# Login throttling. Counted per account and per source IP over the same window:
# the account limit stops someone grinding one password, the IP limit stops
# someone spraying one password across many usernames.
LOGIN_MAX_FAILURES = int(os.getenv("LOGIN_MAX_FAILURES", "5"))
LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "900"))
LOGIN_LOCKOUT_SECONDS = int(os.getenv("LOGIN_LOCKOUT_SECONDS", "900"))
IP_MAX_FAILURES = int(os.getenv("IP_MAX_FAILURES", "20"))

AUDIT_RETENTION = int(os.getenv("AUDIT_RETENTION", "10000"))
RECOVERY_CODE_COUNT = int(os.getenv("RECOVERY_CODE_COUNT", "10"))

# The WebAuthn relying party ID. Passkeys are bound to it, so it must be the
# hostname people actually sign in on and it cannot change without invalidating
# every registered passkey. Left empty, it is derived from the HTTPS hostname
# configured on the Branding tab.
WEBAUTHN_RP_ID = os.getenv("WEBAUTHN_RP_ID", "").strip().lower()
WEBAUTHN_RP_NAME = os.getenv("WEBAUTHN_RP_NAME", "MDM Scheduler")
# Extra origins allowed to complete a ceremony, comma separated. Only needed for
# a non-standard port, e.g. https://mdm.example.com:8443
WEBAUTHN_EXTRA_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in os.getenv("WEBAUTHN_EXTRA_ORIGINS", "").split(",")
    if origin.strip()
]

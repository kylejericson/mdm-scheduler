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

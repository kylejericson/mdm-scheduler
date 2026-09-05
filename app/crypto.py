import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from .config import SECRET_KEY

_fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest()))


def encrypt(value: str | None) -> str:
    if not value:
        return ""
    return _fernet.encrypt(value.encode()).decode()


def decrypt(value: str | None) -> str:
    if not value:
        return ""
    try:
        return _fernet.decrypt(value.encode()).decode()
    except InvalidToken:
        # SECRET_KEY changed since this row was written.
        return ""

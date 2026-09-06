from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .crypto import decrypt, encrypt
from .database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_utc(dt: datetime | None) -> datetime | None:
    """SQLite drops tzinfo on read. Everything is persisted in UTC, so a naive
    value coming back out of the DB is UTC."""
    if dt is None:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


class Instance(Base):
    __tablename__ = "instances"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    vendor: Mapped[str] = mapped_column(String(20), default="jamf")  # jamf | iru
    base_url: Mapped[str] = mapped_column(String(255))
    auth_type: Mapped[str] = mapped_column(String(20), default="client")  # client | user
    api_token_enc: Mapped[str] = mapped_column(Text, default="")  # Iru bearer token
    client_id: Mapped[str] = mapped_column(String(255), default="")
    client_secret_enc: Mapped[str] = mapped_column(Text, default="")
    username: Mapped[str] = mapped_column(String(255), default="")
    password_enc: Mapped[str] = mapped_column(Text, default="")
    verify_ssl: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    jobs: Mapped[list["Job"]] = relationship(back_populates="instance", cascade="all, delete-orphan")

    @property
    def client_secret(self) -> str:
        return decrypt(self.client_secret_enc)

    @client_secret.setter
    def client_secret(self, value: str):
        self.client_secret_enc = encrypt(value)

    @property
    def password(self) -> str:
        return decrypt(self.password_enc)

    @password.setter
    def password(self, value: str):
        self.password_enc = encrypt(value)

    @property
    def api_token(self) -> str:
        return decrypt(self.api_token_enc)

    @api_token.setter
    def api_token(self, value: str):
        self.api_token_enc = encrypt(value)

    @property
    def vendor_label(self) -> str:
        return "Iru" if self.vendor == "iru" else "Jamf Pro"


class Branding(Base):
    """Single-row table (id=1) holding org branding and UI defaults."""

    __tablename__ = "branding"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    org_name: Mapped[str] = mapped_column(String(120), default="")
    logo_file: Mapped[str] = mapped_column(String(255), default="")
    accent: Mapped[str] = mapped_column(String(20), default="")
    default_theme: Mapped[str] = mapped_column(String(10), default="system")  # system|dark|light
    support_note: Mapped[str] = mapped_column(Text, default="")

    # HTTPS, served by the Caddy sidecar (see app/tls.py)
    tls_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    tls_hostname: Mapped[str] = mapped_column(String(255), default="")
    tls_email: Mapped[str] = mapped_column(String(255), default="")
    tls_challenge: Mapped[str] = mapped_column(String(10), default="http")  # http | dns
    tls_dns_provider: Mapped[str] = mapped_column(String(40), default="ionos")
    tls_dns_token_enc: Mapped[str] = mapped_column(Text, default="")
    tls_staging: Mapped[bool] = mapped_column(Boolean, default=False)

    @property
    def title(self) -> str:
        return f"{self.org_name} MDM Scheduler" if self.org_name else "MDM Scheduler"

    @property
    def tls_dns_token(self) -> str:
        return decrypt(self.tls_dns_token_enc)

    @tls_dns_token.setter
    def tls_dns_token(self, value: str):
        self.tls_dns_token_enc = encrypt(value)


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    instance_id: Mapped[int] = mapped_column(ForeignKey("instances.id", ondelete="CASCADE"))
    action: Mapped[str] = mapped_column(String(60))
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    schedule_type: Mapped[str] = mapped_column(String(10), default="once")  # once | cron
    run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cron: Mapped[str] = mapped_column(String(120), default="")
    tz: Mapped[str] = mapped_column(String(64), default="UTC")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str] = mapped_column(String(20), default="")
    last_message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    instance: Mapped["Instance"] = relationship(back_populates="jobs")
    logs: Mapped[list["JobLog"]] = relationship(
        back_populates="job", cascade="all, delete-orphan", order_by="JobLog.ts.desc()"
    )


class JobLog(Base):
    __tablename__ = "job_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    status: Mapped[str] = mapped_column(String(20))
    message: Mapped[str] = mapped_column(Text, default="")
    trigger: Mapped[str] = mapped_column(String(20), default="schedule")  # schedule | manual

    job: Mapped["Job"] = relationship(back_populates="logs")


# --------------------------------------------------------------------- accounts
# Roles are ordered: everything an operator may do, an admin may do. Checks are
# written as "at least this rank" so adding a role later means inserting a rank,
# not auditing every route.
ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}
ROLE_LABELS = {
    "viewer": "Viewer - read dashboards and run logs",
    "operator": "Operator - create and run jobs",
    "admin": "Admin - everything, including users and credentials",
}


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    display_name: Mapped[str] = mapped_column(String(120), default="")
    email: Mapped[str] = mapped_column(String(255), default="")
    password_hash: Mapped[str] = mapped_column(Text, default="")
    role: Mapped[str] = mapped_column(String(20), default="operator")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)

    totp_secret_enc: Mapped[str] = mapped_column(Text, default="")
    totp_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    # Highest TOTP time-step already accepted, so a code shoulder-surfed inside
    # its 30-second window cannot be replayed.
    totp_last_slot: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    credentials: Mapped[list["WebAuthnCredential"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    recovery_codes: Mapped[list["RecoveryCode"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def totp_secret(self) -> str:
        return decrypt(self.totp_secret_enc)

    @totp_secret.setter
    def totp_secret(self, value: str):
        self.totp_secret_enc = encrypt(value)

    @property
    def has_totp(self) -> bool:
        return bool(self.totp_confirmed and self.totp_secret_enc)

    @property
    def has_passkey(self) -> bool:
        return any(self.credentials)

    @property
    def has_mfa(self) -> bool:
        return self.has_totp or self.has_passkey

    @property
    def label(self) -> str:
        return self.display_name or self.username

    def at_least(self, role: str) -> bool:
        return ROLE_RANK.get(self.role, -1) >= ROLE_RANK.get(role, 99)


class WebAuthnCredential(Base):
    """One registered passkey. A user may have several - a laptop, a phone, a
    hardware key - and losing one should not lock them out."""

    __tablename__ = "webauthn_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    credential_id: Mapped[str] = mapped_column(String(255), unique=True)  # base64url
    public_key: Mapped[str] = mapped_column(Text)  # base64
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    transports: Mapped[str] = mapped_column(String(120), default="")
    name: Mapped[str] = mapped_column(String(120), default="")
    rp_id: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship(back_populates="credentials")


class RecoveryCode(Base):
    """Single-use codes, stored hashed. The only way back in when the phone with
    the authenticator app is gone."""

    __tablename__ = "recovery_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    code_hash: Mapped[str] = mapped_column(Text)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped["User"] = relationship(back_populates="recovery_codes")


class UserSession(Base):
    """Server-side sessions, so they can be listed and revoked.

    A signed cookie alone cannot be taken away from someone - it stays valid
    until it expires. A row here means "sign this laptop out now" is a delete.
    """

    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    method: Mapped[str] = mapped_column(String(20), default="password")  # password|passkey|break-glass

    user: Mapped["User"] = relationship(back_populates="sessions")

    @property
    def active(self) -> bool:
        return self.revoked_at is None and as_utc(self.expires_at) > utcnow()


class LoginAttempt(Base):
    """Feeds the throttle. Kept short - this is a rate limiter's memory, not an
    audit trail; the audit trail is AuditEvent."""

    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    username: Mapped[str] = mapped_column(String(64), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    reason: Mapped[str] = mapped_column(String(60), default="")


class AuditEvent(Base):
    """Who did what. The actor's username is copied in rather than joined, so
    deleting a user does not erase what they did."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(64), default="")
    actor_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(60))
    target_type: Mapped[str] = mapped_column(String(40), default="")
    target: Mapped[str] = mapped_column(String(160), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str] = mapped_column(String(64), default="")


class SecuritySettings(Base):
    """Single-row table (id=1). Separate from Branding because these are
    security controls, not presentation."""

    __tablename__ = "security_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    require_mfa: Mapped[bool] = mapped_column(Boolean, default=False)
    break_glass_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

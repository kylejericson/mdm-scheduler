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

    @property
    def title(self) -> str:
        return f"{self.org_name} MDM Scheduler" if self.org_name else "MDM Scheduler"


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

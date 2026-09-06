"""Who did what.

The actor's username is copied into each row rather than joined from `users`,
so deleting an account does not quietly erase the record of what it did. That
is the whole point of an audit trail: it has to outlive the thing it describes.
"""

from __future__ import annotations

from sqlalchemy import select

from .config import AUDIT_RETENTION
from .models import AuditEvent

# Actions worth naming in one place, so the filter dropdown and the log agree.
ACTIONS = {
    "sign-in": "Signed in",
    "sign-in-failed": "Failed sign-in",
    "sign-out": "Signed out",
    "break-glass": "Break-glass sign-in",
    "user-create": "Created user",
    "user-update": "Updated user",
    "user-delete": "Deleted user",
    "user-password": "Changed password",
    "mfa-enroll": "Registered a factor",
    "mfa-remove": "Removed a factor",
    "recovery-codes": "Generated recovery codes",
    "session-revoke": "Revoked a session",
    "instance-create": "Added MDM instance",
    "instance-update": "Updated MDM instance",
    "instance-delete": "Deleted MDM instance",
    "job-create": "Created job",
    "job-update": "Updated job",
    "job-delete": "Deleted job",
    "job-run": "Ran job now",
    "job-toggle": "Enabled/paused job",
    "settings-update": "Changed settings",
    "tls-update": "Changed HTTPS settings",
    "security-update": "Changed security settings",
}


def record(
    session,
    actor,
    action: str,
    target_type: str = "",
    target: str = "",
    detail: str = "",
    ip: str = "",
) -> None:
    """Never let auditing break the thing being audited.

    A failure to write the log should not roll back a job that already ran, so
    callers are expected to treat this as best effort - but it is deliberately
    in the same transaction as the change it describes, so a change that is
    rolled back leaves no misleading log entry either.
    """
    username = getattr(actor, "username", "") or str(actor or "system")
    session.add(
        AuditEvent(
            actor=username[:64],
            actor_id=getattr(actor, "id", None),
            action=action[:60],
            target_type=target_type[:40],
            target=str(target)[:160],
            detail=detail[:2000],
            ip=ip[:64],
        )
    )


def recent(session, limit: int = 200, action: str = "", actor: str = "") -> list[AuditEvent]:
    query = select(AuditEvent).order_by(AuditEvent.id.desc())
    if action:
        query = query.where(AuditEvent.action == action)
    if actor:
        query = query.where(AuditEvent.actor == actor)
    return list(session.scalars(query.limit(limit)).all())


def prune(session) -> None:
    total = len(session.scalars(select(AuditEvent.id)).all())
    if total <= AUDIT_RETENTION:
        return
    surplus = total - AUDIT_RETENTION
    for row in session.scalars(
        select(AuditEvent).order_by(AuditEvent.id.asc()).limit(surplus)
    ).all():
        session.delete(row)

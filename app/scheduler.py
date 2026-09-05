from __future__ import annotations

import logging
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from sqlalchemy import select

from .actions import run_action
from .clients import client_for
from .config import LOG_RETENTION
from .database import session_scope
from .models import Job, JobLog, as_utc, utcnow

log = logging.getLogger("mdm-scheduler")

scheduler = BackgroundScheduler(timezone=UTC, job_defaults={"misfire_grace_time": 3600})


def job_key(job_id: int) -> str:
    return f"job-{job_id}"


def build_trigger(job: Job):
    if job.schedule_type == "cron":
        if not job.cron:
            return None
        return CronTrigger.from_crontab(job.cron, timezone=ZoneInfo(job.tz or "UTC"))
    if not job.run_at:
        return None
    return DateTrigger(run_date=as_utc(job.run_at))


def sync_job(job: Job):
    """Register / re-register / unregister a job with APScheduler."""
    key = job_key(job.id)
    existing = scheduler.get_job(key)
    if existing:
        existing.remove()

    if not job.enabled:
        return

    trigger = build_trigger(job)
    if trigger is None:
        return

    if job.schedule_type == "once" and job.run_at and as_utc(job.run_at) <= datetime.now(UTC):
        return  # one-shot already in the past; leave it for "Run now"

    scheduler.add_job(
        execute_job,
        trigger=trigger,
        args=[job.id],
        id=key,
        name=job.name,
        replace_existing=True,
    )


def remove_job(job_id: int):
    existing = scheduler.get_job(job_key(job_id))
    if existing:
        existing.remove()


def next_run(job_id: int):
    existing = scheduler.get_job(job_key(job_id))
    return existing.next_run_time if existing else None


def execute_job(job_id: int, trigger_source: str = "schedule") -> tuple[str, str]:
    """Run one job. Returns (status, message). Never raises."""
    with session_scope() as session:
        job = session.get(Job, job_id)
        if job is None:
            return "error", f"Job {job_id} no longer exists"
        instance = job.instance
        action, params, name = job.action, dict(job.params or {}), job.name
        client = client_for(instance)
        instance_name = instance.name

    status, message = "success", ""
    try:
        message = run_action(client, action, params)
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI log
        status, message = "error", f"{type(exc).__name__}: {exc}"
        log.warning("job %s (%s) failed: %s", job_id, name, message)
    finally:
        client.close()

    with session_scope() as session:
        job = session.get(Job, job_id)
        if job is not None:
            job.last_run = utcnow()
            job.last_status = status
            job.last_message = message[:2000]
            session.add(
                JobLog(job_id=job.id, status=status, message=message[:4000], trigger=trigger_source)
            )
            if job.schedule_type == "once" and status == "success" and trigger_source == "schedule":
                job.enabled = False
        _trim_logs(session, job_id)

    log.info("job %s (%s @ %s) -> %s: %s", job_id, name, instance_name, status, message)
    return status, message


def _trim_logs(session, job_id: int):
    ids = session.scalars(
        select(JobLog.id).where(JobLog.job_id == job_id).order_by(JobLog.id.desc()).offset(LOG_RETENTION)
    ).all()
    for stale in ids:
        session.delete(session.get(JobLog, stale))


def start():
    if not scheduler.running:
        scheduler.start()
    with session_scope() as session:
        for job in session.scalars(select(Job)).all():
            sync_job(job)
    log.info("scheduler started with %d registered job(s)", len(scheduler.get_jobs()))


def shutdown():
    if scheduler.running:
        scheduler.shutdown(wait=False)

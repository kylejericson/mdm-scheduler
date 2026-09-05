from __future__ import annotations

import logging
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from mimetypes import guess_type
from pathlib import Path
from zoneinfo import ZoneInfo, available_timezones

from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from starlette.middleware.sessions import SessionMiddleware

from . import __version__
from . import scheduler as sched
from .actions import ACTIONS, actions_ordered
from .clients import VENDORS, client_for, test_instance
from .config import (
    ADMIN_PASSWORD,
    BRANDING_DIR,
    DEFAULT_TZ,
    LOGO_TYPES,
    MAX_LOGO_BYTES,
    SECRET_KEY,
    SESSION_MAX_AGE,
)
from .database import init_db, session_scope
from .iru_client import IRU_COMMAND_SPECS, IRU_COMMANDS
from .jamf_client import COMPUTER_COMMANDS, MOBILE_COMMANDS, OBJECTS
from .models import Branding, Instance, Job, JobLog, as_utc
from .tls import DNS_PROVIDERS, DNS_TOKEN_HINTS, TlsError, certificate_status, render_caddyfile
from .tls import apply as tls_apply

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("mdm-scheduler")

PUBLIC_PATHS = {"/login", "/health", "/help", "/branding/logo"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    sched.start()
    reapply_tls()
    yield
    sched.shutdown()


def reapply_tls() -> None:
    """Push the stored HTTPS config back to Caddy at boot.

    A config sent to the admin API lives in Caddy's memory. The sidecar runs
    with `--resume` so it reloads its own autosave across a restart, but that
    file lives on the caddy_config volume - recreate the container without it,
    or bring the stack up on a new host from a restored database, and Caddy
    comes back on the plain-HTTP starting config while the UI still says HTTPS
    is on. Re-applying here keeps the database the source of truth. Best
    effort: if Caddy is not up yet, its own autosave covers the normal restart
    and the Branding tab reports the real state either way.
    """
    with session_scope() as session:
        row = session.get(Branding, 1)
        if row is None or not (row.tls_enabled and row.tls_hostname):
            return
        brand = row
    try:
        tls_apply(brand)
        log.info("re-applied HTTPS config for %s", brand.tls_hostname)
    except TlsError as exc:
        log.warning("could not re-apply HTTPS config at startup: %s", exc)


app = FastAPI(title="MDM Scheduler", version=__version__, lifespan=lifespan)

# Assets are vendored into the image at build time; the CDN is only a fallback
# for a build that had no network. A restricted-egress host still gets a styled UI.
STATIC_DIR = Path("static")
LOCAL_ASSETS = (STATIC_DIR / "bootstrap.min.css").is_file()
if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

templates = Jinja2Templates(directory="templates")
templates.env.globals.update(app_version=__version__, local_assets=LOCAL_ASSETS)


# ------------------------------------------------------------------ helpers
def fmt(dt: datetime | None, tz: str = DEFAULT_TZ) -> str:
    if dt is None:
        return "-"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(ZoneInfo(tz)).strftime("%Y-%m-%d %H:%M %Z")


templates.env.filters["localtime"] = fmt


def branding() -> Branding:
    with session_scope() as session:
        row = session.get(Branding, 1)
        if row is None:
            row = Branding(id=1)
            session.add(row)
            session.flush()
        return row


def ctx(request: Request, **kwargs) -> dict:
    base = {
        "request": request,
        "default_tz": DEFAULT_TZ,
        "flash": request.session.pop("flash", None),
        "brand": branding(),
    }
    base.update(kwargs)
    return base


def flash(request: Request, message: str, level: str = "success"):
    request.session["flash"] = {"message": message, "level": level}


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    if path in PUBLIC_PATHS or path.startswith("/static"):
        return await call_next(request)
    if not request.session.get("auth"):
        if path.startswith("/api/"):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return RedirectResponse("/login", status_code=303)
    return await call_next(request)


# Added last so it wraps the auth middleware above: Starlette runs the most
# recently added middleware first, and require_login needs request.session.
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    max_age=SESSION_MAX_AGE,
    same_site="lax",
    https_only=False,
)


# --------------------------------------------------------------------- auth
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", ctx(request, error=None))


@app.post("/login")
def login(request: Request, password: str = Form(...)):
    if ADMIN_PASSWORD and secrets.compare_digest(password, ADMIN_PASSWORD):
        request.session["auth"] = True
        return RedirectResponse("/", status_code=303)
    if not ADMIN_PASSWORD:
        return templates.TemplateResponse(
            "login.html",
            ctx(request, error="ADMIN_PASSWORD is not set on the container - set it and restart."),
            status_code=500,
        )
    return templates.TemplateResponse(
        "login.html", ctx(request, error="Incorrect password."), status_code=401
    )


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ----------------------------------------------------------- branding / help
@app.get("/branding/logo")
def branding_logo():
    row = branding()
    if not row.logo_file:
        raise HTTPException(404)
    path = BRANDING_DIR / row.logo_file
    if not path.is_file():
        raise HTTPException(404)
    return FileResponse(path, media_type=guess_type(path.name)[0] or "application/octet-stream")


@app.get("/settings", response_class=HTMLResponse)
def settings_form(request: Request):
    return templates.TemplateResponse(
        "settings.html",
        ctx(
            request,
            max_logo_kb=MAX_LOGO_BYTES // 1024,
            dns_providers=DNS_PROVIDERS,
            dns_token_hints=DNS_TOKEN_HINTS,
        ),
    )


@app.post("/settings")
async def settings_save(
    request: Request,
    org_name: str = Form(""),
    accent: str = Form(""),
    default_theme: str = Form("system"),
    support_note: str = Form(""),
    remove_logo: str = Form(""),
    logo: UploadFile | None = File(None),
):
    error = None
    with session_scope() as session:
        row = session.get(Branding, 1) or Branding(id=1)
        row.org_name = org_name.strip()[:120]
        row.accent = accent.strip()[:20]
        row.default_theme = default_theme if default_theme in ("system", "dark", "light") else "system"
        row.support_note = support_note.strip()[:2000]

        if remove_logo == "on" and row.logo_file:
            (BRANDING_DIR / row.logo_file).unlink(missing_ok=True)
            row.logo_file = ""

        if logo is not None and logo.filename:
            suffix = LOGO_TYPES.get((logo.content_type or "").lower())
            if suffix is None:
                error = f"Unsupported image type '{logo.content_type}'. Use PNG, JPEG, WebP, GIF or SVG."
            else:
                content = await logo.read()
                if len(content) > MAX_LOGO_BYTES:
                    error = f"Logo is {len(content) // 1024} KB; the limit is {MAX_LOGO_BYTES // 1024} KB."
                else:
                    for old in BRANDING_DIR.glob("logo.*"):
                        old.unlink(missing_ok=True)
                    (BRANDING_DIR / f"logo{suffix}").write_bytes(content)
                    row.logo_file = f"logo{suffix}"
        session.add(row)

    flash(request, error or "Branding saved.", "danger" if error else "success")
    return RedirectResponse("/settings", status_code=303)


# --------------------------------------------------------------------- TLS
@app.post("/settings/tls")
def settings_tls(
    request: Request,
    tls_enabled: str = Form(""),
    tls_hostname: str = Form(""),
    tls_email: str = Form(""),
    tls_challenge: str = Form("http"),
    tls_dns_provider: str = Form("ionos"),
    tls_dns_token: str = Form(""),
    tls_staging: str = Form(""),
):
    with session_scope() as session:
        row = session.get(Branding, 1) or Branding(id=1)
        row.tls_enabled = tls_enabled == "on"
        row.tls_hostname = tls_hostname.strip().lower()[:255]
        row.tls_email = tls_email.strip()[:255]
        row.tls_challenge = tls_challenge if tls_challenge in ("http", "dns") else "http"
        row.tls_dns_provider = tls_dns_provider if tls_dns_provider in DNS_PROVIDERS else "ionos"
        row.tls_staging = tls_staging == "on"
        if tls_dns_token.strip():  # blank on edit keeps the stored token
            row.tls_dns_token = tls_dns_token.strip()
        session.add(row)
        session.flush()
        brand = row

    if brand.tls_enabled and not brand.tls_hostname:
        flash(request, "A hostname is required to enable HTTPS.", "danger")
        return RedirectResponse("/settings#tls", status_code=303)

    try:
        message = tls_apply(brand)
        flash(request, message)
    except TlsError as exc:
        flash(request, f"Saved, but Caddy was not updated: {exc}", "danger")
    return RedirectResponse("/settings#tls", status_code=303)


@app.get("/api/tls/status")
def api_tls_status():
    return certificate_status(branding())


@app.get("/api/tls/caddyfile")
def api_tls_caddyfile():
    """The exact config the sidecar is given - handy for debugging, and it makes
    the generated file reviewable rather than a black box. The DNS token is
    masked; it is the one secret that would otherwise appear here."""
    brand = branding()
    text = render_caddyfile(brand)
    if brand.tls_dns_token:
        text = text.replace(brand.tls_dns_token, "***REDACTED***")
    return {"caddyfile": text}


@app.get("/help", response_class=HTMLResponse)
def help_page(request: Request):
    return templates.TemplateResponse(
        "help.html",
        ctx(
            request,
            computer_commands=COMPUTER_COMMANDS,
            mobile_commands=MOBILE_COMMANDS,
            iru_commands=IRU_COMMANDS,
            actions=ACTIONS,
            signed_in=bool(request.session.get("auth")),
        ),
    )


@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": __version__,
        "scheduler_running": sched.scheduler.running,
        "registered_jobs": len(sched.scheduler.get_jobs()),
    }


# ---------------------------------------------------------------- dashboard
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    with session_scope() as session:
        jobs = session.scalars(select(Job).order_by(Job.id.desc())).all()
        rows = [
            {
                "job": job,
                "instance": job.instance.name,
                "action_label": ACTIONS.get(job.action, {}).get("label", job.action),
                "next_run": sched.next_run(job.id),
                "summary": describe(job),
            }
            for job in jobs
        ]
    return templates.TemplateResponse("dashboard.html", ctx(request, rows=rows))


def describe(job: Job) -> str:
    params = job.params or {}
    bits = [f"{k}={v}" for k, v in params.items() if v not in ("", None) and k != "pin"]
    if params.get("pin"):
        bits.append("pin=******")
    return ", ".join(bits)


# ---------------------------------------------------------------- instances
@app.get("/instances", response_class=HTMLResponse)
def instances_list(request: Request):
    with session_scope() as session:
        instances = session.scalars(select(Instance).order_by(Instance.name)).all()
        rows = [{"instance": i, "job_count": len(i.jobs)} for i in instances]
    return templates.TemplateResponse("instances.html", ctx(request, rows=rows))


@app.get("/instances/new", response_class=HTMLResponse)
def instance_new(request: Request):
    return templates.TemplateResponse("instance_form.html", ctx(request, instance=None))


@app.get("/instances/{instance_id}/edit", response_class=HTMLResponse)
def instance_edit(request: Request, instance_id: int):
    with session_scope() as session:
        instance = session.get(Instance, instance_id)
        if instance is None:
            raise HTTPException(404)
    return templates.TemplateResponse("instance_form.html", ctx(request, instance=instance))


@app.post("/instances")
def instance_save(
    request: Request,
    instance_id: str = Form(""),
    name: str = Form(...),
    vendor: str = Form("jamf"),
    base_url: str = Form(...),
    auth_type: str = Form("client"),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    api_token: str = Form(""),
    verify_ssl: str = Form(""),
    notes: str = Form(""),
):
    with session_scope() as session:
        instance = session.get(Instance, int(instance_id)) if instance_id else Instance()
        if instance is None:
            raise HTTPException(404)
        instance.name = name.strip()
        instance.vendor = vendor if vendor in VENDORS else "jamf"
        instance.base_url = base_url.strip().rstrip("/")
        instance.auth_type = auth_type
        instance.client_id = client_id.strip()
        instance.username = username.strip()
        instance.verify_ssl = verify_ssl == "on"
        instance.notes = notes
        # blank secret on edit = keep existing
        if client_secret:
            instance.client_secret = client_secret
        if password:
            instance.password = password
        if api_token:
            instance.api_token = api_token
        session.add(instance)
    flash(request, f"Instance '{name}' saved.")
    return RedirectResponse("/instances", status_code=303)


@app.post("/instances/{instance_id}/delete")
def instance_delete(request: Request, instance_id: int):
    with session_scope() as session:
        instance = session.get(Instance, instance_id)
        if instance is None:
            raise HTTPException(404)
        for job in instance.jobs:
            sched.remove_job(job.id)
        session.delete(instance)
    flash(request, "Instance deleted.")
    return RedirectResponse("/instances", status_code=303)


@app.post("/instances/{instance_id}/test")
def instance_test(instance_id: int):
    with session_scope() as session:
        instance = session.get(Instance, instance_id)
        if instance is None:
            raise HTTPException(404)
        return test_instance(instance)


# --------------------------------------------------------- discovery for UI
@app.get("/api/instances/{instance_id}/objects")
def api_objects(instance_id: int, kind: str):
    with session_scope() as session:
        instance = session.get(Instance, instance_id)
        if instance is None:
            raise HTTPException(404)
        vendor = instance.vendor or "jamf"
        client = client_for(instance)

    if vendor == "iru" and kind != "blueprints":
        client.close()
        raise HTTPException(400, f"unknown Iru object kind: {kind}")
    if vendor == "jamf" and kind not in OBJECTS:
        client.close()
        raise HTTPException(400, f"unknown Jamf object kind: {kind}")

    try:
        items = client.blueprints() if vendor == "iru" else client.list_objects(kind)
        return {"ok": True, "items": items}
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, status_code=502)
    finally:
        client.close()


# --------------------------------------------------------------------- jobs
def job_form_ctx(request: Request, job: Job | None, instances):
    return ctx(
        request,
        job=job,
        instances=instances,
        actions=ACTIONS,
        actions_list=actions_ordered(),
        computer_commands=COMPUTER_COMMANDS,
        mobile_commands=MOBILE_COMMANDS,
        iru_commands=IRU_COMMANDS,
        # only the flags the form needs, so the page never ships payload details
        iru_command_specs={
            key: {k: v for k, v in spec.items() if k in ("pin", "message", "phone", "username", "device_name")}
            for key, spec in IRU_COMMAND_SPECS.items()
        },
        vendors={i.id: (i.vendor or "jamf") for i in instances},
        timezones=sorted(available_timezones()),
        run_at_value=(
            as_utc(job.run_at).astimezone(ZoneInfo(job.tz or DEFAULT_TZ)).strftime("%Y-%m-%dT%H:%M")
            if job and job.run_at
            else ""
        ),
    )


@app.get("/jobs/new", response_class=HTMLResponse)
def job_new(request: Request):
    with session_scope() as session:
        instances = session.scalars(select(Instance).order_by(Instance.name)).all()
    if not instances:
        flash(request, "Add a Jamf Pro instance first.", "warning")
        return RedirectResponse("/instances/new", status_code=303)
    return templates.TemplateResponse("job_form.html", job_form_ctx(request, None, instances))


@app.get("/jobs/{job_id}/edit", response_class=HTMLResponse)
def job_edit(request: Request, job_id: int):
    with session_scope() as session:
        job = session.get(Job, job_id)
        if job is None:
            raise HTTPException(404)
        instances = session.scalars(select(Instance).order_by(Instance.name)).all()
    return templates.TemplateResponse("job_form.html", job_form_ctx(request, job, instances))


@app.post("/jobs")
def job_save(
    request: Request,
    job_id: str = Form(""),
    name: str = Form(...),
    instance_id: int = Form(...),
    action: str = Form(...),
    schedule_type: str = Form("once"),
    run_at: str = Form(""),
    cron: str = Form(""),
    tz: str = Form(DEFAULT_TZ),
    enabled: str = Form(""),
    policy_id: str = Form(""),
    profile_id: str = Form(""),
    group_id: str = Form(""),
    command: str = Form(""),
    target_type: str = Form("group"),
    device_ids: str = Form(""),
    pin: str = Form(""),
    message: str = Form(""),
    serials: str = Form(""),
    blueprint_id: str = Form(""),
    source_blueprint_id: str = Form(""),
    phone: str = Form(""),
    username: str = Form(""),
    device_name: str = Form(""),
):
    if action not in ACTIONS:
        raise HTTPException(400, f"unknown action {action}")

    if schedule_type == "cron":
        if not cron.strip():
            flash(request, "A cron expression is required for recurring jobs.", "danger")
            return RedirectResponse("/jobs/new", status_code=303)
        CronTrigger.from_crontab(cron.strip(), timezone=ZoneInfo(tz))
        run_at_dt = None
    else:
        if not run_at:
            flash(request, "A run date/time is required for one-shot jobs.", "danger")
            return RedirectResponse("/jobs/new", status_code=303)
        # wall time in the job's timezone -> stored as UTC
        run_at_dt = datetime.fromisoformat(run_at).replace(tzinfo=ZoneInfo(tz)).astimezone(UTC)

    params = {
        "policy_id": policy_id,
        "profile_id": profile_id,
        "group_id": group_id,
        "command": command,
        "target_type": target_type,
        "device_ids": device_ids.strip(),
        "pin": pin.strip(),
        "message": message.strip(),
        "serials": serials.strip(),
        "blueprint_id": blueprint_id,
        "source_blueprint_id": source_blueprint_id,
        "phone": phone.strip(),
        "username": username.strip(),
        "device_name": device_name.strip(),
    }
    needs = ACTIONS[action]["needs"]
    keep = set()
    if "policy" in needs:
        keep.add("policy_id")
    if "osx_profile" in needs or "mobile_profile" in needs:
        keep.add("profile_id")
    if {"computer_group", "mobile_group"} & set(needs):
        keep.add("group_id")
    if {"computer_command", "mobile_command"} & set(needs):
        keep.update({"command", "target_type", "device_ids", "pin", "message"})
        if target_type == "group":
            keep.add("group_id")
    if "iru_command" in needs:
        keep.update({"command", "pin", "message", "phone", "username", "device_name"})
    if {"iru_command", "iru_blueprint_target"} & set(needs):
        keep.add("target_type")
        keep.add("serials" if target_type == "devices" else "source_blueprint_id")
    if "iru_blueprint_destination" in needs:
        keep.add("blueprint_id")
    params = {k: v for k, v in params.items() if k in keep and v != ""}

    with session_scope() as session:
        job = session.get(Job, int(job_id)) if job_id else Job()
        if job is None:
            raise HTTPException(404)
        job.name = name.strip()
        job.instance_id = instance_id
        job.action = action
        job.params = params
        job.schedule_type = schedule_type
        job.run_at = run_at_dt
        job.cron = cron.strip() if schedule_type == "cron" else ""
        job.tz = tz
        job.enabled = enabled == "on"
        session.add(job)
        session.flush()
        sched.sync_job(job)
        saved_name = job.name
    flash(request, f"Job '{saved_name}' saved.")
    return RedirectResponse("/", status_code=303)


@app.post("/jobs/{job_id}/toggle")
def job_toggle(request: Request, job_id: int):
    with session_scope() as session:
        job = session.get(Job, job_id)
        if job is None:
            raise HTTPException(404)
        job.enabled = not job.enabled
        session.add(job)
        session.flush()
        sched.sync_job(job)
        state = "enabled" if job.enabled else "paused"
    flash(request, f"Job {state}.")
    return RedirectResponse("/", status_code=303)


@app.post("/jobs/{job_id}/delete")
def job_delete(request: Request, job_id: int):
    with session_scope() as session:
        job = session.get(Job, job_id)
        if job is None:
            raise HTTPException(404)
        sched.remove_job(job_id)
        session.delete(job)
    flash(request, "Job deleted.")
    return RedirectResponse("/", status_code=303)


@app.post("/jobs/{job_id}/run")
def job_run(request: Request, job_id: int):
    status, message = sched.execute_job(job_id, trigger_source="manual")
    flash(request, f"Run now: {message}", "success" if status == "success" else "danger")
    return RedirectResponse(f"/jobs/{job_id}/logs", status_code=303)


@app.get("/jobs/{job_id}/logs", response_class=HTMLResponse)
def job_logs(request: Request, job_id: int):
    with session_scope() as session:
        job = session.get(Job, job_id)
        if job is None:
            raise HTTPException(404)
        logs = session.scalars(
            select(JobLog).where(JobLog.job_id == job_id).order_by(JobLog.ts.desc()).limit(200)
        ).all()
        instance_name = job.instance.name
    return templates.TemplateResponse(
        "job_logs.html",
        ctx(
            request,
            job=job,
            logs=logs,
            instance_name=instance_name,
            action_label=ACTIONS.get(job.action, {}).get("label", job.action),
            next_run=sched.next_run(job_id),
        ),
    )

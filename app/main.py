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
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from starlette.middleware.sessions import SessionMiddleware

from . import __version__, audit, auth, mfa, passkeys
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
from .models import (
    ROLE_LABELS,
    ROLE_RANK,
    Branding,
    Instance,
    Job,
    JobLog,
    User,
    WebAuthnCredential,
    as_utc,
    utcnow,
)
from .tls import DNS_PROVIDERS, DNS_TOKEN_HINTS, TlsError, certificate_status, render_caddyfile
from .tls import apply as tls_apply

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("mdm-scheduler")

PUBLIC_PATHS = {"/login", "/login/mfa", "/health", "/help", "/branding/logo"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    with session_scope() as session:
        # Create the singleton rows up front. Both helpers below would otherwise
        # insert them lazily, and lazily means "from inside whatever transaction
        # happens to be open", which on SQLite is a second connection trying to
        # write while the first holds the lock.
        if session.get(Branding, 1) is None:
            session.add(Branding(id=1))
        auth.security_settings(session)
        auth.ensure_bootstrap_user(session)
        auth.prune_attempts(session)
        auth.prune_sessions(session)
        audit.prune(session)
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
    """Read-only on purpose.

    ctx() calls this on every render, including renders that happen while a
    write transaction is open elsewhere. Inserting here would be a second
    connection writing under the first one's lock - which is exactly the
    "database is locked" that used to come out of a failed sign-in.
    """
    with session_scope() as session:
        row = session.get(Branding, 1)
        return row if row is not None else Branding(id=1)


def ctx(request: Request, **kwargs) -> dict:
    base = {
        "request": request,
        "default_tz": DEFAULT_TZ,
        "flash": request.session.pop("flash", None),
        "brand": branding(),
        "user": getattr(request.state, "user", None),
    }
    base.update(kwargs)
    return base


def flash(request: Request, message: str, level: str = "success"):
    request.session["flash"] = {"message": message, "level": level}


def current_user(request: Request):
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(401, "Not signed in")
    return user


def required_role(method: str, path: str) -> str:
    """One table instead of thirty decorators.

    Keeping the policy in a single function means a new route is covered by
    default rather than exposed by omission - the failure mode of per-route
    decorators is the one you never notice.
    """
    if path.startswith("/account"):
        return "viewer"
    if path.startswith("/api/instances"):
        return "operator"  # the job form's live discovery
    for prefix in ("/users", "/audit", "/settings", "/api/tls", "/instances", "/security"):
        if path.startswith(prefix):
            return "admin"
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return "operator"
    return "viewer"


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    if path in PUBLIC_PATHS or path.startswith("/static") or path.startswith("/webauthn/login"):
        return await call_next(request)

    token = request.session.get("sid", "")
    with session_scope() as session:
        user, row = auth.resolve_session(session, token)
        if user is not None:
            request.state.mfa_required = (
                auth.security_settings(session).require_mfa and not user.has_mfa
            )
            # Detached copies: the session closes at the end of this block, and
            # templates read these attributes long after that.
            session.expunge(user)
            request.state.user = user
            request.state.session_id = row.id

    user = getattr(request.state, "user", None)
    if user is None:
        request.session.pop("sid", None)
        if path.startswith("/api/") or path.startswith("/webauthn/"):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return RedirectResponse("/login", status_code=303)

    # Enrolment is a dead end until it's done: an account that must add a factor
    # can reach its own account page and nothing else.
    if getattr(request.state, "mfa_required", False) and not path.startswith(
        ("/account", "/logout", "/webauthn/register")
    ):
        return RedirectResponse("/account?enroll=1", status_code=303)

    needed = required_role(request.method, path)
    if not user.at_least(needed):
        if path.startswith("/api/") or path.startswith("/webauthn/"):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return templates.TemplateResponse(
            "forbidden.html", ctx(request, needed=needed), status_code=403
        )
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
    with session_scope() as session:
        no_accounts = not session.scalars(select(User)).first()
    return templates.TemplateResponse(
        "login.html",
        ctx(request, error=None, no_accounts=no_accounts, passkeys_ok=_passkeys_ok(request)),
    )


def _passkeys_ok(request: Request) -> bool:
    ok, _ = passkeys.availability(request, branding())
    return ok


def _login_error(request: Request, message: str, status: int = 401):
    return templates.TemplateResponse(
        "login.html",
        ctx(request, error=message, no_accounts=False, passkeys_ok=_passkeys_ok(request)),
        status_code=status,
    )


@app.post("/login")
def login(request: Request, username: str = Form(""), password: str = Form(...)):
    """Password step.

    Everything decided inside the transaction, everything rendered outside it.
    Rendering calls ctx(), which reads branding on its own connection - doing
    that while this one holds a write lock is how a failed sign-in used to come
    back as "database is locked".
    """
    ip = auth.client_ip(request)
    username = (username or "").strip().lower()
    error, status, token, pending_id = "", 401, "", 0

    with session_scope() as session:
        blocked = auth.lockout_message(session, username, ip)
        if blocked:
            audit.record(session, username or "?", "sign-in-failed", detail="throttled", ip=ip)
            error, status = blocked, 429
        else:
            settings = auth.security_settings(session)
            user = auth.by_username(session, username)

            # Break-glass: the container's password authenticates the bootstrap
            # admin regardless of that account's own password or factors. It is
            # the documented way back in after a lost authenticator, and it is
            # recorded as its own action so it stands out in the log.
            break_glass = (
                settings.break_glass_enabled
                and ADMIN_PASSWORD
                and secrets.compare_digest(password, ADMIN_PASSWORD)
                and username in ("", auth.BREAK_GLASS_USERNAME)
            )

            if break_glass:
                user = auth.by_username(session, auth.BREAK_GLASS_USERNAME)
                if user is None:
                    user = auth.ensure_bootstrap_user(session)
                if user is None:
                    error = "No admin account exists and ADMIN_PASSWORD is not set."
                    status = 500
                else:
                    auth.record_attempt(session, user.username, ip, True, "break-glass")
                    audit.record(session, user, "break-glass", ip=ip)
                    token = auth.start_session(
                        session, user, ip, request.headers.get("user-agent", ""), "break-glass"
                    )
                    log.warning("break-glass sign-in from %s", ip)

            elif user is None or not user.is_active:
                auth.record_attempt(session, username, ip, False, "no such account")
                audit.record(session, username or "?", "sign-in-failed", detail="unknown", ip=ip)
                error = "Incorrect username or password."

            else:
                ok, rehash = auth.verify_password(user.password_hash, password)
                if not ok:
                    auth.record_attempt(session, username, ip, False, "bad password")
                    audit.record(session, user, "sign-in-failed", detail="bad password", ip=ip)
                    error = "Incorrect username or password."
                else:
                    if rehash:
                        user.password_hash = rehash
                    auth.record_attempt(session, username, ip, True, "password")
                    if user.has_mfa:
                        # A password alone is not a session yet. The pending id
                        # lives in the signed cookie and expires in 5 minutes.
                        pending_id = user.id
                    else:
                        audit.record(session, user, "sign-in", detail="password", ip=ip)
                        token = auth.start_session(
                            session, user, ip, request.headers.get("user-agent", ""), "password"
                        )

    if error:
        return _login_error(request, error, status)
    if pending_id:
        request.session["pending_user"] = pending_id
        request.session["pending_at"] = utcnow().isoformat()
        return RedirectResponse("/login/mfa", status_code=303)

    request.session["sid"] = token
    return RedirectResponse("/", status_code=303)


PENDING_MFA_SECONDS = 300


def _pending_user(request: Request, session):
    user_id = request.session.get("pending_user")
    started = request.session.get("pending_at")
    if not user_id or not started:
        return None
    try:
        age = (utcnow() - datetime.fromisoformat(started)).total_seconds()
    except ValueError:
        return None
    if age > PENDING_MFA_SECONDS:
        return None
    return session.get(User, user_id)


def _pending_view(user, request) -> dict:
    """A plain dict, not the ORM object.

    The template renders after the session closes, and a detached instance
    would raise on the first lazy attribute it touches.
    """
    return {
        "username": user.username,
        "has_totp": user.has_totp,
        "has_passkey": user.has_passkey,
    }


@app.get("/login/mfa", response_class=HTMLResponse)
def login_mfa_form(request: Request):
    with session_scope() as session:
        user = _pending_user(request, session)
        pending = _pending_view(user, request) if user is not None else None
    if pending is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        "login_mfa.html",
        ctx(
            request,
            error=None,
            pending=pending,
            has_totp=pending["has_totp"],
            has_passkey=pending["has_passkey"],
            passkeys_ok=_passkeys_ok(request),
        ),
    )


@app.post("/login/mfa")
def login_mfa(request: Request, code: str = Form(""), recovery: str = Form("")):
    ip = auth.client_ip(request)
    error, status, token, note = "", 401, "", ""
    pending = None

    with session_scope() as session:
        user = _pending_user(request, session)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        pending = _pending_view(user, request)

        blocked = auth.lockout_message(session, user.username, ip)
        if blocked:
            error, status = blocked, 429
        else:
            method = "recovery-code" if recovery.strip() else "totp"
            if method == "recovery-code":
                ok = mfa.consume_recovery_code(session, user, recovery)
                error = "" if ok else "That recovery code is not valid or has already been used."
            else:
                ok, error = mfa.check_totp(user, code)

            if not ok:
                auth.record_attempt(session, user.username, ip, False, method)
                audit.record(session, user, "sign-in-failed", detail=f"{method}: {error}", ip=ip)
            else:
                auth.record_attempt(session, user.username, ip, True, method)
                audit.record(session, user, "sign-in", detail=method, ip=ip)
                token = auth.start_session(
                    session, user, ip, request.headers.get("user-agent", ""), method
                )
                if method == "recovery-code":
                    left = mfa.unused_recovery_codes(user)
                    note = (
                        f"Signed in with a recovery code. {left} left - generate a new set "
                        "from your account page."
                    )

    if error:
        return templates.TemplateResponse(
            "login_mfa.html",
            ctx(
                request,
                error=error,
                pending=pending,
                has_totp=pending["has_totp"],
                has_passkey=pending["has_passkey"],
                passkeys_ok=_passkeys_ok(request),
            ),
            status_code=status,
        )

    request.session.pop("pending_user", None)
    request.session.pop("pending_at", None)
    request.session["sid"] = token
    if note:
        flash(request, note, "warning")
    return RedirectResponse("/", status_code=303)


@app.get("/logout")
def logout(request: Request):
    token = request.session.get("sid", "")
    with session_scope() as session:
        user, _ = auth.resolve_session(session, token)
        if user is not None:
            audit.record(session, user, "sign-out", ip=auth.client_ip(request))
        auth.revoke_session(session, token)
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
        if not error:
            audit.record(
                session, current_user(request), "settings-update", "settings", "branding",
                detail=f"org '{row.org_name}', theme {row.default_theme}",
                ip=auth.client_ip(request),
            )

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
        audit.record(
            session, current_user(request), "tls-update", "settings", row.tls_hostname or "off",
            detail=(
                f"enabled={row.tls_enabled}, challenge={row.tls_challenge}, "
                f"staging={row.tls_staging}"
            ),
            ip=auth.client_ip(request),
        )
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
        session.flush()
        audit.record(
            session,
            current_user(request),
            "instance-update" if instance_id else "instance-create",
            "instance",
            instance.name,
            detail=f"{instance.vendor} at {instance.base_url}",
            ip=auth.client_ip(request),
        )
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
        audit.record(
            session, current_user(request), "instance-delete", "instance", instance.name,
            detail=f"{len(instance.jobs)} job(s) removed with it", ip=auth.client_ip(request),
        )
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
        # Operators cannot add instances, so sending them to that page would be
        # a redirect straight into a 403.
        if current_user(request).at_least("admin"):
            flash(request, "Add an MDM instance first.", "warning")
            return RedirectResponse("/instances/new", status_code=303)
        flash(request, "No MDM instances have been added yet - ask an admin.", "warning")
        return RedirectResponse("/", status_code=303)
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
        audit.record(
            session, current_user(request), "job-toggle", "job", job.name,
            detail=state, ip=auth.client_ip(request),
        )
    flash(request, f"Job {state}.")
    return RedirectResponse("/", status_code=303)


@app.post("/jobs/{job_id}/delete")
def job_delete(request: Request, job_id: int):
    with session_scope() as session:
        job = session.get(Job, job_id)
        if job is None:
            raise HTTPException(404)
        sched.remove_job(job_id)
        audit.record(
            session, current_user(request), "job-delete", "job", job.name,
            detail=job.action, ip=auth.client_ip(request),
        )
        session.delete(job)
    flash(request, "Job deleted.")
    return RedirectResponse("/", status_code=303)


@app.post("/jobs/{job_id}/run")
def job_run(request: Request, job_id: int):
    with session_scope() as session:
        job = session.get(Job, job_id)
        if job is None:
            raise HTTPException(404)
        # Recorded before the run, not after: a job that hangs or takes the
        # container down with it should still show who set it going.
        audit.record(
            session, current_user(request), "job-run", "job", job.name,
            detail=job.action, ip=auth.client_ip(request),
        )
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


# ------------------------------------------------------------------ account
def _account_ctx(request: Request, session, user: User, **extra) -> dict:
    """Everything the template needs, read while the session is still open.

    The response renders after this block closes, and a detached instance
    raises on the first relationship it touches - so credentials, sessions and
    the derived flags are pulled out here rather than left lazy.
    """
    ok, why = passkeys.availability(request, branding())
    return ctx(
        request,
        account=user,
        credentials=list(user.credentials),
        has_mfa=user.has_mfa,
        has_totp=user.has_totp,
        sessions=sorted(
            [s for s in user.sessions if s.active],
            key=lambda s: as_utc(s.last_seen_at),
            reverse=True,
        ),
        this_session=getattr(request.state, "session_id", ""),
        passkeys_ok=ok,
        passkeys_why=why,
        rp_id=passkeys.rp_id_for(request, branding()),
        totp_uri=(
            mfa.provisioning_uri(user.username, user.totp_secret, branding().org_name)
            if user.totp_secret_enc and not user.totp_confirmed
            else ""
        ),
        recovery_left=mfa.unused_recovery_codes(user),
        require_mfa=auth.security_settings(session).require_mfa,
        enroll=request.query_params.get("enroll") == "1",
        **extra,
    )


@app.get("/account", response_class=HTMLResponse)
def account(request: Request):
    with session_scope() as session:
        user = session.get(User, current_user(request).id)
        data = _account_ctx(request, session, user, new_codes=None)
        data["totp_qr"] = mfa.qr_data_uri(data["totp_uri"]) if data["totp_uri"] else ""
    return templates.TemplateResponse("account.html", data)


@app.post("/account/password")
def account_password(
    request: Request,
    current: str = Form(...),
    new_password: str = Form(...),
    confirm: str = Form(...),
):
    with session_scope() as session:
        user = session.get(User, current_user(request).id)
        ok, _ = auth.verify_password(user.password_hash, current)
        if not ok:
            flash(request, "Current password is incorrect.", "danger")
        elif new_password != confirm:
            flash(request, "The new passwords don't match.", "danger")
        elif (problem := auth.password_problem(new_password)):
            flash(request, problem, "danger")
        else:
            user.password_hash = auth.hash_password(new_password)
            user.must_change_password = False
            revoked = auth.revoke_all_for(session, user, getattr(request.state, "session_id", ""))
            audit.record(
                session, user, "user-password", "user", user.username,
                detail=f"changed own password, {revoked} other session(s) signed out",
                ip=auth.client_ip(request),
            )
            flash(
                request,
                f"Password changed. {revoked} other session(s) were signed out."
                if revoked
                else "Password changed.",
            )
    return RedirectResponse("/account", status_code=303)


@app.post("/account/totp/begin")
def totp_begin(request: Request):
    with session_scope() as session:
        user = session.get(User, current_user(request).id)
        if user.has_totp:
            flash(request, "An authenticator app is already set up.", "warning")
        else:
            user.totp_secret = mfa.new_secret()
            user.totp_confirmed = False
    return RedirectResponse("/account", status_code=303)


@app.post("/account/totp/confirm")
def totp_confirm(request: Request, code: str = Form(...)):
    with session_scope() as session:
        user = session.get(User, current_user(request).id)
        ok, error = mfa.check_totp(user, code)
        if not ok:
            flash(request, error, "danger")
            return RedirectResponse("/account", status_code=303)

        user.totp_confirmed = True
        codes = mfa.generate_recovery_codes(session, user)
        audit.record(
            session, user, "mfa-enroll", "user", user.username,
            detail="authenticator app", ip=auth.client_ip(request),
        )
        data = _account_ctx(request, session, user, new_codes=codes)
        data["totp_qr"] = ""
        data["flash"] = {
            "message": "Authenticator app confirmed. Save these recovery codes now.",
            "level": "success",
        }
    return templates.TemplateResponse("account.html", data)


@app.post("/account/totp/remove")
def totp_remove(request: Request):
    with session_scope() as session:
        user = session.get(User, current_user(request).id)
        if auth.security_settings(session).require_mfa and not user.has_passkey:
            flash(
                request,
                "This is your only factor and MFA is required. Register a passkey first.",
                "danger",
            )
        else:
            user.totp_secret_enc = ""
            user.totp_confirmed = False
            user.totp_last_slot = 0
            audit.record(
                session, user, "mfa-remove", "user", user.username,
                detail="authenticator app", ip=auth.client_ip(request),
            )
            flash(request, "Authenticator app removed.")
    return RedirectResponse("/account", status_code=303)


@app.post("/account/recovery/regenerate")
def recovery_regenerate(request: Request):
    with session_scope() as session:
        user = session.get(User, current_user(request).id)
        if not user.has_mfa:
            flash(request, "Set up a factor before generating recovery codes.", "warning")
            return RedirectResponse("/account", status_code=303)
        codes = mfa.generate_recovery_codes(session, user)
        audit.record(
            session, user, "recovery-codes", "user", user.username, ip=auth.client_ip(request)
        )
        data = _account_ctx(request, session, user, new_codes=codes)
        data["totp_qr"] = ""
        data["flash"] = {
            "message": "New recovery codes generated. The old ones no longer work.",
            "level": "success",
        }
    return templates.TemplateResponse("account.html", data)


@app.post("/account/sessions/{session_id}/revoke")
def revoke_own_session(request: Request, session_id: str):
    with session_scope() as session:
        user = session.get(User, current_user(request).id)
        row = next((s for s in user.sessions if s.id == session_id), None)
        if row is None:
            raise HTTPException(404)
        auth.revoke_session_id(session, session_id)
        audit.record(
            session, user, "session-revoke", "session", session_id[:12],
            ip=auth.client_ip(request),
        )
    if session_id == getattr(request.state, "session_id", ""):
        request.session.clear()
        return RedirectResponse("/login", status_code=303)
    flash(request, "Session signed out.")
    return RedirectResponse("/account", status_code=303)


@app.post("/account/sessions/revoke-others")
def revoke_other_sessions(request: Request):
    with session_scope() as session:
        user = session.get(User, current_user(request).id)
        count = auth.revoke_all_for(session, user, getattr(request.state, "session_id", ""))
        audit.record(
            session, user, "session-revoke", "user", user.username,
            detail=f"{count} other session(s)", ip=auth.client_ip(request),
        )
    flash(request, f"Signed out {count} other session(s).")
    return RedirectResponse("/account", status_code=303)


# ----------------------------------------------------------------- passkeys
@app.post("/webauthn/register/options")
def passkey_register_options(request: Request):
    brand = branding()
    ok, why = passkeys.availability(request, brand)
    if not ok:
        return JSONResponse({"error": why}, status_code=400)
    with session_scope() as session:
        user = session.get(User, current_user(request).id)
        rp_id = passkeys.rp_id_for(request, brand)
        options, challenge = passkeys.registration_options(user, rp_id, list(user.credentials))
    request.session["wa_challenge"] = challenge
    request.session["wa_rp"] = rp_id
    return Response(content=options, media_type="application/json")


@app.post("/webauthn/register/verify")
async def passkey_register_verify(request: Request):
    payload = await request.json()
    challenge = request.session.pop("wa_challenge", "")
    rp_id = request.session.pop("wa_rp", "")
    if not challenge:
        return JSONResponse({"error": "That registration expired. Try again."}, status_code=400)

    try:
        verified = passkeys.verify_registration(
            payload.get("credential"),
            challenge,
            rp_id,
            passkeys.expected_origins(request, rp_id),
        )
    except passkeys.PasskeyError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    from webauthn.helpers import bytes_to_base64url

    with session_scope() as session:
        user = session.get(User, current_user(request).id)
        # Read this before adding the new credential: touching the relationship
        # afterwards autoflushes, and the credential being registered would
        # count itself as pre-existing.
        first_factor = not user.has_totp and len(user.credentials) == 0
        session.add(
            WebAuthnCredential(
                user_id=user.id,
                credential_id=bytes_to_base64url(verified.credential_id),
                public_key=bytes_to_base64url(verified.credential_public_key),
                sign_count=verified.sign_count,
                transports=",".join(payload.get("transports") or [])[:120],
                name=(payload.get("name") or "Passkey").strip()[:120],
                rp_id=rp_id,
            )
        )
        audit.record(
            session, user, "mfa-enroll", "user", user.username,
            detail=f"passkey ({payload.get('name') or 'unnamed'})", ip=auth.client_ip(request),
        )
        codes = mfa.generate_recovery_codes(session, user) if first_factor else []

    return JSONResponse({"ok": True, "codes": codes})


@app.post("/account/passkeys/{credential_id}/delete")
def passkey_delete(request: Request, credential_id: int):
    with session_scope() as session:
        user = session.get(User, current_user(request).id)
        cred = session.get(WebAuthnCredential, credential_id)
        if cred is None or cred.user_id != user.id:
            raise HTTPException(404)
        only_factor = user.has_totp is False and len(user.credentials) == 1
        if auth.security_settings(session).require_mfa and only_factor:
            flash(request, "This is your only factor and MFA is required.", "danger")
            return RedirectResponse("/account", status_code=303)
        name = cred.name
        session.delete(cred)
        audit.record(
            session, user, "mfa-remove", "user", user.username,
            detail=f"passkey ({name})", ip=auth.client_ip(request),
        )
    flash(request, "Passkey removed.")
    return RedirectResponse("/account", status_code=303)


@app.post("/webauthn/login/options")
def passkey_login_options(request: Request):
    brand = branding()
    ok, why = passkeys.availability(request, brand)
    if not ok:
        return JSONResponse({"error": why}, status_code=400)
    rp_id = passkeys.rp_id_for(request, brand)
    with session_scope() as session:
        allow = []
        user_id = request.session.get("pending_user")
        if user_id:
            user = session.get(User, user_id)
            allow = list(user.credentials) if user else []
        options, challenge = passkeys.authentication_options(rp_id, allow)
    request.session["wa_challenge"] = challenge
    request.session["wa_rp"] = rp_id
    return Response(content=options, media_type="application/json")


@app.post("/webauthn/login/verify")
async def passkey_login_verify(request: Request):
    payload = await request.json()
    credential = payload.get("credential")
    challenge = request.session.pop("wa_challenge", "")
    rp_id = request.session.pop("wa_rp", "")
    ip = auth.client_ip(request)
    if not challenge:
        return JSONResponse({"error": "That sign-in expired. Try again."}, status_code=400)

    credential_id = passkeys.credential_id_of(credential)
    with session_scope() as session:
        stored = session.scalars(
            select(WebAuthnCredential).where(WebAuthnCredential.credential_id == credential_id)
        ).first()
        if stored is None:
            audit.record(session, "?", "sign-in-failed", detail="unknown passkey", ip=ip)
            return JSONResponse({"error": "That passkey is not registered."}, status_code=400)

        user = session.get(User, stored.user_id)
        if user is None or not user.is_active:
            return JSONResponse({"error": "That account is disabled."}, status_code=403)

        blocked = auth.lockout_message(session, user.username, ip)
        if blocked:
            return JSONResponse({"error": blocked}, status_code=429)

        try:
            verified = passkeys.verify_authentication(
                credential, challenge, rp_id, passkeys.expected_origins(request, rp_id), stored
            )
        except passkeys.PasskeyError as exc:
            auth.record_attempt(session, user.username, ip, False, "passkey")
            audit.record(session, user, "sign-in-failed", detail=str(exc), ip=ip)
            return JSONResponse({"error": str(exc)}, status_code=400)

        stored.sign_count = verified.new_sign_count
        stored.last_used_at = utcnow()
        auth.record_attempt(session, user.username, ip, True, "passkey")
        audit.record(session, user, "sign-in", detail=f"passkey ({stored.name})", ip=ip)
        token = auth.start_session(
            session, user, ip, request.headers.get("user-agent", ""), "passkey"
        )

    request.session.pop("pending_user", None)
    request.session.pop("pending_at", None)
    request.session["sid"] = token
    return JSONResponse({"ok": True, "next": "/"})


# -------------------------------------------------------------------- users
@app.get("/users", response_class=HTMLResponse)
def users_list(request: Request):
    with session_scope() as session:
        users = auth.active_users(session)
        rows = [
            {
                "user": u,
                "sessions": sum(1 for s in u.sessions if s.active),
                "passkeys": len(u.credentials),
                "recovery": mfa.unused_recovery_codes(u),
            }
            for u in users
        ]
        settings = auth.security_settings(session)
        weak = [u.username for u in users if u.is_active and not u.has_mfa]
        return templates.TemplateResponse(
            "users.html",
            ctx(
                request,
                rows=rows,
                roles=ROLE_LABELS,
                settings=settings,
                without_mfa=weak,
                break_glass_available=bool(ADMIN_PASSWORD),
            ),
        )


@app.post("/users")
def user_create(
    request: Request,
    username: str = Form(...),
    display_name: str = Form(""),
    email: str = Form(""),
    role: str = Form("operator"),
    password: str = Form(...),
):
    username = username.strip().lower()
    with session_scope() as session:
        if not username.isascii() or not username.replace("-", "").replace(".", "").isalnum():
            flash(request, "Usernames may contain letters, digits, dots and hyphens.", "danger")
        elif auth.by_username(session, username):
            flash(request, f"There is already a user called {username}.", "danger")
        elif role not in ROLE_RANK:
            flash(request, "Unknown role.", "danger")
        elif (problem := auth.password_problem(password)):
            flash(request, problem, "danger")
        else:
            user = User(
                username=username,
                display_name=display_name.strip()[:120],
                email=email.strip()[:255],
                role=role,
                password_hash=auth.hash_password(password),
                must_change_password=True,
            )
            session.add(user)
            session.flush()
            audit.record(
                session, current_user(request), "user-create", "user", username,
                detail=f"role {role}", ip=auth.client_ip(request),
            )
            flash(request, f"Created {username}. They'll be asked to change that password.")
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_id}")
def user_update(
    request: Request,
    user_id: int,
    display_name: str = Form(""),
    email: str = Form(""),
    role: str = Form("operator"),
    is_active: str = Form(""),
):
    with session_scope() as session:
        user = session.get(User, user_id)
        if user is None:
            raise HTTPException(404)
        active = is_active == "on"

        # Locking every admin out of the console is not a state worth allowing.
        demoting = user.role == "admin" and (role != "admin" or not active)
        if demoting and auth.admin_count(session) <= 1:
            flash(request, "That's the last active admin - promote someone else first.", "danger")
            return RedirectResponse("/users", status_code=303)

        before = f"{user.role}, {'active' if user.is_active else 'disabled'}"
        user.display_name = display_name.strip()[:120]
        user.email = email.strip()[:255]
        user.role = role if role in ROLE_RANK else user.role
        user.is_active = active
        if not active:
            auth.revoke_all_for(session, user)
        audit.record(
            session, current_user(request), "user-update", "user", user.username,
            detail=f"{before} -> {user.role}, {'active' if active else 'disabled'}",
            ip=auth.client_ip(request),
        )
        flash(request, f"Updated {user.username}.")
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_id}/password")
def user_reset_password(request: Request, user_id: int, password: str = Form(...)):
    with session_scope() as session:
        user = session.get(User, user_id)
        if user is None:
            raise HTTPException(404)
        if (problem := auth.password_problem(password)):
            flash(request, problem, "danger")
            return RedirectResponse("/users", status_code=303)
        user.password_hash = auth.hash_password(password)
        user.must_change_password = True
        user.locked_until = None
        count = auth.revoke_all_for(session, user)
        audit.record(
            session, current_user(request), "user-password", "user", user.username,
            detail=f"admin reset, {count} session(s) signed out", ip=auth.client_ip(request),
        )
        flash(request, f"Password reset for {user.username}; their sessions were signed out.")
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_id}/clear-mfa")
def user_clear_mfa(request: Request, user_id: int):
    """The lost-phone path. An admin can clear factors; the user re-enrols."""
    with session_scope() as session:
        user = session.get(User, user_id)
        if user is None:
            raise HTTPException(404)
        user.totp_secret_enc = ""
        user.totp_confirmed = False
        user.totp_last_slot = 0
        for cred in list(user.credentials):
            session.delete(cred)
        for code in list(user.recovery_codes):
            session.delete(code)
        auth.revoke_all_for(session, user)
        audit.record(
            session, current_user(request), "mfa-remove", "user", user.username,
            detail="admin cleared all factors", ip=auth.client_ip(request),
        )
        flash(request, f"Cleared every factor for {user.username}. They must enrol again.")
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_id}/revoke-sessions")
def user_revoke_sessions(request: Request, user_id: int):
    with session_scope() as session:
        user = session.get(User, user_id)
        if user is None:
            raise HTTPException(404)
        count = auth.revoke_all_for(session, user)
        audit.record(
            session, current_user(request), "session-revoke", "user", user.username,
            detail=f"{count} session(s)", ip=auth.client_ip(request),
        )
        flash(request, f"Signed out {count} session(s) for {user.username}.")
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{user_id}/delete")
def user_delete(request: Request, user_id: int):
    with session_scope() as session:
        user = session.get(User, user_id)
        if user is None:
            raise HTTPException(404)
        if user.role == "admin" and auth.admin_count(session) <= 1:
            flash(request, "That's the last active admin.", "danger")
            return RedirectResponse("/users", status_code=303)
        if user.id == current_user(request).id:
            flash(request, "Delete your own account from another admin's session.", "danger")
            return RedirectResponse("/users", status_code=303)
        name = user.username
        session.delete(user)
        audit.record(
            session, current_user(request), "user-delete", "user", name,
            ip=auth.client_ip(request),
        )
        flash(request, f"Deleted {name}. Their audit history is kept.")
    return RedirectResponse("/users", status_code=303)


@app.post("/security")
def security_save(
    request: Request,
    require_mfa: str = Form(""),
    break_glass_enabled: str = Form(""),
):
    with session_scope() as session:
        settings = auth.security_settings(session)
        before = f"require_mfa={settings.require_mfa}, break_glass={settings.break_glass_enabled}"
        settings.require_mfa = require_mfa == "on"
        settings.break_glass_enabled = break_glass_enabled == "on"
        audit.record(
            session, current_user(request), "security-update", "settings", "security",
            detail=(
                f"{before} -> require_mfa={settings.require_mfa}, "
                f"break_glass={settings.break_glass_enabled}"
            ),
            ip=auth.client_ip(request),
        )
        flash(request, "Security settings saved.")
    return RedirectResponse("/users", status_code=303)


# -------------------------------------------------------------------- audit
@app.get("/audit", response_class=HTMLResponse)
def audit_log(request: Request):
    action = request.query_params.get("action", "")
    actor = request.query_params.get("actor", "")
    with session_scope() as session:
        events = audit.recent(session, limit=300, action=action, actor=actor)
        actors = sorted({e.actor for e in audit.recent(session, limit=2000)})
    return templates.TemplateResponse(
        "audit.html",
        ctx(
            request,
            events=events,
            actions=audit.ACTIONS,
            actors=actors,
            selected_action=action,
            selected_actor=actor,
        ),
    )

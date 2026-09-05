"""Branding, help page and theme handling."""

from app.config import BRANDING_DIR

PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06"
    b"\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00"
    b"\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)


def _clear_logos():
    for existing in BRANDING_DIR.glob("logo.*"):
        existing.unlink(missing_ok=True)


def test_defaults_before_any_branding_is_set(auth):
    page = auth.get("/").text
    assert "MDM Scheduler" in page
    assert 'src="/branding/logo"' not in page  # no logo, no broken image
    assert auth.get("/branding/logo").status_code == 404


def test_org_name_and_accent_reach_the_chrome(auth):
    auth.post(
        "/settings",
        data={"org_name": "Ericson Tech", "accent": "#ff6600", "default_theme": "light"},
        follow_redirects=False,
    )
    page = auth.get("/").text
    assert "Ericson Tech MDM Scheduler" in page
    assert "#ff6600" in page
    assert "'light'" in page  # org default fed to the pre-paint theme script


def test_logo_upload_is_served_and_removable(auth):
    _clear_logos()
    resp = auth.post(
        "/settings",
        data={"org_name": "Ericson Tech", "default_theme": "system"},
        files={"logo": ("mark.png", PNG, "image/png")},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    served = auth.get("/branding/logo")
    assert served.status_code == 200
    assert served.headers["content-type"].startswith("image/png")
    assert served.content == PNG
    assert 'src="/branding/logo"' in auth.get("/").text

    auth.post(
        "/settings",
        data={"org_name": "Ericson Tech", "default_theme": "system", "remove_logo": "on"},
        follow_redirects=False,
    )
    assert auth.get("/branding/logo").status_code == 404
    assert list(BRANDING_DIR.glob("logo.*")) == []


def test_replacing_a_logo_does_not_leave_the_old_file_behind(auth):
    _clear_logos()
    auth.post("/settings", data={"default_theme": "system"},
              files={"logo": ("a.png", PNG, "image/png")}, follow_redirects=False)
    auth.post("/settings", data={"default_theme": "system"},
              files={"logo": ("b.webp", PNG, "image/webp")}, follow_redirects=False)
    assert [p.name for p in BRANDING_DIR.glob("logo.*")] == ["logo.webp"]


def test_non_image_upload_is_rejected(auth):
    _clear_logos()
    resp = auth.post(
        "/settings",
        data={"default_theme": "system"},
        files={"logo": ("payload.html", b"<script>alert(1)</script>", "text/html")},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert list(BRANDING_DIR.glob("logo.*")) == []
    assert "Unsupported image type" in auth.get("/settings").text


def test_oversized_logo_is_rejected(auth, monkeypatch):
    _clear_logos()
    monkeypatch.setattr("app.main.MAX_LOGO_BYTES", 10)
    resp = auth.post(
        "/settings",
        data={"default_theme": "system"},
        files={"logo": ("big.png", PNG, "image/png")},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert list(BRANDING_DIR.glob("logo.*")) == []
    assert "the limit is" in auth.get("/settings").text


def test_help_is_readable_without_signing_in(client):
    resp = client.get("/help")
    assert resp.status_code == 200
    page = resp.text

    # the privileges that actually blocked us in the field
    assert "View MDM command information in Jamf Pro API" in page
    assert "Send MDM command information in Jamf Pro API" in page  # the lookalike warning
    assert "Read Computers" in page
    assert "Send MDM Check In Command" in page
    assert "Read Static Computer Groups" in page

    # symptom-keyed troubleshooting
    assert "403 INVALID_PRIVILEGE" in page
    assert "No command was queued" in page

    # Iru half: token setup, the endpoints used, and the blueprint constraint
    assert "API tokens" in page
    assert "PATCH /api/v1/devices/{id}" in page
    assert "unassign" in page
    assert "Command already running" in page
    assert "unlock PIN" in page

    # credits
    assert "Kyle Ericson" in page
    assert "kyle@ericsontech.com" in page
    assert "Claude" in page


def test_help_shows_the_local_support_note(auth):
    auth.post(
        "/settings",
        data={"default_theme": "system", "support_note": "Ask Kyle before any wipe."},
        follow_redirects=False,
    )
    assert "Ask Kyle before any wipe." in auth.get("/help").text


def test_theme_toggle_is_present_and_persists_per_viewer(auth):
    page = auth.get("/")
    assert "toggleTheme()" in page.text
    assert "mdm-scheduler-theme" in page.text  # localStorage key
    assert "prefers-color-scheme" in page.text  # falls back to the OS
    # theme is never a server-side redirect or cookie: no server state to get wrong
    assert "set-cookie" not in {k.lower() for k in page.headers} or "theme" not in page.headers.get(
        "set-cookie", ""
    )


def test_login_page_carries_branding_and_help_link(auth, client):
    auth.post("/settings", data={"org_name": "Ericson Tech", "default_theme": "dark"},
              files={"logo": ("mark.png", PNG, "image/png")}, follow_redirects=False)
    client.cookies.clear()
    page = client.get("/login").text
    assert "Ericson Tech MDM Scheduler" in page
    assert 'src="/branding/logo"' in page
    assert 'href="/help"' in page
    assert "toggleTheme()" in page


def test_ui_assets_are_served_locally_when_vendored(auth):
    """A host with restricted egress must still get a styled UI, so the image
    vendors Bootstrap and the CDN is only a build-failure fallback."""
    from app import main

    page = auth.get("/").text
    if main.LOCAL_ASSETS:
        assert "/static/bootstrap.min.css" in page
        assert "cdn.jsdelivr.net" not in page
        assert auth.get("/static/bootstrap.min.css").status_code == 200
    else:  # build had no network; fallback is expected
        assert "cdn.jsdelivr.net" in page


def test_branding_survives_a_restart(auth):
    """Branding lives in the database and on the data volume, not in memory."""
    auth.post("/settings", data={"org_name": "Persisted Co", "default_theme": "system"},
              follow_redirects=False)
    from app.database import session_scope
    from app.models import Branding

    with session_scope() as session:
        assert session.get(Branding, 1).org_name == "Persisted Co"

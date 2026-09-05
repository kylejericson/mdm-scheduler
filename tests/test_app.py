import re
import sqlite3
import time
from datetime import UTC, datetime, timedelta

from app.config import DB_PATH
from tests.mock_jamf import STATE


def test_health_is_public(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["scheduler_running"] is True


def test_pages_require_login(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_api_returns_401_not_a_redirect(client):
    assert client.get("/api/instances/1/objects?kind=policies").status_code == 401


def test_wrong_password_rejected(client):
    assert client.post("/login", data={"password": "nope"}).status_code == 401


def test_instance_test_button_reports_version_and_counts(instance, auth):
    body = auth.post(f"/instances/{instance}/test").json()
    assert body["ok"] is True
    assert "11.31.1" in body["detail"]
    assert "2 policies" in body["detail"]
    assert "2 computer groups" in body["detail"]


def test_discovery_endpoint_feeds_the_job_form(instance, auth):
    body = auth.get(f"/api/instances/{instance}/objects?kind=policies").json()
    assert body["ok"] is True
    assert [item["name"] for item in body["items"]] == ["Alpha Patch", "Zebra Install"]


def test_credentials_are_encrypted_at_rest(instance):
    row = sqlite3.connect(DB_PATH).execute("select client_secret_enc from instances").fetchone()
    assert row[0].startswith("gAAAAA")
    assert "shhh" not in row[0]


def test_blank_secret_on_edit_keeps_the_stored_one(instance, auth, jamf):
    auth.post(
        "/instances",
        data={
            "instance_id": str(instance),
            "name": "Mock Jamf",
            "base_url": jamf,
            "auth_type": "client",
            "client_id": "abc",
            "client_secret": "",
            "verify_ssl": "on",
        },
        follow_redirects=False,
    )
    assert auth.post(f"/instances/{instance}/test").json()["ok"] is True


def _save_job(auth, **overrides):
    data = {
        "name": "Test job",
        "instance_id": "1",
        "action": "policy_enable",
        "schedule_type": "once",
        "run_at": "2030-01-01T03:00",
        "tz": "America/Chicago",
        "enabled": "on",
        "policy_id": "1",
    }
    data.update(overrides)
    resp = auth.post("/jobs", data=data, follow_redirects=False)
    assert resp.status_code == 303, resp.text
    return resp


def test_run_now_performs_the_write(instance, auth):
    _save_job(auth)
    auth.post("/jobs/1/run", follow_redirects=False)
    assert STATE["policy_enabled"] is True
    logs = auth.get("/jobs/1/logs").text
    assert "success" in logs and "enabled=True" in logs


def test_one_shot_stores_utc_and_renders_local(instance, auth):
    _save_job(auth)
    dashboard = auth.get("/").text
    assert "2030-01-01 03:00 CST" in dashboard
    edit = auth.get("/jobs/1/edit").text
    assert 'value="2030-01-01T03:00"' in edit


def test_scope_add_preserves_existing_groups_and_is_idempotent(instance, auth):
    _save_job(auth, action="osx_profile_scope_add_group", profile_id="3", group_id="7")
    auth.post("/jobs/1/run", follow_redirects=False)
    assert sorted(g["id"] for g in STATE["profile_groups"]) == [5, 7]

    auth.post("/jobs/1/run", follow_redirects=False)
    assert sorted(g["id"] for g in STATE["profile_groups"]) == [5, 7]
    assert "No change" in auth.get("/jobs/1/logs").text


def test_scope_remove_leaves_other_groups_alone(instance, auth):
    _save_job(auth, action="osx_profile_scope_remove_group", profile_id="3", group_id="5")
    auth.post("/jobs/1/run", follow_redirects=False)
    assert STATE["profile_groups"] == []


def test_mdm_command_expands_the_group_at_run_time(instance, auth):
    _save_job(
        auth,
        action="computer_mdm_command",
        command="DeviceLock",
        target_type="group",
        group_id="7",
        pin="123456",
    )
    auth.post("/jobs/1/run", follow_redirects=False)
    sent = STATE["v2_commands"][-1]
    assert sent["clientData"] == [{"managementId": "mgmt-101"}, {"managementId": "mgmt-102"}]
    assert sent["commandData"]["commandType"] == "DEVICE_LOCK"


def test_uncapable_targets_are_skipped_and_named(instance, auth):
    """Group 8 holds mac-01 plus an Intel Mac that is not MDM-capable."""
    _save_job(
        auth,
        action="computer_mdm_command",
        command="DeviceLock",
        target_type="group",
        group_id="8",
        pin="123456",
    )
    auth.post("/jobs/1/run", follow_redirects=False)

    # the capable one still got the command
    assert STATE["v2_commands"][-1]["clientData"] == [{"managementId": "mgmt-101"}]

    logs = auth.get("/jobs/1/logs").text
    assert "success" in logs
    assert "skipped 1" in logs
    assert "old-intel-mac" in logs and "not MDM-capable" in logs


def test_targeting_by_serial_number(instance, auth):
    _save_job(
        auth,
        action="computer_mdm_command",
        command="RestartDevice",
        target_type="devices",
        device_ids="C02X1234JGH5, 102",
        group_id="",
    )
    auth.post("/jobs/1/run", follow_redirects=False)
    assert STATE["v2_commands"][-1]["clientData"] == [
        {"managementId": "mgmt-101"},
        {"managementId": "mgmt-102"},
    ]
    assert "RESTART_DEVICE" in auth.get("/jobs/1/logs").text


def test_all_targets_uncapable_fails_loudly(instance, auth):
    _save_job(
        auth,
        action="computer_mdm_command",
        command="DeviceLock",
        target_type="devices",
        device_ids="30",
        group_id="",
        pin="123456",
    )
    auth.post("/jobs/1/run", follow_redirects=False)
    logs = auth.get("/jobs/1/logs").text
    assert "error" in logs
    assert "no capable targets" in logs
    assert STATE["v2_commands"] == []


def test_pin_is_masked_on_the_dashboard(instance, auth):
    _save_job(
        auth,
        action="computer_mdm_command",
        command="DeviceLock",
        target_type="group",
        group_id="7",
        pin="123456",
    )
    assert "123456" not in auth.get("/").text


def test_failed_run_is_logged_not_raised(instance, auth):
    _save_job(
        auth,
        action="computer_mdm_command",
        command="EraseDevice",
        target_type="group",
        group_id="7",
    )
    resp = auth.post("/jobs/1/run", follow_redirects=False)
    assert resp.status_code == 303
    logs = auth.get("/jobs/1/logs").text
    assert "JamfError" in logs and "6-digit PIN" in logs


def test_cron_job_gets_a_next_run(instance, auth):
    _save_job(auth, schedule_type="cron", cron="0 3 * * 1-5", run_at="")
    dashboard = auth.get("/").text
    assert re.search(r"\d{4}-\d{2}-\d{2} 03:00 C[DS]T", dashboard)


def test_pause_and_resume(instance, auth):
    _save_job(auth)
    auth.post("/jobs/1/toggle", follow_redirects=False)
    assert "paused" in auth.get("/").text
    auth.post("/jobs/1/toggle", follow_redirects=False)
    assert "paused" not in auth.get("/").text


def test_delete_removes_job_and_its_schedule(instance, auth):
    _save_job(auth)
    from app import scheduler as sched

    assert sched.scheduler.get_job("job-1") is not None
    auth.post("/jobs/1/delete", follow_redirects=False)
    assert sched.scheduler.get_job("job-1") is None
    assert "Test job" not in auth.get("/").text


def test_scheduler_fires_a_job_on_its_own(instance, auth):
    fire = datetime.now(UTC) + timedelta(seconds=3)
    _save_job(auth, tz="UTC", run_at=fire.strftime("%Y-%m-%dT%H:%M:%S"))

    # Poll the run log, not the mock: the Jamf call happens before the log row
    # is written, so watching the mock races the commit.
    deadline = time.time() + 30
    logs = ""
    while time.time() < deadline:
        logs = auth.get("/jobs/1/logs").text
        if ">schedule<" in logs:
            break
        time.sleep(0.5)

    assert STATE["policy_enabled"] is True, "scheduled job never fired"
    assert ">schedule<" in logs
    assert "paused" in auth.get("/").text  # one-shot pauses itself after success

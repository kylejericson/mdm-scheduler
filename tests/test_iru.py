"""Iru (Kandji) client and end-to-end scheduling."""

import pytest

from app.iru_client import IruClient, IruError
from tests.mock_iru import STATE, TOKEN


@pytest.fixture
def ic(iru):
    with IruClient(base_url=iru, api_token=TOKEN) as client:
        yield client


# ------------------------------------------------------------------- client
def test_blueprints_are_listed_and_sorted(ic):
    names = [b["name"] for b in ic.blueprints()]
    assert names == ["Executives", "Quarantine", "Standard Macs"]


def test_bad_token_is_a_clear_error(iru):
    with IruClient(base_url=iru, api_token="wrong") as client:
        with pytest.raises(IruError) as exc:
            client.blueprints()
    assert "HTTP 401" in str(exc.value)
    assert "revoked or expired" in str(exc.value)


def test_missing_permission_names_where_to_fix_it(ic):
    STATE["deny"] = True
    with pytest.raises(IruError) as exc:
        ic.blueprints()
    message = str(exc.value)
    assert "HTTP 403" in message
    assert "Settings > Access > API tokens" in message


def test_devices_normalise_to_the_documented_fields(ic):
    devices = ic.devices()
    mac = next(d for d in devices if d["serial"] == "C02X1234JGH5")
    assert mac["id"] == "dev-1"
    assert mac["name"] == "kyle-mbp"
    assert mac["blueprint_name"] == "Standard Macs"
    assert mac["mdm_enabled"] is True


def test_targets_resolve_by_serial_case_insensitively(ic):
    devices, problems = ic.resolve_targets(["c02x1234jgh5", "dev-2"])
    assert [d["id"] for d in devices] == ["dev-1", "dev-2"]
    assert problems == []


def test_unknown_serial_is_reported(ic):
    devices, problems = ic.resolve_targets(["NOPE123"])
    assert devices == []
    assert "NOPE123 (no Iru device with that serial or ID)" in problems


def test_capability_check_catches_mdm_disabled(ic):
    devices, _ = ic.resolve_targets(["C17OLDINTEL1"])
    assert ic.capability_check(devices[0]) == "MDM not enabled"


def test_lock_posts_to_the_official_action_path_and_returns_the_pin(ic):
    devices, _ = ic.resolve_targets(["C02X1234JGH5"])
    message = ic.send_command("Lock", devices, message="Call IT", phone="5551234")

    action = STATE["actions"][-1]
    assert action["action"] == "lock"
    assert action["device_id"] == "dev-1"
    assert action["body"] == {"Message": "Call IT", "PhoneNumber": "5551234"}
    assert "unlock PIN 496406" in message  # Iru generates it; useless if not logged


def test_erase_requires_a_pin_and_sends_the_documented_body(ic):
    devices, _ = ic.resolve_targets(["C02X1234JGH5"])
    with pytest.raises(IruError) as exc:
        ic.send_command("Erase", devices)
    assert "requires pin" in str(exc.value)

    ic.send_command("Erase", devices, pin="123456")
    body = STATE["actions"][-1]["body"]
    assert STATE["actions"][-1]["action"] == "erase"
    assert body["PIN"] == "123456"
    assert body["ReturnToService"] == {"Enabled": False}


def test_toggle_commands_share_a_path_with_different_payloads(ic):
    devices, _ = ic.resolve_targets(["C02X1234JGH5"])
    ic.send_command("RemoteDesktopOn", devices)
    assert STATE["actions"][-1] == {
        "device_id": "dev-1", "action": "remotedesktop", "body": {"EnableRemoteDesktop": True}
    }
    ic.send_command("RemoteDesktopOff", devices)
    assert STATE["actions"][-1]["body"] == {"EnableRemoteDesktop": False}


def test_commands_needing_a_username_refuse_without_one(ic):
    devices, _ = ic.resolve_targets(["C02X1234JGH5"])
    with pytest.raises(IruError):
        ic.send_command("UnlockAccount", devices)
    ic.send_command("UnlockAccount", devices, username="kyle")
    assert STATE["actions"][-1]["body"] == {"UserName": "kyle"}


def test_one_failing_device_does_not_lose_the_others(ic):
    devices = ic.devices()
    devices = devices + [{"id": "dev-missing", "name": "ghost", "serial": "GHOST"}]
    message = ic.send_command("BlankPush", devices)
    assert "sent to 3" in message
    assert "1 failed" in message and "ghost" in message


# --------------------------------------------------------------- blueprints
def test_move_uses_patch_with_blueprint_id(ic):
    devices, _ = ic.resolve_targets(["C02X1234JGH5"])
    message = ic.move_to_blueprint(devices, "bp-quarantine")

    assert STATE["patches"][-1] == {"device_id": "dev-1", "body": {"blueprint_id": "bp-quarantine"}}
    assert "Quarantine" in message
    assert "from Standard Macs" in message
    assert ic.devices(refresh=True)[0]["blueprint_id"] == "bp-quarantine"


def test_move_skips_devices_already_in_the_destination(ic):
    devices, _ = ic.resolve_targets(["C02X1234JGH5"])
    message = ic.move_to_blueprint(devices, "bp-standard")
    assert "already there" in message
    assert STATE["patches"] == []  # no pointless write


# ---------------------------------------------------------------- end to end
def _save(auth, instance_id, **overrides):
    data = {
        "name": "Iru job",
        "instance_id": str(instance_id),
        "action": "iru_mdm_command",
        "schedule_type": "once",
        "run_at": "2030-01-01T03:00",
        "tz": "America/Chicago",
        "enabled": "on",
        "command": "BlankPush",
        "target_type": "devices",
        "serials": "C02X1234JGH5",
    }
    data.update(overrides)
    resp = auth.post("/jobs", data=data, follow_redirects=False)
    assert resp.status_code == 303, resp.text


def test_instance_test_button_reports_iru_counts(iru_instance, auth):
    body = auth.post(f"/instances/{iru_instance}/test").json()
    assert body["ok"] is True
    assert "3 blueprint(s)" in body["detail"]
    assert "3 device(s)" in body["detail"]


def test_blueprint_discovery_feeds_the_form(iru_instance, auth):
    body = auth.get(f"/api/instances/{iru_instance}/objects?kind=blueprints").json()
    assert body["ok"] is True
    assert {b["name"] for b in body["items"]} == {"Standard Macs", "Quarantine", "Executives"}


def test_jamf_object_kinds_are_rejected_for_an_iru_instance(iru_instance, auth):
    assert auth.get(f"/api/instances/{iru_instance}/objects?kind=policies").status_code == 400


def test_scheduled_iru_command_runs(iru_instance, auth):
    _save(auth, iru_instance, command="Restart")
    jobs = auth.get("/").text
    assert "Iru job" in jobs

    import re
    job_id = max(int(m) for m in re.findall(r"/jobs/(\d+)/logs", jobs))
    auth.post(f"/jobs/{job_id}/run", follow_redirects=False)

    assert STATE["actions"][-1]["action"] == "restart"
    logs = auth.get(f"/jobs/{job_id}/logs").text
    assert "success" in logs and "kyle-mbp" in logs


def test_blueprint_move_job_targets_a_whole_blueprint(iru_instance, auth):
    _save(
        auth,
        iru_instance,
        name="Quarantine the standard fleet",
        action="iru_blueprint_move",
        target_type="blueprint",
        source_blueprint_id="bp-standard",
        blueprint_id="bp-quarantine",
        serials="",
    )
    import re
    job_id = max(int(m) for m in re.findall(r"/jobs/(\d+)/logs", auth.get("/").text))
    auth.post(f"/jobs/{job_id}/run", follow_redirects=False)

    moved = {p["device_id"] for p in STATE["patches"]}
    assert moved == {"dev-1", "dev-2"}  # both Standard Macs devices, not the quarantined one
    logs = auth.get(f"/jobs/{job_id}/logs").text
    # Jinja escapes the quotes around the blueprint name
    assert "Moved 2 device(s) to blueprint" in logs
    assert "Quarantine" in logs


def test_uncapable_iru_device_is_skipped_not_fatal(iru_instance, auth):
    _save(auth, iru_instance, command="Restart", serials="C02X1234JGH5, C17OLDINTEL1")
    import re
    job_id = max(int(m) for m in re.findall(r"/jobs/(\d+)/logs", auth.get("/").text))
    auth.post(f"/jobs/{job_id}/run", follow_redirects=False)

    logs = auth.get(f"/jobs/{job_id}/logs").text
    assert "success" in logs
    assert "skipped 1" in logs and "MDM not enabled" in logs
    assert [a["device_id"] for a in STATE["actions"]] == ["dev-1"]


def test_job_form_only_offers_actions_for_the_selected_vendor(iru_instance, auth):
    page = auth.get("/jobs/new").text
    assert '"iru_mdm_command"' in page and '"vendor": "iru"' in page
    assert '"policy_enable"' in page and '"vendor": "jamf"' in page
    # the vendor map lets the form swap menus without a round trip
    assert "VENDORS" in page and "fillActions" in page

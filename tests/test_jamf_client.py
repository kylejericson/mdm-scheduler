import pytest

from app.jamf_client import JamfClient, JamfError


@pytest.fixture
def jc(jamf):
    with JamfClient(base_url=jamf, auth_type="client", client_id="abc", client_secret="shhh") as client:
        yield client


def test_token_exchange_and_version(jc):
    assert jc.version().startswith("11.31.1")


def test_token_is_cached(jc, jamf):
    from tests.mock_jamf import STATE

    jc.token()
    jc.token()
    jc.token()
    assert STATE["token_requests"] == 1


def test_bad_secret_raises():
    from tests.mock_jamf import start

    base_url, server = start()
    try:
        with JamfClient(base_url=base_url, auth_type="client", client_id="abc", client_secret="wrong") as client:
            with pytest.raises(JamfError) as exc:
                client.version()
        assert "OAuth token request failed" in str(exc.value)
    finally:
        server.shutdown()


def test_classic_api_json_labelled_text_plain_is_parsed(jc):
    """Regression: 1.0.0 trusted the content-type header and saw zero objects.

    Jamf's Classic API serves JSON as text/plain;charset=utf-8.
    """
    policies = jc.list_objects("policies")
    assert [p["name"] for p in policies] == ["Alpha Patch", "Zebra Install"]  # sorted by name

    groups = jc.list_objects("computer_groups")
    assert {g["id"] for g in groups} == {5, 7}
    assert next(g for g in groups if g["id"] == 5)["smart"] is True


def test_unexpected_body_raises_instead_of_reporting_empty(jc):
    """A non-Jamf response must be loud, not silently zero objects."""
    jc.OBJECTS = None  # not used; guard against accidental reliance
    from app.jamf_client import OBJECTS

    original = OBJECTS["policies"]
    OBJECTS["policies"] = ("/not-jamf", "policies", "/not-jamf", "policy")
    try:
        with pytest.raises(JamfError) as exc:
            jc.list_objects("policies")
        assert "Unexpected response listing policies" in str(exc.value)
    finally:
        OBJECTS["policies"] = original


def test_write_rejected_with_401_html_explains_the_missing_privilege(jc):
    """A read-only role: Jamf 401s the write and returns an HTML status page."""
    from tests.mock_jamf import STATE

    STATE["deny_writes"] = True
    with pytest.raises(JamfError) as exc:
        jc.set_profile_scope_groups("osx_profiles", 3, [5, 7])

    message = str(exc.value)
    assert "HTTP 401" in message
    assert "The request requires user authentication" in message  # HTML stripped to words
    assert "<p" not in message and "<html" not in message  # no markup dumped at the user
    assert "Update macOS Configuration Profiles" in message  # names the likely fix


def test_v2_403_names_the_view_mdm_privilege_and_the_lookalike(jc):
    """The real failure: INVALID_PRIVILEGE from /api/v2/mdm/blank-push."""
    from tests.mock_jamf import STATE

    devices, _ = jc.resolve_targets("computer", ["101"])
    STATE["deny_writes"] = True
    with pytest.raises(JamfError) as exc:
        jc.send_command("computer", "BlankPush", devices)

    message = str(exc.value)
    assert "HTTP 403" in message
    assert "INVALID_PRIVILEGE Forbidden" in message  # JSON envelope reduced to one line
    assert '"httpStatus"' not in message  # raw JSON not dumped at the user
    assert "View MDM command information in Jamf Pro API" in message
    assert "does NOT satisfy it" in message  # warns about the Send/View lookalike


def test_rejected_classic_command_names_the_read_privilege(jc):
    """A Send privilege alone is not enough - Jamf also needs Read Computers."""
    from tests.mock_jamf import STATE

    devices, _ = jc.resolve_targets("computer", ["101"])
    STATE["deny_writes"] = True
    with pytest.raises(JamfError) as exc:
        jc.send_command("computer", "UnmanageDevice", devices)

    message = str(exc.value)
    assert "Read Computers" in message
    assert "Send MDM Check In Command" in message


def test_redirected_write_is_reported_not_followed(jc):
    """httpx drops Authorization across origins, so never silently follow a write."""
    from tests.mock_jamf import STATE

    STATE["redirect_writes"] = True
    with pytest.raises(JamfError) as exc:
        jc.set_policy_enabled(1, True)

    message = str(exc.value)
    assert "redirect to https://elsewhere.example.com" in message
    assert "Base URL" in message
    assert STATE["policy_enabled"] is False  # the write did not happen anywhere


def test_writes_are_sent_as_application_xml(jc):
    captured = {}
    original = jc._http.request

    def spy(method, url, **kwargs):
        if method == "PUT":
            captured.update(kwargs.get("headers") or {})
        return original(method, url, **kwargs)

    jc._http.request = spy
    jc.set_policy_enabled(1, True)
    assert captured.get("Content-Type") == "application/xml"


def test_scope_read_modify_write_is_additive(jc):
    current = jc.profile_scope_group_ids("osx_profiles", 3)
    assert current == [5]
    jc.set_profile_scope_groups("osx_profiles", 3, current + [7])
    assert sorted(jc.profile_scope_group_ids("osx_profiles", 3)) == [5, 7]


def test_group_membership_expands_at_call_time(jc):
    assert jc.group_member_ids("computer_groups", 7) == [101, 102]
    assert jc.group_member_ids("mobile_groups", 9) == [201]


def test_inventory_normalises_both_platforms(jc):
    computers = jc.inventory("computer")
    assert {d["id"] for d in computers} == {"101", "102", "30"}
    mac = next(d for d in computers if d["id"] == "101")
    assert mac["management_id"] == "mgmt-101"
    assert mac["serial"] == "C02X1234JGH5"
    assert mac["managed"] is True and mac["capable"] is True

    ipad = jc.inventory("mobile")[0]
    assert ipad["management_id"] == "mgmt-201"  # mobile reports general.managed
    assert ipad["managed"] is True


def test_inventory_is_cached_per_client(jc):
    jc.inventory("computer")
    calls = {"n": 0}
    original = jc.request

    def counting(*args, **kwargs):
        calls["n"] += 1
        return original(*args, **kwargs)

    jc.request = counting
    jc.inventory("computer")
    assert calls["n"] == 0


def test_targets_resolve_by_id_and_by_serial(jc):
    devices, problems = jc.resolve_targets("computer", ["101", "FVFXQ12ABCDE", "c02x1234jgh5"])
    assert [d["id"] for d in devices] == ["101", "102"]  # third is a dup of 101, case-insensitive
    assert problems == []


def test_unknown_target_is_reported_by_kind(jc):
    devices, problems = jc.resolve_targets("computer", ["9999", "NOSUCHSERIAL"])
    assert devices == []
    assert "9999 (no computer with that id in inventory)" in problems
    assert "NOSUCHSERIAL (no computer with that serial in inventory)" in problems


def test_capability_check_flags_the_uncapable_mac(jc):
    devices, _ = jc.resolve_targets("computer", ["30"])
    assert jc.capability_check("computer", devices[0]) == "not MDM-capable"
    assert jc.capability_check("computer", {"managed": False}) == "not managed"
    assert jc.capability_check("computer", {"management_id": None}) == "no managementId in inventory"


def test_lock_goes_over_v2_with_management_ids(jc):
    from tests.mock_jamf import STATE

    devices, _ = jc.resolve_targets("computer", ["101", "102"])
    message = jc.send_command("computer", "DeviceLock", devices, pin="123456", message="Call IT")

    sent = STATE["v2_commands"][-1]
    assert sent["clientData"] == [{"managementId": "mgmt-101"}, {"managementId": "mgmt-102"}]
    assert sent["commandData"]["commandType"] == "DEVICE_LOCK"
    assert sent["commandData"]["pin"] == "123456"
    assert sent["commandData"]["message"] == "Call IT"
    assert "/api/v2/mdm/commands" in message
    assert STATE["commands"] == []  # nothing went to the Classic endpoint


def test_erase_sends_the_required_return_to_service_field(jc):
    from tests.mock_jamf import STATE

    devices, _ = jc.resolve_targets("computer", ["101"])
    jc.send_command("computer", "EraseDevice", devices, pin="123456")

    data = STATE["v2_commands"][-1]["commandData"]
    assert data["commandType"] == "ERASE_DEVICE"
    assert data["returnToService"] == {"enabled": False}  # required by the v2 schema
    assert data["pin"] == "123456"


def test_blank_push_uses_its_own_endpoint(jc):
    from tests.mock_jamf import STATE

    devices, _ = jc.resolve_targets("computer", ["101", "102"])
    message = jc.send_command("computer", "BlankPush", devices)

    assert STATE["blank_pushes"][-1] == {"clientManagementIds": ["mgmt-101", "mgmt-102"]}
    assert "blank-push" in message
    assert STATE["v2_commands"] == []


def test_lost_mode_message_maps_to_lost_mode_message_field(jc):
    from tests.mock_jamf import STATE

    devices, _ = jc.resolve_targets("mobile", ["201"])
    jc.send_command("mobile", "EnableLostMode", devices, message="Property of Acme")

    data = STATE["v2_commands"][-1]["commandData"]
    assert data["commandType"] == "ENABLE_LOST_MODE"
    assert data["lostModeMessage"] == "Property of Acme"


def test_lost_mode_requires_a_message(jc):
    devices, _ = jc.resolve_targets("mobile", ["201"])
    with pytest.raises(JamfError) as exc:
        jc.send_command("mobile", "EnableLostMode", devices)
    assert "requires a message" in str(exc.value)


def test_commands_without_a_v2_equivalent_stay_on_classic(jc):
    from tests.mock_jamf import STATE

    devices, _ = jc.resolve_targets("computer", ["101"])
    message = jc.send_command("computer", "UnmanageDevice", devices)
    assert STATE["commands"][-1]["command"] == "UnmanageDevice"
    assert "Classic API" in message
    assert STATE["v2_commands"] == []

    ipads, _ = jc.resolve_targets("mobile", ["201"])
    jc.send_command("mobile", "ClearPasscode", ipads)  # v2 needs an unlockToken
    assert STATE["commands"][-1]["command"] == "ClearPasscode"


def test_computer_lock_requires_pin(jc):
    devices, _ = jc.resolve_targets("computer", ["101"])
    with pytest.raises(JamfError) as exc:
        jc.send_command("computer", "DeviceLock", devices, pin="")
    assert "6-digit PIN" in str(exc.value)


def test_empty_target_list_refuses_rather_than_no_ops(jc):
    from tests.mock_jamf import STATE

    with pytest.raises(JamfError) as exc:
        jc.send_command("computer", "RestartDevice", [])
    assert "nothing sent" in str(exc.value)
    assert STATE["v2_commands"] == []

"""Action catalog + dispatch. Add new actions here and to the form in
templates/job_form.html.
"""

from __future__ import annotations

from .iru_client import IRU_COMMANDS, IruClient, IruError
from .jamf_client import COMPUTER_COMMANDS, MOBILE_COMMANDS, JamfClient, JamfError

# vendor: which MDM this action belongs to - the job form shows only the
#         actions for the selected instance's vendor.
# needs:  which pickers the job form shows for this action.
ACTIONS = {
    "policy_enable": {
        "vendor": "jamf",
        "label": "Enable a policy",
        "needs": ["policy"],
    },
    "policy_disable": {
        "vendor": "jamf",
        "label": "Disable a policy",
        "needs": ["policy"],
    },
    "policy_scope_add_group": {
        "vendor": "jamf",
        "label": "Add computer group to policy scope",
        "needs": ["policy", "computer_group"],
    },
    "policy_scope_remove_group": {
        "vendor": "jamf",
        "label": "Remove computer group from policy scope",
        "needs": ["policy", "computer_group"],
    },
    "osx_profile_scope_add_group": {
        "vendor": "jamf",
        "label": "Assign macOS config profile to computer group",
        "needs": ["osx_profile", "computer_group"],
    },
    "osx_profile_scope_remove_group": {
        "vendor": "jamf",
        "label": "Unassign macOS config profile from computer group",
        "needs": ["osx_profile", "computer_group"],
    },
    "mobile_profile_scope_add_group": {
        "vendor": "jamf",
        "label": "Assign mobile config profile to mobile device group",
        "needs": ["mobile_profile", "mobile_group"],
    },
    "mobile_profile_scope_remove_group": {
        "vendor": "jamf",
        "label": "Unassign mobile config profile from mobile device group",
        "needs": ["mobile_profile", "mobile_group"],
    },
    "computer_mdm_command": {
        "vendor": "jamf",
        "label": "Send MDM command to computers",
        "needs": ["computer_command", "computer_target"],
    },
    "mobile_mdm_command": {
        "vendor": "jamf",
        "label": "Send MDM command to mobile devices",
        "needs": ["mobile_command", "mobile_target"],
    },
    # ------------------------------------------------------------------- Iru
    "iru_blueprint_move": {
        "vendor": "iru",
        "label": "Move devices to a blueprint",
        "needs": ["iru_blueprint_target", "iru_blueprint_destination"],
    },
    "iru_mdm_command": {
        "vendor": "iru",
        "label": "Send MDM command to devices",
        "needs": ["iru_command", "iru_target"],
    },
}


def actions_for(vendor: str) -> dict:
    return {key: spec for key, spec in ACTIONS.items() if spec["vendor"] == vendor}


def actions_ordered() -> list[dict]:
    """ACTIONS as a list, because Jinja's tojson sorts dict keys and the menu
    order is deliberate: the least destructive action for each vendor first."""
    return [{"key": key, **spec} for key, spec in ACTIONS.items()]


def _int(params: dict, key: str) -> int:
    value = params.get(key)
    if value in (None, ""):
        raise JamfError(f"Missing required parameter: {key}")
    return int(value)


def run_action(client, action: str, params: dict) -> str:
    """Dispatch by action. `client` is the vendor client for the job's instance."""
    if ACTIONS.get(action, {}).get("vendor") == "iru":
        return _run_iru(client, action, params)

    if action in ("policy_enable", "policy_disable"):
        return client.set_policy_enabled(_int(params, "policy_id"), action == "policy_enable")

    if action in ("policy_scope_add_group", "policy_scope_remove_group"):
        policy_id = _int(params, "policy_id")
        group_id = _int(params, "group_id")
        adding = action.endswith("add_group")
        current = client.policy_scope_group_ids(policy_id)
        target = _apply_membership(current, group_id, adding)
        if target == current:
            return _no_change(group_id, adding, "policy", policy_id)
        return client.set_policy_scope_groups(policy_id, target)

    if action.startswith(("osx_profile_scope", "mobile_profile_scope")):
        kind = "osx_profiles" if action.startswith("osx") else "mobile_profiles"
        profile_id = _int(params, "profile_id")
        group_id = _int(params, "group_id")
        adding = action.endswith("add_group")
        current = client.profile_scope_group_ids(kind, profile_id)
        target = _apply_membership(current, group_id, adding)
        if target == current:
            return _no_change(group_id, adding, "profile", profile_id)
        return client.set_profile_scope_groups(kind, profile_id, target)

    if action in ("computer_mdm_command", "mobile_mdm_command"):
        platform = "computer" if action == "computer_mdm_command" else "mobile"
        catalog = COMPUTER_COMMANDS if platform == "computer" else MOBILE_COMMANDS
        command = params.get("command", "")
        if command not in catalog:
            raise JamfError(f"Unsupported {platform} command: {command}")
        return _send_mdm(client, platform, command, params)

    raise JamfError(f"Unknown action: {action}")


def _send_mdm(client: JamfClient, platform: str, command: str, params: dict) -> str:
    group_kind = "computer_groups" if platform == "computer" else "mobile_groups"

    # Targets are resolved when the job fires, never when it is saved.
    if params.get("target_type") == "devices":
        tokens = [t.strip() for t in str(params.get("device_ids", "")).split(",") if t.strip()]
        if not tokens:
            raise JamfError("No device IDs or serial numbers supplied.")
        source = f"{len(tokens)} listed device(s)"
    else:
        group_id = _int(params, "group_id")
        tokens = [str(i) for i in client.group_member_ids(group_kind, group_id)]
        source = f"group {group_id} ({len(tokens)} member(s))"
        if not tokens:
            raise JamfError(f"Group {group_id} has no members - nothing sent.")

    devices, problems = client.resolve_targets(platform, tokens)

    # Pre-flight: a device that cannot take the command is skipped and named,
    # so one stale laptop never blocks a scheduled fleet action.
    sendable, skipped = [], list(problems)
    for device in devices:
        reason = client.capability_check(platform, device)
        if reason:
            skipped.append(f"{device.get('name')} (id {device.get('id')}) - {reason}")
        else:
            sendable.append(device)

    if not sendable:
        raise JamfError(
            f"{command}: no capable targets out of {source}. Skipped: {'; '.join(skipped) or 'none'}"
        )

    result = client.send_command(
        platform,
        command,
        sendable,
        pin=params.get("pin", ""),
        message=params.get("message", ""),
    )
    summary = f"{result} [from {source}]"
    if skipped:
        summary += f" | skipped {len(skipped)}: {'; '.join(skipped)}"
    return summary


# --------------------------------------------------------------------- Iru
def _iru_targets(client: IruClient, params: dict) -> tuple[list[dict], list[str], str]:
    """Resolve targets at run time: a serial/ID list, or every device in a blueprint."""
    if params.get("target_type") == "blueprint":
        blueprint_id = params.get("source_blueprint_id") or ""
        if not blueprint_id:
            raise IruError("No source blueprint selected.")
        devices = client.devices_in_blueprint(blueprint_id)
        source = f"blueprint '{client.blueprint_name(blueprint_id)}' ({len(devices)} device(s))"
        if not devices:
            raise IruError(f"{source} has no devices - nothing to do.")
        return devices, [], source

    tokens = [t.strip() for t in str(params.get("serials", "")).split(",") if t.strip()]
    if not tokens:
        raise IruError("No serial numbers or device IDs supplied.")
    devices, problems = client.resolve_targets(tokens)
    return devices, problems, f"{len(tokens)} listed device(s)"


def _run_iru(client: IruClient, action: str, params: dict) -> str:
    devices, problems, source = _iru_targets(client, params)

    if action == "iru_blueprint_move":
        destination = params.get("blueprint_id") or ""
        if not destination:
            raise IruError("No destination blueprint selected.")
        # A removed device can still be re-homed, so only unknown targets are dropped.
        result = client.move_to_blueprint(devices, destination)
        summary = f"{result} [from {source}]"
        if problems:
            summary += f" | skipped {len(problems)}: {'; '.join(problems)}"
        return summary

    if action == "iru_mdm_command":
        command = params.get("command", "")
        if command not in IRU_COMMANDS:
            raise IruError(f"Unsupported Iru command: {command}")

        sendable, skipped = [], list(problems)
        for device in devices:
            reason = client.capability_check(device)
            if reason:
                skipped.append(f"{device.get('name')} ({device.get('serial')}) - {reason}")
            else:
                sendable.append(device)

        if not sendable:
            raise IruError(
                f"{command}: no capable targets out of {source}. Skipped: {'; '.join(skipped) or 'none'}"
            )

        result = client.send_command(
            command,
            sendable,
            pin=params.get("pin", ""),
            message=params.get("message", ""),
            phone=params.get("phone", ""),
            username=params.get("username", ""),
            device_name=params.get("device_name", ""),
        )
        summary = f"{result} [from {source}]"
        if skipped:
            summary += f" | skipped {len(skipped)}: {'; '.join(skipped)}"
        return summary

    raise IruError(f"Unknown Iru action: {action}")


def _no_change(group_id: int, adding: bool, object_kind: str, object_id: int) -> str:
    where = "in" if adding else "absent from"
    return f"No change - group {group_id} already {where} {object_kind} {object_id} scope"


def _apply_membership(current: list[int], group_id: int, add: bool) -> list[int]:
    target = list(current)
    if add and group_id not in target:
        target.append(group_id)
    if not add and group_id in target:
        target = [g for g in target if g != group_id]
    return target



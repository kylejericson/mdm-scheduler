"""Minimal Jamf Pro API client covering the Classic and Pro (v1/v2) endpoints
this scheduler needs. Bearer tokens work against both API surfaces on
Jamf Pro 10.35+.
"""

from __future__ import annotations

import json
import re
import time
from xml.sax.saxutils import escape

import httpx

from .config import HTTP_TIMEOUT

# Classic API object kinds -> (list endpoint, list key, item endpoint, item key)
OBJECTS = {
    "policies": ("/JSSResource/policies", "policies", "/JSSResource/policies/id/{id}", "policy"),
    "osx_profiles": (
        "/JSSResource/osxconfigurationprofiles",
        "os_x_configuration_profiles",
        "/JSSResource/osxconfigurationprofiles/id/{id}",
        "os_x_configuration_profile",
    ),
    "mobile_profiles": (
        "/JSSResource/mobiledeviceconfigurationprofiles",
        "configuration_profiles",
        "/JSSResource/mobiledeviceconfigurationprofiles/id/{id}",
        "configuration_profile",
    ),
    "computer_groups": (
        "/JSSResource/computergroups",
        "computer_groups",
        "/JSSResource/computergroups/id/{id}",
        "computer_group",
    ),
    "mobile_groups": (
        "/JSSResource/mobiledevicegroups",
        "mobile_device_groups",
        "/JSSResource/mobiledevicegroups/id/{id}",
        "mobile_device_group",
    ),
}

# MDM command catalog.
#
# Keys are stable - saved jobs reference them - and are the Classic API command
# names for continuity. Transport says which API actually carries the command:
#   v2          -> POST /api/v2/mdm/commands   (the documented modern path)
#   blank_push  -> POST /api/v2/mdm/blank-push (its own endpoint; not a commandType)
#   classic     -> POST /JSSResource/{computer,mobiledevice}commands/...
#                  used only where v2 has no equivalent, or needs data we can't
#                  supply (v2 CLEAR_PASSCODE requires an unlockToken).
COMMAND_SPECS = {
    ("computer", "DeviceLock"): {
        "label": "Lock computer (6-digit PIN required)",
        "transport": "v2",
        "v2_type": "DEVICE_LOCK",
        "pin": "required",
        "message": "optional",
    },
    ("computer", "EraseDevice"): {
        "label": "Wipe computer - Erase All Content and Settings (6-digit PIN required)",
        "transport": "v2",
        "v2_type": "ERASE_DEVICE",
        "pin": "required",
        # returnToService.enabled is a required field of the v2 schema.
        "payload": {"returnToService": {"enabled": False}},
    },
    ("computer", "RestartDevice"): {
        "label": "Restart computer",
        "transport": "v2",
        "v2_type": "RESTART_DEVICE",
        "payload": {"notifyUser": True},
    },
    ("computer", "ShutDownDevice"): {
        "label": "Shut down computer",
        "transport": "v2",
        "v2_type": "SHUT_DOWN_DEVICE",
    },
    ("computer", "EnableRemoteDesktop"): {
        "label": "Enable remote desktop",
        "transport": "v2",
        "v2_type": "ENABLE_REMOTE_DESKTOP",
    },
    ("computer", "DisableRemoteDesktop"): {
        "label": "Disable remote desktop",
        "transport": "v2",
        "v2_type": "DISABLE_REMOTE_DESKTOP",
    },
    ("computer", "BlankPush"): {
        "label": "Blank push (wake MDM check-in)",
        "transport": "blank_push",
    },
    ("computer", "UnmanageDevice"): {
        "label": "Remove MDM management (no v2 equivalent - uses Classic API)",
        "transport": "classic",
        "classic_name": "UnmanageDevice",
    },
    ("mobile", "DeviceLock"): {
        "label": "Lock device",
        "transport": "v2",
        "v2_type": "DEVICE_LOCK",
        "message": "optional",
    },
    ("mobile", "EraseDevice"): {
        "label": "Wipe device",
        "transport": "v2",
        "v2_type": "ERASE_DEVICE",
        "payload": {"returnToService": {"enabled": False}},
    },
    ("mobile", "RestartDevice"): {
        "label": "Restart device",
        "transport": "v2",
        "v2_type": "RESTART_DEVICE",
    },
    ("mobile", "ShutDownDevice"): {
        "label": "Shut down device",
        "transport": "v2",
        "v2_type": "SHUT_DOWN_DEVICE",
    },
    ("mobile", "EnableLostMode"): {
        "label": "Enable Lost Mode (supervised; message required)",
        "transport": "v2",
        "v2_type": "ENABLE_LOST_MODE",
        "message": "required",
    },
    ("mobile", "DisableLostMode"): {
        "label": "Disable Lost Mode",
        "transport": "v2",
        "v2_type": "DISABLE_LOST_MODE",
    },
    ("mobile", "ClearPasscode"): {
        "label": "Clear passcode (v2 needs an unlockToken - uses Classic API)",
        "transport": "classic",
        "classic_name": "ClearPasscode",
    },
    ("mobile", "UpdateInventory"): {
        "label": "Update inventory (no v2 equivalent - uses Classic API)",
        "transport": "classic",
        "classic_name": "UpdateInventory",
    },
    ("mobile", "UnmanageDevice"): {
        "label": "Remove MDM management (no v2 equivalent - uses Classic API)",
        "transport": "classic",
        "classic_name": "UnmanageDevice",
    },
}

COMPUTER_COMMANDS = {k[1]: v["label"] for k, v in COMMAND_SPECS.items() if k[0] == "computer"}
MOBILE_COMMANDS = {k[1]: v["label"] for k, v in COMMAND_SPECS.items() if k[0] == "mobile"}

INVENTORY = {
    "computer": ("/api/v1/computers-inventory", "computercommands"),
    "mobile": ("/api/v2/mobile-devices-detail", "mobiledevicecommands"),
}


class JamfError(RuntimeError):
    pass


def _dig(obj, *path, default=None):
    for key in path:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(key)
    return default if obj is None else obj


def _device_record(item: dict) -> dict:
    """Normalise a computer or mobile inventory row.

    Computers report managed under general.remoteManagement.managed and
    capability under general.mdmCapable.capable; mobile devices report
    general.managed. Anything missing stays None rather than guessing, and
    capability_check() treats only an explicit False as a blocker.
    """
    general = item.get("general") or {}
    hardware = item.get("hardware") or {}
    managed = _dig(general, "remoteManagement", "managed")
    if managed is None:
        managed = general.get("managed")
    return {
        "id": item.get("id") or general.get("id"),
        "name": general.get("name") or hardware.get("serialNumber") or "?",
        "serial": hardware.get("serialNumber") or general.get("serialNumber"),
        "management_id": general.get("managementId") or item.get("managementId"),
        "managed": managed,
        "capable": _dig(general, "mdmCapable", "capable"),
        "last_contact": general.get("lastContactTime") or general.get("lastContactDate"),
    }


def _describe(device: dict) -> str:
    serial = f"/{device['serial']}" if device.get("serial") else ""
    return f"{device.get('name')} (id {device.get('id')}{serial})"


def _readable(body: str) -> str:
    """Jamf answers failures with either an HTML status page or a JSON error
    envelope. Reduce both to one readable line."""
    text = (body or "").strip()
    if text.startswith("{"):
        try:
            errors = (json.loads(text) or {}).get("errors") or []
            codes = [
                " ".join(filter(None, [e.get("code"), e.get("description"), e.get("field")]))
                for e in errors
                if isinstance(e, dict)
            ]
            if codes:
                return "; ".join(codes)
        except ValueError:
            pass
    if "<html" in text[:200].lower():
        text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", text, flags=re.S | re.I)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
    return text


class JamfClient:
    def __init__(
        self,
        base_url: str,
        auth_type: str = "client",
        client_id: str = "",
        client_secret: str = "",
        username: str = "",
        password: str = "",
        verify_ssl: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth_type = auth_type
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self._token = ""
        self._token_expiry = 0.0
        self._inventory: dict[str, list[dict]] = {}
        # follow_redirects stays off deliberately: httpx drops the Authorization
        # header on a cross-origin redirect, so a followed write would either
        # 401 confusingly or, worse, replay unauthenticated. Surface it instead.
        self._http = httpx.Client(verify=verify_ssl, timeout=HTTP_TIMEOUT, follow_redirects=False)

    # ---------------------------------------------------------------- lifecycle
    def close(self):
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    @classmethod
    def from_instance(cls, instance) -> JamfClient:
        return cls(
            base_url=instance.base_url,
            auth_type=instance.auth_type,
            client_id=instance.client_id,
            client_secret=instance.client_secret,
            username=instance.username,
            password=instance.password,
            verify_ssl=instance.verify_ssl,
        )

    # -------------------------------------------------------------------- auth
    def token(self) -> str:
        if self._token and time.time() < self._token_expiry - 60:
            return self._token

        if self.auth_type == "client":
            if not (self.client_id and self.client_secret):
                raise JamfError("API client ID/secret missing for this instance.")
            resp = self._http.post(
                f"{self.base_url}/api/oauth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            self._raise(resp, "OAuth token request")
            body = resp.json()
            self._token = body["access_token"]
            self._token_expiry = time.time() + float(body.get("expires_in", 1200))
        else:
            if not (self.username and self.password):
                raise JamfError("Username/password missing for this instance.")
            resp = self._http.post(
                f"{self.base_url}/api/v1/auth/token",
                auth=(self.username, self.password),
            )
            self._raise(resp, "Basic auth token request")
            self._token = resp.json()["token"]
            self._token_expiry = time.time() + 1500

        return self._token

    # ----------------------------------------------------------------- request
    def _raise(self, resp: httpx.Response, what: str):
        if resp.is_success:
            return

        if resp.is_redirect:
            raise JamfError(
                f"{what} failed: HTTP {resp.status_code} redirect to "
                f"{resp.headers.get('location', '?')}. Check the instance Base URL - "
                "it should be the canonical https host with no trailing path."
            )

        detail = _readable(resp.text)
        hint = ""
        if resp.status_code in (401, 403):
            if "/api/v2/mdm/" in what:
                hint = (
                    " - every /api/v2/mdm/ endpoint requires the API Role privilege"
                    " 'View MDM command information in Jamf Pro API'. Note the near-identical"
                    " 'Send MDM command information in Jamf Pro API' does NOT satisfy it. You also"
                    " need Read Computers / Read Mobile Devices and the per-command Send privilege"
                    " (BlankPush maps to Send MDM Check In Command)."
                )
            elif "computercommands" in what or "mobiledevicecommands" in what:
                hint = (
                    " - Jamf rejected this command. MDM commands need BOTH the per-command Send"
                    " privilege (e.g. Send Computer Remote Lock Command; BlankPush maps to Send MDM"
                    " Check In Command) AND read access to the target object type - add Read Computers"
                    " or Read Mobile Devices to the API Role, which is also what group expansion needs."
                )
            else:
                hint = (
                    " - Jamf rejected the credentials for THIS request. Reads working while a write"
                    " fails means the API Role is missing the matching Update/Send privilege"
                    " (e.g. Update macOS Configuration Profiles, Update Policies), or the API client"
                    " is scoped to a Site that excludes this object."
                )
        elif resp.status_code == 409:
            hint = " - Jamf rejected the payload as conflicting or invalid (409 is Classic API's validation error)."
        raise JamfError(f"{what} failed: HTTP {resp.status_code} {detail[:400]}{hint}")

    def request(self, method: str, path: str, *, xml: str | None = None, json_body=None, accept="application/json"):
        headers = {"Authorization": f"Bearer {self.token()}", "Accept": accept}
        content = None
        if xml is not None:
            headers["Content-Type"] = "application/xml"
            content = xml.encode()
        resp = self._http.request(
            method,
            f"{self.base_url}{path}",
            headers=headers,
            content=content,
            json=json_body,
        )
        self._raise(resp, f"{method} {path}")
        if not resp.content:
            return {}
        # The Classic API labels JSON bodies "text/plain;charset=utf-8", so the
        # content-type header is not trustworthy - try to parse regardless.
        try:
            return resp.json()
        except ValueError:
            return resp.text

    # -------------------------------------------------------------- discovery
    def version(self) -> str:
        data = self.request("GET", "/api/v1/jamf-pro-version")
        if not isinstance(data, dict) or "version" not in data:
            raise JamfError(f"Unexpected /jamf-pro-version response: {str(data)[:200]}")
        return data["version"]

    def test(self) -> dict:
        # /jamf-pro-version needs no privileges, so it only proves the
        # credentials exchanged. The reads below prove the role can see things.
        version = self.version()
        counts = {}
        for kind in ("policies", "computer_groups"):
            counts[kind] = len(self.list_objects(kind))
        note = ""
        if not any(counts.values()):
            note = (
                " - credentials are valid but the API Role cannot read any of them;"
                " check Read Policies / Read Smart+Static Computer Groups, and whether"
                " the API client is scoped to a Site"
            )
        return {"version": version, "counts": counts, "note": note}

    def list_objects(self, kind: str) -> list[dict]:
        if kind not in OBJECTS:
            raise JamfError(f"Unknown object kind: {kind}")
        path, key, _, _ = OBJECTS[kind]
        data = self.request("GET", path)
        if not isinstance(data, dict) or key not in data:
            raise JamfError(f"Unexpected response listing {kind} from {path}: {str(data)[:300]}")
        items = data[key] or []
        out = [{"id": i["id"], "name": i["name"], "smart": i.get("is_smart")} for i in items]
        return sorted(out, key=lambda i: i["name"].lower())

    def get_object(self, kind: str, obj_id: int) -> dict:
        _, _, item_path, item_key = OBJECTS[kind]
        path = item_path.format(id=obj_id)
        data = self.request("GET", path)
        if not isinstance(data, dict) or item_key not in data:
            raise JamfError(f"Unexpected response reading {kind} id {obj_id}: {str(data)[:300]}")
        return data[item_key] or {}

    # ---------------------------------------------------------------- policies
    def set_policy_enabled(self, policy_id: int, enabled: bool) -> str:
        xml = (
            "<policy><general><enabled>"
            f"{'true' if enabled else 'false'}"
            "</enabled></general></policy>"
        )
        self.request("PUT", f"/JSSResource/policies/id/{policy_id}", xml=xml)
        policy = self.get_object("policies", policy_id)
        name = policy.get("general", {}).get("name", policy_id)
        state = policy.get("general", {}).get("enabled")
        return f"Policy '{name}' (id {policy_id}) enabled={state}"

    def set_policy_scope_groups(self, policy_id: int, group_ids: list[int]) -> str:
        groups = "".join(f"<computer_group><id>{int(g)}</id></computer_group>" for g in group_ids)
        xml = (
            "<policy><scope><computer_groups>"
            f"{groups}"
            "</computer_groups></scope></policy>"
        )
        self.request("PUT", f"/JSSResource/policies/id/{policy_id}", xml=xml)
        return f"Policy id {policy_id} scoped to computer groups {group_ids or '[]'}"

    def policy_scope_group_ids(self, policy_id: int) -> list[int]:
        policy = self.get_object("policies", policy_id)
        groups = policy.get("scope", {}).get("computer_groups") or []
        return [int(g["id"]) for g in groups]

    # ---------------------------------------------------------------- profiles
    _PROFILE_XML = {
        "osx_profiles": ("os_x_configuration_profile", "computer_groups", "computer_group"),
        "mobile_profiles": ("mobile_device_configuration_profile", "mobile_device_groups", "mobile_device_group"),
    }
    _PROFILE_SCOPE_KEY = {"osx_profiles": "computer_groups", "mobile_profiles": "mobile_device_groups"}

    def profile_scope_group_ids(self, kind: str, profile_id: int) -> list[int]:
        profile = self.get_object(kind, profile_id)
        groups = profile.get("scope", {}).get(self._PROFILE_SCOPE_KEY[kind]) or []
        return [int(g["id"]) for g in groups]

    def set_profile_scope_groups(self, kind: str, profile_id: int, group_ids: list[int]) -> str:
        root, list_tag, item_tag = self._PROFILE_XML[kind]
        _, _, item_path, _ = OBJECTS[kind]
        inner = "".join(f"<{item_tag}><id>{int(g)}</id></{item_tag}>" for g in group_ids)
        xml = f"<{root}><scope><{list_tag}>{inner}</{list_tag}></scope></{root}>"
        self.request("PUT", item_path.format(id=profile_id), xml=xml)
        return f"Profile id {profile_id} scoped to groups {group_ids or '[]'}"

    # ------------------------------------------------------------ group members
    def group_member_ids(self, kind: str, group_id: int) -> list[int]:
        group = self.get_object(kind, group_id)
        key = "computers" if kind == "computer_groups" else "mobile_devices"
        return [int(d["id"]) for d in (group.get(key) or [])]

    # ------------------------------------------------------------- inventory
    def inventory(self, platform: str, refresh: bool = False) -> list[dict]:
        """One paged sweep giving id, name, serial, managementId and management
        state for every device. Cached per client instance, so a job run costs
        a handful of calls no matter how many devices it targets.
        """
        if platform in self._inventory and not refresh:
            return self._inventory[platform]

        path, _ = INVENTORY[platform]
        devices: list[dict] = []
        page = 0
        while page < 200:  # hard stop: 200 pages x 200 = 40k devices
            data = self.request("GET", f"{path}?section=GENERAL&section=HARDWARE&page={page}&page-size=200")
            if not isinstance(data, dict):
                raise JamfError(f"Unexpected inventory response from {path}: {str(data)[:300]}")
            results = data.get("results") or []
            for item in results:
                devices.append(_device_record(item))
            if len(devices) >= int(data.get("totalCount") or 0) or not results:
                break
            page += 1

        self._inventory[platform] = devices
        return devices

    def resolve_targets(self, platform: str, tokens: list[str]) -> tuple[list[dict], list[str]]:
        """Map Jamf IDs and/or serial numbers to device records.

        Returns (devices, problems). A purely numeric token is treated as a
        Jamf ID, anything else as a serial number (case-insensitive).
        """
        devices = self.inventory(platform)
        by_id = {str(d["id"]): d for d in devices}
        by_serial = {str(d["serial"]).upper(): d for d in devices if d.get("serial")}

        found, problems = [], []
        for raw in tokens:
            token = str(raw).strip()
            if not token:
                continue
            match = by_id.get(token) if token.isdigit() else by_serial.get(token.upper())
            if match is None and not token.isdigit():
                match = by_id.get(token)
            if match is None:
                kind = "id" if token.isdigit() else "serial"
                problems.append(f"{token} (no {platform} with that {kind} in inventory)")
            elif match not in found:
                found.append(match)
        return found, problems

    @staticmethod
    def capability_check(platform: str, device: dict) -> str:
        """Empty string means the device can take a command."""
        if device.get("managed") is False:
            return "not managed"
        if platform == "computer" and device.get("capable") is False:
            return "not MDM-capable"
        if not device.get("management_id"):
            return "no managementId in inventory"
        return ""

    # ----------------------------------------------------------- MDM commands
    def send_command(
        self,
        platform: str,
        command: str,
        devices: list[dict],
        pin: str = "",
        message: str = "",
    ) -> str:
        spec = COMMAND_SPECS.get((platform, command))
        if spec is None:
            raise JamfError(f"Unsupported {platform} command: {command}")
        if not devices:
            raise JamfError(f"No {platform} targets could take {command} - nothing sent.")

        if spec.get("pin") == "required" and not pin:
            raise JamfError(f"{command} on {platform}s requires a 6-digit PIN.")
        if spec.get("message") == "required" and not message:
            raise JamfError(f"{command} requires a message.")

        transport = spec["transport"]
        described = ", ".join(_describe(d) for d in devices)

        if transport == "blank_push":
            body = {"clientManagementIds": [d["management_id"] for d in devices]}
            self.request("POST", "/api/v2/mdm/blank-push", json_body=body)
            return f"Blank push sent via /api/v2/mdm/blank-push to {len(devices)}: {described}"

        if transport == "v2":
            command_data = {"commandType": spec["v2_type"], **(spec.get("payload") or {})}
            if pin and spec.get("pin"):
                command_data["pin"] = pin
            if message and spec.get("message"):
                key = "lostModeMessage" if spec["v2_type"] == "ENABLE_LOST_MODE" else "message"
                command_data[key] = message
            body = {
                "clientData": [{"managementId": d["management_id"]} for d in devices],
                "commandData": command_data,
            }
            self.request("POST", "/api/v2/mdm/commands", json_body=body)
            return f"{spec['v2_type']} sent via /api/v2/mdm/commands to {len(devices)}: {described}"

        # Classic fallback: only where v2 has no equivalent.
        resource = INVENTORY[platform][1]
        name = spec["classic_name"]
        ids = ",".join(str(d["id"]) for d in devices)
        if pin and spec.get("pin"):
            path = f"/JSSResource/{resource}/command/{name}/passcode/{escape(pin)}/id/{ids}"
        else:
            path = f"/JSSResource/{resource}/command/{name}/id/{ids}"
        self.request("POST", path)
        return f"{name} sent via Classic API to {len(devices)}: {described}"

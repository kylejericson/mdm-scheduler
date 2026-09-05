"""Iru (formerly Kandji) Endpoint Management API client.

Every endpoint here comes from the official API reference at
https://api-docs.iru.com (published Postman collection):

    GET   /api/v1/blueprints
    GET   /api/v1/devices                      (filters: serial_number, blueprint_id, ...)
    PATCH /api/v1/devices/{device_id}          ({"blueprint_id": "..."})
    POST  /api/v1/devices/{device_id}/action/{action}

Base URL is https://<subdomain>.api.kandji.io (US) or
https://<subdomain>.api.eu.kandji.io (EU). Tenants migrated to Iru may also use
https://<subdomain>.api.iru.com; both hostnames are supported by Iru, so
whatever the tenant's Settings > Access page shows is what goes in the instance.
Auth is a tenant-level bearer token.
"""

from __future__ import annotations

import json

import httpx

from .config import HTTP_TIMEOUT

PAGE_SIZE = 300  # hard upper limit documented for /devices

# Iru device actions. Keys are stable (saved jobs reference them).
#   path    - the {action} segment of /devices/{id}/action/{action}
#   payload - static body fields
#   needs   - typed inputs the job form collects
#   returns_pin - Iru generates and returns an unlock PIN (macOS lock)
IRU_COMMAND_SPECS = {
    "Lock": {
        "label": "Lock device (Iru returns the unlock PIN)",
        "path": "lock",
        "message": "optional",
        "phone": "optional",
        "returns_pin": True,
    },
    "Erase": {
        "label": "Erase device - Erase All Content and Settings (6-digit PIN required for Mac)",
        "path": "erase",
        "pin": "required",
        "payload": {
            "PreserveDataPlan": True,
            "DisallowProximitySetup": False,
            "ReturnToService": {"Enabled": False},
        },
    },
    "Restart": {
        "label": "Restart device",
        "path": "restart",
        "payload": {"RebuildKernelCache": False, "NotifyUser": True},
    },
    "Shutdown": {"label": "Shut down device", "path": "shutdown"},
    "BlankPush": {"label": "Blank push (wake MDM check-in)", "path": "blankpush"},
    "UpdateInventory": {"label": "Update inventory", "path": "updateinventory"},
    "DailyCheckIn": {"label": "Perform daily check-in", "path": "dailycheckin"},
    "ReinstallAgent": {"label": "Reinstall the Iru agent", "path": "reinstallagent"},
    "RenewMDMProfile": {"label": "Renew MDM profile", "path": "renewmdmprofile"},
    "ConfigureDevice": {"label": "Configure device (mark as configured)", "path": "deviceconfigured"},
    "RemoteDesktopOn": {
        "label": "Enable remote desktop",
        "path": "remotedesktop",
        "payload": {"EnableRemoteDesktop": True},
    },
    "RemoteDesktopOff": {
        "label": "Disable remote desktop",
        "path": "remotedesktop",
        "payload": {"EnableRemoteDesktop": False},
    },
    "ClearPasscode": {"label": "Clear passcode", "path": "clearpasscode"},
    "UnlockAccount": {
        "label": "Unlock a local account (username required)",
        "path": "unlockaccount",
        "username": "required",
    },
    "DeleteUser": {
        "label": "Delete a local user (username required)",
        "path": "deleteuser",
        "username": "required",
        "payload": {"DeleteAllUsers": False, "ForceDeletion": False},
    },
    "SetName": {
        "label": "Set device name (name required)",
        "path": "setname",
        "device_name": "required",
    },
    "EnableLostMode": {
        "label": "Enable Lost Mode (message required; iOS/iPadOS)",
        "path": "enablelostmode",
        "message": "required",
        "phone": "optional",
    },
    "DisableLostMode": {"label": "Disable Lost Mode", "path": "disablelostmode"},
    "PlayLostModeSound": {"label": "Play Lost Mode sound", "path": "playlostmodesound"},
    "UpdateLocation": {"label": "Update Lost Mode location", "path": "updatelocation"},
    "PersonalHotspotOn": {
        "label": "Enable personal hotspot",
        "path": "togglepersonalhotspot",
        "payload": {"Enabled": True},
    },
    "PersonalHotspotOff": {
        "label": "Disable personal hotspot",
        "path": "togglepersonalhotspot",
        "payload": {"Enabled": False},
    },
    "DataRoamingOn": {
        "label": "Enable data roaming",
        "path": "toggledataroaming",
        "payload": {"Enabled": True},
    },
    "DataRoamingOff": {
        "label": "Disable data roaming",
        "path": "toggledataroaming",
        "payload": {"Enabled": False},
    },
}

IRU_COMMANDS = {key: spec["label"] for key, spec in IRU_COMMAND_SPECS.items()}


class IruError(RuntimeError):
    pass


def _readable(body: str) -> str:
    text = (body or "").strip()
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            return text
        for key in ("detail", "message", "error"):
            if data.get(key):
                return str(data[key])
        return json.dumps(data)[:400]
    return text


def _device_record(item: dict) -> dict:
    return {
        "id": item.get("device_id"),
        "name": item.get("device_name") or item.get("serial_number") or "?",
        "serial": item.get("serial_number"),
        "platform": item.get("platform"),
        "blueprint_id": item.get("blueprint_id"),
        "blueprint_name": item.get("blueprint_name"),
        "mdm_enabled": item.get("mdm_enabled"),
        "is_removed": item.get("is_removed"),
        "last_check_in": item.get("last_check_in"),
    }


def _describe(device: dict) -> str:
    serial = f"/{device['serial']}" if device.get("serial") else ""
    return f"{device.get('name')} ({serial.lstrip('/') or device.get('id')})"


class IruClient:
    def __init__(self, base_url: str, api_token: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self._devices: list[dict] | None = None
        self._blueprints: list[dict] | None = None
        self._http = httpx.Client(verify=verify_ssl, timeout=HTTP_TIMEOUT, follow_redirects=False)

    def close(self):
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    @classmethod
    def from_instance(cls, instance) -> IruClient:
        return cls(
            base_url=instance.base_url,
            api_token=instance.api_token,
            verify_ssl=instance.verify_ssl,
        )

    # ----------------------------------------------------------------- request
    def request(self, method: str, path: str, *, json_body=None, params=None):
        if not self.api_token:
            raise IruError("API token missing for this Iru instance.")
        resp = self._http.request(
            method,
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {self.api_token}", "Accept": "application/json"},
            json=json_body,
            params=params,
        )
        if resp.is_redirect:
            raise IruError(
                f"{method} {path} redirected to {resp.headers.get('location', '?')} - "
                "check the instance Base URL (Settings > Access in Iru shows the exact API URL)."
            )
        if not resp.is_success:
            detail = _readable(resp.text)
            hint = ""
            if resp.status_code == 401:
                hint = " - the API token is wrong, revoked or expired."
            elif resp.status_code == 403:
                hint = (
                    " - the token lacks the permission for this endpoint. Iru scopes tokens per"
                    " endpoint under Settings > Access > API tokens."
                )
            elif resp.status_code == 400 and "already running" in detail.lower():
                hint = " - Iru already has this command pending for the device."
            elif resp.status_code == 400:
                hint = " - Iru rejected the command for this device (often 'not allowed for current device')."
            raise IruError(f"{method} {path} failed: HTTP {resp.status_code} {detail[:300]}{hint}")

        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            return resp.text

    # --------------------------------------------------------------- discovery
    def blueprints(self, refresh: bool = False) -> list[dict]:
        if self._blueprints is not None and not refresh:
            return self._blueprints
        data = self.request("GET", "/api/v1/blueprints", params={"limit": PAGE_SIZE})
        if not isinstance(data, dict) or "results" not in data:
            raise IruError(f"Unexpected /blueprints response: {str(data)[:300]}")
        self._blueprints = [
            {"id": b["id"], "name": b.get("name", b["id"]), "type": b.get("type")}
            for b in data["results"]
        ]
        return sorted(self._blueprints, key=lambda b: b["name"].lower())

    def blueprint_name(self, blueprint_id: str) -> str:
        for blueprint in self.blueprints():
            if blueprint["id"] == blueprint_id:
                return blueprint["name"]
        return blueprint_id

    def devices(self, refresh: bool = False) -> list[dict]:
        """One paged sweep of the tenant, cached per client instance."""
        if self._devices is not None and not refresh:
            return self._devices
        out: list[dict] = []
        page = 1
        while page <= 200:
            data = self.request("GET", "/api/v1/devices", params={"limit": PAGE_SIZE, "page": page})
            batch = data if isinstance(data, list) else (data or {}).get("results") or []
            out.extend(_device_record(item) for item in batch)
            if len(batch) < PAGE_SIZE:
                break
            page += 1
        self._devices = out
        return out

    def test(self) -> dict:
        blueprints = self.blueprints(refresh=True)
        devices = self.devices(refresh=True)
        note = ""
        if not blueprints:
            note = " - no blueprints visible; check the token's permissions under Settings > Access"
        return {"blueprints": len(blueprints), "devices": len(devices), "note": note}

    # ----------------------------------------------------------------- targets
    def resolve_targets(self, tokens: list[str]) -> tuple[list[dict], list[str]]:
        """Serial numbers (preferred) or Iru device UUIDs."""
        devices = self.devices()
        by_serial = {str(d["serial"]).upper(): d for d in devices if d.get("serial")}
        by_id = {str(d["id"]): d for d in devices if d.get("id")}

        found, problems = [], []
        for raw in tokens:
            token = str(raw).strip()
            if not token:
                continue
            match = by_serial.get(token.upper()) or by_id.get(token)
            if match is None:
                problems.append(f"{token} (no Iru device with that serial or ID)")
            elif match not in found:
                found.append(match)
        return found, problems

    def devices_in_blueprint(self, blueprint_id: str) -> list[dict]:
        return [d for d in self.devices() if d.get("blueprint_id") == blueprint_id]

    @staticmethod
    def capability_check(device: dict) -> str:
        if device.get("is_removed"):
            return "removed from Iru"
        if device.get("mdm_enabled") is False:
            return "MDM not enabled"
        if not device.get("id"):
            return "no device ID in inventory"
        return ""

    # ---------------------------------------------------------------- commands
    def send_command(
        self,
        command: str,
        devices: list[dict],
        pin: str = "",
        message: str = "",
        phone: str = "",
        username: str = "",
        device_name: str = "",
    ) -> str:
        spec = IRU_COMMAND_SPECS.get(command)
        if spec is None:
            raise IruError(f"Unsupported Iru command: {command}")
        if not devices:
            raise IruError(f"No Iru targets could take {command} - nothing sent.")

        for field, value in (
            ("pin", pin),
            ("message", message),
            ("username", username),
            ("device_name", device_name),
        ):
            if spec.get(field) == "required" and not value:
                raise IruError(f"{command} requires {field.replace('_', ' ')}.")

        body = dict(spec.get("payload") or {})
        if pin and spec.get("pin"):
            body["PIN"] = pin
        if message and spec.get("message"):
            body["Message"] = message
        if phone and spec.get("phone"):
            body["PhoneNumber"] = phone
        if username and spec.get("username"):
            body["UserName"] = username
        if device_name and spec.get("device_name"):
            body["DeviceName"] = device_name

        # Iru actions are per device; there is no batch command endpoint.
        sent, failures, pins = [], [], []
        for device in devices:
            try:
                result = self.request(
                    "POST",
                    f"/api/v1/devices/{device['id']}/action/{spec['path']}",
                    json_body=body or None,
                )
            except IruError as exc:
                failures.append(f"{_describe(device)}: {exc}")
                continue
            sent.append(_describe(device))
            if spec.get("returns_pin") and isinstance(result, dict) and result.get("PIN"):
                pins.append(f"{_describe(device)} unlock PIN {result['PIN']}")

        if not sent:
            raise IruError(f"{command} failed for every target. {' | '.join(failures)}")

        summary = f"{command} sent to {len(sent)}: {', '.join(sent)}"
        if pins:
            summary += f" | {'; '.join(pins)}"
        if failures:
            summary += f" | {len(failures)} failed: {' ; '.join(failures)}"
        return summary

    # -------------------------------------------------------------- blueprints
    def move_to_blueprint(self, devices: list[dict], blueprint_id: str) -> str:
        """Iru devices always belong to exactly one blueprint; there is no
        unassign. Moving is PATCH /devices/{id} with the destination id."""
        if not devices:
            raise IruError("No Iru targets to move - nothing changed.")
        target_name = self.blueprint_name(blueprint_id)

        moved, skipped, failures = [], [], []
        for device in devices:
            if device.get("blueprint_id") == blueprint_id:
                skipped.append(f"{_describe(device)} already in {target_name}")
                continue
            try:
                self.request(
                    "PATCH",
                    f"/api/v1/devices/{device['id']}",
                    json_body={"blueprint_id": blueprint_id},
                )
            except IruError as exc:
                failures.append(f"{_describe(device)}: {exc}")
                continue
            moved.append(f"{_describe(device)} from {device.get('blueprint_name') or '?'}")

        if not moved and not skipped:
            raise IruError(f"Blueprint move failed for every target. {' | '.join(failures)}")

        summary = f"Moved {len(moved)} device(s) to blueprint '{target_name}'"
        if moved:
            summary += f": {', '.join(moved)}"
        if skipped:
            summary += f" | {len(skipped)} already there: {'; '.join(skipped)}"
        if failures:
            summary += f" | {len(failures)} failed: {' ; '.join(failures)}"
        return summary

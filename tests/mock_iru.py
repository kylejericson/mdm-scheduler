"""A fake Iru (Kandji) tenant, shaped after the official API reference.

Field names and response shapes come from https://api-docs.iru.com:
devices carry device_id / device_name / serial_number / blueprint_id /
blueprint_name / mdm_enabled / is_removed, blueprints are returned as
{count, next, previous, results[]}, and a macOS lock returns {"PIN": "..."}.
"""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = "iru-test-token"

BLUEPRINTS = [
    {"id": "bp-standard", "name": "Standard Macs", "type": "classic"},
    {"id": "bp-quarantine", "name": "Quarantine", "type": "classic"},
    {"id": "bp-execs", "name": "Executives", "type": "map"},
]


def _device(did, name, serial, blueprint, mdm=True, removed=False):
    return {
        "device_id": did,
        "device_name": name,
        "serial_number": serial,
        "platform": "Mac",
        "os_version": "15.3",
        "last_check_in": "2026-09-04T12:00:00.000000Z",
        "asset_tag": "",
        "blueprint_id": blueprint,
        "blueprint_name": next(b["name"] for b in BLUEPRINTS if b["id"] == blueprint),
        "mdm_enabled": mdm,
        "agent_installed": True,
        "is_missing": False,
        "is_removed": removed,
        "tags": [],
    }


STATE = {}


def reset():
    STATE.clear()
    STATE.update(
        {
            "devices": [
                _device("dev-1", "kyle-mbp", "C02X1234JGH5", "bp-standard"),
                _device("dev-2", "loaner-01", "FVFXQ12ABCDE", "bp-standard"),
                _device("dev-3", "old-mac", "C17OLDINTEL1", "bp-quarantine", mdm=False),
            ],
            "actions": [],
            "patches": [],
            "deny": False,
        }
    )


reset()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> bool:
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self._send(401, {"detail": "Invalid token."})
            return False
        if STATE["deny"]:
            self._send(403, {"detail": "You do not have permission to perform this action."})
            return False
        return True

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length).decode() or "{}") if length else {}

    def _find(self, device_id):
        return next((d for d in STATE["devices"] if d["device_id"] == device_id), None)

    def do_GET(self):
        if not self._authorized():
            return
        if self.path.startswith("/api/v1/blueprints"):
            return self._send(200, {"count": len(BLUEPRINTS), "next": None, "previous": None,
                                    "results": BLUEPRINTS})
        if self.path.startswith("/api/v1/devices"):
            return self._send(200, STATE["devices"])
        return self._send(404, {"detail": "Not found."})

    def do_POST(self):
        if not self._authorized():
            return
        m = re.match(r"/api/v1/devices/([\w-]+)/action/(\w+)$", self.path)
        if not m:
            return self._send(404, {"detail": "Not found."})
        device_id, action = m.group(1), m.group(2)
        if self._find(device_id) is None:
            return self._send(404, {"detail": "Device not found."})
        STATE["actions"].append({"device_id": device_id, "action": action, "body": self._body()})
        if action == "lock":
            return self._send(200, {"PIN": "496406"})  # Iru generates the unlock PIN
        return self._send(200, {})

    def do_PATCH(self):
        if not self._authorized():
            return
        m = re.match(r"/api/v1/devices/([\w-]+)$", self.path)
        if not m:
            return self._send(404, {"detail": "Not found."})
        device = self._find(m.group(1))
        if device is None:
            return self._send(404, {"detail": "Device not found."})
        body = self._body()
        STATE["patches"].append({"device_id": m.group(1), "body": body})
        if "blueprint_id" in body:
            match = next((b for b in BLUEPRINTS if b["id"] == body["blueprint_id"]), None)
            if match is None:
                return self._send(400, {"detail": "Invalid blueprint_id."})
            device["blueprint_id"] = match["id"]
            device["blueprint_name"] = match["name"]
        return self._send(200, device)


def start() -> tuple[str, HTTPServer]:
    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    return f"http://{host}:{port}", server

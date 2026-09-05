"""A fake Jamf Pro, faithful to the quirks that matter.

Notably: the Classic API serves JSON bodies labelled ``text/plain;charset=utf-8``.
Trusting the content-type header is what broke discovery in 1.0.0.
"""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

DEFAULT_STATE = {
    "policy_enabled": False,
    "policy_scope_groups": [{"id": 7, "name": "Pilot"}],
    "profile_groups": [{"id": 5, "name": "Existing Group"}],
    "commands": [],
    "v2_commands": [],
    "blank_pushes": [],
    "token_requests": 0,
    # A role that can read but not write: Jamf answers Classic API writes with
    # 401 and a full HTML status page, not a clean 403.
    "deny_writes": False,
    # A Base URL whose writes get redirected elsewhere.
    "redirect_writes": False,
}

STATE = dict(DEFAULT_STATE)

UNAUTHORIZED_HTML = (
    '<html> <head> <title>Status page</title> </head> <body style="font-family: sans-serif;">'
    '<p style="font-size: 1.2em;font-weight: bold;margin: 1em 0px;">Unauthorized</p>'
    "<p>The request requires user authentication</p> </body> </html>"
)

INVALID_PRIVILEGE_JSON = {
    "httpStatus": 403,
    "errors": [{"code": "INVALID_PRIVILEGE", "description": "Forbidden", "id": "0", "field": None}],
}


def reset():
    STATE.clear()
    STATE.update({k: (list(v) if isinstance(v, list) else v) for k, v in DEFAULT_STATE.items()})
    STATE["policy_scope_groups"] = [{"id": 7, "name": "Pilot"}]
    STATE["profile_groups"] = [{"id": 5, "name": "Existing Group"}]
    STATE["commands"] = []
    STATE["v2_commands"] = []
    STATE["blank_pushes"] = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _send(self, code, body, ctype="application/json"):
        if ctype == "application/json":
            data = json.dumps(body).encode()
            if self.path.startswith("/JSSResource/"):
                ctype = "text/plain;charset=utf-8"  # the Classic API really does this
        else:
            data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length).decode() or "{}")

    # ------------------------------------------------------------------ POST
    def do_POST(self):
        if self.path.startswith("/api/v2/mdm/"):
            # Missing 'View MDM command information in Jamf Pro API' looks like this.
            if STATE.get("deny_writes"):
                return self._send(403, INVALID_PRIVILEGE_JSON)
            if self.path == "/api/v2/mdm/commands":
                STATE["v2_commands"].append(self._json_body())
                return self._send(201, [{"id": "1", "href": "/v1/mdm/commands/1"}])
            if self.path == "/api/v2/mdm/blank-push":
                STATE["blank_pushes"].append(self._json_body())
                return self._send(200, {"failedManagementIds": []})
            return self._send(404, {"error": self.path})

        if self.path == "/api/oauth/token":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            if "client_secret=shhh" not in body:
                return self._send(401, {"error": "invalid_client"})
            STATE["token_requests"] += 1
            return self._send(200, {"access_token": "faketoken", "expires_in": 1200})

        if STATE.get("deny_writes") and "commands/command/" in self.path:
            return self._send(401, UNAUTHORIZED_HTML, "text/html")

        m = re.match(r"/JSSResource/computercommands/command/(\w+)(?:/passcode/(\d+))?/id/([\d,]+)$", self.path)
        if m:
            STATE["commands"].append({"command": m.group(1), "pin": m.group(2), "ids": m.group(3)})
            return self._send(201, {"computer_command": {"command": {"name": m.group(1)}}})

        m = re.match(r"/JSSResource/mobiledevicecommands/command/(\w+)/id/([\d,]+)$", self.path)
        if m:
            STATE["commands"].append({"command": m.group(1), "pin": None, "ids": m.group(2)})
            return self._send(201, {"mobile_device_command": {"command": m.group(1)}})

        return self._send(404, {"error": self.path})

    # ------------------------------------------------------------------- PUT
    def do_PUT(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()

        if STATE.get("redirect_writes"):
            self.send_response(301)
            self.send_header("Location", "https://elsewhere.example.com" + self.path)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if STATE.get("deny_writes"):
            return self._send(401, UNAUTHORIZED_HTML, "text/html")

        if re.match(r"/JSSResource/policies/id/\d+$", self.path):
            if "<enabled>true</enabled>" in body:
                STATE["policy_enabled"] = True
            elif "<enabled>false</enabled>" in body:
                STATE["policy_enabled"] = False
            if "<computer_groups>" in body:
                ids = re.findall(r"<computer_group><id>(\d+)</id></computer_group>", body)
                STATE["policy_scope_groups"] = [{"id": int(i), "name": f"Group {i}"} for i in ids]
            return self._send(201, "<policy><id>1</id></policy>", "text/xml")

        if re.match(r"/JSSResource/osxconfigurationprofiles/id/\d+$", self.path):
            ids = re.findall(r"<computer_group><id>(\d+)</id></computer_group>", body)
            STATE["profile_groups"] = [{"id": int(i), "name": f"Group {i}"} for i in ids]
            return self._send(201, "<os_x_configuration_profile><id>3</id></os_x_configuration_profile>", "text/xml")

        return self._send(404, {"error": self.path})

    # ------------------------------------------------------------------- GET
    def do_GET(self):
        p = self.path

        if p == "/api/v1/jamf-pro-version":
            return self._send(200, {"version": "11.31.1-t1787060595569"})

        # Inventory: computers report managed under general.remoteManagement,
        # mobile devices under general.managed. Paged, with totalCount.
        if p.startswith("/api/v1/computers-inventory"):
            return self._send(200, {"totalCount": 3, "results": [
                {"id": "101", "general": {
                    "name": "mac-01", "managementId": "mgmt-101",
                    "remoteManagement": {"managed": True}, "mdmCapable": {"capable": True},
                    "lastContactTime": "2026-09-04T12:00:00Z"},
                    "hardware": {"serialNumber": "C02X1234JGH5"}},
                {"id": "102", "general": {
                    "name": "mac-02", "managementId": "mgmt-102",
                    "remoteManagement": {"managed": True}, "mdmCapable": {"capable": True}},
                    "hardware": {"serialNumber": "FVFXQ12ABCDE"}},
                # id 30: enrolled but not MDM-capable - the real-world 400 case
                {"id": "30", "general": {
                    "name": "old-intel-mac", "managementId": "mgmt-030",
                    "remoteManagement": {"managed": True}, "mdmCapable": {"capable": False}},
                    "hardware": {"serialNumber": "C17OLDINTEL1"}},
            ]})

        if p.startswith("/api/v2/mobile-devices-detail"):
            return self._send(200, {"totalCount": 1, "results": [
                {"id": "201", "general": {
                    "name": "ipad-01", "managementId": "mgmt-201", "managed": True},
                    "hardware": {"serialNumber": "DMPX1234IPAD"}},
            ]})

        if p == "/JSSResource/policies":
            return self._send(200, {"policies": [
                {"id": 1, "name": "Zebra Install"},
                {"id": 2, "name": "Alpha Patch"},
            ]})
        if re.match(r"/JSSResource/policies/id/\d+$", p):
            return self._send(200, {"policy": {
                "general": {"id": 1, "name": "Zebra Install", "enabled": STATE["policy_enabled"]},
                "scope": {"computer_groups": STATE["policy_scope_groups"]},
            }})

        if p == "/JSSResource/osxconfigurationprofiles":
            return self._send(200, {"os_x_configuration_profiles": [{"id": 3, "name": "Firewall Baseline"}]})
        if re.match(r"/JSSResource/osxconfigurationprofiles/id/\d+$", p):
            return self._send(200, {"os_x_configuration_profile": {
                "general": {"id": 3, "name": "Firewall Baseline"},
                "scope": {"computer_groups": STATE["profile_groups"]},
            }})

        if p == "/JSSResource/mobiledeviceconfigurationprofiles":
            return self._send(200, {"configuration_profiles": [{"id": 4, "name": "Wi-Fi"}]})

        if p == "/JSSResource/computergroups":
            return self._send(200, {"computer_groups": [
                {"id": 5, "name": "All Managed", "is_smart": True},
                {"id": 7, "name": "Pilot", "is_smart": False},
            ]})
        if re.match(r"/JSSResource/computergroups/id/8$", p):
            # A group with a member that cannot take MDM commands.
            return self._send(200, {"computer_group": {
                "id": 8, "name": "Mixed",
                "computers": [{"id": 101, "name": "mac-01"}, {"id": 30, "name": "old-intel-mac"}],
            }})
        if re.match(r"/JSSResource/computergroups/id/\d+$", p):
            return self._send(200, {"computer_group": {
                "id": 7, "name": "Pilot",
                "computers": [{"id": 101, "name": "mac-01"}, {"id": 102, "name": "mac-02"}],
            }})

        if p == "/JSSResource/mobiledevicegroups":
            return self._send(200, {"mobile_device_groups": [{"id": 9, "name": "iPads", "is_smart": False}]})
        if re.match(r"/JSSResource/mobiledevicegroups/id/\d+$", p):
            return self._send(200, {"mobile_device_group": {
                "id": 9, "name": "iPads", "mobile_devices": [{"id": 201, "name": "ipad-01"}],
            }})

        if p == "/not-jamf":
            return self._send(200, "<html><body>a login page, not an API</body></html>", "text/html")

        return self._send(404, {"error": p})


def start() -> tuple[str, HTTPServer]:
    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    return f"http://{host}:{port}", server

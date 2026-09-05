"""Vendor client selection.

One place decides which MDM client an instance gets, so routes and the
scheduler never branch on vendor themselves.
"""

from __future__ import annotations

from .iru_client import IruClient, IruError
from .jamf_client import JamfClient, JamfError

VENDORS = {
    "jamf": {
        "label": "Jamf Pro",
        "client": JamfClient,
        "error": JamfError,
        "base_url_hint": "https://yourorg.jamfcloud.com",
    },
    "iru": {
        "label": "Iru",
        "client": IruClient,
        "error": IruError,
        "base_url_hint": "https://yourtenant.api.kandji.io",
    },
}


def client_for(instance):
    vendor = VENDORS.get(instance.vendor or "jamf")
    if vendor is None:
        raise ValueError(f"Unknown vendor: {instance.vendor}")
    return vendor["client"].from_instance(instance)


def test_instance(instance) -> dict:
    """Vendor-appropriate connectivity check for the Test button."""
    client = client_for(instance)
    try:
        result = client.test()
        if instance.vendor == "iru":
            detail = (
                f"Iru reachable - {result['blueprints']} blueprint(s), "
                f"{result['devices']} device(s){result['note']}"
            )
        else:
            detail = (
                f"Jamf Pro {result['version']} - {result['counts']['policies']} policies, "
                f"{result['counts']['computer_groups']} computer groups{result['note']}"
            )
        return {"ok": True, "detail": detail}
    except Exception as exc:  # noqa: BLE001 - surfaced in the UI
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}
    finally:
        client.close()

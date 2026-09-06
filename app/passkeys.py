"""Passkeys (WebAuthn).

Two flows are supported, and they are genuinely different things:

  * **Passkey sign-in** - one step, no password. The authenticator proves
    possession and verifies the user locally (biometric or device PIN), so this
    is already two factors and does not need a third.
  * **Passkey as second factor** - after a password, for accounts that also
    want a password in the mix.

The awkward part of WebAuthn in a self-hosted tool is that credentials are
bound to a *domain*, not to the app. A passkey registered at
mdm.example.com cannot be used at http://192.168.1.10:8000, and the browser
will not even offer it. That is not a bug to work around - it is the property
that makes passkeys unphishable - so the UI says so plainly and keeps TOTP
available for the LAN address.
"""

from __future__ import annotations

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .config import WEBAUTHN_EXTRA_ORIGINS, WEBAUTHN_RP_ID, WEBAUTHN_RP_NAME

CLONE_WARNING = (
    "That passkey's signature counter went backwards, which can mean it has "
    "been cloned. It has not been accepted - remove it and register a new one."
)


class PasskeyError(Exception):
    """Something in a ceremony didn't verify. The message is shown to the user."""


# --------------------------------------------------------------- environment
def forwarded(request, header: str, fallback: str) -> str:
    """Read an X-Forwarded-* header, but only from the sidecar.

    Behind Caddy the app sees plain HTTP on the compose network, so without
    this every origin check would fail. The headers are attacker-controlled on
    a direct connection to port 8000, hence the private-peer test - the same
    reasoning as auth.client_ip.
    """
    from .auth import _is_private  # local import keeps the dependency one-way

    peer = getattr(request.client, "host", "") or ""
    value = request.headers.get(header, "")
    if value and _is_private(peer):
        return value.split(",")[0].strip()
    return fallback


def rp_id_for(request, brand) -> str:
    """The domain passkeys are bound to.

    Order matters: an explicit environment override wins, then the HTTPS
    hostname configured on the Branding tab, then whatever host the request
    arrived on. Changing this invalidates every registered passkey, which is
    why the configured hostname is preferred over the request - the request can
    vary, the configuration does not.
    """
    if WEBAUTHN_RP_ID:
        return WEBAUTHN_RP_ID
    if brand is not None and brand.tls_enabled and brand.tls_hostname:
        return brand.tls_hostname.lower()
    host = forwarded(request, "x-forwarded-host", request.url.hostname or "")
    return host.split(":")[0].lower()


def origin_for(request) -> str:
    scheme = forwarded(request, "x-forwarded-proto", request.url.scheme)
    host = forwarded(request, "x-forwarded-host", request.url.netloc)
    return f"{scheme}://{host}"


def expected_origins(request, rp_id: str) -> list[str]:
    origins = {origin_for(request), f"https://{rp_id}"}
    origins.update(WEBAUTHN_EXTRA_ORIGINS)
    return sorted(o for o in origins if o)


def availability(request, brand) -> tuple[bool, str]:
    """Whether this request can do WebAuthn at all, and why not if it can't.

    Browsers refuse WebAuthn outside a secure context. localhost counts as
    secure; a plain-HTTP LAN IP does not, and a bare IP address cannot be a
    relying party ID either.
    """
    origin = origin_for(request)
    rp_id = rp_id_for(request, brand)

    if _looks_like_ip(rp_id):
        # A bare IP cannot be a relying party ID, whatever the scheme. Checking
        # this before the secure-context test matters for 127.0.0.1, which is a
        # secure origin but still not a valid RP ID.
        return False, "Passkeys need a hostname, not an IP address."
    if origin.startswith("https://"):
        return True, ""
    if request.url.hostname == "localhost":
        return True, ""
    return False, (
        "Passkeys need HTTPS. Set up a hostname and certificate under "
        "Branding -> HTTPS, then register a passkey from that address. "
        "An authenticator app works over plain HTTP."
    )


def _looks_like_ip(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(part.isdigit() for part in parts)


# ------------------------------------------------------------- registration
def registration_options(user, rp_id: str, existing: list) -> tuple[str, str]:
    """(options_json, challenge_b64url).

    Resident keys are required so the credential is discoverable - that is what
    lets someone click "Sign in with a passkey" without first typing a username.
    """
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=WEBAUTHN_RP_NAME,
        user_id=str(user.id).encode(),
        user_name=user.username,
        user_display_name=user.label,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred.credential_id))
            for cred in existing
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    return options_to_json(options), bytes_to_base64url(options.challenge)


def verify_registration(credential, challenge_b64: str, rp_id: str, origins: list[str]):
    try:
        return verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=rp_id,
            expected_origin=origins,
            require_user_verification=True,
        )
    except (InvalidRegistrationResponse, ValueError) as exc:
        raise PasskeyError(f"Passkey registration failed: {exc}") from exc


# ----------------------------------------------------------- authentication
def authentication_options(rp_id: str, allow: list | None = None) -> tuple[str, str]:
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred.credential_id))
            for cred in (allow or [])
        ]
        or None,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options_to_json(options), bytes_to_base64url(options.challenge)


def verify_authentication(credential, challenge_b64: str, rp_id: str, origins: list[str], stored):
    try:
        result = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=rp_id,
            expected_origin=origins,
            credential_public_key=base64url_to_bytes(stored.public_key),
            credential_current_sign_count=stored.sign_count,
            require_user_verification=True,
        )
    except (InvalidAuthenticationResponse, ValueError) as exc:
        # The library detects a regressed counter itself, but reports it as
        # arithmetic. Say what it actually means.
        if "sign count" in str(exc).lower():
            raise PasskeyError(CLONE_WARNING) from exc
        raise PasskeyError(f"Passkey sign-in failed: {exc}") from exc

    # Belt and braces for the equal-counter case, which the library allows.
    # Authenticators that don't count at all report zero forever, which is
    # normal and not a signal.
    if result.new_sign_count and result.new_sign_count <= stored.sign_count:
        raise PasskeyError(CLONE_WARNING)
    return result


def credential_id_of(credential) -> str:
    """The credential's id as stored, from a raw client response."""
    if isinstance(credential, str):
        import json

        credential = json.loads(credential)
    return credential.get("id", "")

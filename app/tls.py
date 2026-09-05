"""HTTPS via a Caddy sidecar, configured from the Branding tab.

Caddy fronts the app and gets certificates from Let's Encrypt. The app never
handles TLS itself: it renders a Caddyfile and hands it to Caddy's admin API
(POST /load with Content-Type: text/caddyfile), which reloads with no downtime
and no restart of the scheduler. Renewal is Caddy's job and needs no cron.

Two ACME challenges, because they have different prerequisites:

  http  - Let's Encrypt fetches http://<host>/.well-known/acme-challenge/... from
          the public internet. Needs a public A record for <host> and inbound
          port 80 forwarded to this container. Writing the file locally is not
          enough; their servers must reach it.
  dns   - Caddy writes a TXT record through the DNS provider's API. Nothing
          inbound is opened, so the host can stay on a private network.

The admin endpoint must be re-declared in every config we load: POST /load
replaces the whole config, and omitting it would drop Caddy back to
localhost:2019, out of reach of this container.
"""

from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime

import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID

CADDY_ADMIN = "http://caddy:2019"
CADDY_HTTPS = ("caddy", 443)
UPSTREAM = "mdm-scheduler:8000"
STAGING_CA = "https://acme-staging-v02.api.letsencrypt.org/directory"

# Providers whose Caddy DNS module is compiled into the sidecar image
# (Dockerfile.caddy) AND whose credential is a single API token, which is what
# the Branding form collects. Adding one is a --with line there plus an entry
# here; the dropdown and help page are generated from this map.
#
# Deliberately absent: Route 53, Azure, Google Cloud DNS, GoDaddy, OVH and
# Namecheap authenticate with several values, so they need per-provider
# credential fields in the form before they can work.
DNS_PROVIDERS = {
    "ionos": "IONOS",
    "cloudflare": "Cloudflare",
    "digitalocean": "DigitalOcean",
    "hetzner": "Hetzner",
    "linode": "Linode",
    "vultr": "Vultr",
    "desec": "deSEC",
    "duckdns": "DuckDNS",
    "gandi": "Gandi",
}

# Where to create the token, shown next to the field.
DNS_TOKEN_HINTS = {
    "ionos": "IONOS Developer portal -> DNS API, token in the form prefix.secret",
    "cloudflare": "My Profile -> API Tokens -> Edit zone DNS template (Zone:DNS:Edit)",
    "digitalocean": "API -> Tokens/Keys -> Personal access token with write scope",
    "hetzner": "DNS Console -> API tokens",
    "linode": "Profile -> API Tokens -> personal access token with Domains read/write",
    "vultr": "Account -> API -> personal access token (allow this host's IP)",
    "desec": "desec.io -> Token management",
    "duckdns": "duckdns.org dashboard - the account token",
    "gandi": "Gandi account -> Security -> Personal Access Token with DNS rights",
}


class TlsError(RuntimeError):
    pass


def render_caddyfile(brand) -> str:
    """Caddyfile for the current branding settings."""
    if not (brand.tls_enabled and brand.tls_hostname):
        # Plain HTTP passthrough - the state the stack ships in.
        return f"""{{
\tadmin 0.0.0.0:2019
\tauto_https off
}}

:80 {{
\treverse_proxy {UPSTREAM}
}}
"""

    globals_block = ["\tadmin 0.0.0.0:2019"]
    if brand.tls_email:
        globals_block.append(f"\temail {brand.tls_email}")
    if brand.tls_staging:
        globals_block.append(f"\tacme_ca {STAGING_CA}")

    site_lines = [f"\treverse_proxy {UPSTREAM}", "\tencode zstd gzip"]
    if brand.tls_challenge == "dns":
        provider = brand.tls_dns_provider or "ionos"
        token = brand.tls_dns_token
        if not token:
            raise TlsError("DNS challenge selected but no DNS API token is saved.")
        site_lines.append(f"\ttls {{\n\t\tdns {provider} {token}\n\t}}")

    globals_text = "\n".join(globals_block)
    site_text = "\n".join(site_lines)
    return f"{{\n{globals_text}\n}}\n\n{brand.tls_hostname} {{\n{site_text}\n}}\n"


def apply(brand, timeout: float = 30.0) -> str:
    """Push the rendered config to Caddy. Returns a human-readable result."""
    caddyfile = render_caddyfile(brand)
    try:
        resp = httpx.post(
            f"{CADDY_ADMIN}/load",
            content=caddyfile.encode(),
            headers={"Content-Type": "text/caddyfile"},
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise TlsError(
            f"Could not reach the Caddy sidecar at {CADDY_ADMIN} ({exc}). Is the caddy "
            "service running in this stack?"
        ) from exc

    if not resp.is_success:
        raise TlsError(f"Caddy rejected the config: HTTP {resp.status_code} {resp.text[:300]}")

    if not (brand.tls_enabled and brand.tls_hostname):
        return "HTTPS disabled - Caddy is serving plain HTTP on port 80."

    provider = brand.tls_dns_provider or "ionos"
    how = (
        f"DNS-01 via {DNS_PROVIDERS.get(provider, provider)}"
        if brand.tls_challenge == "dns"
        else "HTTP-01"
    )
    staging = " (staging certificate - not trusted by browsers)" if brand.tls_staging else ""
    return (
        f"Config accepted for {brand.tls_hostname} using {how}{staging}. "
        "Issuance happens in the background; check status in a few seconds."
    )


def certificate_status(brand, timeout: float = 8.0) -> dict:
    """Read the certificate Caddy is actually serving.

    Asks Caddy for a handshake with the configured hostname as SNI, which is the
    only honest way to tell whether issuance really happened - a loaded config
    proves nothing about whether Let's Encrypt answered.
    """
    if not (brand.tls_enabled and brand.tls_hostname):
        return {"state": "off", "detail": "HTTPS is not enabled."}

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # we inspect the cert, we don't trust-check it here

    try:
        with socket.create_connection(CADDY_HTTPS, timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=brand.tls_hostname) as tls_sock:
                # binary_form matters: with verify_mode=CERT_NONE, Python never
                # parses the chain, so getpeercert() returns {} even on a
                # perfectly good handshake. The DER is always there.
                der = tls_sock.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        return {
            "state": "error",
            "detail": f"No TLS handshake from the Caddy sidecar yet ({type(exc).__name__}: {exc}).",
        }

    if not der:
        return {
            "state": "error",
            "detail": "Caddy completed a handshake but sent no certificate.",
        }

    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError as exc:
        return {"state": "error", "detail": f"Could not parse the served certificate ({exc})."}

    issuer = _rdn(cert.issuer, NameOID.ORGANIZATION_NAME) or "unknown"
    common = _rdn(cert.issuer, NameOID.COMMON_NAME)
    expires = cert.not_valid_after_utc
    days_left = (expires - datetime.now(UTC)).days

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []

    label = f"{issuer} {common}".strip()
    self_signed = "Caddy Local Authority" in common or issuer == "Caddy"
    # Staging certificates chain to "(STAGING) Let's Encrypt" / "(STAGING) ...".
    # They are real ACME certificates, so nothing above flags them - but no
    # browser trusts them, which is the single most confusing way for this to
    # look like it worked.
    staging = "staging" in label.lower()

    if self_signed:
        state = "self-signed"
        detail = (
            "Caddy is serving its internal certificate, not a Let's Encrypt one - "
            "issuance has not succeeded yet."
        )
    elif staging:
        state = "staging"
        if brand.tls_staging:
            detail = (
                f"Staging certificate from {label}, valid for {days_left} more day(s). "
                "Browsers will not trust it - untick 'Use Let's Encrypt staging' and "
                "apply again for a real one."
            )
        else:
            # Caddy will not throw away a certificate that is still valid just
            # because the configured CA changed, so switching staging off leaves
            # the old one being served until the sidecar reloads its cache.
            detail = (
                f"Staging certificate from {label}, valid for {days_left} more day(s). "
                "Staging is switched off here, but Caddy is still serving the "
                "certificate it already had - changing CA does not discard a valid "
                "one. Restart the caddy container to pick up the production "
                "certificate."
            )
    else:
        state = "ok"
        detail = f"Certificate from {label}, valid for {days_left} more day(s)."

    return {
        "state": state,
        "issuer": label,
        "expires": expires.isoformat(),
        "days_left": days_left,
        "names": names,
        "detail": detail,
    }


def _rdn(name: x509.Name, oid) -> str:
    """First value for an OID in a certificate name, or "" if absent."""
    values = name.get_attributes_for_oid(oid)
    return str(values[0].value) if values else ""

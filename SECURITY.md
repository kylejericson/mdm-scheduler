# Security

## What this tool can do

It stores MDM API credentials and can send `EraseDevice` and `DeviceLock` to
fleets of managed machines, on a schedule, unattended. Treat access to the UI as
equivalent to admin access to your MDM tenant.

## Authentication

Since 3.0.0:

- **Named accounts** with per-user Argon2id password hashes.
- **Roles** - admin, operator, viewer. An operator can schedule jobs without
  ever seeing an API credential; a viewer can read run logs and nothing else.
- **Passkeys (WebAuthn)** and **TOTP**, with single-use recovery codes. MFA can
  be required org-wide.
- **Server-side sessions**, listable and revocable per device; the cookie holds
  a token whose SHA-256 is what the database stores.
- **Login throttling** per account and per source IP, with temporary lockout.
- **An audit log** of sign-ins, user and factor changes, session revocations,
  instance and settings changes, and every job created, edited, deleted or run.

### Break-glass

`ADMIN_PASSWORD` still signs in as `admin` and skips MFA. That is deliberate -
it is how you get back in after a lost authenticator - but it means anyone who
can read the container's environment can bypass MFA. Every use is recorded as
its own audit action.

**Turn it off** (Users -> Security policy) once your recovery codes are stored
somewhere you can reach without the device holding your second factor.

## Deploying it sanely

- **Put it behind TLS.** The session cookie is not marked `secure`, so it works
  on plain HTTP for a LAN-only install. If you expose it beyond your own
  network, terminate TLS in front of it - the built-in Caddy sidecar does this.
- **Prefer DNS-01 over HTTP-01** for certificates. HTTP-01 needs inbound port 80
  permanently, which means putting the login page on the public internet. DNS-01
  gets the same certificate with nothing forwarded.
- **Don't publish port 8000 to the internet.** It is the plain-HTTP path that
  bypasses the proxy, and passkeys cannot be used on it.
- **Give the API Role the least privilege your schedules need.** A role that can
  read groups and update profile scope cannot wipe a laptop. This is the single
  most effective control available to you, because it bounds the damage
  regardless of what happens to the app.
- **Back up the `/data` volume** - it holds the schedule database, accounts and
  registered factors. Restoring it onto a container with a different
  `SECRET_KEY` leaves credentials and TOTP secrets unreadable, so store the key
  with the backup.

## Credentials at rest

MDM credentials, DNS API tokens and TOTP secrets are encrypted with Fernet
(AES-128-CBC + HMAC) using a key derived from `SECRET_KEY` via SHA-256, and
stored in SQLite on the data volume. Passwords are Argon2id hashes; recovery
codes are keyed SHA-256.

This protects a copied database file. It does not protect against a compromised
container - anything that can read the environment can decrypt them.

## What still isn't there

Being explicit, so you can decide whether that's acceptable:

- No SSO or SCIM. Accounts are managed in this app only.
- No per-instance or per-job permissions - an operator can run any job against
  any configured tenant.
- No approval workflow. Any operator can schedule a fleet wipe on their own.
- No email or webhook alerting; the audit log is read in the UI.
- No outbound allowlisting. The app talks to whatever Base URL you configure.

## Reporting a vulnerability

Open a GitHub issue for anything low-risk. For something that would let somebody
wipe a fleet, email **kyle@ericsontech.com** instead of filing publicly, and
allow a reasonable window before disclosure.

This is a side project maintained by one person, not a vendor with an on-call
rotation - set your expectations for response time accordingly, and don't deploy
it anywhere that assumes otherwise.

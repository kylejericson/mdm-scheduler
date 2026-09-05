# Security

## What this tool can do

It stores Jamf Pro API credentials and can send `EraseDevice` and `DeviceLock`
to fleets of managed machines. Treat access to the UI as equivalent to admin
access to your Jamf tenant.

## Deploying it sanely

- Put it behind a reverse proxy with TLS. The session cookie is not marked
  `secure` (so it works on plain HTTP for a LAN-only install) — if you expose it
  beyond your own network, terminate TLS in front of it.
- Don't publish port 8000 to the internet. There is a single password and no
  rate limiting, MFA, or lockout.
- Give the API Role the least privilege the schedules you actually run need.
  A role that can read groups and update profile scope cannot wipe a laptop.
- Back up the `/data` volume — it holds the schedule database. Restoring it
  onto a container with a different `SECRET_KEY` leaves the credentials
  unreadable, so store the key with the backup.

## Credentials at rest

Jamf credentials are encrypted with Fernet (AES-128-CBC + HMAC) using a key
derived from `SECRET_KEY` via SHA-256, stored in SQLite on the data volume.
This protects a copied database file, not a compromised container — anything
that can read the environment can decrypt them.

## Reporting a vulnerability

Open a GitHub issue for anything low-risk. For something that would let
somebody wipe a fleet, email the maintainer instead of filing publicly, and
allow a reasonable window before disclosure.

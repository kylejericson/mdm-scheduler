# MDM Scheduler

Schedule Jamf Pro and Iru (formerly Kandji) API actions — enable a Jamf policy at 2am, scope a
configuration profile to a group on Friday, move a Mac into an Iru blueprint by
serial number, send an MDM command to a smart group on a cron.
Self-hosted, single container, one SQLite file.

[![CI](https://github.com/kylejericson/mdm-scheduler/actions/workflows/ci.yml/badge.svg)](https://github.com/kylejericson/mdm-scheduler/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> Not affiliated with, endorsed by, or supported by Jamf or Iru. "Jamf" and
> "Jamf Pro" are trademarks of JAMF Software, LLC. "Iru" and "Kandji" are
> trademarks of Iru, Inc.

## Why

Jamf Pro has no built-in way to say "make this policy live at 6am Saturday" or
"scope this profile to the pilot group after hours, then unscope it Monday".
The usual answers are a cron job wrapping curl, or doing it by hand at an
inconvenient time. This is the small tool in between: a form that lists your
actual policies and groups, and a scheduler that runs the change when you said.

## Features

| | |
|---|---|
| **Multi-MDM, multi-tenant** | Any number of Jamf Pro *and* Iru instances; each schedule is bound to one, and the form changes to match that vendor |
| **Auth** | API Client (client credentials, recommended) or a Jamf Pro user account |
| **Policies** | Enable/disable; add or remove a computer group from the scope |
| **Config profiles** | Assign/unassign a computer group (macOS) or mobile device group |
| **MDM commands** | Computers: lock, wipe, restart, shut down, blank push, enable/disable remote desktop, unmanage. Mobile: lock, wipe, restart, shut down, enable/disable Lost Mode, clear passcode, update inventory, unmanage. Sent via `POST /api/v2/mdm/commands` (blank push via `/api/v2/mdm/blank-push`); Classic API only where v2 has no equivalent |
| **Targeting** | A group, or a list of Jamf IDs **and/or serial numbers** mixed freely |
| **Pre-flight** | One inventory sweep per run resolves management IDs and management state; devices that can't take the command are skipped and named in the log rather than failing the whole job |
| **Run-time group expansion** | Membership is resolved when the job fires, so a smart group that changes between scheduling and firing does the right thing |
| **Live discovery** | Dropdowns are populated from the selected instance's real policies, profiles and groups |
| **Scheduling** | One-shot datetime or 5-field cron, each with its own timezone |
| **Auditing** | Per-job run log with the Jamf response or the exact error, last 500 runs |
| **Accounts** | Named users with roles (admin / operator / viewer), passkeys and TOTP, single-use recovery codes, server-side sessions you can revoke, login throttling |
| **Audit log** | Who created, edited, ran or deleted each job; sign-ins, factor changes and settings changes, with source address |
| **Org branding** | Your logo, name and accent color in the header and on the sign-in page |
| **Light / dark** | Per-viewer toggle, org-level default, OS fallback |
| **Iru blueprints** | Move devices into a blueprint by serial number, or move everything out of one; Iru has no unassign, so moving is the mechanism |
| **Built-in help** | `/help` documents every Jamf privilege and Iru token permission the tool needs, and what each error means — readable before you sign in |
| **HTTPS** | Let's Encrypt via a Caddy sidecar, configured from the Branding tab; HTTP-01 or DNS-01, automatic renewal |
| **No CDN at runtime** | UI assets are vendored into the image, so a restricted-egress host still renders |

## Quick start

Needs Docker with the Compose plugin. Nothing else — no Python, no database, no
reverse proxy to configure.

```bash
git clone https://github.com/kylejericson/mdm-scheduler.git
cd mdm-scheduler
./scripts/bootstrap.sh        # generates SECRET_KEY, asks for a UI password
docker compose up -d
```

Open `http://<host>:8000` and sign in as **admin** with that password. Add an MDM
instance, press **Test**, then head to **Users** to create real accounts and turn
on MFA.

Upgrading from 2.x? Your `ADMIN_PASSWORD` becomes the `admin` account on first
boot - nothing to migrate, and nothing stops working.

`bootstrap.sh` just writes `.env`; do it by hand if you prefer:

```bash
cp .env.example .env
printf 'SECRET_KEY=%s\n' "$(openssl rand -hex 32)" >> .env
$EDITOR .env                  # set ADMIN_PASSWORD and TZ
```

**Keep `SECRET_KEY` safe and back it up with the data volume** — it encrypts
your stored MDM credentials. Replacing it means re-entering every API
credential.

### Build from source instead

`compose.yaml` pulls a prebuilt multi-arch image from GHCR. To build locally —
also what you want if you're modifying the code:

```bash
docker compose -f compose.dev.yaml up -d --build
```

The Caddy sidecar is always built locally, because DNS-01 needs DNS provider
modules compiled into the binary. First build takes a few minutes.

### Upgrading

If you run the stack in a Proxmox LXC, `scripts/deploy.sh` does the whole
three-machine dance from your workstation - backup, copy, extract, rebuild,
health check - and prints the rollback commands at the end:

```bash
./scripts/deploy.sh ~/Downloads/mdm-scheduler-3.0.0.tar.gz
```

Otherwise:

```bash
git pull
docker compose pull && docker compose up -d          # prebuilt
docker compose -f compose.dev.yaml up -d --build     # from source
```

Database migrations run at startup; there is nothing to apply by hand. Your
schedules, run history, branding and credentials live in the `/data` volume and
survive upgrades.

### Dockge / Portainer

Clone into your stacks directory and deploy the stack — Dockge reads
`compose.yaml` directly:

```bash
cd /opt/stacks
git clone https://github.com/kylejericson/mdm-scheduler.git
cd mdm-scheduler && ./scripts/bootstrap.sh
```

Then refresh Dockge and start the `mdm-scheduler` stack. Portainer: point a Git
stack at the repo and add `SECRET_KEY`, `ADMIN_PASSWORD` and `TZ` as stack
environment variables instead of using `.env`.

### What it publishes

| Port | Serves |
|---|---|
| 8000 | The app directly, plain HTTP (handy on a LAN, and how you set HTTPS up in the first place) |
| 80 | Caddy — HTTP, plus ACME HTTP-01 challenges |
| 443 | Caddy — HTTPS once you enable it |

Set `PORT`, `HTTP_PORT` or `HTTPS_PORT` in `.env` if any of those clash with
something already on the host.

## HTTPS

The stack ships a Caddy sidecar that fronts the app. Turn on HTTPS under
**Branding → HTTPS**: hostname, contact email, and how Let's Encrypt should
validate you.

| Challenge | What it needs | Exposure |
|---|---|---|
| HTTP-01 | Public A record for the hostname, inbound port 80 forwarded to the container | The console becomes reachable from the internet |
| DNS-01 | A DNS API token for the zone | Nothing opened; host can stay on a private network |

Let's Encrypt validates by fetching a file over the internet (HTTP-01) or by
reading a TXT record (DNS-01). There is no offline or email-only validation —
the contact email only receives expiry notices. For a tool that can wipe a
fleet, DNS-01 plus a LAN-only host is the safer posture.

DNS-01 providers built into the sidecar: **IONOS, Cloudflare, DigitalOcean,
Hetzner, Linode, Vultr, deSEC, DuckDNS, Gandi**. These all authenticate with a
single API token, which is what the form collects. Route 53, Azure, Google Cloud
DNS, GoDaddy, OVH and Namecheap need several credential values and would need
per-provider fields in the form before they could be offered.

Saving reloads Caddy immediately over its admin API; renewal needs no cron.
**Check certificate** does a real handshake and reports the issuer and days
remaining, and **View generated config** shows the Caddyfile in use with the DNS
token redacted. To add another DNS provider, add its module to
`Dockerfile.caddy` and its name to `DNS_PROVIDERS` in `app/tls.py`.

> The Caddy admin API is reachable only on the compose network and is never
> published to the host — anything that can reach it can reconfigure the proxy.

## Accounts

**Users** (admin only) creates accounts and sets roles:

| Role | Can |
|---|---|
| **Admin** | Everything - users, MDM instances, credentials, settings, HTTPS |
| **Operator** | Create, edit and run jobs. Never sees an API credential |
| **Viewer** | Read the dashboard and run logs |

Each user manages their own factors under **Your account**: passkeys, an
authenticator app, recovery codes, and the list of their active sessions.

Admins can reset a password, clear a lost second factor, sign someone out
everywhere, or disable an account - and can require MFA for everyone, which
holds accounts without a factor on their account page until they enrol.

The **Audit** page records who did what, with source addresses.

## Branding

**Branding** in the header sets the org name, accent color, logo, default theme
and an internal support note shown on the Help page. The logo is written to the
data volume (`/data/branding/`), so back that up with the database. Uploads are
restricted by content type and capped at 2 MB (`MAX_LOGO_BYTES`).

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `SECRET_KEY` | *required* | Encrypts stored Jamf credentials, signs session cookies. `openssl rand -hex 32`. Changing it makes stored credentials unreadable |
| `ADMIN_PASSWORD` | *required* | Creates the first `admin` account, and remains a break-glass sign-in that skips MFA. Turn that off under Users once you have recovery codes |
| `LOGIN_MAX_FAILURES` | `5` | Failed sign-ins per account before a temporary lockout |
| `IP_MAX_FAILURES` | `20` | Failed sign-ins per source IP in the same window |
| `LOGIN_LOCKOUT_SECONDS` | `900` | How long a locked account stays locked |
| `WEBAUTHN_RP_ID` | *derived* | Domain passkeys bind to. Defaults to your HTTPS hostname; changing it invalidates every registered passkey |
| `AUDIT_RETENTION` | `10000` | Audit rows kept |
| `TZ` | `UTC` | Default timezone for new schedules and dashboard timestamps |
| `PORT` | `8000` | Host port |
| `DATA_DIR` | `/data` | Where the SQLite database lives; mount it as a volume |
| `SESSION_MAX_AGE` | `86400` | Session lifetime, seconds |
| `LOG_RETENTION` | `500` | Run-log rows kept per job |
| `HTTP_TIMEOUT` | `45` | Per-request timeout against Jamf, seconds |

## Iru API token permissions

Iru is the current name for Kandji; its API still answers on the `api.kandji.io`
hostnames as well as `api.iru.com`. Create a token under **Settings → Access →
API tokens** and enable only what you schedule:

| Permission | Needed for |
|---|---|
| Device list | Serial resolution, blueprint membership, the pre-flight check |
| List Blueprints | The blueprint dropdowns |
| Get Blueprint | Naming source and destination blueprints in the run log |
| Update Blueprint | Moving a device to another blueprint |
| Device Actions | Each command is its own permission, named for what it does — `Send a blank push`, `Erase Device`, … |

The Base URL is whatever Settings → Access shows —
`https://yourtenant.api.kandji.io` (US) or `…api.eu.kandji.io` (EU).

Notes specific to Iru:

- **Locking a Mac returns an unlock PIN** that Iru generates; it is recorded in
  the run log, and you cannot unlock the machine without it.
- Iru sends one API call per device (there is no batch command endpoint), and the
  tenant rate limit is 10,000 requests/hour.
- `400 Command already running` means Iru still has that command pending for the
  device; `400 Command is not allowed for current device` means it doesn't apply
  to that hardware or OS.

## Jamf API Role privileges

Create an API Role with only what your schedules need, then an API Client bound
to it (Settings → System → API roles and clients).

Read, for discovery:

- `Read Policies`
- `Read macOS Configuration Profiles`, `Read Mobile Device Configuration Profiles`
- `Read Smart Computer Groups`, `Read Static Computer Groups` (both — one alone gives a partial list)
- `Read Smart Mobile Device Groups`, `Read Static Mobile Device Groups`
- `Read Computers`, `Read Mobile Devices` — needed to expand group membership at run time

Write, per action you use:

- `Update Policies` — covers enabling/disabling a policy **and** changing its scope
- `Update macOS Configuration Profiles`, `Update Mobile Device Configuration Profiles`
  — likewise cover profile scope changes

Scope lives on the policy or profile object, so the `Update … Computer Groups`
privileges are **not** needed; this tool never edits a group's definition.

MDM commands need **three** things together:

1. `View MDM command information in Jamf Pro API` — required by every
   `/api/v2/mdm/` endpoint. The near-identical `Send MDM command information in
   Jamf Pro API` does **not** satisfy it.
2. `Read Computers` / `Read Mobile Devices` — the inventory sweep that resolves
   management IDs, serials and capability depends on it. Every Send privilege
   and no read access still gets `401`.
3. The per-command Send privilege:

| Command | Privilege |
|---|---|
| Computer lock / wipe | `Send Computer Remote Lock Command` / `Send Computer Remote Wipe Command` |
| Computer restart / shut down | `Send Computer Restart Command` / `Send Computer Shut Down Command` |
| Computer remote desktop on/off | `Send Computer Remote Desktop Command` |
| Computer unmanage | `Send Computer Unmanage Command` |
| Blank push | `Send MDM Check In Command` |
| Mobile lock / wipe | `Send Mobile Device Remote Lock Command` / `Send Mobile Device Remote Wipe Command` |
| Mobile restart / shut down | `Send Mobile Device Restart Device Command` / `Send Mobile Device Shut Down Command` |
| Mobile Lost Mode on/off | `Send Mobile Device Enable Lost Mode Command` / `… Disable Lost Mode Command` |
| Mobile clear passcode | `Send Mobile Device Clear Passcode Command` |
| Mobile update inventory | `Send Inventory Requests to Mobile Devices` |
| Mobile unmanage | `Send Mobile Device Unmanage Command` |

Troubleshooting **Test**:

- version but zero objects → missing read privileges, or the client is Site-scoped
- `401` on a write, reads fine → missing the matching Update/Send privilege
- `401` on an MDM command with Send privileges present → missing `Read Computers`
- `403 INVALID_PRIVILEGE` on a v2 endpoint → missing
  `View MDM command information in Jamf Pro API` (check you didn't add the
  `Send MDM command information…` lookalike instead)
- `400 No command was queued` → Jamf accepted it and declined; the device isn't
  eligible for that command (Erase All Content and Settings needs Apple Silicon
  or T2 on macOS 12+)
- a mobile smart group resolving to nothing → `Read Smart Mobile Device Groups`
  is separate from the Static one

## How it works

```
FastAPI (routes, Jinja templates, single-password session auth)
   └── APScheduler (in-process, one job per schedule, misfire grace 1h)
         └── app/actions.py  dispatch: action name -> Jamf calls
               └── app/jamf_client.py  token cache, Classic + Pro endpoints
                     └── SQLite via SQLAlchemy (instances, jobs, run logs)
```

Schedules live in the database and are re-registered with APScheduler on
startup, so a container restart doesn't lose them. Times are persisted in UTC
and rendered in each job's timezone.

## Sharp edges

- **Scope writes are read-modify-write.** The app fetches the current group
  list, adds or removes one group, and PUTs the whole list back. A scope change
  made in the Jamf console between the read and the write is overwritten.
- **Computer `DeviceLock` / `EraseDevice` require a 6-digit PIN**, enforced by
  the form. Mobile wipes take no PIN.
- **Jamf can accept a command and still not queue it.** Erase All Content and
  Settings needs Apple Silicon or T2 on macOS 12+; an older Intel Mac returns
  `400 No command was queued`. The pre-flight catches unmanaged and
  non-MDM-capable devices, but it cannot predict hardware/OS eligibility — that
  failure still lands in the run log.
- **`returnToService.enabled` is sent as `false`** on wipes. If you want erased
  Macs to re-enroll automatically you'll need to extend the payload with the
  profile data Jamf expects.
- **A one-shot job pauses itself** after a successful scheduled run so its
  history stays visible. **Run now** never auto-pauses.
- **Missed runs** (container down at fire time) execute on startup within a
  1-hour misfire grace window, then are skipped.
- **Passkeys are bound to a hostname.** One registered at `mdm.example.com` will
  not work at `http://192.168.1.10:8000` - that is what makes them unphishable.
  TOTP covers the LAN address.
- **Break-glass is on by default.** `ADMIN_PASSWORD` signs in as `admin` and
  skips MFA. Turn it off under Users once your recovery codes are saved.
- **This tool can wipe your fleet.** See [SECURITY.md](SECURITY.md) before
  exposing it anywhere.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). The test suite runs the real app against
a fake Jamf Pro, so `pytest` needs no tenant and touches no devices.

## License

MIT — see [LICENSE](LICENSE).

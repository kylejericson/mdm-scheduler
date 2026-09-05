# MDM Scheduler

Schedule Jamf Pro and Iru (formerly Kandji) API actions — enable a Jamf policy at 2am, scope a
configuration profile to a group on Friday, move a Mac into an Iru blueprint by
serial number, send an MDM command to a smart group on a cron.
Self-hosted, single container, one SQLite file.

[![CI](https://github.com/__YOUR_GH_HANDLE__/mdm-scheduler/actions/workflows/ci.yml/badge.svg)](https://github.com/__YOUR_GH_HANDLE__/mdm-scheduler/actions/workflows/ci.yml)
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
| **Auth on the UI** | Single password; Jamf credentials Fernet-encrypted at rest |
| **Org branding** | Your logo, name and accent color in the header and on the sign-in page |
| **Light / dark** | Per-viewer toggle, org-level default, OS fallback |
| **Iru blueprints** | Move devices into a blueprint by serial number, or move everything out of one; Iru has no unassign, so moving is the mechanism |
| **Built-in help** | `/help` documents every Jamf privilege and Iru token permission the tool needs, and what each error means — readable before you sign in |
| **No CDN at runtime** | UI assets are vendored into the image, so a restricted-egress host still renders |

## Quick start

```bash
git clone https://github.com/__YOUR_GH_HANDLE__/mdm-scheduler.git
cd mdm-scheduler

cp .env.example .env
printf 'SECRET_KEY=%s\n' "$(openssl rand -hex 32)" >> .env
$EDITOR .env          # set ADMIN_PASSWORD and TZ

docker compose up -d
```

Open `http://<host>:8000`, sign in, add an instance, press **Test**.

`compose.yaml` pulls a prebuilt multi-arch image from GHCR. To build from source
instead:

```bash
docker compose -f compose.dev.yaml up -d --build
```

### Dockge / Portainer

Clone the repo into your stacks directory (`/opt/stacks/mdm-scheduler`), create
the `.env` beside `compose.yaml`, and deploy the stack. Dockge reads
`compose.yaml` directly.

## Branding

**Branding** in the header sets the org name, accent color, logo, default theme
and an internal support note shown on the Help page. The logo is written to the
data volume (`/data/branding/`), so back that up with the database. Uploads are
restricted by content type and capped at 2 MB (`MAX_LOGO_BYTES`).

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `SECRET_KEY` | *required* | Encrypts stored Jamf credentials, signs session cookies. `openssl rand -hex 32`. Changing it makes stored credentials unreadable |
| `ADMIN_PASSWORD` | *required* | The UI password. No username |
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
| Blueprint list | The blueprint dropdowns |
| Update device | Moving a device to another blueprint |
| The device actions you use | Each action (lock, erase, restart, …) is its own permission |

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
- **This tool can wipe your fleet.** See [SECURITY.md](SECURITY.md) before
  exposing it anywhere.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). The test suite runs the real app against
a fake Jamf Pro, so `pytest` needs no tenant and touches no devices.

## License

MIT — see [LICENSE](LICENSE).

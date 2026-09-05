# Changelog

## 2.0.0

Renamed to **MDM Scheduler** and now speaks to more than one MDM.

- **Iru (formerly Kandji) support.** Instances carry a vendor, and picking an Iru
  instance swaps the whole action menu, its pickers and its discovery calls.
  Every endpoint used is from the official reference at api-docs.iru.com:
  - `GET /api/v1/blueprints` for the blueprint dropdowns
  - `GET /api/v1/devices` for serial resolution, blueprint membership and the pre-flight
  - `POST /api/v1/devices/{id}/action/{action}` for MDM commands
  - `PATCH /api/v1/devices/{id}` with `blueprint_id` for blueprint moves
- **All Iru device actions**: lock, erase, restart, shut down, blank push, update
  inventory, daily check-in, reinstall agent, renew MDM profile, mark configured,
  remote desktop on/off, clear passcode, unlock account, delete user, set name,
  Lost Mode enable/disable/sound/location, personal hotspot and data roaming
  on/off. Payload fields match the documented schemas (`Erase` sends `PIN` plus
  `ReturnToService`, `Restart` sends `NotifyUser`, and so on).
- **Locking a Mac through Iru records the unlock PIN** Iru generates in the run
  log - without it the machine cannot be unlocked.
- **Blueprint moves by serial number**, or every device in a source blueprint.
  Iru has no "unassign": a device always belongs to exactly one blueprint, so
  taking a Mac out of one means moving it to another. Devices already in the
  destination are left alone, so the job is safe to re-run.
- Iru targets are pre-flighted like Jamf's: MDM-disabled or removed devices are
  skipped and named, the rest still get the command.
- Renamed throughout: repo, image, container, volume, UI title and default page
  title are now `mdm-scheduler` / MDM Scheduler. Help covers both platforms.
- **Schema migration on startup.** `instances` gains `vendor` and
  `api_token_enc`; a forward-only ADD COLUMN step runs at boot so an existing
  database upgrades without manual work.
- Action menu order is now explicit rather than alphabetical - Jinja's `tojson`
  sorts keys, which had been putting an MDM command first for Jamf and the
  blueprint move first for Iru.

## 1.2.0

- **Org branding.** A Branding page sets the organization name, an accent color,
  a default theme and an internal support note, and takes a logo upload (PNG,
  JPEG, WebP, GIF or SVG, 2 MB cap, type-checked). The logo appears in the header
  and on the sign-in page; it is stored on the data volume and survives restarts.
- **Light / dark mode**, toggled from the header. The choice is per viewer
  (localStorage), falls back to the org default, then to the OS setting, and is
  applied before first paint so there is no flash of the wrong theme.
- **Help page** at `/help`, readable without signing in: how to build the API
  Role and Client, the always-required reads, the per-action writes, the
  three-part MDM privilege requirement including the
  `View` vs `Send MDM command information` trap, a per-command privilege and
  transport table, targeting rules, and a troubleshooting table keyed on the
  exact errors Jamf returns. Credits and developer contact are in the footer.
- **UI assets are vendored into the image at build time.** The container no
  longer needs CDN access at runtime; a host with restricted egress was getting
  an unstyled page. The CDN remains a fallback if the build itself has no network.
- Navbar no longer repeats the org name next to the logo, and "never" in the Last
  run column no longer prints a stray dash.

## 1.1.1

- `403 INVALID_PRIVILEGE` from any `/api/v2/mdm/` endpoint now names the exact
  privilege Jamf wants — `View MDM command information in Jamf Pro API` — and
  warns that the near-identical `Send MDM command information in Jamf Pro API`
  does not satisfy it.
- Jamf's JSON error envelope is reduced to one line (`INVALID_PRIVILEGE
  Forbidden`) instead of being dumped raw into the run log, where its own
  `"id": "0", "field": null` metadata reads like a problem with the device you
  targeted.

## 1.1.0

MDM commands rebuilt on the documented Jamf Pro API.

- **Commands now go through `POST /api/v2/mdm/commands`** — `DEVICE_LOCK`,
  `ERASE_DEVICE`, `RESTART_DEVICE`, `SHUT_DOWN_DEVICE`, `ENABLE_LOST_MODE`,
  `DISABLE_LOST_MODE`, `ENABLE_REMOTE_DESKTOP`, `DISABLE_REMOTE_DESKTOP` — one
  batched call per run instead of one Classic URL per command.
- **Blank push uses `POST /api/v2/mdm/blank-push`**, which is its own endpoint
  rather than a `commandType`.
- `ERASE_DEVICE` sends `returnToService.enabled`, which the v2 schema requires.
- `UnmanageDevice`, mobile `ClearPasscode` and mobile `UpdateInventory` stay on
  the Classic API: v2 has no equivalent, and v2 `CLEAR_PASSCODE` requires an
  `unlockToken` this tool has no way to supply.
- **Target by serial number or Jamf ID**, mixed in one list. Digits are read as
  IDs, anything else as a serial, case-insensitive.
- **Pre-flight capability check.** One paged inventory sweep per run
  (`/api/v1/computers-inventory`, `/api/v2/mobile-devices-detail`) resolves
  management IDs, serials and management state. Devices that cannot take the
  command are skipped and named in the run log — `sent to 1: mac-01 … |
  skipped 1: old-intel-mac (id 30) - not MDM-capable` — so one stale laptop no
  longer aborts a scheduled fleet action. If nothing is sendable the run fails
  loudly rather than reporting success.
- Run logs now identify devices by name, ID and serial instead of bare IDs.
- Optional message field for `DEVICE_LOCK`; required for `ENABLE_LOST_MODE`.
- Needs `View MDM command information in Jamf Pro API` and `Read Computers` /
  `Read Mobile Devices` on the API Role.

## 1.0.2

- Writes are sent as `Content-Type: application/xml` (was `text/xml`).
- **Redirects are no longer followed.** httpx strips the `Authorization` header
  on a cross-origin redirect, so a redirected write would 401 confusingly or
  replay unauthenticated. A redirect now raises, naming the `Location` and
  pointing at the instance's Base URL.
- `401`/`403` from Jamf now says what it usually means: the API Role is missing
  the matching Update/Send privilege, or the client is scoped to a Site that
  excludes the object. `409` is called out as Classic API's validation error.
- MDM command failures name both requirements: the per-command Send privilege
  and `Read Computers` / `Read Mobile Devices`.
- HTML error pages from Jamf are stripped to their text instead of dumping
  markup into the run log.

## 1.0.1

- **Fixed:** discovery silently returned zero policies, profiles and groups
  against real Jamf Pro tenants. The Classic API serves JSON bodies labelled
  `text/plain;charset=utf-8`, and the client only parsed responses whose
  content-type said `json` — everything else came back as a raw string and was
  treated as an empty collection.
- `list_objects()` and `get_object()` now raise with a snippet of the actual
  response instead of reporting an empty list.
- **Test** now says when credentials are valid but the API Role cannot read
  anything, rather than implying the tenant is empty.
- Test suite added: the fake Jamf Pro now mislabels its content types the way
  the real thing does, so this class of bug fails CI.

## 1.0.0

Initial release.

- Multiple Jamf Pro instances, API Client (client credentials) or username/password
- Enable/disable a policy; add/remove a computer group from a policy's scope
- Assign/unassign macOS and mobile configuration profiles to/from groups
- MDM commands for computers and mobile devices, targeted at a group or explicit device IDs
- Group membership expanded at run time, not at schedule time
- One-shot and cron schedules, each with its own timezone
- Live discovery of policies, profiles and groups in the job form
- Single-password UI auth, Fernet-encrypted credentials, per-job run logs

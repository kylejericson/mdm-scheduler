# Changelog

## 3.0.1

Packaging fixes. No behaviour change.

- **`.env.example` documents the 3.0 settings.** All nine new variables - the
  login throttle, recovery code count, audit retention and the three WebAuthn
  ones - were missing, so the only place to discover them was the README.
- The `SECRET_KEY` comment now says what it actually protects in 3.0: stored
  credentials *and* TOTP secrets, so losing it also breaks every enrolled
  authenticator app.
- The `ADMIN_PASSWORD` comment explains that it creates the first account and
  then stays a break-glass sign-in that skips MFA, with a pointer to the switch
  that turns it off.
- `scripts/deploy.sh` is in the tree. It was written for 3.0.0 but missed the
  release tarball.


## 3.0.0

Real accounts, two-factor authentication and an audit trail. If you are putting
this on the public internet, this is the release that makes that defensible.

**Upgrading is automatic and nothing is lost.** On first boot the existing
`ADMIN_PASSWORD` becomes an `admin` account with that same password, so an
existing install keeps working with no action. See "Break-glass" below for the
one thing worth turning off afterwards.

### Accounts and roles

- **Named user accounts**, each with its own password (Argon2id) and its own
  sessions, so sign-ins are attributable and individually revocable.
- **Three roles.** *Admin* manages users, MDM instances and settings. *Operator*
  creates and runs jobs but never sees credentials. *Viewer* reads dashboards
  and run logs. Enforcement is a single policy function rather than per-route
  decorators, so a new route is covered by default instead of exposed by
  omission.
- Admins can reset a password, clear a lost second factor, disable an account,
  or sign someone out everywhere. The last active admin cannot be demoted,
  disabled or deleted.

### Two factors

- **Passkeys (WebAuthn).** Touch ID, Windows Hello, hardware keys. Either as a
  one-step sign-in - the authenticator verifies the user locally, so it is
  already two factors - or as a second step after a password. Several per
  account, each named, each removable. Registered as discoverable credentials,
  so "Sign in with a passkey" needs no username.
- **Authenticator apps (TOTP)**, enrolled from a QR code rendered by the app
  itself. No CDN, and the secret never passes through third-party JavaScript.
- **Recovery codes**, ten per account, single-use, stored hashed. Issued when
  the first factor is added.
- **Require MFA** is an admin setting: accounts without a factor can reach their
  own account page and nothing else until they enrol.
- Passkeys are bound to a domain, so they work on your HTTPS hostname and not on
  the plain-HTTP LAN address. The UI says so rather than failing silently, and
  TOTP covers that case.

### Hardening

- **Login throttling.** Failures are counted per account and per source IP over
  the same window - the first stops someone grinding one password, the second
  stops a spray across many usernames - with a temporary lockout after five
  account failures. `X-Forwarded-For` is trusted only when the peer is the
  Caddy sidecar, since port 8000 is directly reachable and the header is
  trivially forged.
- **Server-side sessions.** The cookie carries a random token; only its SHA-256
  is stored. Sessions can be listed and revoked - by their owner, or by an
  admin for anyone - which a signed cookie alone can never be. Changing a
  password or disabling an account signs out every other session.
- **TOTP codes cannot be replayed.** The time step a code came from is recorded
  and never accepted twice, so a code seen over someone's shoulder is useless
  the moment it is used.
- **A regressed passkey counter is treated as a cloned authenticator** and
  refused, with an explanation rather than the library's arithmetic.
- Failed sign-ins say the same thing whether or not the account exists, so the
  form is not a username oracle.

### Audit log

- Every sign-in, failed sign-in, sign-out, user change, factor change, session
  revocation, instance change, settings change and job create/edit/delete/run
  is recorded with actor, target, detail and source address. Filterable by
  actor and action.
- The actor's username is copied onto each row rather than joined, so deleting
  a user does not erase the record of what they did.
- `job-run` is written before the run starts, so a job that hangs still shows
  who set it going.

### Break-glass

`ADMIN_PASSWORD` continues to sign in as `admin`, bypassing MFA. That is the
documented way back in after a lost authenticator - and it is also a way past
MFA for anyone who can read the container's environment. It is recorded as its
own audit action, and there is a switch on the Users page to turn it off once
your recovery codes are somewhere safe.

### Deployment

- `scripts/deploy.sh` ships a release to a Proxmox LXC from your workstation in
  one command: backs up the data volume, `.env` and the current code, copies the
  tarball via the Proxmox host, extracts, rebuilds, waits for `/health`, and
  prints the exact rollback commands. It refuses a tarball containing a `.env`
  or a database, and stops before changing anything if the backup fails.

### Deployment

- `scripts/deploy.sh` releases in one command from your workstation: backs up
  the data volume, `.env` and the current code; copies the tarball via the
  Proxmox host into the container; extracts, rebuilds and waits for `/health`;
  then commits, tags `vX.Y.Z` and pushes to GitHub, which starts the release
  workflow. Deploy runs before publish, so a tag never points at a build that
  didn't start. `--no-git` and `--no-deploy` run either half alone.
- It refuses a tarball containing a `.env` or a database, refuses a tag that
  already exists locally or on the remote, stops before changing anything if
  the backup fails, and scans the staged diff for high-entropy values assigned
  to `SECRET_KEY`, `ADMIN_PASSWORD`, `API_TOKEN` or `CLIENT_SECRET` before
  pushing.

### Also fixed

- **TOTP codes no longer depend on the container's timezone.** pyotp derives the
  counter from local wall-clock time for naive datetimes, so a container with
  `TZ` set to anything but UTC would have generated codes that disagreed with
  every real authenticator app. Verification now passes explicitly UTC-aware
  timestamps.
- The empty-state redirect on "New job" used to send operators to the instance
  form, which they cannot open - a redirect straight into a 403. They now get
  the dashboard and a message.
- `static/*.js` is no longer git-ignored. Only the two vendored Bootstrap files
  are, so app JavaScript is tracked like the source it is.


## 2.3.2

- **Fixed: restarting the Caddy container silently turned HTTPS off.** The
  config the app sends to Caddy's admin API lives in memory, and the container
  starts from `Caddyfile.initial` - plain HTTP - so any restart dropped TLS
  while the Branding tab still showed HTTPS enabled and the site stopped
  answering on 443 entirely. Two changes, because they cover different
  failures:
  - The sidecar now runs with `--resume`, so it reloads the config it last
    accepted instead of the starting one.
  - The app re-applies the stored config at startup, which covers a recreated
    container, a lost `caddy_config` volume, or a database restored onto a new
    host. It is best effort and logs rather than blocking boot if Caddy is not
    up yet.


## 2.3.1

- **Fixed: certificate status always said "Caddy served no certificate for that
  hostname"**, even with a valid certificate being served. The probe read
  `getpeercert()`, which returns `{}` whenever `verify_mode` is `CERT_NONE` -
  Python only builds that dict as a side effect of validating the chain, and
  this check deliberately doesn't validate. It now reads the DER
  (`getpeercert(binary_form=True)`, always populated) and parses it with
  `cryptography`, which is already a dependency.
- **Staging certificates are now called out as their own state.** A staging
  certificate is a real ACME certificate, so nothing flagged it, yet no browser
  trusts it - the most confusing possible way for HTTPS to look finished. The
  status line now names it and says to untick staging and apply again.
- **Switching staging off no longer looks broken.** Caddy does not discard a
  certificate that is still valid just because the configured CA changed, so
  the staging certificate keeps being served until the sidecar reloads. The
  status line now detects exactly that case - staging off, staging certificate
  on the wire - and says to restart the caddy container.
- Status tests run against an actual TLS server with a generated certificate
  rather than mocking the probe, so this class of bug fails CI.

## 2.3.0

Packaging for public use.

- `scripts/bootstrap.sh` writes `.env` with a generated `SECRET_KEY` and asks
  for a UI password, so first run is clone -> bootstrap -> `docker compose up`.
  It refuses to overwrite an existing `.env`, since a new `SECRET_KEY` orphans
  stored MDM credentials.
- README quick start rewritten for someone who has never seen the tool: what it
  needs, the prebuilt-image and build-from-source paths, upgrading, Dockge and
  Portainer, and which ports are published and why.
- `RELEASING.md` documents cutting a release - including that GHCR packages are
  private by default, so the first published image needs its visibility flipped
  or nobody else can pull it.
- Issue and PR templates, both of which lead with "don't paste credentials".
- Security contact is a real address, with an honest note that this is a
  one-person side project rather than a vendor with an on-call rotation.

## 2.2.1

- **Fixed the Caddy sidecar build.** The pinned `caddy:2.8.4-builder` ships Go
  1.23 with `GOTOOLCHAIN=local`, and current `caddy-dns` modules require Go
  1.24+, so `xcaddy build` failed with
  `requires go >= 1.24 (running go 1.23.4; GOTOOLCHAIN=local)`. Now builds on
  `caddy:2.11.4-builder` and sets `GOTOOLCHAIN=auto` so Go fetches whatever
  toolchain a module asks for - this keeps building as modules move on rather
  than breaking on the next bump.

## 2.2.0

- **Nine DNS providers for DNS-01**, up from one: IONOS, Cloudflare,
  DigitalOcean, Hetzner, Linode, Vultr, deSEC, DuckDNS and Gandi. Module import
  paths were taken from Caddy's own package registry rather than guessed.
- Each provider shows where to create its token next to the field.
- A test cross-checks the provider dropdown against the `--with` lines in
  `Dockerfile.caddy`, so offering a provider whose module was never compiled in
  fails CI instead of failing at issuance time.
- Providers that need more than a single token (Route 53, Azure, Google Cloud
  DNS, GoDaddy, OVH, Namecheap) are deliberately not offered - the form collects
  one token, so they need per-provider credential fields first. Selecting an
  unknown provider falls back to IONOS rather than writing an unbuildable config.

## 2.1.1

- Help and README now use Iru's actual API token permission names -
  `List Blueprints`, `Get Blueprint`, `Update Blueprint`, and the per-command
  `Device Actions` entries (`Send a blank push`, `Erase Device`, …) - rather
  than paraphrases that don't match what the token editor shows.

## 2.1.0

- **HTTPS from the Branding tab.** A Caddy sidecar terminates TLS and gets
  certificates from Let's Encrypt. Set the hostname, contact email and
  validation method in the UI; the app renders a Caddyfile and hands it to
  Caddy's admin API (`POST /load`, `Content-Type: text/caddyfile`), which
  reloads with no downtime and no restart of the scheduler. Renewal is
  automatic - there is no cron to maintain.
- **Both ACME challenges**, because they have different prerequisites:
  - **HTTP-01** - Let's Encrypt fetches the challenge file over the public
    internet, so it needs a public A record and inbound port 80. The UI says so.
  - **DNS-01** - Caddy writes a TXT record through the provider's API, so
    nothing inbound is opened and the host can stay on a private network.
    IONOS and Cloudflare modules are compiled into the sidecar image.
- Let's Encrypt **staging** toggle, worth one run before spending production
  rate limit (5 failures per hostname per hour).
- **Certificate status** is read by asking Caddy for a real handshake and
  inspecting the certificate it serves - issuer and days remaining. A loaded
  config proves nothing about whether issuance actually happened, and Caddy's
  internal self-signed certificate is called out as "not a Let's Encrypt one".
- **View generated config** shows the exact Caddyfile being used, with the DNS
  token redacted, so the proxy config is reviewable rather than a black box.
- The DNS API token is Fernet-encrypted at rest like the MDM credentials, and
  never rendered into the page.
- `branding` gains the TLS columns via the same startup ADD COLUMN migration.

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

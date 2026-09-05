# Releasing

Maintainer notes. Users don't need this.

## Cut a release

```bash
# version lives in one place
$EDITOR app/__init__.py      # __version__ = "2.3.2"
$EDITOR CHANGELOG.md         # add the section

git commit -am "Release 2.3.2"
git tag v2.3.2
git push && git push --tags
```

The `Release` workflow builds `linux/amd64` and `linux/arm64` and pushes to
`ghcr.io/<owner>/<repo>` tagged `2.3.2`, `2.3`, and `latest`.

## One-time: make the package public

GHCR packages are **private by default**, so the first release will publish an
image nobody else can pull — `docker compose up -d` fails for them with
`denied` or `unauthorized`.

Fix it once, after the first successful release:

1. GitHub → your profile → **Packages** → `mdm-scheduler`
2. **Package settings** → *Danger Zone* → **Change visibility** → Public
3. Also under package settings, confirm the repository is linked, so the
   package inherits the repo's README and shows on the repo page

Verify from a machine with no credentials:

```bash
docker logout ghcr.io
docker pull ghcr.io/<owner>/mdm-scheduler:latest
```

## Before tagging

```bash
ruff check .
pytest -q
docker compose -f compose.dev.yaml build      # both images, including Caddy
```

CI runs the first two plus a container boot check on every push and PR.

## Caddy sidecar upkeep

`Dockerfile.caddy` pins `CADDY_VERSION` and compiles DNS provider modules with
xcaddy. Two things go stale:

- **The Caddy version.** Bump it when a new stable ships.
- **Go's minimum.** `caddy-dns` modules raise their minimum Go version over
  time. `GOTOOLCHAIN=auto` is set so Go fetches what a module asks for; without
  it the build fails with `requires go >= 1.xx (running go 1.yy;
  GOTOOLCHAIN=local)`.

Adding a DNS provider: add a `--with github.com/caddy-dns/<name>` line, then add
the same name to `DNS_PROVIDERS` in `app/tls.py`. A test asserts those two lists
agree. Only single-token providers fit the current form — see the comment in
`app/tls.py`.

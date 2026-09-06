#!/usr/bin/env bash
# Release MDM Scheduler: deploy to your own stack, then publish to GitHub.
#
#   ./deploy.sh ~/Downloads/mdm-scheduler-3.0.0.tar.gz
#
# Run it from your workstation. It does the three-machine dance for you -
# workstation -> Proxmox host (scp) -> container (pct push) -> extract, rebuild,
# health check - and then, only if that worked, commits and tags the release in
# your clone and pushes it.
#
# Deploy first, publish second, deliberately. A tag is what other people pull;
# you don't want one pointing at a build that turned out not to start.
#
#   --no-git      deploy only, don't touch the repo
#   --no-deploy   publish only, don't touch the container
#   --yes         don't stop to confirm the commit
#
# Environment overrides:
#   PVE_HOST      root@192.168.50.103   ssh target for the Proxmox host
#   CTID          104                   container id
#   STACK_DIR     /opt/stacks/mdm-scheduler
#   COMPOSE_FILE  compose.dev.yaml      use compose.yaml for the GHCR image
#   REPO_DIR      ~/mdm-scheduler       your git clone
#   BRANCH        main
#   SKIP_BACKUP   (unset)               set to 1 to skip the backup step
set -euo pipefail

PVE_HOST="${PVE_HOST:-root@192.168.50.103}"
CTID="${CTID:-104}"
STACK_DIR="${STACK_DIR:-/opt/stacks/mdm-scheduler}"
COMPOSE_FILE="${COMPOSE_FILE:-compose.dev.yaml}"
BACKUP_DIR="${BACKUP_DIR:-/opt/stacks/mdm-scheduler-backups}"
REPO_DIR="${REPO_DIR:-$HOME/mdm-scheduler}"
BRANCH="${BRANCH:-main}"
STAMP="$(date -u +%Y%m%d-%H%M%S)"

DO_DEPLOY=1
DO_GIT=1
ASSUME_YES=0
TARBALL=""

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33m    %s\033[0m\n' "$*"; }
die()  { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

confirm() {
  [ "$ASSUME_YES" = 1 ] && return 0
  read -r -p "    $1 [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

# `pct exec` gives you no shell, so anything with a pipe or a redirect has to be
# wrapped in one explicitly.
in_ct() { ssh "$PVE_HOST" "pct exec $CTID -- bash -lc $(printf '%q' "$1")"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --no-git)    DO_GIT=0 ;;
    --no-deploy) DO_DEPLOY=0 ;;
    --yes|-y)    ASSUME_YES=1 ;;
    -h|--help)   sed -n '2,25p' "$0"; exit 0 ;;
    -*)          die "unknown option: $1" ;;
    *)           TARBALL="$1" ;;
  esac
  shift
done

# ------------------------------------------------------------------- checks
[ -n "$TARBALL" ] || die "usage: $0 [--no-git|--no-deploy|--yes] <release.tar.gz>"
[ -f "$TARBALL" ] || die "no such file: $TARBALL"
TARBALL="$(cd "$(dirname "$TARBALL")" && pwd)/$(basename "$TARBALL")"

# Listed once into a variable rather than piped into grep: `grep -q` exits at
# the first match, tar takes SIGPIPE, and under `set -o pipefail` that reads as
# a failed check on a perfectly good archive.
LISTING="$(tar -tzf "$TARBALL")"

grep -q '^mdm-scheduler/app/main.py$' <<<"$LISTING" \
  || die "$TARBALL doesn't look like an MDM Scheduler release"

# Refuse to move a tarball carrying secrets, whatever produced it.
grep -qE '^mdm-scheduler/\.env$|\.db$' <<<"$LISTING" \
  && die "that tarball contains a .env or a database - do not use it"

VERSION="$(tar -xzOf "$TARBALL" mdm-scheduler/app/__init__.py | sed -n 's/.*"\(.*\)".*/\1/p')"
[ -n "$VERSION" ] || die "could not read a version out of app/__init__.py"

# A release with no changelog entry is one nobody can read later.
CHANGELOG="$(tar -xzOf "$TARBALL" mdm-scheduler/CHANGELOG.md 2>/dev/null || true)"
grep -q "^## $VERSION\$" <<<"$CHANGELOG" \
  || warn "CHANGELOG.md has no '## $VERSION' section"

say "MDM Scheduler $VERSION"
[ "$DO_DEPLOY" = 1 ] && echo "    deploy  -> CT $CTID at $PVE_HOST"
[ "$DO_GIT" = 1 ]    && echo "    publish -> $REPO_DIR, tag v$VERSION"

# Everything that can refuse the run is checked before anything changes, so a
# duplicate tag or a stopped container fails on the way in rather than halfway.
if [ "$DO_GIT" = 1 ]; then
  [ -d "$REPO_DIR/.git" ] || die "$REPO_DIR is not a git clone (set REPO_DIR)"
  git -C "$REPO_DIR" remote get-url origin >/dev/null 2>&1 \
    || die "$REPO_DIR has no 'origin' remote"

  git -C "$REPO_DIR" rev-parse -q --verify "refs/tags/v$VERSION" >/dev/null \
    && die "tag v$VERSION already exists locally - bump the version or delete the tag"

  say "Fetching $REPO_DIR"
  git -C "$REPO_DIR" fetch --quiet --tags origin || die "git fetch failed"
  git -C "$REPO_DIR" rev-parse -q --verify "refs/tags/v$VERSION" >/dev/null \
    && die "tag v$VERSION is already on the remote - that version is published"

  CURRENT_BRANCH="$(git -C "$REPO_DIR" rev-parse --abbrev-ref HEAD)"
  [ "$CURRENT_BRANCH" = "$BRANCH" ] \
    || warn "clone is on '$CURRENT_BRANCH', not '$BRANCH' - it will push that branch"
fi

if [ "$DO_DEPLOY" = 1 ]; then
  say "Checking the stack"
  STATUS="$(ssh "$PVE_HOST" "pct status $CTID")"
  case "$STATUS" in *running*) ;; *) die "CT $CTID is not running ($STATUS)" ;; esac
  in_ct "test -d $STACK_DIR" || die "$STACK_DIR does not exist in CT $CTID"
  in_ct "command -v docker >/dev/null" || die "docker is not installed in CT $CTID"
  in_ct "test -f $STACK_DIR/.env" \
    || warn ".env not found in $STACK_DIR - the stack may keep its secrets elsewhere"

  CURRENT="$(in_ct "curl -fsS localhost:8000/health 2>/dev/null || true" \
             | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
  if [ -n "$CURRENT" ]; then
    echo "    currently running $CURRENT"
  else
    warn "app is not answering on :8000 yet"
  fi
fi

# ------------------------------------------------------------------- deploy
if [ "$DO_DEPLOY" = 1 ]; then
  if [ -z "${SKIP_BACKUP:-}" ]; then
    say "Backing up data volume, .env and current code"
    in_ct "mkdir -p $BACKUP_DIR"

    # --volumes-from mounts whatever the running container has at /data, so
    # this works regardless of what the volume ended up being named.
    if in_ct "docker ps --format '{{.Names}}' | grep -qx mdm-scheduler"; then
      in_ct "docker run --rm --volumes-from mdm-scheduler -v $BACKUP_DIR:/backup alpine \
               tar czf /backup/data-$STAMP.tar.gz -C /data ." \
        || die "data volume backup failed - stopping before anything is changed"
    else
      warn "mdm-scheduler container is not running; skipping data volume backup"
    fi

    in_ct "cd $STACK_DIR && cp -a .env $BACKUP_DIR/env-$STAMP 2>/dev/null || true"
    in_ct "cd $STACK_DIR && tar czf $BACKUP_DIR/code-$STAMP.tar.gz \
             app templates static compose.yaml compose.dev.yaml requirements.txt 2>/dev/null || true"
    in_ct "chmod 600 $BACKUP_DIR/env-$STAMP 2>/dev/null || true"
    echo "    $BACKUP_DIR/{data,code}-$STAMP.tar.gz and env-$STAMP"
  else
    warn "SKIP_BACKUP set - going ahead with no backup"
  fi

  REMOTE_TMP="/tmp/mdm-scheduler-$STAMP.tar.gz"
  say "Copying to the Proxmox host"
  scp -q "$TARBALL" "$PVE_HOST:$REMOTE_TMP"

  say "Pushing into CT $CTID"
  ssh "$PVE_HOST" "pct push $CTID $REMOTE_TMP /root/mdm-scheduler-release.tar.gz"
  ssh "$PVE_HOST" "rm -f $REMOTE_TMP"

  say "Extracting over $STACK_DIR"
  # .env is not in the archive, so it is never overwritten. Everything else is
  # code and is meant to be replaced.
  in_ct "cd $STACK_DIR && tar -xzf /root/mdm-scheduler-release.tar.gz --strip-components=1"
  in_ct "rm -f /root/mdm-scheduler-release.tar.gz"

  say "Building and starting (a first Caddy build takes a few minutes)"
  in_ct "cd $STACK_DIR && docker compose -f $COMPOSE_FILE up -d --build" \
    || die "compose failed - your old containers may still be running; see rollback below"

  say "Waiting for health"
  NEW=""
  for _ in $(seq 1 45); do
    NEW="$(in_ct "curl -fsS localhost:8000/health 2>/dev/null || true" \
           | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
    [ -n "$NEW" ] && break
    sleep 2
  done
  [ -n "$NEW" ] || die "app never became healthy - check: docker logs mdm-scheduler --tail 100"

  if [ "$NEW" != "$VERSION" ]; then
    warn "expected $VERSION but /health says $NEW - did the app container actually rebuild?"
    if [ "$DO_GIT" = 1 ]; then
      confirm "Publish v$VERSION anyway?" || die "stopped before publishing"
    fi
  fi

  say "Running $NEW"
  in_ct "cd $STACK_DIR && docker compose -f $COMPOSE_FILE ps"

  CERT="$(in_ct "docker exec mdm-scheduler-caddy sh -c 'ls /data/caddy/certificates 2>/dev/null' || true")"
  [ -n "$CERT" ] && echo "    caddy certificates: $(tr '\n' ' ' <<<"$CERT")"
fi

# ------------------------------------------------------------------ publish
if [ "$DO_GIT" = 1 ]; then
  say "Updating $REPO_DIR"
  tar -xzf "$TARBALL" -C "$REPO_DIR" --strip-components=1
  git -C "$REPO_DIR" add -A

  if git -C "$REPO_DIR" diff --cached --quiet; then
    warn "nothing changed in the clone - the tarball matches what is already committed"
    confirm "Tag the current commit as v$VERSION?" || die "stopped"
    git -C "$REPO_DIR" tag "v$VERSION"
    git -C "$REPO_DIR" push -q origin "v$VERSION"
    say "Tagged v$VERSION"
  else
    # Last line of defence. .gitignore covers .env, but a pushed key stays in
    # the history even if the next commit deletes the file.
    # Matches on the shape of the value, not the name of the variable: a real
    # SECRET_KEY is 64 hex characters, while CI fixtures and dev exports say
    # things like SECRET_KEY=ci-secret. Anything shorter than 24 characters of
    # key-ish alphabet is noise, and flagging noise every run is how people
    # learn to type y without reading.
    LEAKS="$(git -C "$REPO_DIR" diff --cached -U0 \
             | grep -E '^\+' \
             | grep -E '(SECRET_KEY|ADMIN_PASSWORD|API_TOKEN|CLIENT_SECRET)[=:][\"'\''[:space:]]*[A-Za-z0-9+/=_-]{24,}|BEGIN [A-Z ]*PRIVATE KEY' \
             | grep -viE 'example|changeme|your-|placeholder|rand -hex' || true)"
    if [ -n "$LEAKS" ]; then
      warn "possible secrets in the staged changes:"
      sed 's/^/      /' <<<"$LEAKS"
      confirm "Commit and push anyway?" || die "stopped - nothing was pushed"
    fi

    echo
    git -C "$REPO_DIR" status --short | sed 's/^/    /'
    echo
    confirm "Commit as \"Release $VERSION\", tag v$VERSION and push?" \
      || die "stopped - the clone has staged changes you can inspect or reset"

    git -C "$REPO_DIR" commit -qm "Release $VERSION"
    git -C "$REPO_DIR" tag "v$VERSION"
    git -C "$REPO_DIR" push -q origin HEAD
    git -C "$REPO_DIR" push -q origin "v$VERSION"
    say "Pushed and tagged v$VERSION"
  fi

  REPO_URL="$(git -C "$REPO_DIR" remote get-url origin \
              | sed -e 's/^git@github.com:/https:\/\/github.com\//' -e 's/\.git$//')"
  echo "    the tag starts the release workflow: $REPO_URL/actions"
  echo "    first release only: make the GHCR package public, or nobody can pull it"
fi

# --------------------------------------------------------------------- done
printf '\n\033[1mDone.\033[0m\n'

if [ "$DO_DEPLOY" = 1 ] && [ -z "${SKIP_BACKUP:-}" ]; then
  cat <<EOF

Rollback, if you need it:

  ssh $PVE_HOST "pct exec $CTID -- bash -lc 'cd $STACK_DIR \\
    && tar -xzf $BACKUP_DIR/code-$STAMP.tar.gz \\
    && cp -a $BACKUP_DIR/env-$STAMP .env \\
    && docker compose -f $COMPOSE_FILE up -d --build'"

The data volume backup is $BACKUP_DIR/data-$STAMP.tar.gz. Restoring it only
makes sense alongside the SECRET_KEY that was in .env at the time - that key
decrypts every stored MDM credential.
EOF
fi
